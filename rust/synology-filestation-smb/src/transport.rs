//! [`SmbTransport`] — an in-process SMB read path for NAS files.
//!
//! Reads bytes over SMB3 (pure Rust, no OS mount, no privileges,
//! cross-platform) so bulk staging bypasses the FileStation HTTP Download API
//! and its shared `synoscgi` backend. This crate is the transport only; a
//! future selection layer (in core / the Python bindings) will prefer it and
//! fall back to the throttled HTTP path when SMB is unavailable.
//!
//! All ops on one transport share a single SMB connection and are serialized
//! behind a mutex — correct and simple. Concurrency across files would use a
//! connection pool (future work).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use smb2::{ClientConfig, SmbClient, Tree};
use synology_filestation_core::{
    ReadTransport, StreamReadTransport, StreamWriteTransport, SynoFsError, SynologyClient,
    WriteTransport,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::error::to_syno_error;
use crate::path::SmbPath;

/// Process-wide sequence making temp write names unique so concurrent writers
/// to the same target don't clobber each other's `.part` file.
static PART_SEQ: AtomicU64 = AtomicU64::new(0);

/// Name of the adjacent temp file an atomic write goes to before the rename.
fn part_name(path: &str, seq: u64) -> String {
    format!("{path}.part-{}-{}", std::process::id(), seq)
}

/// Whether an `smb2` error means the connection itself is dead (so the transport
/// should reconnect before the next operation), vs. a per-request error the live
/// connection can keep serving.
fn is_connection_lost(kind: smb2::ErrorKind) -> bool {
    matches!(
        kind,
        smb2::ErrorKind::ConnectionLost
            | smb2::ErrorKind::TimedOut
            | smb2::ErrorKind::SessionExpired
    )
}

/// Tracks whether the SMB link needs re-establishing. Isolated from `SmbClient`
/// so the reconnect decision is unit-testable without a live connection.
#[derive(Debug, Default)]
struct ReconnectState {
    needs: AtomicBool,
}

impl ReconnectState {
    /// Flag for reconnect if `kind` means the link is dead.
    fn flag_if_lost(&self, kind: smb2::ErrorKind) {
        if is_connection_lost(kind) {
            self.needs.store(true, Ordering::SeqCst);
        }
    }

    /// If flagged, run `reconnect` (clearing the flag first). Returns `Ok(true)`
    /// when a reconnect ran and succeeded — the caller then drops its stale tree
    /// cache. On failure the flag is re-set so the next operation retries, and
    /// the error is returned. `Ok(false)` means no reconnect was needed.
    async fn reconnect_if_needed<F, Fut>(&self, reconnect: F) -> Result<bool, smb2::Error>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), smb2::Error>>,
    {
        if !self.needs.swap(false, Ordering::SeqCst) {
            return Ok(false);
        }
        match reconnect().await {
            Ok(()) => Ok(true),
            Err(e) => {
                self.needs.store(true, Ordering::SeqCst);
                Err(e)
            }
        }
    }
}

/// Map a **local** filesystem error to a *definitive* [`SynoFsError`] (never
/// `Transport`).
///
/// A local failure — disk full, unwritable destination, missing source — can't
/// be fixed by falling back to another transport (HTTP would hit the same local
/// I/O, after buffering the whole file in memory first), so the selection layer
/// must not retry it elsewhere. The detail is logged since the definitive
/// variants carry no message.
fn local_fs_error(what: &str, e: &std::io::Error) -> SynoFsError {
    use std::io::ErrorKind;
    tracing::warn!(error = %e, "{what}");
    match e.kind() {
        ErrorKind::PermissionDenied => SynoFsError::PermissionDenied,
        ErrorKind::NotFound => SynoFsError::NotFound,
        ErrorKind::AlreadyExists => SynoFsError::AlreadyExists,
        // ENOSPC has no stable ErrorKind; detect via the raw errno (28 on unix).
        _ if e.raw_os_error() == Some(28) => SynoFsError::NoSpace,
        // Any other local FS failure is still definitive — don't fall back.
        _ => SynoFsError::InvalidArg,
    }
}

/// Connection parameters for [`SmbTransport::connect`].
#[derive(Debug, Clone)]
pub struct SmbConfig {
    /// NAS host, either `host` or `host:port`. If no port is present, [`port`]
    /// is appended.
    ///
    /// [`port`]: Self::port
    pub host: String,
    /// Port used when `host` carries none. SMB is 445.
    pub port: u16,
    /// Account name (the sAMAccountName for AD users, e.g. `c.crutchfield.642`).
    pub username: String,
    /// Password (kept in memory by the SMB client for the session lifetime).
    pub password: String,
    /// NetBIOS domain for AD accounts (e.g. `KRG`); empty for local DSM users.
    pub domain: String,
    /// Connection/negotiate timeout.
    pub timeout: Duration,
}

impl SmbConfig {
    /// A config with the SMB defaults (port 445, 10 s timeout, no domain).
    pub fn new(
        host: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port: 445,
            username: username.into(),
            password: password.into(),
            domain: String::new(),
            timeout: Duration::from_secs(10),
        }
    }

    /// Build an auto-SMB config from the same credentials the HTTP login uses,
    /// parsing the domain out of the username so AD accounts work with no extra
    /// input: `DOMAIN\user`, or `user@REALM` (NetBIOS domain = the first realm
    /// label, upper-cased — e.g. `KRG.LOCAL` → `KRG`), else a local account with
    /// no domain. Port defaults to 445.
    pub fn from_login(host: &str, username: &str, password: &str) -> Self {
        let (domain, user) = if let Some((d, u)) = username.split_once('\\') {
            (d.to_string(), u.to_string())
        } else if let Some((u, realm)) = username.split_once('@') {
            let netbios = realm.split('.').next().unwrap_or(realm).to_uppercase();
            (netbios, u.to_string())
        } else {
            (String::new(), username.to_string())
        };
        let mut cfg = SmbConfig::new(host, user, password);
        cfg.domain = domain;
        cfg
    }

    fn addr(&self) -> String {
        if self.host.contains(':') {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Transparently connect an SMB backend from the HTTP login credentials, for the
/// "always prefer SMB when reachable" policy — so bulk transfers avoid the HTTP
/// Download/Upload API (and the shared `synoscgi` backend it can saturate).
///
/// Returns `None` (→ HTTP only) whenever SMB is disabled, unreachable, or auth
/// fails — **never** an error, so a failed probe silently degrades to HTTP. A
/// short probe timeout bounds the cost off-network (where port 445 is dropped),
/// and the caller's circuit breaker takes over from there.
///
/// Deploy escape hatches (environment, invisible to any public API):
/// * `SYNOLOGY_FS_SMB_DISABLE` (any value) — never use SMB.
/// * `SYNOLOGY_FS_SMB_DOMAIN` — override the domain parsed from the username.
/// * `SYNOLOGY_FS_SMB_PORT` — override the SMB port (default 445).
/// * `SYNOLOGY_FS_SMB_TIMEOUT_MS` — probe timeout (default 2000).
pub async fn auto_connect(host: &str, username: &str, password: &str) -> Option<Arc<SmbTransport>> {
    if std::env::var_os("SYNOLOGY_FS_SMB_DISABLE").is_some() {
        return None;
    }
    let mut cfg = SmbConfig::from_login(host, username, password);
    if let Ok(domain) = std::env::var("SYNOLOGY_FS_SMB_DOMAIN") {
        cfg.domain = domain;
    }
    if let Some(port) = std::env::var("SYNOLOGY_FS_SMB_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        cfg.port = port;
    }
    cfg.timeout = Duration::from_millis(
        std::env::var("SYNOLOGY_FS_SMB_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2000),
    );

    match SmbTransport::connect(&cfg).await {
        Ok(transport) => {
            tracing::info!(host, "SMB transport enabled; preferring it over HTTP");
            Some(Arc::new(transport))
        }
        Err(e) => {
            tracing::debug!(host, error = %e, "SMB unavailable; using HTTP only");
            None
        }
    }
}

/// [`auto_connect`] + attach: connect SMB from the login credentials and inject
/// it into `client` as the preferred backend for **reads, writes, and streaming
/// transfers**. Returns the client unchanged when SMB is unavailable.
///
/// This one call is the entire consumer integration — a consumer never lists the
/// individual backends, so adding a future backend here never touches consumers.
pub async fn auto_attach(
    client: SynologyClient,
    host: &str,
    username: &str,
    password: &str,
) -> SynologyClient {
    match auto_connect(host, username, password).await {
        Some(smb) => client
            .with_read_transport(smb.clone())
            .with_write_transport(smb.clone())
            .with_stream_write_transport(smb.clone())
            .with_stream_read_transport(smb),
        None => client,
    }
}

/// Minimal file metadata — enough for the verify-once integrity check that
/// compares SMB against the FileStation API's `getinfo` before trusting SMB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub size: u64,
    pub is_directory: bool,
}

struct Inner {
    client: SmbClient,
    /// One attached `Tree` per share name, connected lazily on first use.
    trees: HashMap<String, Tree>,
}

/// An authenticated SMB connection that reads NAS files.
pub struct SmbTransport {
    inner: Mutex<Inner>,
    /// Tracks whether the SMB link needs re-establishing. `smb2` doesn't
    /// auto-reconnect, so without this a mount would degrade to HTTP permanently
    /// after one network flap.
    reconnect: ReconnectState,
}

impl SmbTransport {
    /// Connect + authenticate (SMB3 negotiate, NTLMv2, signing).
    pub async fn connect(cfg: &SmbConfig) -> Result<Self, SynoFsError> {
        let client = SmbClient::connect(ClientConfig {
            addr: cfg.addr(),
            timeout: cfg.timeout,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            domain: cfg.domain.clone(),
            auto_reconnect: false,
            compression: true,
            dfs_enabled: true,
            dfs_target_overrides: HashMap::new(),
        })
        .await
        .map_err(|e| to_syno_error(&e))?;
        Ok(Self {
            inner: Mutex::new(Inner {
                client,
                trees: HashMap::new(),
            }),
            reconnect: ReconnectState::default(),
        })
    }

    /// Map an `smb2::Error`, flagging the connection for reconnect when the
    /// error means the link is dead — so the next operation re-establishes it.
    fn mark_and_map(&self, e: &smb2::Error) -> SynoFsError {
        self.reconnect.flag_if_lost(e.kind());
        to_syno_error(e)
    }

    /// Run a best-effort cleanup op, ignoring its result **except** to flag the
    /// link for reconnect if it revealed a dead connection.
    fn note_cleanup(&self, r: Result<(), smb2::Error>) {
        if let Err(e) = r {
            self.reconnect.flag_if_lost(e.kind());
        }
    }

    /// Reconnect if a prior operation flagged the SMB link dead, then attach the
    /// share. This is what lets a long-lived mount recover after a network flap:
    /// once the network is back, the next operation (e.g. a circuit-breaker
    /// half-open probe) rebuilds the session here and succeeds, closing the
    /// breaker — instead of degrading to HTTP for the rest of the session.
    async fn ensure_ready(
        &self,
        client: &mut SmbClient,
        trees: &mut HashMap<String, Tree>,
        share: &str,
    ) -> Result<(), SynoFsError> {
        let reconnected = self
            .reconnect
            .reconnect_if_needed(|| client.reconnect())
            .await
            .map_err(|e| self.mark_and_map(&e))?;
        if reconnected {
            trees.clear(); // the cached trees belonged to the dead session
        }
        if !trees.contains_key(share) {
            let tree = client
                .connect_share(share)
                .await
                .map_err(|e| self.mark_and_map(&e))?;
            trees.insert(share.to_string(), tree);
        }
        Ok(())
    }

    /// Commit a fully-written temp file onto `target` with an **old-or-new**
    /// guarantee (fast rename, or move-aside on a name collision). See the
    /// module note; shared by `write_atomic` and `write_from_path`.
    async fn commit_temp(
        &self,
        client: &mut SmbClient,
        tree: &mut Tree,
        tmp: &str,
        target: &str,
        seq: u64,
    ) -> Result<(), SynoFsError> {
        match client.rename(tree, tmp, target).await {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == smb2::ErrorKind::AlreadyExists => {} // replace below
            Err(e) => {
                self.note_cleanup(client.delete_file(tree, tmp).await);
                return Err(self.mark_and_map(&e));
            }
        }
        // Move the old file aside so no step ever deletes the only copy.
        let backup = part_name(&format!("{target}.bak"), seq);
        if let Err(e) = client.rename(tree, target, &backup).await {
            self.note_cleanup(client.delete_file(tree, tmp).await);
            return Err(self.mark_and_map(&e));
        }
        match client.rename(tree, tmp, target).await {
            Ok(()) => {
                self.note_cleanup(client.delete_file(tree, &backup).await); // best-effort
                Ok(())
            }
            Err(e) => {
                self.note_cleanup(client.rename(tree, &backup, target).await); // restore old
                Err(self.mark_and_map(&e))
            }
        }
    }

    /// Metadata for a logical path (`/share/sub/file`).
    pub async fn stat(&self, logical: &str) -> Result<FileMeta, SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let mut guard = self.inner.lock().await;
        let Inner { client, trees } = &mut *guard;
        self.ensure_ready(client, trees, &loc.share).await?;
        let tree = trees.get_mut(&loc.share).expect("tree just ensured");
        let info = client
            .stat(tree, &loc.path)
            .await
            .map_err(|e| self.mark_and_map(&e))?;
        Ok(FileMeta {
            size: info.size,
            is_directory: info.is_directory,
        })
    }

    /// Read `length` bytes at `offset`. `length == 0` reads the whole file
    /// (from `offset == 0`), mirroring the core HTTP client's `download`
    /// contract. Ranged reads are chunked to the server's `MaxReadSize` by the
    /// underlying SMB layer, so any `length` is valid.
    pub async fn read(
        &self,
        logical: &str,
        offset: u64,
        length: u64,
    ) -> Result<Bytes, SynoFsError> {
        if length == 0 {
            return self.read_full(logical).await;
        }
        let loc = SmbPath::from_logical(logical)?;
        let guard = self.inner.lock().await;
        // open_file_reader takes &SmbClient + &Tree (shared); ensure the tree
        // under a short mutable reborrow, then read.
        let mut guard = guard;
        {
            let Inner { client, trees } = &mut *guard;
            self.ensure_ready(client, trees, &loc.share).await?;
        }
        let Inner { client, trees } = &*guard;
        let tree = trees.get(&loc.share).expect("tree just ensured");
        let reader = client
            .open_file_reader(tree, &loc.path)
            .await
            .map_err(|e| self.mark_and_map(&e))?;
        let data = reader
            .read_at(offset, length)
            .await
            .map_err(|e| self.mark_and_map(&e))?;
        Ok(Bytes::from(data))
    }

    /// Delete a file at `logical`.
    pub async fn delete(&self, logical: &str) -> Result<(), SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let mut guard = self.inner.lock().await;
        let Inner { client, trees } = &mut *guard;
        self.ensure_ready(client, trees, &loc.share).await?;
        let tree = trees.get_mut(&loc.share).expect("tree just ensured");
        client
            .delete_file(tree, &loc.path)
            .await
            .map_err(|e| self.mark_and_map(&e))
    }

    /// Read an entire file. Uses the pipelined, chunked read so multi-MB `.ORF`
    /// files (past the 8 MiB `MaxReadSize`) come back whole.
    pub async fn read_full(&self, logical: &str) -> Result<Bytes, SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let mut guard = self.inner.lock().await;
        let Inner { client, trees } = &mut *guard;
        self.ensure_ready(client, trees, &loc.share).await?;
        let tree = trees.get_mut(&loc.share).expect("tree just ensured");
        let data = client
            .read_file_pipelined(tree, &loc.path)
            .await
            .map_err(|e| self.mark_and_map(&e))?;
        Ok(Bytes::from(data))
    }

    /// Stream a remote file to the local path `local` **without buffering it in
    /// memory** — for fetching large files. Chunks stream from SMB straight to a
    /// local temp file, which is fsynced and renamed onto `local` (atomic
    /// old-or-nothing; a failure leaves no destination).
    pub async fn read_to_path(&self, logical: &str, local: &Path) -> Result<(), SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let tmp = {
            let mut t = local.as_os_str().to_os_string();
            t.push(".part");
            std::path::PathBuf::from(t)
        };

        let result: Result<(), SynoFsError> = async {
            let mut guard = self.inner.lock().await;
            let Inner { client, trees } = &mut *guard;
            self.ensure_ready(client, trees, &loc.share).await?;

            // Streaming download handle (owned; retains no borrow of client).
            let mut download = {
                let tree = trees.get(&loc.share).expect("tree just ensured");
                client
                    .download(tree, &loc.path)
                    .await
                    .map_err(|e| self.mark_and_map(&e))?
            };

            // Pump SMB → local temp in bounded chunks (constant memory).
            let mut file = tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| local_fs_error(&format!("create {}", tmp.display()), &e))?;
            while let Some(chunk) = download.next_chunk().await {
                let bytes = chunk.map_err(|e| self.mark_and_map(&e))?;
                file.write_all(&bytes)
                    .await
                    .map_err(|e| local_fs_error(&format!("write {}", tmp.display()), &e))?;
            }
            file.sync_all()
                .await
                .map_err(|e| local_fs_error(&format!("fsync {}", tmp.display()), &e))?;
            drop(file);
            tokio::fs::rename(&tmp, local)
                .await
                .map_err(|e| local_fs_error(&format!("rename to {}", local.display()), &e))
        }
        .await;

        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await; // best-effort cleanup
        }
        result
    }

    /// Replace the file at `logical` with `data`, guaranteeing **old-or-new**:
    /// a reader always sees either the previous file or the fully-written new
    /// one — never a partial/corrupt file — and no data is lost on failure.
    /// That is what makes the selection layer's fallback to HTTP safe.
    ///
    /// New bytes go to an adjacent temp file first. If the target name is free,
    /// a single rename commits. If it already exists (DSM's rename is
    /// `ReplaceIfExists=false`, so it can't replace in one step) the old file is
    /// moved aside to a backup, the new file is renamed in, and the backup is
    /// dropped; a failure mid-swap restores the old file, and the new bytes stay
    /// in the temp — so no copy of the data is ever the only casualty of a
    /// failed step.
    ///
    /// Caveat: during the swap there is a brief window where the target *name*
    /// is momentarily absent (the bytes are safe in the backup/temp). A truly
    /// atomic replace needs `ReplaceIfExists=true` in the SMB layer — tracked as
    /// a follow-up.
    pub async fn write_atomic(&self, logical: &str, data: &[u8]) -> Result<(), SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let seq = PART_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = part_name(&loc.path, seq);

        let mut guard = self.inner.lock().await;
        let Inner { client, trees } = &mut *guard;
        self.ensure_ready(client, trees, &loc.share).await?;
        let tree = trees.get_mut(&loc.share).expect("tree just ensured");

        // New contents → temp file adjacent to the target (pipelined, so files
        // past the server's MaxWriteSize go in chunks).
        if let Err(e) = client.write_file_pipelined(tree, &tmp, data).await {
            self.note_cleanup(client.delete_file(tree, &tmp).await); // best-effort cleanup
            return Err(self.mark_and_map(&e));
        }

        self.commit_temp(client, tree, &tmp, &loc.path, seq).await
    }

    /// Stream a local file to `logical` (old-or-new) **without buffering it in
    /// memory** — for staging large files. Chunks are read from disk and written
    /// straight to an SMB temp file via a streaming writer, then committed onto
    /// the target with the same move-aside guarantee as [`write_atomic`].
    ///
    /// [`write_atomic`]: Self::write_atomic
    pub async fn write_from_path(&self, logical: &str, local: &Path) -> Result<(), SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let seq = PART_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = part_name(&loc.path, seq);

        let mut file = tokio::fs::File::open(local)
            .await
            .map_err(|e| local_fs_error(&format!("open {}", local.display()), &e))?;

        let mut guard = self.inner.lock().await;
        let Inner { client, trees } = &mut *guard;
        self.ensure_ready(client, trees, &loc.share).await?;

        // Streaming writer to the temp file (owned; retains no borrow of client).
        let mut writer = {
            let tree = trees.get(&loc.share).expect("tree just ensured");
            match client.create_file_writer(tree, &tmp).await {
                Ok(w) => w,
                Err(e) => return Err(self.mark_and_map(&e)),
            }
        };

        // Pump disk → SMB in bounded chunks (constant memory, ~1 MiB).
        let mut buf = vec![0u8; 1 << 20];
        let mut stream_err: Option<SynoFsError> = None;
        loop {
            match file.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = writer.write_chunk(&buf[..n]).await {
                        stream_err = Some(self.mark_and_map(&e));
                        break;
                    }
                }
                Err(e) => {
                    stream_err = Some(SynoFsError::Io(format!("read {}: {e}", local.display())));
                    break;
                }
            }
        }
        // Always finalize to close the SMB handle; surface a finish error only if
        // the pump itself hadn't already failed.
        if let Err(e) = writer.finish().await {
            stream_err.get_or_insert_with(|| self.mark_and_map(&e));
        }

        if let Some(e) = stream_err {
            let tree = trees.get_mut(&loc.share).expect("tree just ensured");
            self.note_cleanup(client.delete_file(tree, &tmp).await); // best-effort cleanup
            return Err(e);
        }

        let tree = trees.get_mut(&loc.share).expect("tree just ensured");
        self.commit_temp(client, tree, &tmp, &loc.path, seq).await
    }
}

// ── core transport traits (dependency inversion) ─────────────────────────────
//
// Implementing these is the entire integration surface: SynologyClient prefers
// an injected backend over HTTP and falls back on transport failures, with no
// change to any read/write call site.

#[async_trait]
impl ReadTransport for SmbTransport {
    async fn read(&self, path: &str, offset: u64, length: u64) -> Result<Bytes, SynoFsError> {
        // Delegate to the inherent method (inherent wins over the trait method
        // for this path syntax, so this is not recursive).
        SmbTransport::read(self, path, offset, length).await
    }
}

#[async_trait]
impl WriteTransport for SmbTransport {
    async fn write(&self, path: &str, data: &[u8]) -> Result<(), SynoFsError> {
        self.write_atomic(path, data).await
    }
}

#[async_trait]
impl StreamWriteTransport for SmbTransport {
    async fn write_from_path(&self, remote_path: &str, local: &Path) -> Result<(), SynoFsError> {
        SmbTransport::write_from_path(self, remote_path, local).await
    }
}

#[async_trait]
impl StreamReadTransport for SmbTransport {
    async fn read_to_path(&self, remote_path: &str, local: &Path) -> Result<(), SynoFsError> {
        SmbTransport::read_to_path(self, remote_path, local).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_lost_kinds_trigger_reconnect() {
        // These mean the link is dead → reconnect before the next op.
        assert!(is_connection_lost(smb2::ErrorKind::ConnectionLost));
        assert!(is_connection_lost(smb2::ErrorKind::TimedOut));
        assert!(is_connection_lost(smb2::ErrorKind::SessionExpired));
        // These are per-request; the connection is still good.
        assert!(!is_connection_lost(smb2::ErrorKind::NotFound));
        assert!(!is_connection_lost(smb2::ErrorKind::AccessDenied));
        assert!(!is_connection_lost(smb2::ErrorKind::SharingViolation));
    }

    #[tokio::test]
    async fn reconnect_runs_only_when_flagged_then_clears() {
        let state = ReconnectState::default();
        // Not flagged → no reconnect, and the closure is never run.
        let ran = state
            .reconnect_if_needed(|| async { panic!("should not reconnect") })
            .await
            .unwrap();
        assert!(!ran);

        // A connection-lost error flags it → reconnect runs once and succeeds.
        state.flag_if_lost(smb2::ErrorKind::ConnectionLost);
        let ran = state
            .reconnect_if_needed(|| async { Ok(()) })
            .await
            .unwrap();
        assert!(
            ran,
            "flagged → reconnect ran (caller clears its tree cache)"
        );

        // Flag cleared on success → the next op is a no-op again.
        let ran = state
            .reconnect_if_needed(|| async { panic!("should not reconnect") })
            .await
            .unwrap();
        assert!(!ran);
    }

    #[tokio::test]
    async fn failed_reconnect_keeps_the_flag_set_for_retry() {
        let state = ReconnectState::default();
        state.flag_if_lost(smb2::ErrorKind::TimedOut);
        // Reconnect fails → error surfaces, flag stays set.
        assert!(state
            .reconnect_if_needed(|| async { Err(smb2::Error::Disconnected) })
            .await
            .is_err());
        // Still flagged → the next operation retries the reconnect.
        let ran = state
            .reconnect_if_needed(|| async { Ok(()) })
            .await
            .unwrap();
        assert!(ran, "flag persisted so reconnect is retried");
    }

    #[tokio::test]
    async fn per_request_errors_do_not_flag_reconnect() {
        let state = ReconnectState::default();
        state.flag_if_lost(smb2::ErrorKind::NotFound); // not a link failure
        let ran = state
            .reconnect_if_needed(|| async { panic!("should not reconnect") })
            .await
            .unwrap();
        assert!(!ran);
    }

    #[test]
    fn part_name_is_adjacent_and_unique_per_seq() {
        let pid = std::process::id();
        assert_eq!(
            part_name("REEF/img.orf", 7),
            format!("REEF/img.orf.part-{pid}-7")
        );
        // Different sequence numbers yield different temp names (so concurrent
        // writers to the same target don't collide).
        assert_ne!(part_name("x", 1), part_name("x", 2));
    }

    #[test]
    fn from_login_parses_domain_from_username() {
        // DOMAIN\user — unambiguous.
        let c = SmbConfig::from_login("nas", "KRG\\c.crutchfield.642", "pw");
        assert_eq!(c.domain, "KRG");
        assert_eq!(c.username, "c.crutchfield.642");

        // user@REALM (UPN) — NetBIOS domain is the first realm label, upper-cased.
        let c = SmbConfig::from_login("nas", "c.crutchfield.642@krg.local", "pw");
        assert_eq!(c.domain, "KRG");
        assert_eq!(c.username, "c.crutchfield.642");

        // Local account — no domain.
        let c = SmbConfig::from_login("nas", "admin", "pw");
        assert_eq!(c.domain, "");
        assert_eq!(c.username, "admin");
        assert_eq!(c.port, 445);
    }

    #[test]
    fn smbconfig_new_defaults_and_addr() {
        let cfg = SmbConfig::new("nas.example.com", "user", "pass");
        assert_eq!(cfg.port, 445);
        assert_eq!(cfg.addr(), "nas.example.com:445");
        let cfg2 = SmbConfig::new("nas.example.com:1445", "user", "pass");
        assert_eq!(
            cfg2.addr(),
            "nas.example.com:1445",
            "explicit port preserved"
        );
    }
}

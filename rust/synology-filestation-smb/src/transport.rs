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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use smb2::{ClientConfig, SmbClient, Tree};
use synology_filestation_core::{ReadTransport, SynoFsError, WriteTransport};
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
        })
    }

    /// Metadata for a logical path (`/share/sub/file`).
    pub async fn stat(&self, logical: &str) -> Result<FileMeta, SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let mut guard = self.inner.lock().await;
        let Inner { client, trees } = &mut *guard;
        ensure_tree(client, trees, &loc.share).await?;
        let tree = trees.get_mut(&loc.share).expect("tree just ensured");
        let info = client
            .stat(tree, &loc.path)
            .await
            .map_err(|e| to_syno_error(&e))?;
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
            ensure_tree(client, trees, &loc.share).await?;
        }
        let Inner { client, trees } = &*guard;
        let tree = trees.get(&loc.share).expect("tree just ensured");
        let reader = client
            .open_file_reader(tree, &loc.path)
            .await
            .map_err(|e| to_syno_error(&e))?;
        let data = reader
            .read_at(offset, length)
            .await
            .map_err(|e| to_syno_error(&e))?;
        Ok(Bytes::from(data))
    }

    /// Delete a file at `logical`.
    pub async fn delete(&self, logical: &str) -> Result<(), SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let mut guard = self.inner.lock().await;
        let Inner { client, trees } = &mut *guard;
        ensure_tree(client, trees, &loc.share).await?;
        let tree = trees.get_mut(&loc.share).expect("tree just ensured");
        client
            .delete_file(tree, &loc.path)
            .await
            .map_err(|e| to_syno_error(&e))
    }

    /// Read an entire file. Uses the pipelined, chunked read so multi-MB `.ORF`
    /// files (past the 8 MiB `MaxReadSize`) come back whole.
    pub async fn read_full(&self, logical: &str) -> Result<Bytes, SynoFsError> {
        let loc = SmbPath::from_logical(logical)?;
        let mut guard = self.inner.lock().await;
        let Inner { client, trees } = &mut *guard;
        ensure_tree(client, trees, &loc.share).await?;
        let tree = trees.get_mut(&loc.share).expect("tree just ensured");
        let data = client
            .read_file_pipelined(tree, &loc.path)
            .await
            .map_err(|e| to_syno_error(&e))?;
        Ok(Bytes::from(data))
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
        ensure_tree(client, trees, &loc.share).await?;
        let tree = trees.get_mut(&loc.share).expect("tree just ensured");

        // New contents → temp file adjacent to the target (pipelined, so files
        // past the server's MaxWriteSize go in chunks).
        if let Err(e) = client.write_file_pipelined(tree, &tmp, data).await {
            let _ = client.delete_file(tree, &tmp).await; // best-effort cleanup
            return Err(to_syno_error(&e));
        }

        // Fast path: the target name is free → a single rename commits.
        match client.rename(tree, &tmp, &loc.path).await {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == smb2::ErrorKind::AlreadyExists => {} // replace below
            Err(e) => {
                let _ = client.delete_file(tree, &tmp).await;
                return Err(to_syno_error(&e));
            }
        }

        // Replace path: move the old file aside, move the new one in, drop the
        // backup. We never delete the only copy of the data, so a failure at any
        // step leaves the old file recoverable (from the backup) and the new
        // bytes recoverable (from the temp).
        let backup = part_name(&format!("{}.bak", loc.path), seq);
        if let Err(e) = client.rename(tree, &loc.path, &backup).await {
            let _ = client.delete_file(tree, &tmp).await;
            return Err(to_syno_error(&e));
        }
        match client.rename(tree, &tmp, &loc.path).await {
            Ok(()) => {
                let _ = client.delete_file(tree, &backup).await; // best-effort
                Ok(())
            }
            Err(e) => {
                // Put the old file back; leave the new bytes in `tmp`.
                let _ = client.rename(tree, &backup, &loc.path).await;
                Err(to_syno_error(&e))
            }
        }
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

/// Attach `share` if it isn't already, caching the `Tree`. Split borrows of the
/// two `Inner` fields so callers can then use `client` and the tree together.
async fn ensure_tree(
    client: &mut SmbClient,
    trees: &mut HashMap<String, Tree>,
    share: &str,
) -> Result<(), SynoFsError> {
    if !trees.contains_key(share) {
        let tree = client
            .connect_share(share)
            .await
            .map_err(|e| to_syno_error(&e))?;
        trees.insert(share.to_string(), tree);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

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
use std::time::Duration;

use bytes::Bytes;
use smb2::{ClientConfig, SmbClient, Tree};
use synology_filestation_core::SynoFsError;
use tokio::sync::Mutex;

use crate::error::to_syno_error;
use crate::path::SmbPath;

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

    fn addr(&self) -> String {
        if self.host.contains(':') {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
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

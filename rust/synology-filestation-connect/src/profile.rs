//! Getting the tunnel's configuration onto the client.
//!
//! The profile is one file, the same for every user: OpenVPN authenticates
//! people by AD username and password (`verify-client-cert none`), so there are
//! no per-user certificates to issue, renew or revoke. What it *does* embed is
//! the `tls-auth` key, which drops packets without a valid HMAC before OpenVPN
//! does any TLS work. That makes the file a **shared secret** — not a
//! credential, but the thing keeping internet background scanning off the
//! daemon — so it is kept readable only by its owner and never logged.
//!
//! ## Why fetching beats shipping
//!
//! The alternative is baking it into the installer, which turns any change to
//! the server config into a release. Fetching also removes the bootstrap
//! problem: the NAS publishes it on a share readable by every AD user, over the
//! same HTTPS the chain already authenticates against *before* any tunnel
//! exists. A user off campus with no tunnel can still get the file that gives
//! them one.

use std::path::{Path, PathBuf};

use synology_filestation_core::{SynoFsError, SynologyClient};
use tracing::{debug, info};

/// Where the profile lives, on the NAS and on this machine.
#[derive(Debug, Clone)]
pub struct ProfileSource {
    /// Path on the NAS. On e4e-nas this is `/installers/e4e-nas-vpn.ovpn`,
    /// published to a share that is readable by `@users` and writable only by
    /// admins.
    pub remote: String,
    /// Where to keep the copy. The caller chooses, because only it knows the
    /// platform's app-data conventions — and because a CLI user may point at a
    /// profile their IT handed them instead.
    pub local: PathBuf,
}

impl ProfileSource {
    /// Fetch the profile if it is not already here.
    ///
    /// Cheap on the common path: an existing copy is used as-is, so a mount
    /// does not re-download the file on every connect.
    pub async fn ensure(&self, client: &SynologyClient) -> Result<PathBuf, SynoFsError> {
        if tokio::fs::metadata(&self.local).await.is_ok() {
            debug!("vpn profile: using the copy at {}", self.local.display());
            return Ok(self.local.clone());
        }
        self.refresh(client).await
    }

    /// Fetch the profile, replacing any copy already here.
    ///
    /// Worth doing when the tunnel refuses to come up: the server's key or
    /// address may have changed under a cached file, and re-fetching is far
    /// cheaper than diagnosing that by hand.
    pub async fn refresh(&self, client: &SynologyClient) -> Result<PathBuf, SynoFsError> {
        if let Some(dir) = self.local.parent() {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|e| SynoFsError::Io(format!("vpn profile: {} : {e}", dir.display())))?;
            // Lock the directory down *before* the file lands in it. The
            // download writes with the process umask, so on a shared machine
            // there is otherwise a window where a world-readable copy of a
            // shared secret exists.
            restrict_dir(dir)?;
        }

        info!("vpn profile: fetching {}", self.remote);
        client.download_to_path(&self.remote, &self.local).await?;
        restrict_file(&self.local)?;
        Ok(self.local.clone())
    }
}

/// Make a directory reachable only by its owner (`0700`).
#[cfg(unix)]
fn restrict_dir(dir: &Path) -> Result<(), SynoFsError> {
    set_mode(dir, 0o700)
}

/// Make a file readable only by its owner (`0600`).
#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), SynoFsError> {
    set_mode(path, 0o600)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), SynoFsError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        SynoFsError::Io(format!(
            "vpn profile: cannot restrict {} : {e}",
            path.display()
        ))
    })
}

/// Windows has no mode bits; a file in the user's own app-data inherits an ACL
/// that already excludes other users, so there is nothing to tighten here.
#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) -> Result<(), SynoFsError> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<(), SynoFsError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path as path_matcher, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PROFILE: &[u8] =
        b"client\nremote e4e-nas.ucsd.edu 1194 udp\n<tls-auth>\nSECRET\n</tls-auth>\n";

    fn client_for(server: &MockServer) -> SynologyClient {
        let uri = server.uri();
        let (host, port) = uri
            .trim_start_matches("http://")
            .rsplit_once(':')
            .expect("host:port");
        SynologyClient::new(host, port.parse().unwrap(), false)
    }

    async fn mount_download(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path_matcher("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/octet-stream")
                    .set_body_bytes(PROFILE.to_vec()),
            )
            .mount(server)
            .await;
    }

    fn scratch(name: &str) -> PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "syno-vpn-{}-{}-{name}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        p.push("e4e-nas-vpn.ovpn");
        p
    }

    fn source(local: PathBuf) -> ProfileSource {
        ProfileSource {
            remote: "/installers/e4e-nas-vpn.ovpn".to_string(),
            local,
        }
    }

    #[tokio::test]
    async fn a_missing_profile_is_fetched_from_the_share() {
        let server = MockServer::start().await;
        mount_download(&server).await;
        let src = source(scratch("fetch"));

        let got = src.ensure(&client_for(&server)).await.unwrap();

        assert_eq!(tokio::fs::read(&got).await.unwrap(), PROFILE);
        std::fs::remove_dir_all(got.parent().unwrap()).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_fetched_profile_is_readable_only_by_its_owner() {
        // It embeds ta.key. Not a per-user credential, but the thing that keeps
        // internet scanning off the daemon — so a world-readable copy on a
        // shared machine hands that away.
        use std::os::unix::fs::PermissionsExt;

        let server = MockServer::start().await;
        mount_download(&server).await;
        let src = source(scratch("perms"));

        let got = src.ensure(&client_for(&server)).await.unwrap();

        let file = std::fs::metadata(&got).unwrap().permissions().mode() & 0o777;
        let dir = std::fs::metadata(got.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file, 0o600, "file mode");
        assert_eq!(
            dir, 0o700,
            "the directory is locked before the file lands in it, so the \
             download's umask never leaves a readable window"
        );
        std::fs::remove_dir_all(got.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn an_existing_profile_is_not_re_fetched() {
        let server = MockServer::start().await;
        mount_download(&server).await;
        let src = source(scratch("cached"));
        let client = client_for(&server);

        src.ensure(&client).await.unwrap();
        src.ensure(&client).await.unwrap();

        let downloads = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.query().is_some_and(|q| q.contains("method=download")))
            .count();
        assert_eq!(downloads, 1, "the second connect used the copy it had");
        std::fs::remove_dir_all(src.local.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn refresh_replaces_a_stale_copy() {
        // What to do when the tunnel will not come up: the server's key or
        // address may have moved under a cached file.
        let server = MockServer::start().await;
        mount_download(&server).await;
        let src = source(scratch("refresh"));
        let client = client_for(&server);

        src.ensure(&client).await.unwrap();
        std::fs::write(&src.local, b"stale").unwrap();
        src.refresh(&client).await.unwrap();

        assert_eq!(tokio::fs::read(&src.local).await.unwrap(), PROFILE);
        std::fs::remove_dir_all(src.local.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn a_failed_fetch_leaves_no_half_written_profile() {
        // A truncated .ovpn is worse than none: OpenVPN would fail somewhere
        // less obvious than "there is no config".
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_matcher("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let src = source(scratch("failed"));

        assert!(src.ensure(&client_for(&server)).await.is_err());
        assert!(
            !src.local.exists(),
            "nothing was left behind for the next connect to trust"
        );
        std::fs::remove_dir_all(src.local.parent().unwrap()).ok();
    }
}

use std::sync::RwLock;
use std::time::Duration;
use bytes::Bytes;
use reqwest::{Client, multipart};
use tracing::debug;

use crate::error::SynoFsError;
use crate::types::{
    AuthData, CreateFolderData, GetInfoData, ListData, ListShareData, RenameData, UploadData,
    SynoFileInfo, SynoResponse, ADDITIONAL_FIELDS, SHARE_ADDITIONAL_FIELDS,
};

#[derive(Debug)]
pub struct SynologyClient {
    http: Client,
    base_url: String,
    sid: RwLock<Option<String>>,
}

impl SynologyClient {
    pub fn new(host: &str, port: u16, https: bool) -> Self {
        let scheme = if https { "https" } else { "http" };
        let base_url = format!("{}://{}:{}/webapi", scheme, host, port);
        let http = Client::builder()
            .danger_accept_invalid_certs(true) // common for self-signed NAS certs
            // Drop idle connections after 4 s so we don't reuse connections the NAS
            // has already closed on its side (~7 s keep-alive on most DSM versions).
            .pool_idle_timeout(Duration::from_secs(4))
            // Fail fast if the NAS is unreachable rather than waiting for the OS-level
            // TCP timeout (~75 s on macOS, ETIMEDOUT / os error 60).
            .connect_timeout(Duration::from_secs(10))
            // Send TCP keepalive probes so stalled mid-transfer connections are
            // detected in seconds rather than waiting for the full OS TCP timeout
            // (~75 s on macOS, ETIMEDOUT / os error 60).
            .tcp_keepalive(Duration::from_secs(10))
            // Bound how long we'll wait for data on a request. Without this, a
            // silently-dead connection (e.g. routes changed when a VPN comes up
            // mid-session) hangs the FUSE callback indefinitely — the user sees
            // their file manager freeze with no error. read_timeout fires when
            // no bytes have arrived for the duration, so it doesn't cap
            // legitimately long large-file uploads.
            .read_timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self { http, base_url, sid: RwLock::new(None) }
    }

    fn sid(&self) -> String {
        self.sid.read().unwrap().clone().unwrap_or_default()
    }

    /// Issue a GET request and return the response body as a string, retrying up
    /// to 3 times on transient connection errors (connection reset, read
    /// timeout, etc.). Used by every read-only API call so a momentary network
    /// blip — e.g. a VPN coming up and silently killing existing TCP
    /// connections — recovers transparently instead of bubbling up as EIO.
    async fn get_text_retried(
        &self,
        url: &str,
        params: &[(&str, &str)],
    ) -> Result<String, SynoFsError> {
        let mut last_err = SynoFsError::Io("no attempts".into());
        for attempt in 0..3u8 {
            if attempt > 0 {
                debug!("retry {} for GET {}", attempt, url);
                tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
            }
            let resp = match self.http.get(url).query(params).send().await {
                Ok(r) => r,
                Err(e) => { last_err = e.into(); continue; }
            };
            match resp.text().await {
                Ok(t) => return Ok(t),
                Err(e) => { last_err = e.into(); }
            }
        }
        Err(last_err)
    }

    /// Login and store the session ID.
    ///
    /// `otp_code` is the 6-digit TOTP code required when the account has 2-factor
    /// authentication enabled. Pass `None` if 2FA is not configured.
    pub async fn login(
        &self,
        user: &str,
        password: &str,
        otp_code: Option<&str>,
    ) -> Result<(), SynoFsError> {
        let url = format!("{}/auth.cgi", self.base_url);
        let mut params = vec![
            ("api", "SYNO.API.Auth"),
            ("version", "7"),
            ("method", "login"),
            ("account", user),
            ("passwd", password),
            ("session", "FileStation"),
            ("format", "sid"),
        ];
        if let Some(otp) = otp_code {
            params.push(("otp_code", otp));
        }
        let resp = self.http
            .get(&url)
            .query(&params)
            .send()
            .await?
            .json::<SynoResponse<AuthData>>()
            .await?;

        if resp.success {
            let sid = resp.data.ok_or_else(|| SynoFsError::Io("no auth data".into()))?.sid;
            debug!("Logged in, SID: {}...", &sid[..8.min(sid.len())]);
            *self.sid.write().unwrap() = Some(sid);
            Ok(())
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Logout and clear the session ID.
    pub async fn logout(&self) -> Result<(), SynoFsError> {
        let url = format!("{}/auth.cgi", self.base_url);
        let _ = self.http
            .get(&url)
            .query(&[
                ("api", "SYNO.API.Auth"),
                ("version", "7"),
                ("method", "logout"),
                ("session", "FileStation"),
                ("_sid", &self.sid()),
            ])
            .send()
            .await;
        *self.sid.write().unwrap() = None;
        Ok(())
    }

    /// List all FileStation shares the account can see.
    pub async fn list_shares(&self) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        debug!("list_shares");
        let text = self.get_text_retried(&url, &[
            ("api", "SYNO.FileStation.List"),
            ("version", "2"),
            ("method", "list_share"),
            ("additional", SHARE_ADDITIONAL_FIELDS),
            ("limit", "500"),
            ("offset", "0"),
            ("_sid", &self.sid()),
        ]).await?;

        let resp: SynoResponse<ListShareData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("list_shares parse error: {e}")))?;

        if resp.success {
            let shares = resp.data.map(|d| d.shares).unwrap_or_default();
            debug!("list_shares: {} shares returned", shares.len());
            Ok(shares)
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// List the contents of a directory.
    pub async fn list_dir(&self, folder_path: &str) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        debug!("list_dir: {}", folder_path);
        let text = self.get_text_retried(&url, &[
            ("api", "SYNO.FileStation.List"),
            ("version", "2"),
            ("method", "list"),
            ("folder_path", folder_path),
            ("additional", ADDITIONAL_FIELDS),
            ("limit", "5000"),
            ("offset", "0"),
            ("_sid", &self.sid()),
        ]).await?;

        let resp: SynoResponse<ListData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("list_dir parse error: {e}")))?;

        if resp.success {
            Ok(resp.data.map(|d| d.files).unwrap_or_default())
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Get metadata for a single file or directory.
    pub async fn get_info(&self, path: &str) -> Result<SynoFileInfo, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[path]).unwrap();
        debug!("get_info: {}", path);
        let text = self.get_text_retried(&url, &[
            ("api", "SYNO.FileStation.List"),
            ("version", "2"),
            ("method", "getinfo"),
            ("path", &path_json),
            ("additional", ADDITIONAL_FIELDS),
            ("_sid", &self.sid()),
        ]).await?;

        debug!("get_info raw response: {}", text);

        let resp: SynoResponse<GetInfoData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("get_info parse error: {e}")))?;

        if resp.success {
            let mut files = resp.data.ok_or(SynoFsError::NotFound)?.files;
            let file = files.pop().ok_or(SynoFsError::NotFound)?;
            if let Some(code) = file.code {
                return Err(SynoFsError::ApiError(code));
            }
            Ok(file)
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Download file bytes, optionally with a byte range.
    ///
    /// Retries up to 2 times on transient connection errors (e.g. the NAS closing a
    /// keep-alive connection mid-stream while the response body is being read).
    pub async fn download(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<Bytes, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[path]).unwrap();
        debug!("download: {} offset={} len={}", path, offset, length);

        let range_header = if length > 0 {
            Some(format!("bytes={}-{}", offset, offset + length - 1))
        } else {
            None
        };

        let mut last_err = SynoFsError::Io("no attempts".into());
        for attempt in 0..3u8 {
            if attempt > 0 {
                debug!("download retry {} for {} offset={}", attempt, path, offset);
            }

            let mut req = self.http
                .get(&url)
                .query(&[
                    ("api", "SYNO.FileStation.Download"),
                    ("version", "2"),
                    ("method", "download"),
                    ("path", &path_json),
                    ("mode", "download"),
                    ("_sid", &self.sid()),
                ]);

            if let Some(ref range) = range_header {
                req = req.header("Range", range.as_str());
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => { last_err = e.into(); continue; }
            };

            let status = resp.status();

            // 416 Range Not Satisfiable = requested range starts past EOF; return empty (EOF signal).
            if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
                return Ok(Bytes::new());
            }
            if !status.is_success() {
                return Err(SynoFsError::Io(format!("download HTTP {}", status)));
            }

            match resp.bytes().await {
                Ok(b) => return Ok(b),
                Err(e) => { last_err = e.into(); }
            }
        }
        Err(last_err)
    }

    /// Upload file contents (replaces entire file).
    pub async fn upload(
        &self,
        folder_path: &str,
        filename: &str,
        data: Vec<u8>,
        overwrite: bool,
    ) -> Result<(), SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        debug!("upload: {}/{} ({} bytes)", folder_path, filename, data.len());

        // overwrite=true via the multipart API times out on some DSM versions.
        // Delete the existing file first so we can always upload with overwrite=false.
        if overwrite {
            let full_path = format!("{}/{}", folder_path.trim_end_matches('/'), filename);
            let _ = self.delete(&full_path).await; // ignore error — file may not exist yet

            // Synology Delete is async on modern DSM: poll get_info until the file is
            // gone (or inaccessible) before uploading, to avoid 418 AlreadyExists.
            for _ in 0..10u8 {
                match self.get_info(&full_path).await {
                    Ok(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                    Err(_) => break, // gone or inaccessible — safe to upload
                }
            }
        }

        let mut last_err = SynoFsError::Io("no attempts".into());
        for attempt in 0..3u8 {
            if attempt > 0 {
                debug!("upload retry {} for {}/{}", attempt, folder_path, filename);
            }

            let file_part = multipart::Part::bytes(data.clone())
                .file_name(filename.to_string())
                .mime_str("application/octet-stream")
                .map_err(|e| SynoFsError::Io(e.to_string()))?;

            let form = multipart::Form::new()
                .text("api", "SYNO.FileStation.Upload")
                .text("version", "3")
                .text("method", "upload")
                .text("path", folder_path.to_string())
                .text("create_parents", "true")
                .text("overwrite", "false")
                .part("file", file_part);

            let resp = match self.http
                .post(&url)
                .query(&[("_sid", self.sid())])
                .multipart(form)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => { last_err = e.into(); continue; }
            };

            let text = match resp.text().await {
                Ok(t) => t,
                Err(e) => { last_err = e.into(); continue; }
            };

            debug!("upload raw response: {}", text);

            let parsed: SynoResponse<UploadData> = serde_json::from_str(&text)
                .map_err(|e| SynoFsError::Io(format!("upload parse error: {e}")))?;

            return if parsed.success {
                Ok(())
            } else {
                let code = parsed.error.map(|e| e.code).unwrap_or(0);
                Err(SynoFsError::ApiError(code))
            };
        }
        Err(last_err)
    }

    /// Delete a file or directory (recursive for directories).
    pub async fn delete(&self, path: &str) -> Result<(), SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[path]).unwrap();
        debug!("delete: {}", path);

        let text = self.get_text_retried(&url, &[
            ("api", "SYNO.FileStation.Delete"),
            ("version", "2"),
            ("method", "delete"),
            ("path", &path_json),
            ("recursive", "true"),
            ("accurate_progress", "false"),
            ("_sid", &self.sid()),
        ]).await?;

        let resp: SynoResponse<serde_json::Value> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("delete parse error: {e}")))?;

        if resp.success {
            Ok(())
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Create a directory.
    pub async fn create_folder(
        &self,
        parent: &str,
        name: &str,
    ) -> Result<SynoFileInfo, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let parent_json = serde_json::to_string(&[parent]).unwrap();
        let name_json = serde_json::to_string(&[name]).unwrap();
        debug!("create_folder: {}/{}", parent, name);

        let text = self.get_text_retried(&url, &[
            ("api", "SYNO.FileStation.CreateFolder"),
            ("version", "2"),
            ("method", "create"),
            ("folder_path", &parent_json),
            ("name", &name_json),
            ("additional", ADDITIONAL_FIELDS),
            ("_sid", &self.sid()),
        ]).await?;

        debug!("create_folder raw response: {}", text);

        let resp: SynoResponse<CreateFolderData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("create_folder parse error: {e}")))?;

        if resp.success {
            let mut folders = resp.data.ok_or(SynoFsError::Io("no folder data".into()))?.folders;
            folders.pop().ok_or(SynoFsError::Io("empty folder list".into()))
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Rename a file or directory (same-directory rename only).
    pub async fn rename(&self, old_path: &str, new_name: &str) -> Result<SynoFileInfo, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[old_path]).unwrap();
        let name_json = serde_json::to_string(&[new_name]).unwrap();
        debug!("rename: {} -> {}", old_path, new_name);

        let text = self.get_text_retried(&url, &[
            ("api", "SYNO.FileStation.Rename"),
            ("version", "2"),
            ("method", "rename"),
            ("path", &path_json),
            ("name", &name_json),
            ("additional", ADDITIONAL_FIELDS),
            ("_sid", &self.sid()),
        ]).await?;

        debug!("rename raw response: {}", text);

        let resp: SynoResponse<RenameData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("rename parse error: {e}")))?;

        if resp.success {
            let mut files = resp.data.ok_or(SynoFsError::Io("no rename data".into()))?.files;
            files.pop().ok_or(SynoFsError::Io("empty file list".into()))
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a client pointed at the given mock server.
    fn client_for(server: &MockServer) -> SynologyClient {
        let uri = server.uri(); // "http://127.0.0.1:PORT"
        let without_scheme = uri.trim_start_matches("http://");
        let (host, port_str) = without_scheme.rsplit_once(':').unwrap();
        let port: u16 = port_str.parse().unwrap();
        SynologyClient::new(host, port, false)
    }

    // ── login ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn login_stores_sid_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "abc123def"}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        assert_eq!(client.sid(), "abc123def");
    }

    #[tokio::test]
    async fn login_returns_api_error_on_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 400}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.login("alice", "wrong", None).await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(400)));
    }

    #[tokio::test]
    async fn login_with_otp_includes_otp_param() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .and(query_param("otp_code", "123456"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "otp_sid_xyz"}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", Some("123456")).await.unwrap();
        assert_eq!(client.sid(), "otp_sid_xyz");
    }

    // ── logout ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn logout_clears_sid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"sid": "session_abc"}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.login("alice", "secret", None).await.unwrap();
        assert_eq!(client.sid(), "session_abc");
        client.logout().await.unwrap();
        assert_eq!(client.sid(), "");
    }

    // ── list_shares ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_shares_returns_shares() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list_share"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"shares": [
                    {"name": "photos", "path": "/photos", "isdir": true, "additional": null},
                    {"name": "docs",   "path": "/docs",   "isdir": true, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let shares = client.list_shares().await.unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].name, "photos");
        assert_eq!(shares[1].name, "docs");
    }

    #[tokio::test]
    async fn list_shares_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list_share"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 408}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.list_shares().await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(408)));
    }

    // ── list_dir ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_dir_returns_files() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [
                    {"name": "file.txt", "path": "/share/file.txt", "isdir": false, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let files = client.list_dir("/share").await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "file.txt");
    }

    #[tokio::test]
    async fn list_dir_null_data_returns_empty_vec() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let files = client.list_dir("/empty").await.unwrap();
        assert!(files.is_empty());
    }

    // ── get_info ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_info_returns_file_metadata() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [{
                    "name": "notes.txt",
                    "path": "/share/notes.txt",
                    "isdir": false,
                    "additional": {"size": 512, "owner": null, "time": null, "perm": null}
                }]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let info = client.get_info("/share/notes.txt").await.unwrap();
        assert_eq!(info.name, "notes.txt");
        assert_eq!(info.additional.unwrap().size, Some(512));
    }

    #[tokio::test]
    async fn get_info_per_entry_error_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [{"code": 408, "path": "/share/missing"}]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.get_info("/share/missing").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(408)));
    }

    #[tokio::test]
    async fn get_info_envelope_error_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 119}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.get_info("/share/restricted").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(119)));
    }

    // ── download ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn download_returns_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello world".to_vec()))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let data = client.download("/share/file.txt", 0, 11).await.unwrap();
        assert_eq!(data.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn download_416_returns_empty_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(416))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let data = client.download("/share/file.txt", 9999, 10).await.unwrap();
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn download_http_error_returns_io_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "download"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.download("/share/file.txt", 0, 10).await.unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)));
    }

    // ── upload ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn upload_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"blks": null}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .upload("/share", "test.txt", b"content".to_vec(), false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upload_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 1805}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client
            .upload("/share", "test.txt", b"data".to_vec(), false)
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(1805)));
    }

    #[tokio::test]
    async fn upload_with_overwrite_deletes_then_polls_then_uploads() {
        let server = MockServer::start().await;
        // DELETE call (GET method=delete)
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&server)
            .await;
        // Poll for file gone (GET method=getinfo) — return error so upload proceeds
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "getinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 414}
            })))
            .mount(&server)
            .await;
        // Actual upload (POST)
        Mock::given(method("POST"))
            .and(path("/webapi/entry.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"blks": null}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client
            .upload("/share", "test.txt", b"new content".to_vec(), true)
            .await
            .unwrap();
    }

    // ── delete ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        client.delete("/share/file.txt").await.unwrap();
    }

    #[tokio::test]
    async fn delete_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 414}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.delete("/share/missing.txt").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(414)));
    }

    // ── create_folder ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_folder_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "create"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"folders": [
                    {"name": "newdir", "path": "/share/newdir", "isdir": true, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let info = client.create_folder("/share", "newdir").await.unwrap();
        assert_eq!(info.name, "newdir");
        assert!(info.isdir);
    }

    #[tokio::test]
    async fn create_folder_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "create"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 1101}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.create_folder("/share", "existing").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(1101)));
    }

    // ── rename ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rename_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "rename"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "data": {"files": [
                    {"name": "new.txt", "path": "/share/new.txt", "isdir": false, "additional": null}
                ]}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let info = client.rename("/share/old.txt", "new.txt").await.unwrap();
        assert_eq!(info.name, "new.txt");
    }

    #[tokio::test]
    async fn rename_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "rename"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 418}
            })))
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client
            .rename("/share/old.txt", "existing.txt")
            .await
            .unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(418)));
    }

    // ── retry behaviour ──────────────────────────────────────────────────────
    //
    // A VPN coming up mid-session silently kills existing TCP connections.
    // reqwest's pool happily hands out the dead connection, the request fails,
    // and without a retry the FUSE callback returns EIO to the user. The retry
    // helper re-issues the request — pool_idle_timeout(4s) gets us a fresh
    // connection, which routes correctly over the new VPN interface.
    //
    // wiremock can't simulate a connection-layer fault (it only models HTTP
    // responses), so these tests stand up a tiny tokio TcpListener that closes
    // the socket without responding to trigger a real reqwest::Error.

    /// Spawn a TCP server that drops the first `failures` connections, then
    /// answers the next one with `body` as a JSON HTTP/1.1 response.
    async fn flaky_json_server(
        failures: usize,
        body: &'static str,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            for _ in 0..failures {
                if let Ok((stream, _)) = listener.accept().await {
                    drop(stream); // close immediately, no HTTP response
                }
            }
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (port, handle)
    }

    #[tokio::test]
    async fn list_dir_recovers_after_transient_connection_drops() {
        // Simulates the VPN-flap scenario: first 2 connections die, 3rd succeeds.
        let body = r#"{"success":true,"data":{"files":[{"name":"hi.txt","path":"/share/hi.txt","isdir":false,"additional":null}]}}"#;
        let (port, handle) = flaky_json_server(2, body).await;

        let client = SynologyClient::new("127.0.0.1", port, false);
        let files = client.list_dir("/share").await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "hi.txt");
        handle.await.ok();
    }

    #[tokio::test]
    async fn list_dir_returns_io_error_when_all_retries_fail() {
        // 10 failures > 3 attempts — verifies the helper eventually gives up
        // with an Io error instead of hanging the FUSE callback forever.
        let (port, handle) = flaky_json_server(10, "").await;

        let client = SynologyClient::new("127.0.0.1", port, false);
        let err = client.list_dir("/share").await.unwrap_err();
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
        handle.abort();
    }

    #[tokio::test]
    async fn list_dir_does_not_retry_on_api_error() {
        // API-level failures (success: false) must NOT be retried — they're
        // deterministic, and retrying would multiply the user's wait on a real
        // permission denial or rate-limit.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/webapi/entry.cgi"))
            .and(query_param("method", "list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "error": {"code": 408}
            })))
            .expect(1) // verified when MockServer is dropped
            .mount(&server)
            .await;

        let client = client_for(&server);
        let err = client.list_dir("/share").await.unwrap_err();
        assert!(matches!(err, SynoFsError::ApiError(408)));
    }
}

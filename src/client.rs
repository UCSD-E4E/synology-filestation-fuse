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
            .build()
            .expect("failed to build HTTP client");
        Self { http, base_url, sid: RwLock::new(None) }
    }

    fn sid(&self) -> String {
        self.sid.read().unwrap().clone().unwrap_or_default()
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
        let resp = self.http
            .get(&url)
            .query(&[
                ("api", "SYNO.FileStation.List"),
                ("version", "2"),
                ("method", "list_share"),
                ("additional", SHARE_ADDITIONAL_FIELDS),
                ("limit", "500"),
                ("offset", "0"),
                ("_sid", &self.sid()),
            ])
            .send()
            .await?
            .json::<SynoResponse<ListShareData>>()
            .await?;

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
        let resp = self.http
            .get(&url)
            .query(&[
                ("api", "SYNO.FileStation.List"),
                ("version", "2"),
                ("method", "list"),
                ("folder_path", folder_path),
                ("additional", ADDITIONAL_FIELDS),
                ("limit", "5000"),
                ("offset", "0"),
                ("_sid", &self.sid()),
            ])
            .send()
            .await?
            .json::<SynoResponse<ListData>>()
            .await?;

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
        let text = self.http
            .get(&url)
            .query(&[
                ("api", "SYNO.FileStation.List"),
                ("version", "2"),
                ("method", "getinfo"),
                ("path", &path_json),
                ("additional", ADDITIONAL_FIELDS),
                ("_sid", &self.sid()),
            ])
            .send()
            .await?
            .text()
            .await?;

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
            for attempt in 0..10u8 {
                match self.get_info(&full_path).await {
                    // File still present: wait a bit and poll again.
                    Ok(_) => {
                        tokio::time::sleep(Duration::from_millis(50 * (attempt as u64 + 1))).await;
                    }
                    Err(err) => {
                        match err {
                            // Definitive "not found" / already gone: safe to proceed.
                            SynoFsError::NotFound
                            | SynoFsError::ApiError(414 | 415) => {
                                break;
                            }
                            // Transient or other errors: keep polling until attempts exhausted.
                            _ => {
                                debug!(
                                    "get_info error while waiting for delete of {}: {:?} (attempt {}), retrying",
                                    full_path,
                                    err,
                                    attempt
                                );
                                tokio::time::sleep(Duration::from_millis(50 * (attempt as u64 + 1))).await;
                            }
                        }
                    }
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

        let resp = self.http
            .get(&url)
            .query(&[
                ("api", "SYNO.FileStation.Delete"),
                ("version", "2"),
                ("method", "delete"),
                ("path", &path_json),
                ("recursive", "true"),
                ("accurate_progress", "false"),
                ("_sid", &self.sid()),
            ])
            .send()
            .await?
            .json::<SynoResponse<serde_json::Value>>()
            .await?;

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

        let text = self.http
            .get(&url)
            .query(&[
                ("api", "SYNO.FileStation.CreateFolder"),
                ("version", "2"),
                ("method", "create"),
                ("folder_path", &parent_json),
                ("name", &name_json),
                ("additional", ADDITIONAL_FIELDS),
                ("_sid", &self.sid()),
            ])
            .send()
            .await?
            .text()
            .await?;

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

        let resp = self.http
            .get(&url)
            .query(&[
                ("api", "SYNO.FileStation.Rename"),
                ("version", "2"),
                ("method", "rename"),
                ("path", &path_json),
                ("name", &name_json),
                ("additional", ADDITIONAL_FIELDS),
                ("_sid", &self.sid()),
            ])
            .send()
            .await?
            .json::<SynoResponse<RenameData>>()
            .await?;

        if resp.success {
            let mut files = resp.data.ok_or(SynoFsError::Io("no rename data".into()))?.files;
            files.pop().ok_or(SynoFsError::Io("empty file list".into()))
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }
}

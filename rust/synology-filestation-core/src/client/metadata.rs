//! Listing, stat and namespace operations — the calls a mount makes constantly.

use super::*;

/// Entries requested per `list` / `list_share` page.
///
/// DSM caps what one response may carry, so a directory larger than this needs
/// several requests. Kept modest rather than maximal: a page is parsed whole, so
/// this trades one extra round trip on very large directories for a bounded
/// per-response allocation.
pub const LIST_PAGE_SIZE: usize = 1000;

/// Ceiling on pages fetched for a single listing, so a server that reports an
/// unreachable `total` (or keeps handing back full pages) cannot spin us
/// forever. At [`LIST_PAGE_SIZE`] this covers 10M entries in one directory.
pub(super) const LIST_MAX_PAGES: usize = 10_000;

/// How long a metadata or download request may take to produce response headers
/// (and, on the response body, how long it may go without delivering a chunk).
/// Uploads deliberately do not use it — see [`build_http_transfer`].
pub(super) const METADATA_READ_TIMEOUT: Duration = Duration::from_secs(30);

impl SynologyClient {
    /// Fetch a `SYNO.FileStation.List` listing in full, following pagination.
    ///
    /// A single request only ever returns one page, so asking once and keeping
    /// whatever came back silently truncates any directory bigger than the
    /// limit — and a filesystem that omits files is worse than one that errors.
    /// This keeps requesting at increasing offsets until the server says it is
    /// done, which it signals either by reporting a `total` we have reached or
    /// by handing back a partial (or empty) page.
    pub(super) async fn list_paged<T, F>(
        &self,
        method: &str,
        extra_params: &[(&str, &str)],
        additional: &str,
        label: &str,
        unpack: F,
    ) -> Result<Vec<SynoFileInfo>, SynoFsError>
    where
        T: serde::de::DeserializeOwned,
        F: Fn(T) -> (Vec<SynoFileInfo>, Option<u64>),
    {
        let url = format!("{}/entry.cgi", self.base_url);
        let limit = LIST_PAGE_SIZE.to_string();
        let mut collected: Vec<SynoFileInfo> = Vec::new();

        for _ in 0..LIST_MAX_PAGES {
            let offset = collected.len().to_string();
            let mut params: Vec<(&str, &str)> = vec![
                ("api", "SYNO.FileStation.List"),
                ("version", "2"),
                ("method", method),
            ];
            params.extend_from_slice(extra_params);
            params.push(("additional", additional));
            params.push(("limit", &limit));
            params.push(("offset", &offset));

            let text = self.get_text_retried(&url, &params).await?;
            let resp: SynoResponse<T> = serde_json::from_str(&text)
                .map_err(|e| SynoFsError::Io(format!("{label} parse error: {e}")))?;
            if !resp.success {
                let code = resp.error.map(|e| e.code).unwrap_or(0);
                return Err(SynoFsError::ApiError(code));
            }

            let (page, total) = match resp.data {
                Some(d) => unpack(d),
                None => (Vec::new(), None),
            };
            let page_len = page.len();
            collected.extend(page);

            let done = page_len == 0
                || page_len < LIST_PAGE_SIZE
                || total.is_some_and(|t| collected.len() as u64 >= t);
            if done {
                debug!("{label}: {} entries", collected.len());
                return Ok(collected);
            }
        }

        // Only reachable from a server that keeps handing back full pages
        // without ever satisfying its own `total`. Return what we have rather
        // than looping, but say so — a short listing must never look normal.
        warn!(
            "{label}: stopped at the {LIST_MAX_PAGES}-page cap with {} entries; listing may be incomplete",
            collected.len()
        );
        Ok(collected)
    }

    /// List all FileStation shares the account can see.
    pub async fn list_shares(&self) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        debug!("list_shares");
        via_metadata!(self, list_shares());
        self.list_paged::<ListShareData, _>(
            "list_share",
            &[],
            SHARE_ADDITIONAL_FIELDS,
            "list_shares",
            |d| (d.shares, d.total),
        )
        .await
    }

    /// List the contents of a directory.
    pub async fn list_dir(&self, folder_path: &str) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        debug!("list_dir: {}", folder_path);
        via_metadata!(self, list_dir(folder_path));
        self.list_paged::<ListData, _>(
            "list",
            &[("folder_path", folder_path)],
            ADDITIONAL_FIELDS,
            "list_dir",
            |d| (d.files, d.total),
        )
        .await
    }

    /// Get metadata for a single file or directory.
    pub async fn get_info(&self, path: &str) -> Result<SynoFileInfo, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[path]).unwrap();
        debug!("get_info: {}", path);
        via_metadata!(self, get_info(path));
        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.List"),
                    ("version", "2"),
                    ("method", "getinfo"),
                    ("path", &path_json),
                    ("additional", ADDITIONAL_FIELDS),
                ],
            )
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

    /// Split a NAS path into `(parent, filename)`. `None` when there is no
    /// separator, or when the path names no file at all.
    ///
    /// A trailing slash is the dangerous case: it yields an empty filename,
    /// and an empty filename rejoined to its parent is the parent. Handed to
    /// an overwriting upload, `clear_for_overwrite` would then delete the
    /// *directory* before writing. Refusing here is the difference between an
    /// invalid argument and a removed folder.
    pub(super) fn split_parent(path: &str) -> Option<(&str, &str)> {
        let idx = path.rfind('/')?;
        let (parent, filename) = (&path[..idx], &path[idx + 1..]);
        if filename.is_empty() {
            return None;
        }
        Some((parent, filename))
    }

    /// Delete a file or directory (recursive for directories).
    pub async fn delete(&self, path: &str) -> Result<(), SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[path]).unwrap();
        debug!("delete: {}", path);
        via_metadata!(self, delete(path));

        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.Delete"),
                    ("version", "2"),
                    ("method", "delete"),
                    ("path", &path_json),
                    ("recursive", "true"),
                    ("accurate_progress", "false"),
                ],
            )
            .await?;

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
        via_metadata!(self, create_folder(parent, name));

        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.CreateFolder"),
                    ("version", "2"),
                    ("method", "create"),
                    ("folder_path", &parent_json),
                    ("name", &name_json),
                    ("additional", ADDITIONAL_FIELDS),
                ],
            )
            .await?;

        debug!("create_folder raw response: {}", text);

        let resp: SynoResponse<CreateFolderData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("create_folder parse error: {e}")))?;

        if resp.success {
            let mut folders = resp
                .data
                .ok_or(SynoFsError::Io("no folder data".into()))?
                .folders;
            folders
                .pop()
                .ok_or(SynoFsError::Io("empty folder list".into()))
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }

    /// Rename a file or directory (same-directory rename only).
    pub async fn rename(
        &self,
        old_path: &str,
        new_name: &str,
    ) -> Result<SynoFileInfo, SynoFsError> {
        let url = format!("{}/entry.cgi", self.base_url);
        let path_json = serde_json::to_string(&[old_path]).unwrap();
        let name_json = serde_json::to_string(&[new_name]).unwrap();
        debug!("rename: {} -> {}", old_path, new_name);
        via_metadata!(self, rename(old_path, new_name));

        let text = self
            .get_text_retried(
                &url,
                &[
                    ("api", "SYNO.FileStation.Rename"),
                    ("version", "2"),
                    ("method", "rename"),
                    ("path", &path_json),
                    ("name", &name_json),
                    ("additional", ADDITIONAL_FIELDS),
                ],
            )
            .await?;

        debug!("rename raw response: {}", text);

        let resp: SynoResponse<RenameData> = serde_json::from_str(&text)
            .map_err(|e| SynoFsError::Io(format!("rename parse error: {e}")))?;

        if resp.success {
            let mut files = resp
                .data
                .ok_or(SynoFsError::Io("no rename data".into()))?
                .files;
            files.pop().ok_or(SynoFsError::Io("empty file list".into()))
        } else {
            let code = resp.error.map(|e| e.code).unwrap_or(0);
            Err(SynoFsError::ApiError(code))
        }
    }
}

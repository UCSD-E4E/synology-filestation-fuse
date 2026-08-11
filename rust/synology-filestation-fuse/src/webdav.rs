use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes};
use dav_server::davpath::DavPath;
use dav_server::fs::*;
use futures_util::stream;
use tracing::debug;

use crate::spill::{payload_for, upload_payload, SpillBuffer};
use synology_filestation_core::client::SynologyClient;
use synology_filestation_core::error::SynoFsError;
use synology_filestation_core::types::SynoFileInfo;

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Convert a `DavPath` to the corresponding Synology NAS path string,
/// stripping an optional URL prefix (e.g. "/nas").
/// e.g. `/nas/share/dir/file.txt` with prefix `/nas` → `/share/dir/file.txt`
fn dav_to_nas(path: &DavPath, prefix: &str) -> String {
    let pb = path.as_pathbuf();
    let s = pb.to_string_lossy();
    let s = s.trim_end_matches('/');
    let s = if !prefix.is_empty() && s.starts_with(prefix) {
        &s[prefix.len()..]
    } else {
        s
    };
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        "/".to_string()
    } else {
        s.to_string()
    }
}

/// Returns true for macOS AppleDouble companion files (`._*`).
/// Synology DSM does not store these as regular files; operations on them
/// should be silently discarded rather than forwarded to the NAS API.
fn is_apple_double(nas_path: &str) -> bool {
    nas_path
        .rsplit('/')
        .next()
        .map(|n| n.starts_with("._"))
        .unwrap_or(false)
}

/// Split `/parent/name` → `("/parent", "name")`.
/// Handles the single-segment case: `/name` → `("/", "name")`.
fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => ("/", path),
    }
}

fn ts_to_system(ts: i64) -> SystemTime {
    if ts > 0 {
        UNIX_EPOCH + std::time::Duration::from_secs(ts as u64)
    } else {
        UNIX_EPOCH
    }
}

fn syno_err(e: SynoFsError) -> FsError {
    match e {
        SynoFsError::NotFound => FsError::NotFound,
        SynoFsError::PermissionDenied => FsError::Forbidden,
        SynoFsError::AlreadyExists => FsError::Exists,
        SynoFsError::NoSpace => FsError::InsufficientStorage,
        // Map known Synology API error codes to appropriate WebDAV errors.
        // 408 = "no such file or no permission" — treat as NotFound so macOS
        //       receives 404 rather than 500 (which maps to EPERM).
        // 414/415 = no such file / no such folder
        SynoFsError::ApiError(408 | 414 | 415) => FsError::NotFound,
        SynoFsError::ApiError(418) => FsError::Exists,
        SynoFsError::ApiError(419) => FsError::InsufficientStorage,
        _ => FsError::GeneralFailure,
    }
}

// ── Metadata ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SynoDavMeta {
    info: SynoFileInfo,
}

impl SynoDavMeta {
    fn new(info: SynoFileInfo) -> Self {
        Self { info }
    }

    fn root() -> Self {
        Self {
            info: SynoFileInfo {
                name: String::new(),
                path: "/".into(),
                isdir: true,
                additional: None,
                code: None,
            },
        }
    }
}

impl DavMetaData for SynoDavMeta {
    fn len(&self) -> u64 {
        if self.info.isdir {
            0
        } else {
            self.info
                .additional
                .as_ref()
                .and_then(|a| a.size)
                .unwrap_or(0)
        }
    }

    fn modified(&self) -> FsResult<SystemTime> {
        let ts = self
            .info
            .additional
            .as_ref()
            .and_then(|a| a.time.as_ref())
            .map(|t| t.mtime)
            .unwrap_or(0);
        Ok(ts_to_system(ts))
    }

    fn is_dir(&self) -> bool {
        self.info.isdir
    }

    fn created(&self) -> FsResult<SystemTime> {
        let ts = self
            .info
            .additional
            .as_ref()
            .and_then(|a| a.time.as_ref())
            .map(|t| t.crtime)
            .unwrap_or(0);
        Ok(ts_to_system(ts))
    }
}

// ── Dir entry ────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct SynoDavDirEntry {
    info: SynoFileInfo,
}

impl DavDirEntry for SynoDavDirEntry {
    fn name(&self) -> Vec<u8> {
        self.info.name.as_bytes().to_vec()
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta: Box<dyn DavMetaData> = Box::new(SynoDavMeta::new(self.info.clone()));
        Box::pin(async move { Ok(meta) })
    }
}

// ── File ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct SynoDavFile {
    client: Arc<SynologyClient>,
    nas_path: String,
    info: SynoFileInfo,
    offset: u64,
    /// Buffered write data; `Some` when opened for writing.
    write_buf: Option<SpillBuffer>,
    /// True when the file did not exist on the NAS at open time.
    /// Used to skip the delete-before-upload overwrite path.
    is_new: bool,
}

impl DavFile for SynoDavFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta: Box<dyn DavMetaData> = Box::new(SynoDavMeta::new(self.info.clone()));
        Box::pin(async move { Ok(meta) })
    }

    fn write_buf(&mut self, buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        let mut b = buf;
        let chunk = b.copy_to_bytes(b.remaining());
        Box::pin(async move {
            let sink = self.write_buf.get_or_insert_with(SpillBuffer::new);
            sink.write_at(sink.len(), &chunk)
                .map_err(|_| FsError::GeneralFailure)
        })
    }

    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<'_, ()> {
        Box::pin(async move {
            let sink = self.write_buf.get_or_insert_with(SpillBuffer::new);
            sink.write_at(sink.len(), &buf)
                .map_err(|_| FsError::GeneralFailure)
        })
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        // Split the borrow so the future can update self.offset after the await.
        let client = self.client.clone();
        let path = self.nas_path.clone();
        let offset_ref = &mut self.offset;

        Box::pin(async move {
            let cur = *offset_ref;
            let bytes = client
                .download(&path, cur, count as u64)
                .await
                .map_err(syno_err)?;
            *offset_ref += bytes.len() as u64;
            Ok(bytes)
        })
    }

    fn seek(&mut self, pos: std::io::SeekFrom) -> FsFuture<'_, u64> {
        let size = self
            .info
            .additional
            .as_ref()
            .and_then(|a| a.size)
            .unwrap_or(0);
        let new_offset = match pos {
            std::io::SeekFrom::Start(o) => o,
            std::io::SeekFrom::Current(o) => (self.offset as i64).saturating_add(o).max(0) as u64,
            std::io::SeekFrom::End(o) => (size as i64).saturating_add(o).max(0) as u64,
        };
        self.offset = new_offset;
        Box::pin(async move { Ok(new_offset) })
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        if let Some(mut buf) = self.write_buf.take() {
            // AppleDouble companion files (._*) are discarded — not stored on the NAS.
            if is_apple_double(&self.nas_path) {
                return Box::pin(async { Ok(()) });
            }
            let client = self.client.clone();
            let path = self.nas_path.clone();
            let overwrite = !self.is_new;
            let payload = match payload_for(&mut buf) {
                Ok(p) => p,
                Err(_) => return Box::pin(async { Err(FsError::GeneralFailure) }),
            };
            debug!("flush: uploading {} ({} bytes)", path, payload.len());
            Box::pin(async move {
                // The buffer rides along so it outlives the upload: a spilled
                // buffer deletes its temp file on drop, and that file is the
                // payload being sent.
                let _buf = buf;
                let (parent, filename) = split_path(&path);
                upload_payload(&client, parent, filename, payload, overwrite)
                    .await
                    .map_err(syno_err)
            })
        } else {
            Box::pin(async { Ok(()) })
        }
    }
}

// ── Filesystem ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SynologyDavFs {
    client: Arc<SynologyClient>,
    /// URL path prefix stripped before forwarding to the NAS API.
    /// e.g. "/nas" when the WebDAV server is mounted at `http://host/nas/`.
    path_prefix: String,
}

impl SynologyDavFs {
    pub fn new(client: Arc<SynologyClient>, path_prefix: String) -> Self {
        Self {
            client,
            path_prefix,
        }
    }

    fn nas_path(&self, path: &DavPath) -> String {
        dav_to_nas(path, &self.path_prefix)
    }
}

impl DavFileSystem for SynologyDavFs {
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let nas = self.nas_path(path);
            debug!("webdav metadata: {}", nas);

            if nas == "/" {
                let meta: Box<dyn DavMetaData> = Box::new(SynoDavMeta::root());
                return Ok(meta);
            }

            if is_apple_double(&nas) {
                return Err(FsError::NotFound);
            }

            let info = self.client.get_info(&nas).await.map_err(syno_err)?;
            let meta: Box<dyn DavMetaData> = Box::new(SynoDavMeta::new(info));
            Ok(meta)
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            let nas = self.nas_path(path);
            debug!("webdav read_dir: {}", nas);

            let entries: Vec<SynoFileInfo> = if nas == "/" {
                self.client.list_shares().await.map_err(syno_err)?
            } else {
                self.client.list_dir(&nas).await.map_err(syno_err)?
            };

            let items: Vec<FsResult<Box<dyn DavDirEntry>>> = entries
                .into_iter()
                .map(|info| -> FsResult<Box<dyn DavDirEntry>> {
                    Ok(Box::new(SynoDavDirEntry { info }))
                })
                .collect();

            let s: FsStream<Box<dyn DavDirEntry>> = Box::pin(stream::iter(items));
            Ok(s)
        })
    }

    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            let nas = self.nas_path(path);
            debug!(
                "webdav open: {} read={} write={} create={}",
                nas, options.read, options.write, options.create
            );

            if options.write || options.create {
                // AppleDouble companion files (._*) are not stored on the NAS.
                // Accept the write but discard the data — flush() is a no-op for these.
                if is_apple_double(&nas) {
                    let info = SynoFileInfo {
                        name: nas.rsplit('/').next().unwrap_or("").to_string(),
                        path: nas.clone(),
                        isdir: false,
                        additional: None,
                        code: None,
                    };
                    let file: Box<dyn DavFile> = Box::new(SynoDavFile {
                        client: self.client.clone(),
                        nas_path: nas,
                        info,
                        offset: 0,
                        write_buf: Some(SpillBuffer::new()),
                        is_new: false,
                    });
                    return Ok(file);
                }

                // For a write/create open, the caller will PUT the content.
                // We build a placeholder SynoFileInfo so flush() knows where to upload.
                // Track whether the file already exists so flush() can skip the
                // delete-before-overwrite path for brand-new files.
                let (info, is_new) = match self.client.get_info(&nas).await {
                    Ok(info) => (info, false),
                    Err(_) => (
                        SynoFileInfo {
                            name: nas.rsplit('/').next().unwrap_or("").to_string(),
                            path: nas.clone(),
                            isdir: false,
                            additional: None,
                            code: None,
                        },
                        true,
                    ),
                };

                let file: Box<dyn DavFile> = Box::new(SynoDavFile {
                    client: self.client.clone(),
                    nas_path: nas,
                    info,
                    offset: 0,
                    write_buf: Some(SpillBuffer::new()),
                    is_new,
                });
                Ok(file)
            } else {
                let info = self.client.get_info(&nas).await.map_err(syno_err)?;
                let file: Box<dyn DavFile> = Box::new(SynoDavFile {
                    client: self.client.clone(),
                    nas_path: nas,
                    info,
                    offset: 0,
                    write_buf: None,
                    is_new: false,
                });
                Ok(file)
            }
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let nas = self.nas_path(path);
            debug!("webdav create_dir: {}", nas);
            let (parent, name) = split_path(&nas);
            self.client
                .create_folder(parent, name)
                .await
                .map_err(syno_err)
                .map(|_| ())
        })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let nas = self.nas_path(path);
            debug!("webdav remove_file: {}", nas);
            if is_apple_double(&nas) {
                return Ok(());
            }
            self.client.delete(&nas).await.map_err(syno_err)
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let nas = self.nas_path(path);
            debug!("webdav remove_dir: {}", nas);
            self.client.delete(&nas).await.map_err(syno_err)
        })
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let from_nas = self.nas_path(from);
            let to_nas = self.nas_path(to);
            debug!("webdav rename: {} -> {}", from_nas, to_nas);

            let (from_parent, _) = split_path(&from_nas);
            let (to_parent, to_name) = split_path(&to_nas);

            if from_parent == to_parent {
                self.client
                    .rename(&from_nas, to_name)
                    .await
                    .map_err(syno_err)
                    .map(|_| ())
            } else {
                // Cross-directory move: download → upload → delete.
                // Only works for files; directory moves return an error.
                let info = self.client.get_info(&from_nas).await.map_err(syno_err)?;
                if info.isdir {
                    return Err(FsError::NotImplemented);
                }
                let size = info.additional.as_ref().and_then(|a| a.size).unwrap_or(0);
                let data = self
                    .client
                    .download(&from_nas, 0, size)
                    .await
                    .map_err(syno_err)?;
                self.client
                    .upload(to_parent, to_name, data.to_vec(), true)
                    .await
                    .map_err(syno_err)?;
                self.client.delete(&from_nas).await.map_err(syno_err)
            }
        })
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let from_nas = self.nas_path(from);
            let to_nas = self.nas_path(to);
            debug!("webdav copy: {} -> {}", from_nas, to_nas);

            let info = self.client.get_info(&from_nas).await.map_err(syno_err)?;
            if info.isdir {
                return Err(FsError::NotImplemented);
            }
            let size = info.additional.as_ref().and_then(|a| a.size).unwrap_or(0);
            let data = self
                .client
                .download(&from_nas, 0, size)
                .await
                .map_err(syno_err)?;
            let (to_parent, to_name) = split_path(&to_nas);
            self.client
                .upload(to_parent, to_name, data.to_vec(), true)
                .await
                .map_err(syno_err)
        })
    }
}

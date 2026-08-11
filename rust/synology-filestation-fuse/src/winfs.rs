use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use widestring::U16CStr;
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::FspError;

use crate::spill::{payload_for, upload_payload, SpillBuffer};
use synology_filestation_core::client::SynologyClient;
use synology_filestation_core::error::SynoFsError;
use synology_filestation_core::types::SynoFileInfo;

// ── Windows constants ─────────────────────────────────────────────────────────

/// 100-nanosecond intervals between 1601-01-01 and 1970-01-01 (FILETIME epoch).
const EPOCH_DIFF: u64 = 116_444_736_000_000_000;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;

/// FILE_DIRECTORY_FILE create option — set when creating a directory.
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

/// FspCleanupDelete flag — set in cleanup() when the file must be deleted.
const FSP_CLEANUP_DELETE: u32 = 0x01;

// NTSTATUS codes used for error mapping.
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001_u32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
const STATUS_DISK_FULL: i32 = 0xC000_007F_u32 as i32;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_to_filetime(ts: i64) -> u64 {
    if ts <= 0 {
        return 0;
    }
    (ts as u64)
        .saturating_mul(10_000_000)
        .saturating_add(EPOCH_DIFF)
}

/// Convert an NT path (backslash-separated, e.g. `\share\dir\file`) to the
/// NAS API path format (`/share/dir/file`).  The root `\` maps to `/`.
fn nt_to_nas(path: &U16CStr) -> String {
    let s = path.to_string_lossy();
    if s == "\\" || s.is_empty() {
        return "/".to_string();
    }
    s.replace('\\', "/")
}

fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => ("/", path),
    }
}

fn syno_to_fsp(e: SynoFsError) -> FspError {
    match e {
        SynoFsError::NotFound => FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND),
        SynoFsError::PermissionDenied => FspError::NTSTATUS(STATUS_ACCESS_DENIED),
        SynoFsError::AlreadyExists => FspError::NTSTATUS(STATUS_OBJECT_NAME_COLLISION),
        SynoFsError::NoSpace => FspError::NTSTATUS(STATUS_DISK_FULL),
        SynoFsError::ApiError(408 | 414 | 415) => FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND),
        SynoFsError::ApiError(418) => FspError::NTSTATUS(STATUS_OBJECT_NAME_COLLISION),
        SynoFsError::ApiError(419) => FspError::NTSTATUS(STATUS_DISK_FULL),
        _ => FspError::NTSTATUS(STATUS_UNSUCCESSFUL),
    }
}

fn fill_file_info(fi: &mut FileInfo, info: &SynoFileInfo) {
    fi.file_attributes = if info.isdir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    };
    fi.reparse_tag = 0;
    fi.file_size = if info.isdir {
        0
    } else {
        info.additional.as_ref().and_then(|a| a.size).unwrap_or(0)
    };
    fi.allocation_size = (fi.file_size + 511) & !511;

    let times = info.additional.as_ref().and_then(|a| a.time.as_ref());
    fi.creation_time = times.map(|t| unix_to_filetime(t.crtime)).unwrap_or(0);
    fi.last_access_time = times.map(|t| unix_to_filetime(t.atime)).unwrap_or(0);
    fi.last_write_time = times.map(|t| unix_to_filetime(t.mtime)).unwrap_or(0);
    fi.change_time = fi.last_write_time;
    fi.index_number = 0;
    fi.hard_links = 0;
    fi.ea_size = 0;
}

fn now_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    unix_to_filetime(secs)
}

// ── Pending-file registry ─────────────────────────────────────────────────────

/// Shared write buffer type — an Arc so multiple FileContexts for the same
/// pending path can all point at the same buffer.
type SharedBuf = Arc<Mutex<Option<SpillBuffer>>>;

/// Entry stored for each file that has been `create()`d but not yet uploaded.
/// Keeping FileInfo here lets `open()` return plausible metadata without an
/// extra NAS round-trip.
struct PendingEntry {
    file_info: FileInfo,
    buf: SharedBuf,
}

// ── FileContext ───────────────────────────────────────────────────────────────

/// Represents one open file or directory handle.
pub struct SynoFileContext {
    pub nas_path: String,
    #[allow(dead_code)]
    pub is_dir: bool,
    /// Snapshot of metadata at open/create time; updated on write.
    pub file_info: FileInfo,
    /// Buffered write data (files only).  Shared via Arc so that a rename()
    /// issued on a secondary handle can still find and upload the data.
    pub write_buf: SharedBuf,
    /// True when the file did not exist at create time.
    pub is_new: bool,
    /// Set by set_delete(); acted on in cleanup().
    pub delete_pending: AtomicBool,
    /// Cached directory listing, filled on first read_directory call.
    pub dir_buffer: DirBuffer,
}

impl SynoFileContext {
    fn from_syno_info(nas_path: String, info: &SynoFileInfo) -> Self {
        let mut fi: FileInfo = unsafe { std::mem::zeroed() };
        fill_file_info(&mut fi, info);
        Self {
            nas_path,
            is_dir: info.isdir,
            file_info: fi,
            write_buf: Arc::new(Mutex::new(None)),
            is_new: false,
            delete_pending: AtomicBool::new(false),
            dir_buffer: DirBuffer::new(),
        }
    }

    fn root() -> Self {
        let mut fi: FileInfo = unsafe { std::mem::zeroed() };
        fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
        let now = now_filetime();
        fi.creation_time = now;
        fi.last_access_time = now;
        fi.last_write_time = now;
        fi.change_time = now;
        Self {
            nas_path: "/".to_string(),
            is_dir: true,
            file_info: fi,
            write_buf: Arc::new(Mutex::new(None)),
            is_new: false,
            delete_pending: AtomicBool::new(false),
            dir_buffer: DirBuffer::new(),
        }
    }

    fn new_file(nas_path: String, is_dir: bool) -> Self {
        let mut fi: FileInfo = unsafe { std::mem::zeroed() };
        fi.file_attributes = if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };
        let now = now_filetime();
        fi.creation_time = now;
        fi.last_access_time = now;
        fi.last_write_time = now;
        fi.change_time = now;
        let write_buf = if is_dir {
            Arc::new(Mutex::new(None))
        } else {
            Arc::new(Mutex::new(Some(SpillBuffer::new())))
        };
        Self {
            nas_path,
            is_dir,
            file_info: fi,
            write_buf,
            is_new: true,
            delete_pending: AtomicBool::new(false),
            dir_buffer: DirBuffer::new(),
        }
    }

    /// Build a context for a pending file using its shared buffer and cached
    /// FileInfo.  Used by `open()` when the file hasn't been uploaded yet.
    fn from_pending(nas_path: String, entry: &PendingEntry) -> Self {
        Self {
            nas_path,
            is_dir: false,
            file_info: entry.file_info.clone(),
            write_buf: Arc::clone(&entry.buf),
            is_new: true,
            delete_pending: AtomicBool::new(false),
            dir_buffer: DirBuffer::new(),
        }
    }
}

// ── Filesystem ────────────────────────────────────────────────────────────────

pub struct SynologyWinFs {
    client: Arc<SynologyClient>,
    runtime: tokio::runtime::Handle,
    /// Files created via create() but not yet uploaded to the NAS.
    /// Keyed by NAS path.  Entries are removed after a successful upload or
    /// when the last handle to the file is closed.
    pending_files: RwLock<HashMap<String, PendingEntry>>,
}

impl SynologyWinFs {
    pub fn new(client: Arc<SynologyClient>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            client,
            runtime,
            pending_files: RwLock::new(HashMap::new()),
        }
    }
}

impl FileSystemContext for SynologyWinFs {
    type FileContext = SynoFileContext;

    // ── Required methods ──────────────────────────────────────────────────────

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [std::ffi::c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let nas = nt_to_nas(file_name);
        tracing::debug!("get_security_by_name: {}", nas);

        let attributes = if nas == "/" {
            FILE_ATTRIBUTE_DIRECTORY
        } else if self.pending_files.read().unwrap().contains_key(&nas) {
            tracing::debug!("get_security_by_name: pending hit {}", nas);
            // File was created but not yet uploaded — it logically exists.
            FILE_ATTRIBUTE_ARCHIVE
        } else {
            let info = self
                .runtime
                .block_on(self.client.get_info(&nas))
                .map_err(syno_to_fsp)?;
            if info.isdir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            }
        };

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let nas = nt_to_nas(file_name);
        tracing::debug!("open: {}", nas);

        let ctx = if nas == "/" {
            SynoFileContext::root()
        } else if let Some(entry) = self.pending_files.read().unwrap().get(&nas) {
            // File is pending (created but not yet on the NAS).  Return a
            // context that shares the same write buffer so that rename() or
            // flush() on this handle can still upload the data.
            SynoFileContext::from_pending(nas, entry)
        } else {
            let info = self
                .runtime
                .block_on(self.client.get_info(&nas))
                .map_err(syno_to_fsp)?;
            SynoFileContext::from_syno_info(nas, &info)
        };

        *file_info.as_mut() = ctx.file_info.clone();
        Ok(ctx)
    }

    fn close(&self, context: Self::FileContext) {
        // Last-chance upload: if flush() was never called (or was bypassed),
        // upload any remaining buffered data before dropping the context.
        // The buffer is held in `taken` across the upload: dropping a spilled
        // buffer deletes its temp file, which is exactly what we are uploading.
        let mut taken = context.write_buf.lock().unwrap().take();
        if let Some(buf) = taken.as_mut() {
            if let Ok(payload) = payload_for(buf) {
                tracing::debug!(
                    "close: last-chance upload {} ({} bytes)",
                    context.nas_path,
                    payload.len()
                );
                let (parent, name) = split_path(&context.nas_path);
                let _ = self.runtime.block_on(upload_payload(
                    &self.client,
                    parent,
                    name,
                    payload,
                    !context.is_new,
                ));
            }
        }
        tracing::debug!("close: removing pending {}", context.nas_path);
        self.pending_files
            .write()
            .unwrap()
            .remove(&context.nas_path);
    }

    // ── Optional methods ──────────────────────────────────────────────────────

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[std::ffi::c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let nas = nt_to_nas(file_name);
        let is_dir = create_options & FILE_DIRECTORY_FILE != 0;

        if is_dir {
            let (parent, name) = split_path(&nas);
            self.runtime
                .block_on(self.client.create_folder(parent, name))
                .map_err(syno_to_fsp)?;
        }
        // File content is written later via write() / flush().

        let ctx = SynoFileContext::new_file(nas.clone(), is_dir);

        // Register non-directory files as pending so that concurrent opens
        // (e.g. from os.rename()) can find them before the upload completes.
        if !is_dir {
            tracing::debug!("create: registering pending {}", ctx.nas_path);
            self.pending_files.write().unwrap().insert(
                ctx.nas_path.clone(),
                PendingEntry {
                    file_info: ctx.file_info.clone(),
                    buf: Arc::clone(&ctx.write_buf),
                },
            );
        }

        *file_info.as_mut() = ctx.file_info.clone();
        Ok(ctx)
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let bytes = self
            .runtime
            .block_on(
                self.client
                    .download(&context.nas_path, offset, buffer.len() as u64),
            )
            .map_err(syno_to_fsp)?;
        let len = bytes.len().min(buffer.len());
        buffer[..len].copy_from_slice(&bytes[..len]);
        Ok(len as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let mut wb = context.write_buf.lock().unwrap();
        let buf = wb.get_or_insert_with(SpillBuffer::new);
        // Spills to a temp file past its threshold, so a large copy through the
        // mount no longer pins the whole file in memory.
        buf.write_at(offset, buffer).map_err(FspError::from)?;
        *file_info = context.file_info.clone();
        file_info.file_size = buf.len();
        file_info.allocation_size = (file_info.file_size + 511) & !511;
        Ok(buffer.len() as u32)
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if let Some(ctx) = context {
            // Snapshot the buffer without consuming it, so a failed upload
            // leaves the data in write_buf for close() to retry. For a spilled
            // buffer the snapshot is just the temp path — no copy, and the
            // upload streams it in slices.
            let payload = {
                let mut wb = ctx.write_buf.lock().unwrap();
                match wb.as_mut() {
                    Some(buf) => Some(payload_for(buf).map_err(FspError::from)?),
                    None => None,
                }
            };
            if let Some(payload) = payload {
                tracing::debug!(
                    "flush: uploading {} ({} bytes)",
                    ctx.nas_path,
                    payload.len()
                );
                let (parent, name) = split_path(&ctx.nas_path);
                match self.runtime.block_on(upload_payload(
                    &self.client,
                    parent,
                    name,
                    payload,
                    !ctx.is_new,
                )) {
                    Ok(()) => {
                        // Upload succeeded — consume the buffer, but keep the pending
                        // entry alive so that a subsequent get_security_by_name() for
                        // a rename can still find the file without a NAS round-trip.
                        // The entry is removed in rename() or close().
                        ctx.write_buf.lock().unwrap().take();
                    }
                    Err(e) => {
                        // Upload failed — leave data in write_buf so close() can retry.
                        return Err(syno_to_fsp(e));
                    }
                }
            }
            *file_info = ctx.file_info.clone();
        }
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        *file_info = context.file_info.clone();
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut wb = context.write_buf.lock().unwrap();
        let buf = wb.get_or_insert_with(SpillBuffer::new);
        buf.set_len(new_size).map_err(FspError::from)?;
        *file_info = context.file_info.clone();
        file_info.file_size = new_size;
        file_info.allocation_size = (new_size + 511) & !511;
        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        context.delete_pending.store(delete_file, Ordering::Relaxed);
        Ok(())
    }

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        if flags & FSP_CLEANUP_DELETE != 0 && context.delete_pending.load(Ordering::Relaxed) {
            let _ = self.runtime.block_on(self.client.delete(&context.nas_path));
        }
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        // On the first call for this handle (marker is None) fill the dir buffer.
        if let Ok(dir_lock) = context.dir_buffer.acquire(marker.is_none(), None) {
            let entries: Vec<SynoFileInfo> = if context.nas_path == "/" {
                self.runtime
                    .block_on(self.client.list_shares())
                    .map_err(syno_to_fsp)?
            } else {
                self.runtime
                    .block_on(self.client.list_dir(&context.nas_path))
                    .map_err(syno_to_fsp)?
            };

            for entry in entries {
                let mut dir_info = DirInfo::<255>::new();
                fill_file_info(dir_info.file_info_mut(), &entry);
                let name = if entry.name.is_empty() {
                    entry.path.rsplit('/').next().unwrap_or(&entry.path)
                } else {
                    &entry.name
                };
                let name_wide: Vec<u16> = name.encode_utf16().collect();
                let _ = dir_info.set_name_raw(name_wide.as_slice());
                dir_lock.write(&mut dir_info)?;
            }
        }

        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let from = &context.nas_path;
        let to = nt_to_nas(new_file_name);
        let (to_parent, to_name) = split_path(&to);
        let (from_parent, _) = split_path(from);

        // WinFsp (or Windows) may supply the destination path in a different
        // case than the NAS directories use.  The NAS runs Linux (case-
        // sensitive), so always prefer from_parent (correct mixed-case) over
        // to_parent (may be all-uppercase) when operating within the same
        // logical directory.
        let same_dir = from_parent.eq_ignore_ascii_case(to_parent);
        let upload_parent = if same_dir { from_parent } else { to_parent };

        tracing::debug!(
            "rename: {} -> {} (is_new={}, buf={}, same_dir={})",
            from,
            to,
            context.is_new,
            if context.write_buf.lock().unwrap().is_some() {
                "Some"
            } else {
                "None"
            },
            same_dir
        );

        // If the file has buffered data not yet uploaded (either because this
        // is the original create() handle or a secondary handle that shares
        // the same Arc<Mutex<...>>), upload directly under the new name.
        // Held across the upload for the same reason as in close(): dropping a
        // spilled buffer would delete the temp file being uploaded.
        let mut taken = context.write_buf.lock().unwrap().take();
        if let Some(buf) = taken.as_mut() {
            let payload = payload_for(buf).map_err(FspError::from)?;
            tracing::debug!(
                "rename: uploading pending {} -> {}/{} ({} bytes)",
                from,
                upload_parent,
                to_name,
                payload.len()
            );
            self.runtime
                .block_on(upload_payload(
                    &self.client,
                    upload_parent,
                    to_name,
                    payload,
                    !context.is_new,
                ))
                .map_err(syno_to_fsp)?;
            self.pending_files.write().unwrap().remove(from);
            return Ok(());
        }
        tracing::debug!(
            "rename: no pending data, calling client.rename {} -> {}",
            from,
            to
        );

        if same_dir {
            // Same-directory rename: use the NAS rename API with the source
            // path (correct case) and just the new filename.
            self.runtime
                .block_on(self.client.rename(from, to_name))
                .map_err(syno_to_fsp)
                .map(|_| ())
        } else {
            // Cross-directory move: download → upload → delete.
            // Only supported for files; directory moves would need recursive copy.
            let info = self
                .runtime
                .block_on(self.client.get_info(from))
                .map_err(syno_to_fsp)?;
            if info.isdir {
                return Err(FspError::NTSTATUS(STATUS_UNSUCCESSFUL));
            }
            let size = info.additional.as_ref().and_then(|a| a.size).unwrap_or(0);
            let data = self
                .runtime
                .block_on(self.client.download(from, 0, size))
                .map_err(syno_to_fsp)?;
            self.runtime
                .block_on(
                    self.client
                        .upload(upload_parent, to_name, data.to_vec(), true),
                )
                .map_err(syno_to_fsp)?;
            self.runtime
                .block_on(self.client.delete(from))
                .map_err(syno_to_fsp)
        }
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        // Report a generous fake capacity — the NAS API doesn't expose quota info.
        out_volume_info.total_size = 1024_u64 * 1024 * 1024 * 1024; // 1 TiB
        out_volume_info.free_size = 512_u64 * 1024 * 1024 * 1024; // 512 GiB
        Ok(())
    }
}

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, INodeNo,
    LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, WriteFlags,
};
use tracing::{debug, error, info, warn};

use crate::cache::{InodeCache, ReadCache};
use crate::spill::{payload_for, upload_payload, SpillBuffer};
use synology_filestation_core::client::SynologyClient;
use synology_filestation_core::error::SynoFsError;
use synology_filestation_core::types::{SynoFileInfo, VIRTUAL_ROOT_PATH};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

/// Convert a raw errno (`SynoFsError::to_errno`, `libc::ENOENT`, etc.) into the
/// `fuser::Errno` newtype that `Reply*::error` expects in fuser 0.17+.
fn errno(raw: i32) -> Errno {
    Errno::from_i32(raw)
}

/// Split a NAS path into `(parent, filename)`. `None` for a path with no
/// separator, which cannot name a file inside a share.
///
/// Previously open-coded at three call sites as `rfind('/')` followed by a
/// second `rfind('/').unwrap()` — the `unwrap` being safe only because the
/// preceding match had already proven the separator exists.
fn split_nas_path(path: &str) -> Option<(&str, &str)> {
    let idx = path.rfind('/')?;
    Some((&path[..idx], &path[idx + 1..]))
}

struct WriteBuffer {
    nas_path: String,
    ino: u64,
    data: SpillBuffer,
    dirty: bool,
    /// True when the file was just created and has not yet been uploaded.
    /// Allows the first upload to use overwrite=false, skipping the
    /// delete-before-upload round trips. Cleared once an upload succeeds.
    new_file: bool,
}

pub struct SynologyFS {
    client: Arc<SynologyClient>,
    cache: Arc<InodeCache>,
    read_cache: Arc<ReadCache>,
    rt: tokio::runtime::Handle,
    write_buffers: Mutex<HashMap<u64, WriteBuffer>>,
    next_fh: AtomicU64,
    uid: u32,
    gid: u32,
}

impl SynologyFS {
    pub fn new(
        client: Arc<SynologyClient>,
        cache: Arc<InodeCache>,
        read_cache: Arc<ReadCache>,
        rt: tokio::runtime::Handle,
        uid: u32,
        gid: u32,
    ) -> Self {
        Self {
            client,
            cache,
            read_cache,
            rt,
            write_buffers: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            uid,
            gid,
        }
    }

    fn block<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.rt.block_on(fut)
    }

    fn syno_to_attr(&self, ino: u64, info: &SynoFileInfo) -> FileAttr {
        let kind = if info.isdir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        let size = info.additional.as_ref().and_then(|a| a.size).unwrap_or(0);
        let perm = info
            .additional
            .as_ref()
            .and_then(|a| a.perm.as_ref())
            .map(|p| p.posix as u16)
            .unwrap_or(if info.isdir { 0o755 } else { 0o644 });

        let ts_to_system = |ts: i64| {
            if ts >= 0 {
                UNIX_EPOCH + Duration::from_secs(ts as u64)
            } else {
                UNIX_EPOCH
            }
        };

        let (atime, mtime, ctime, crtime) = info
            .additional
            .as_ref()
            .and_then(|a| a.time.as_ref())
            .map(|t| {
                (
                    ts_to_system(t.atime),
                    ts_to_system(t.mtime),
                    ts_to_system(t.ctime),
                    ts_to_system(t.crtime),
                )
            })
            .unwrap_or_else(|| {
                let now = SystemTime::now();
                (now, now, now, now)
            });

        let uid = info
            .additional
            .as_ref()
            .and_then(|a| a.owner.as_ref())
            .map(|o| o.uid)
            .unwrap_or(self.uid);
        let gid = info
            .additional
            .as_ref()
            .and_then(|a| a.owner.as_ref())
            .map(|o| o.gid)
            .unwrap_or(self.gid);

        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime,
            mtime,
            ctime,
            crtime,
            kind,
            perm,
            nlink: if info.isdir { 2 } else { 1 },
            uid,
            gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn get_path_for_ino(&self, ino: u64) -> Option<String> {
        self.cache.get_path_for_ino(ino)
    }

    /// Upload `fh`'s buffered data and block until the NAS has it.
    ///
    /// This is what `flush` (and therefore `close(2)`) reports on, so it must
    /// be synchronous: an upload still in flight when we return is an upload
    /// whose failure nobody will ever hear about.
    ///
    /// `dirty` is cleared only *after* the upload succeeds. A failed flush
    /// therefore leaves the data buffered for `release` to retry, matching what
    /// the WinFsp backend already does — previously the flag was cleared before
    /// the upload even started, so a failure silently discarded the write.
    fn finish_upload(&self, fh: u64) -> Result<(), SynoFsError> {
        // Snapshot under the lock; never hold it across the upload. For a
        // spilled buffer the payload is just the temp path, and that file stays
        // alive because the buffer itself stays in `write_buffers` until
        // `release` removes it — after this call has returned.
        let (nas_path, ino, payload, overwrite) = {
            let mut buffers = self.write_buffers.lock().unwrap();
            let buf = match buffers.get_mut(&fh) {
                Some(b) if b.dirty => b,
                // Unknown handle, or nothing written since the last successful
                // upload: there is genuinely nothing to do.
                _ => return Ok(()),
            };
            let payload = payload_for(&mut buf.data).map_err(|e| SynoFsError::Io(e.to_string()))?;
            (buf.nas_path.clone(), buf.ino, payload, !buf.new_file)
        };

        let (parent, filename) = match split_nas_path(&nas_path) {
            Some(v) => v,
            None => return Err(SynoFsError::InvalidArg),
        };

        debug!(
            "finish_upload: fh={} parent={:?} filename={:?} size={}",
            fh,
            parent,
            filename,
            payload.len()
        );
        self.block(upload_payload(
            &self.client,
            parent,
            filename,
            payload,
            overwrite,
        ))?;

        // Durable now: stop advertising the buffer as dirty, and record that the
        // file exists on the NAS so a later flush overwrites instead of racing
        // an `overwrite=false` create against itself.
        if let Some(buf) = self.write_buffers.lock().unwrap().get_mut(&fh) {
            buf.dirty = false;
            buf.new_file = false;
        }
        self.cache.invalidate_path(&nas_path);
        self.read_cache.invalidate_ino(ino);
        Ok(())
    }

    /// Assemble a byte range for `read`, block by block, out of the read cache.
    ///
    /// Split out of the `read` callback so the assembly rules are testable
    /// without a live mount; `read` keeps the prefetch and the reply.
    fn read_range(
        &self,
        ino: u64,
        path: &str,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, SynoFsError> {
        let block_size = self.read_cache.block_size;
        let first_block = offset / block_size;
        let last_block = (offset + size - 1) / block_size;

        let mut result: Vec<u8> = Vec::with_capacity(size as usize);

        for block_idx in first_block..=last_block {
            let block_start = block_idx * block_size;

            let block = if let Some(cached) = self.read_cache.get(ino, block_idx) {
                if cached.is_empty() {
                    debug!("read: EOF sentinel hit ino={} block={}", ino, block_idx);
                    break;
                }
                cached
            } else if self.read_cache.claim_inflight(ino, block_idx) {
                // We won the race — download synchronously.
                debug!("read cache miss: ino={} block={}", ino, block_idx);
                match self.block(self.client.download(path, block_start, block_size)) {
                    Ok(b) if !b.is_empty() => {
                        self.read_cache.insert(ino, block_idx, b.clone());
                        b
                    }
                    Ok(empty) => {
                        // EOF — cache empty sentinel so any waiters know too.
                        self.read_cache.insert(ino, block_idx, empty);
                        break;
                    }
                    Err(e) => {
                        self.read_cache.cancel_inflight(ino, block_idx);
                        error!("read {}: {}", path, e);
                        return Err(e);
                    }
                }
            } else {
                // Another task is downloading this block — wait for it.
                debug!("read waiting for inflight: ino={} block={}", ino, block_idx);
                match self.read_cache.wait_for_block(ino, block_idx) {
                    Some(b) if b.is_empty() => break, // EOF sentinel
                    Some(b) => b,
                    // Other task had a real network error.
                    None => return Err(SynoFsError::Io("block download failed".into())),
                }
            };

            // Slice the portion of this block that overlaps [offset, offset+size)
            let local_start = offset.saturating_sub(block_start) as usize;
            let local_end = (offset + size)
                .saturating_sub(block_start)
                .min(block_size)
                .min(block.len() as u64) as usize;

            if local_start < local_end {
                result.extend_from_slice(&block[local_start..local_end]);
            }

            // A block shorter than the block size is the last one with data:
            // the server had nothing beyond it to give. Stop here. Continuing
            // would append the *next* block's bytes directly behind this one,
            // handing the caller a buffer whose tail comes from a different file
            // offset than it claims — silent corruption rather than a short read.
            if (block.len() as u64) < block_size {
                debug!(
                    "read: short block ino={} idx={} len={} < {}; stopping",
                    ino,
                    block_idx,
                    block.len(),
                    block_size
                );
                break;
            }
        }

        Ok(result)
    }

    /// Resize `path` to `new_size`, zero-extending or truncating.
    ///
    /// FileStation has no truncate call, so this is read-modify-write. Split out
    /// of `setattr` so the failure behaviour is testable: a download that fails
    /// must abort the whole operation, because the alternative — treating an
    /// unreadable file as an empty one — uploads `new_size` zero bytes over
    /// perfectly good data.
    fn truncate_file(
        &self,
        ino: u64,
        path: &str,
        new_size: u64,
    ) -> Result<SynoFileInfo, SynoFsError> {
        // Shrinking to nothing needs no prior content, and this is the common
        // case (O_TRUNC, `> file`). Skip the round trip entirely rather than
        // downloading a file we are about to discard.
        let data = if new_size == 0 {
            Vec::new()
        } else {
            let current = self.block(self.client.download(path, 0, 0))?;
            let mut data = current.to_vec();
            data.resize(new_size as usize, 0);
            data
        };

        let (parent, filename) = match split_nas_path(path) {
            Some(v) => v,
            None => return Err(SynoFsError::InvalidArg),
        };
        self.block(self.client.upload(parent, filename, data, true))?;

        self.read_cache.invalidate_ino(ino);
        self.cache.invalidate_path(path);
        self.block(self.client.get_info(path))
    }

    /// Move a file between directories: download, upload to the new location,
    /// then delete the source. FileStation's Rename API cannot move across
    /// directories, so this is the only route.
    ///
    /// Split out of `rename` so the download sizing is testable — it must ask
    /// for the *whole* file rather than a length taken from cached metadata.
    fn move_across_dirs(
        &self,
        old_path: &str,
        new_parent: &str,
        new_name: &str,
    ) -> Result<(), SynoFsError> {
        // `length = 0` means "the whole file". Sizing this request from the
        // inode cache instead would silently truncate the file whenever that
        // cached size is stale-low — and this path deletes the source
        // afterwards, so the missing bytes are simply gone.
        let data = self.block(self.client.download(old_path, 0, 0))?;

        self.block(
            self.client
                .upload(new_parent, new_name, data.to_vec(), true),
        )?;

        // Only the source deletion is best-effort: the copy is already safe on
        // the NAS, so a failure here leaves a duplicate rather than losing data.
        if let Err(e) = self.block(self.client.delete(old_path)) {
            warn!(
                "rename: uploaded {}/{} but failed to delete {}: {}",
                new_parent, new_name, old_path, e
            );
        }
        Ok(())
    }

    /// Synthetic FileAttr for the virtual root (inode 1).
    fn virtual_root_attr(&self) -> FileAttr {
        FileAttr {
            ino: INodeNo(ROOT_INO),
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

impl Filesystem for SynologyFS {
    fn init(&mut self, _req: &Request, _config: &mut fuser::KernelConfig) -> io::Result<()> {
        debug!("init: seeding virtual root");
        // Seed inode 1 with a virtual root that has no real NAS path.
        // readdir and lookup on this inode use list_shares() instead of list_dir().
        // We don't make any API call here — the session was already verified during login.
        let root_info = SynoFileInfo {
            name: String::new(),
            path: VIRTUAL_ROOT_PATH.to_string(),
            isdir: true,
            additional: None,
            code: None,
        };
        self.cache.seed_root(root_info);
        info!("NAS is mounted and ready for use");
        Ok(())
    }

    fn destroy(&mut self) {
        debug!("destroy: flushing write buffers and logging out");
        // Flush any remaining write buffers
        let fhs: Vec<u64> = self.write_buffers.lock().unwrap().keys().cloned().collect();
        for fh in fhs {
            if let Err(e) = self.finish_upload(fh) {
                warn!("destroy: failed to flush fh {}: {}", fh, e);
            }
        }
        let _ = self.block(self.client.logout());
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let parent_path = match self.get_path_for_ino(parent.0) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        // Looking up a share name directly under the virtual root.
        if parent_path == VIRTUAL_ROOT_PATH {
            debug!("lookup share: {}", name_str);
            let shares = match self.block(self.client.list_shares()) {
                Ok(s) => s,
                Err(e) => {
                    reply.error(errno(e.to_errno()));
                    return;
                }
            };
            match shares.into_iter().find(|s| s.name == name_str) {
                Some(info) => {
                    let ino = self.cache.get_or_alloc_ino(&info.path);
                    let attr = self.syno_to_attr(ino, &info);
                    self.cache.insert(ino, info);
                    reply.entry(&TTL, &attr, fuser::Generation(0));
                }
                None => reply.error(Errno::ENOENT),
            }
            return;
        }

        let child_path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        debug!("lookup: {}", child_path);

        // Check cache first
        if let Some(entry) = self
            .cache
            .get_by_ino(self.cache.get_or_alloc_ino(&child_path))
        {
            let attr = self.syno_to_attr(entry.ino, &entry.info);
            reply.entry(&TTL, &attr, fuser::Generation(0));
            return;
        }

        match self.block(self.client.get_info(&child_path)) {
            Ok(info) => {
                let ino = self.cache.get_or_alloc_ino(&child_path);
                let attr = self.syno_to_attr(ino, &info);
                self.cache.insert(ino, info);
                reply.entry(&TTL, &attr, fuser::Generation(0));
            }
            Err(SynoFsError::NotFound) | Err(SynoFsError::ApiError(408 | 414 | 415)) => {
                reply.error(Errno::ENOENT);
            }
            Err(e) => {
                error!("lookup {}: {}", child_path, e);
                reply.error(errno(e.to_errno()));
            }
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let ino = ino.0;
        debug!("getattr: ino={}", ino);

        // The virtual root has no real NAS path — always return synthetic attrs directly.
        if ino == ROOT_INO {
            reply.attr(&TTL, &self.virtual_root_attr());
            return;
        }

        // Serve from cache if available
        if let Some(entry) = self.cache.get_by_ino(ino) {
            let attr = self.syno_to_attr(ino, &entry.info);
            reply.attr(&TTL, &attr);
            return;
        }

        // Cache miss: look up the path and fetch from API
        let path = match self.get_path_for_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        match self.block(self.client.get_info(&path)) {
            Ok(info) => {
                let attr = self.syno_to_attr(ino, &info);
                self.cache.insert(ino, info);
                reply.attr(&TTL, &attr);
            }
            Err(e) => {
                error!("getattr ino={} path={}: {}", ino, path, e);
                reply.error(errno(e.to_errno()));
            }
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let ino = ino.0;
        let path = match self.get_path_for_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        debug!("readdir: ino={} path={} offset={}", ino, path, offset);

        // Virtual root: list FileStation shares instead of a real directory.
        let (entries, parent_ino) = if path == VIRTUAL_ROOT_PATH {
            let shares = match self.block(self.client.list_shares()) {
                Ok(s) => s,
                Err(e) => {
                    error!("readdir shares: {}", e);
                    reply.error(errno(e.to_errno()));
                    return;
                }
            };
            debug!("readdir root: got {} shares", shares.len());
            (shares, ROOT_INO)
        } else {
            let entries = match self.block(self.client.list_dir(&path)) {
                Ok(e) => e,
                Err(e) => {
                    error!("readdir {}: {}", path, e);
                    reply.error(errno(e.to_errno()));
                    return;
                }
            };
            let parent_ino = path
                .rfind('/')
                .map(|i| {
                    let parent_path = &path[..i];
                    // parent of a top-level share (e.g. "/homes") is the virtual root
                    if parent_path.is_empty() {
                        ROOT_INO
                    } else {
                        self.cache.get_or_alloc_ino(parent_path)
                    }
                })
                .unwrap_or(ROOT_INO);
            (entries, parent_ino)
        };

        // Build full entry list: ".", "..", then actual entries
        let mut all_entries: Vec<(u64, FileType, String)> = Vec::new();
        all_entries.push((ino, FileType::Directory, ".".to_string()));
        all_entries.push((parent_ino, FileType::Directory, "..".to_string()));

        for file_info in entries {
            let child_ino = self.cache.get_or_alloc_ino(&file_info.path);
            let kind = if file_info.isdir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            let name = file_info.name.clone();
            self.cache.insert(child_ino, file_info);
            all_entries.push((child_ino, kind, name));
        }

        for (i, (child_ino, kind, name)) in all_entries.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(*child_ino), (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let ino = ino.0;
        if size == 0 {
            reply.data(&[]);
            return;
        }

        let path = match self.get_path_for_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let size = size as u64;
        let block_size = self.read_cache.block_size;
        let last_block = (offset + size - 1) / block_size;

        debug!(
            "read: ino={} path={} offset={} size={} blocks=[{}..={}]",
            ino,
            path,
            offset,
            size,
            offset / block_size,
            last_block
        );

        let result = match self.read_range(ino, &path, offset, size) {
            Ok(r) => r,
            Err(e) => {
                reply.error(errno(e.to_errno()));
                return;
            }
        };

        // Background prefetch of the next 16 blocks to keep VLC's read-ahead buffer full.
        for prefetch_idx in (last_block + 1)..=(last_block + 16) {
            if !self.read_cache.contains(ino, prefetch_idx)
                && self.read_cache.claim_inflight(ino, prefetch_idx)
            {
                let client = self.client.clone();
                let rc = self.read_cache.clone();
                let path_clone = path.clone();
                self.rt.spawn(async move {
                    let start = prefetch_idx * block_size;
                    match client.download(&path_clone, start, block_size).await {
                        Ok(data) => rc.insert(ino, prefetch_idx, data), // empty == EOF sentinel
                        Err(_) => rc.cancel_inflight(ino, prefetch_idx),
                    }
                });
            }
        }

        reply.data(&result);
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let ino = ino.0;
        let path = match self.get_path_for_ino(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        debug!("open: ino={} path={} flags={:#o}", ino, path, flags.0);

        let block_size = self.read_cache.block_size;
        let file_size = self.cache.get_size_for_ino(ino).unwrap_or(0);
        let total_blocks = if file_size > 0 {
            file_size.div_ceil(block_size)
        } else {
            0
        };

        // If block 0 is cached as an empty EOF sentinel but the file is known to be
        // non-empty, evict the stale sentinel so we re-download real data below.
        // This can happen when a previous read attempt received an empty body or
        // HTTP 416 for a block that should have content.
        if total_blocks > 0 {
            if let Some(b) = self.read_cache.get(ino, 0) {
                if b.is_empty() {
                    debug!("open: evicting stale EOF sentinel for ino={} block=0", ino);
                    self.read_cache.invalidate_block(ino, 0);
                }
            }
        }

        // Block 0: download synchronously so VLC's very first read() is a guaranteed cache hit.
        // If another task already claimed it, skip — it'll be in cache when read() runs.
        if total_blocks > 0
            && !self.read_cache.contains(ino, 0)
            && self.read_cache.claim_inflight(ino, 0)
        {
            match self.block(self.client.download(&path, 0, block_size)) {
                Ok(data) if !data.is_empty() => self.read_cache.insert(ino, 0, data),
                _ => self.read_cache.cancel_inflight(ino, 0),
            }
        }

        // Head: blocks 1-15 async — covers container headers and codec init data.
        let head_end = 16u64.min(total_blocks);
        for block_idx in 1..head_end {
            if !self.read_cache.contains(ino, block_idx)
                && self.read_cache.claim_inflight(ino, block_idx)
            {
                let client = self.client.clone();
                let rc = self.read_cache.clone();
                let p = path.clone();
                self.rt.spawn(async move {
                    let start = block_idx * block_size;
                    match client.download(&p, start, block_size).await {
                        Ok(data) => rc.insert(ino, block_idx, data), // empty == EOF sentinel
                        Err(_) => rc.cancel_inflight(ino, block_idx),
                    }
                });
            }
        }

        // Tail: last 4 blocks — MP4 MOOV boxes are often written at the end of the file.
        if total_blocks > head_end {
            let tail_start = total_blocks.saturating_sub(4).max(head_end);
            for block_idx in tail_start..total_blocks {
                if !self.read_cache.contains(ino, block_idx)
                    && self.read_cache.claim_inflight(ino, block_idx)
                {
                    let client = self.client.clone();
                    let rc = self.read_cache.clone();
                    let p = path.clone();
                    self.rt.spawn(async move {
                        let start = block_idx * block_size;
                        match client.download(&p, start, block_size).await {
                            Ok(data) => rc.insert(ino, block_idx, data), // empty == EOF sentinel
                            Err(_) => rc.cancel_inflight(ino, block_idx),
                        }
                    });
                }
            }
        }

        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.write_buffers.lock().unwrap().insert(
            fh,
            WriteBuffer {
                nas_path: path,
                ino,
                data: SpillBuffer::new(),
                dirty: false,
                new_file: false,
            },
        );
        // FOPEN_KEEP_CACHE: don't invalidate the kernel page cache between opens.
        reply.opened(FileHandle(fh), FopenFlags::FOPEN_KEEP_CACHE);
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        debug!(
            "write: ino={} fh={} offset={} len={}",
            ino,
            fh,
            offset,
            data.len()
        );

        // No background upload can be in flight: flush() uploads synchronously,
        // so by the time a write is dispatched any earlier flush has completed
        // and already cleared `new_file`.
        let mut buffers = self.write_buffers.lock().unwrap();
        let buf = match buffers.get_mut(&fh) {
            Some(b) => b,
            None => {
                reply.error(Errno::EIO);
                return;
            }
        };

        // If writing at an offset beyond current buffer, we need the existing file content first.
        // This is handled by seeding the buffer in create/open if needed.
        // For simplicity: if offset > current len, seed from API on first write.
        // The buffer spills to a temp file once it outgrows SpillBuffer's
        // threshold, so a large copy no longer pins the whole file in RAM (and
        // no longer stalls every other FUSE callback behind that allocation).
        if let Err(e) = buf.data.write_at(offset, data) {
            error!("write: buffering failed: {}", e);
            reply.error(Errno::EIO);
            return;
        }
        buf.dirty = true;
        reply.written(data.len() as u32);
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let fh = fh.0;
        debug!("flush: fh={}", fh);
        // The kernel returns *this* reply from close(2), and discards whatever
        // release() reports. So the upload has to happen here, synchronously,
        // and its error has to come back here — otherwise a failed upload is
        // reported to the application as a successful close.
        match self.finish_upload(fh) {
            Ok(()) => reply.ok(),
            Err(e) => {
                error!("flush fh={}: {}", fh, e);
                reply.error(errno(e.to_errno()));
            }
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let fh = fh.0;
        debug!("release: fh={}", fh);
        let result = self.finish_upload(fh);
        self.write_buffers.lock().unwrap().remove(&fh);
        match result {
            Ok(()) => reply.ok(),
            Err(e) => {
                error!("release fh={}: {}", fh, e);
                reply.error(errno(e.to_errno()));
            }
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let parent_path = match self.get_path_for_ino(parent.0) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let new_path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        debug!("create: {}", new_path);

        // Defer the actual NAS upload to flush/release.  Allocate an inode and
        // seed the cache with a synthetic entry so getattr works before the first
        // flush.  The write buffer is marked new_file=true so flush uses
        // overwrite=false, skipping the delete-before-upload round trips.
        let ino = self.cache.get_or_alloc_ino(&new_path);
        let synthetic_info = synology_filestation_core::types::SynoFileInfo {
            name: name_str.to_string(),
            path: new_path.clone(),
            isdir: false,
            additional: None,
            code: None,
        };
        let attr = self.syno_to_attr(ino, &synthetic_info);
        self.cache.insert(ino, synthetic_info);

        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.write_buffers.lock().unwrap().insert(
            fh,
            WriteBuffer {
                nas_path: new_path,
                ino,
                data: SpillBuffer::new(),
                dirty: false,
                new_file: true,
            },
        );

        reply.created(
            &TTL,
            &attr,
            fuser::Generation(0),
            FileHandle(fh),
            FopenFlags::empty(),
        );
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let parent_path = match self.get_path_for_ino(parent.0) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        debug!("unlink: {}", path);

        match self.block(self.client.delete(&path)) {
            Ok(()) => {
                if let Some(ino) = self.cache.get_ino_for_path(&path) {
                    self.read_cache.invalidate_ino(ino);
                }
                self.cache.invalidate_path(&path);
                reply.ok();
            }
            Err(e) => {
                error!("unlink {}: {}", path, e);
                reply.error(errno(e.to_errno()));
            }
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let parent_path = match self.get_path_for_ino(parent.0) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        debug!("rmdir: {}", path);

        match self.block(self.client.delete(&path)) {
            Ok(()) => {
                self.cache.invalidate_prefix(&path);
                reply.ok();
            }
            Err(e) => {
                error!("rmdir {}: {}", path, e);
                reply.error(errno(e.to_errno()));
            }
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let parent_path = match self.get_path_for_ino(parent.0) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        debug!("mkdir: {}/{}", parent_path, name_str);

        match self.block(self.client.create_folder(&parent_path, name_str)) {
            Ok(info) => {
                let ino = self.cache.get_or_alloc_ino(&info.path);
                let attr = self.syno_to_attr(ino, &info);
                self.cache.insert(ino, info);
                reply.entry(&TTL, &attr, fuser::Generation(0));
            }
            Err(e) => {
                error!("mkdir {}/{}: {}", parent_path, name_str, e);
                reply.error(errno(e.to_errno()));
            }
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        new_parent: INodeNo,
        new_name: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let parent = parent.0;
        let new_parent = new_parent.0;
        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let new_name_str = match new_name.to_str() {
            Some(s) => s,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let parent_path = match self.get_path_for_ino(parent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        let new_parent_path = match self.get_path_for_ino(new_parent) {
            Some(p) => p,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        let old_path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        let new_path = format!("{}/{}", new_parent_path.trim_end_matches('/'), new_name_str);
        debug!("rename: {} -> {}", old_path, new_path);

        // Same directory: use the efficient Rename API.
        // POSIX rename(2) must atomically replace the destination if it exists.
        // The Synology Rename API does not overwrite — delete the destination first.
        if parent == new_parent {
            if old_path != new_path {
                if let Some(ino) = self.cache.get_ino_for_path(&new_path) {
                    self.read_cache.invalidate_ino(ino);
                }
                self.cache.invalidate_path(&new_path);
                let _ = self.block(self.client.delete(&new_path)); // ignore error — may not exist
            }
            match self.block(self.client.rename(&old_path, new_name_str)) {
                Ok(info) => {
                    if let Some(ino) = self.cache.get_ino_for_path(&old_path) {
                        self.read_cache.invalidate_ino(ino);
                    }
                    self.cache.invalidate_path(&old_path);
                    let ino = self.cache.get_or_alloc_ino(&new_path);
                    self.cache.insert(ino, info);
                    reply.ok();
                }
                Err(e) => {
                    error!("rename {} -> {}: {}", old_path, new_path, e);
                    reply.error(errno(e.to_errno()));
                }
            }
            return;
        }

        // Cross-directory: check if it's a directory (not supported atomically)
        let is_dir = self
            .cache
            .get_by_ino(self.cache.get_or_alloc_ino(&old_path))
            .map(|e| e.info.isdir)
            .unwrap_or(false);

        if is_dir {
            // Cross-directory move of directories is not supported
            warn!("rename: cross-directory move of directories not supported");
            reply.error(Errno::ENOSYS);
            return;
        }

        // Cross-directory file move: download, upload, delete.
        match self.move_across_dirs(&old_path, &new_parent_path, new_name_str) {
            Ok(()) => {
                self.cache.invalidate_path(&old_path);
                reply.ok();
            }
            Err(e) => {
                error!("rename {} -> {}: {}", old_path, new_path, e);
                reply.error(errno(e.to_errno()));
            }
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let ino = ino.0;
        // Only handle size truncation (used by truncate())
        if let Some(new_size) = size {
            let path = match self.get_path_for_ino(ino) {
                Some(p) => p,
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            };
            debug!(
                "setattr truncate: ino={} path={} new_size={}",
                ino, path, new_size
            );

            match self.truncate_file(ino, &path, new_size) {
                Ok(info) => {
                    let attr = self.syno_to_attr(ino, &info);
                    self.cache.insert(ino, info);
                    reply.attr(&TTL, &attr);
                }
                Err(e) => {
                    error!("setattr truncate {}: {}", path, e);
                    reply.error(errno(e.to_errno()));
                }
            }
        } else {
            // For other attribute changes (permissions, timestamps), return current attrs
            // The Synology API doesn't support changing these
            if let Some(entry) = self.cache.get_by_ino(ino) {
                let attr = self.syno_to_attr(ino, &entry.info);
                reply.attr(&TTL, &attr);
            } else {
                reply.error(Errno::ENOENT);
            }
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: fuser::ReplyStatfs) {
        // Return reasonable placeholder stats
        // A future improvement could call SYNO.FileStation.Info for real quota info
        reply.statfs(
            u64::MAX / 4096, // blocks
            u64::MAX / 4096, // bfree
            u64::MAX / 4096, // bavail
            u64::MAX,        // files
            u64::MAX,        // ffree
            4096,            // bsize
            255,             // namelen
            4096,            // frsize
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;
    use synology_filestation_core::types::SynoAdditional;
    use wiremock::matchers::{method as http_method, path as http_path, query_param};
    use wiremock::{Mock, MockServer, Request as WmRequest, Respond, ResponseTemplate};

    /// Small blocks keep the fixtures readable; the assembly rules under test
    /// don't depend on the real 256 KiB size.
    const BLOCK: u64 = 1024;

    fn client_for(server: &MockServer) -> SynologyClient {
        let uri = server.uri();
        let (host, port) = uri
            .trim_start_matches("http://")
            .rsplit_once(':')
            .expect("mock server uri has a port");
        SynologyClient::new(host, port.parse().unwrap(), false)
    }

    /// Field order matters: `rt` is declared last so it is dropped last, after
    /// the mock server has had a runtime to shut itself down on.
    struct Fixture {
        fs: SynologyFS,
        server: MockServer,
        rt: tokio::runtime::Runtime,
    }

    fn fixture() -> Fixture {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let fs = SynologyFS::new(
            Arc::new(client_for(&server)),
            Arc::new(InodeCache::new(30)),
            Arc::new(ReadCache::new(BLOCK, 64)),
            rt.handle().clone(),
            1000,
            1000,
        );
        Fixture { fs, server, rt }
    }

    /// Serves file bytes the way DSM's Download API does: honours `Range`, and
    /// answers 416 past EOF. `short` caps how many bytes a given range *start*
    /// may return, which is how a test reproduces a truncated response — a
    /// successful HTTP 200 carrying fewer bytes than the range asked for.
    struct RangeFile {
        body: Vec<u8>,
        short: Map<u64, usize>,
    }

    impl Respond for RangeFile {
        fn respond(&self, req: &WmRequest) -> ResponseTemplate {
            if self.body.is_empty() {
                return ResponseTemplate::new(200).set_body_bytes(Vec::new());
            }
            let (start, end) = match req.headers.get("range").and_then(|v| v.to_str().ok()) {
                Some(r) => {
                    let (s, e) = r
                        .trim_start_matches("bytes=")
                        .split_once('-')
                        .expect("range header is bytes=S-E");
                    (
                        s.parse::<u64>().unwrap(),
                        e.parse::<u64>().unwrap_or(u64::MAX),
                    )
                }
                None => (0, self.body.len() as u64 - 1),
            };
            if start as usize >= self.body.len() {
                return ResponseTemplate::new(416);
            }
            let end = (end as usize).min(self.body.len() - 1);
            let mut slice = self.body[start as usize..=end].to_vec();
            if let Some(&cap) = self.short.get(&start) {
                slice.truncate(cap);
            }
            ResponseTemplate::new(206).set_body_bytes(slice)
        }
    }

    fn mount_download(f: &Fixture, body: Vec<u8>, short: Map<u64, usize>) {
        f.rt.block_on(
            Mock::given(http_method("GET"))
                .and(http_path("/webapi/entry.cgi"))
                .and(query_param("method", "download"))
                .respond_with(RangeFile { body, short })
                .mount(&f.server),
        );
    }

    fn mount_upload_ok(f: &Fixture) {
        f.rt.block_on(
            Mock::given(http_method("POST"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({"success": true, "data": {"blks": null}}),
                    ),
                )
                .mount(&f.server),
        );
    }

    fn mount_delete_ok(f: &Fixture) {
        f.rt.block_on(
            Mock::given(http_method("GET"))
                .and(query_param("method", "delete"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({"success": true})),
                )
                .mount(&f.server),
        );
    }

    /// `clear_for_overwrite` polls getinfo until the file is gone; answering
    /// "no such file" lets the upload proceed on the first poll.
    fn mount_getinfo_gone(f: &Fixture) {
        f.rt.block_on(
            Mock::given(http_method("GET"))
                .and(query_param("method", "getinfo"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({"success": false, "error": {"code": 414}}),
                    ),
                )
                .mount(&f.server),
        );
    }

    fn ramp(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn posted_bodies(f: &Fixture) -> Vec<Vec<u8>> {
        f.rt.block_on(f.server.received_requests())
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method.as_str() == "POST")
            .map(|r| r.body)
            .collect()
    }

    fn seed_dirty_buffer(f: &Fixture, nas_path: &str, data: &[u8]) -> u64 {
        let ino = f.fs.cache.get_or_alloc_ino(nas_path);
        let mut buf = SpillBuffer::new();
        buf.write_at(0, data).unwrap();
        let fh = 1u64;
        f.fs.write_buffers.lock().unwrap().insert(
            fh,
            WriteBuffer {
                nas_path: nas_path.to_string(),
                ino,
                data: buf,
                dirty: true,
                new_file: true,
            },
        );
        fh
    }

    // ── T1.4: block assembly ──────────────────────────────────────────────────

    /// Regression: the assembly loop only stopped on a *fully empty* block, so a
    /// block that came back short was appended and then the next block's bytes
    /// were appended directly behind it. The caller received a contiguous-looking
    /// buffer whose tail actually came from a different file offset — silent
    /// corruption. A short block must end the read.
    #[test]
    fn a_short_block_ends_the_read_instead_of_fabricating_contiguity() {
        let f = fixture();
        let body = ramp(4096);
        // Block 0 is truncated to 300 bytes. This is *not* EOF: the file really
        // is 4096 bytes, and block 1 would happily serve its full 1024.
        mount_download(&f, body.clone(), Map::from([(0u64, 300usize)]));

        let out = f.fs.read_range(7, "/share/f.bin", 0, 2 * BLOCK).unwrap();

        assert_eq!(
            out.as_slice(),
            &body[..300],
            "a short block must end the read, not be back-filled with block 1's bytes"
        );
    }

    /// The stop-on-short rule must not break the ordinary case it resembles:
    /// a final partial block at genuine EOF still contributes its bytes.
    #[test]
    fn a_genuinely_short_final_block_still_returns_the_whole_tail() {
        let f = fixture();
        let body = ramp(1500); // one full block + a 476-byte tail
        mount_download(&f, body.clone(), Map::new());

        let out = f.fs.read_range(8, "/share/f.bin", 0, 4 * BLOCK).unwrap();

        assert_eq!(out, body, "the short tail block is EOF, not corruption");
    }

    /// Reads that start part-way into a block must still line up.
    #[test]
    fn a_mid_block_offset_read_returns_the_right_slice() {
        let f = fixture();
        let body = ramp(4096);
        mount_download(&f, body.clone(), Map::new());

        let out = f.fs.read_range(11, "/share/f.bin", 1500, 1000).unwrap();

        assert_eq!(out.as_slice(), &body[1500..2500]);
    }

    // ── T1.2: truncate ────────────────────────────────────────────────────────

    /// Regression: a failed download was mapped to `Vec::new()`, so truncate
    /// then uploaded `new_size` zero bytes over a perfectly good file. One read
    /// timeout during `truncate -s N` destroyed the contents. It must abort.
    #[test]
    fn truncate_aborts_rather_than_zeroing_the_file_when_the_download_fails() {
        let f = fixture();
        f.rt.block_on(
            Mock::given(http_method("GET"))
                .and(query_param("method", "download"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&f.server),
        );
        // If truncate ever reaches the upload after a failed read, this catches it.
        f.rt.block_on(
            Mock::given(http_method("POST"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({"success": true, "data": {"blks": null}}),
                    ),
                )
                .expect(0)
                .mount(&f.server),
        );

        let err =
            f.fs.truncate_file(9, "/share/big.bin", 100)
                .expect_err("an unreadable file must not be silently replaced with zeros");
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
        // The `expect(0)` on the upload mock is asserted when the server drops.
    }

    /// Truncating to zero needs no prior content, and it is the common case
    /// (`O_TRUNC`, `> file`). Downloading a file we are about to discard is pure
    /// waste — and on a large file it is the whole file, in memory.
    #[test]
    fn truncate_to_zero_does_not_download_the_file_first() {
        let f = fixture();
        f.rt.block_on(
            Mock::given(http_method("GET"))
                .and(query_param("method", "download"))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(&f.server),
        );
        mount_delete_ok(&f);
        mount_getinfo_gone(&f);
        mount_upload_ok(&f);

        // The trailing get_info re-read fails against these mocks (getinfo is
        // wired to "gone" for the overwrite poll), which is irrelevant here: the
        // assertion is the `expect(0)` on the download mock.
        let _ = f.fs.truncate_file(10, "/share/f.bin", 0);
    }

    /// Truncation still has to do its actual job.
    #[test]
    fn truncate_uploads_the_resized_content() {
        let f = fixture();
        let body = ramp(4096);
        mount_download(&f, body.clone(), Map::new());
        mount_delete_ok(&f);
        mount_getinfo_gone(&f);
        mount_upload_ok(&f);

        let _ = f.fs.truncate_file(12, "/share/f.bin", 100);

        let posted = posted_bodies(&f);
        assert_eq!(posted.len(), 1, "exactly one upload");
        assert!(
            posted[0].windows(100).any(|w| w == &body[..100]),
            "the upload must carry the first 100 bytes of the original file"
        );
    }

    // ── T1.3: cross-directory move ────────────────────────────────────────────

    /// Regression: the move sized its download from the inode cache, then
    /// deleted the source. A stale-low cached size therefore truncated the file
    /// permanently. The download must ask for the whole file.
    #[test]
    fn cross_directory_move_copies_the_whole_file_not_the_cached_size() {
        let f = fixture();
        let body = ramp(4096);
        mount_download(&f, body.clone(), Map::new());
        mount_delete_ok(&f);
        mount_getinfo_gone(&f);
        mount_upload_ok(&f);

        // Stale metadata claiming the file is 10 bytes long.
        let ino = f.fs.cache.get_or_alloc_ino("/a/f.bin");
        f.fs.cache.insert(
            ino,
            SynoFileInfo {
                name: "f.bin".into(),
                path: "/a/f.bin".into(),
                isdir: false,
                additional: Some(SynoAdditional {
                    size: Some(10),
                    owner: None,
                    time: None,
                    perm: None,
                }),
                code: None,
            },
        );

        f.fs.move_across_dirs("/a/f.bin", "/b", "f.bin").unwrap();

        let posted = posted_bodies(&f);
        assert_eq!(posted.len(), 1, "exactly one upload");
        assert!(
            posted[0].windows(body.len()).any(|w| w == body.as_slice()),
            "the moved file must carry all {} bytes, not the {} the cache claimed",
            body.len(),
            10
        );
    }

    // ── T1.1: flush ───────────────────────────────────────────────────────────

    /// Regression: `flush` spawned the upload and replied OK immediately, and
    /// the kernel discards whatever `release` later reports — so a failed upload
    /// reached the application as a successful `close(2)`. The call `flush`
    /// delegates to must surface the failure.
    #[test]
    fn flush_reports_an_upload_failure_instead_of_swallowing_it() {
        let f = fixture();
        f.rt.block_on(
            Mock::given(http_method("POST"))
                .respond_with(ResponseTemplate::new(400))
                .mount(&f.server),
        );

        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"payload");
        let err =
            f.fs.finish_upload(fh)
                .expect_err("a failed upload must not look like a successful close");
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
    }

    /// `flush` must not return until the bytes are actually on the NAS — a
    /// merely-queued upload is one whose failure nobody can report.
    #[test]
    fn flush_completes_the_upload_before_returning() {
        let f = fixture();
        mount_upload_ok(&f);

        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"payload");
        f.fs.finish_upload(fh).unwrap();

        assert_eq!(
            posted_bodies(&f).len(),
            1,
            "the upload must have completed by the time flush returns, not merely been queued"
        );
    }

    /// A failed flush must leave the data buffered so `release` can retry it.
    /// Previously `dirty` was cleared *before* the upload was even started, so a
    /// failure silently discarded the write.
    #[test]
    fn a_failed_flush_keeps_the_data_pending_for_a_retry() {
        let f = fixture();
        f.rt.block_on(
            Mock::given(http_method("POST"))
                .respond_with(ResponseTemplate::new(400))
                .mount(&f.server),
        );

        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"payload");
        assert!(f.fs.finish_upload(fh).is_err());

        assert!(
            f.fs.write_buffers.lock().unwrap().get(&fh).unwrap().dirty,
            "a failed upload must leave the buffer dirty so release() retries it"
        );
    }

    /// A successful flush clears `new_file`, so a second flush of the same
    /// handle overwrites rather than racing an `overwrite=false` create against
    /// the file it just created.
    #[test]
    fn a_successful_flush_marks_the_file_as_existing() {
        let f = fixture();
        mount_upload_ok(&f);

        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"payload");
        f.fs.finish_upload(fh).unwrap();

        let buffers = f.fs.write_buffers.lock().unwrap();
        let buf = buffers.get(&fh).unwrap();
        assert!(!buf.dirty, "a successful upload clears dirty");
        assert!(!buf.new_file, "the file now exists on the NAS");
    }

    #[test]
    fn flush_of_a_clean_buffer_is_a_no_op() {
        let f = fixture();
        f.rt.block_on(
            Mock::given(http_method("POST"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&f.server),
        );

        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"payload");
        f.fs.write_buffers
            .lock()
            .unwrap()
            .get_mut(&fh)
            .unwrap()
            .dirty = false;

        f.fs.finish_upload(fh).unwrap();
    }

    #[test]
    fn split_nas_path_splits_on_the_last_separator() {
        assert_eq!(
            split_nas_path("/share/dir/f.txt"),
            Some(("/share/dir", "f.txt"))
        );
        assert_eq!(split_nas_path("/f.txt"), Some(("", "f.txt")));
        assert_eq!(split_nas_path("f.txt"), None);
    }
}

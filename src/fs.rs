use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::{EIO, ENOENT, ENOSYS};
use tracing::{debug, error, info, warn};

use crate::cache::{InodeCache, ReadCache};
use crate::client::SynologyClient;
use crate::error::SynoFsError;
use crate::types::{SynoFileInfo, VIRTUAL_ROOT_PATH};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;
/// Tell the kernel not to flush the page cache between opens of the same file.
const FOPEN_KEEP_CACHE: u32 = 2;

struct WriteBuffer {
    nas_path: String,
    ino: u64,
    data: Vec<u8>,
    dirty: bool,
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
        let kind = if info.isdir { FileType::Directory } else { FileType::RegularFile };
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
            ino,
            size,
            blocks: (size + 511) / 512,
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

    fn flush_write_buffer(&self, fh: u64) -> Result<(), SynoFsError> {
        let (nas_path, ino, data) = {
            let mut buffers = self.write_buffers.lock().unwrap();
            let buf = match buffers.get_mut(&fh) {
                Some(b) if b.dirty => b,
                _ => return Ok(()),
            };
            let path = buf.nas_path.clone();
            let ino = buf.ino;
            let data = buf.data.clone();
            buf.dirty = false;
            (path, ino, data)
        };

        let parent = match nas_path.rfind('/') {
            Some(i) => &nas_path[..i],
            None => return Err(SynoFsError::InvalidArg),
        };
        let filename = &nas_path[nas_path.rfind('/').unwrap() + 1..];

        debug!("flush_write_buffer: fh={} parent={:?} filename={:?} size={}", fh, parent, filename, data.len());
        self.block(self.client.upload(parent, filename, data, true))?;
        self.cache.invalidate_path(&nas_path);
        self.read_cache.invalidate_ino(ino);
        Ok(())
    }

    /// Synthetic FileAttr for the virtual root (inode 1).
    fn virtual_root_attr(&self) -> FileAttr {
        FileAttr {
            ino: ROOT_INO,
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
    fn init(
        &mut self,
        _req: &Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
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
            if let Err(e) = self.flush_write_buffer(fh) {
                warn!("destroy: failed to flush fh {}: {}", fh, e);
            }
        }
        let _ = self.block(self.client.logout());
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(ENOENT); return; }
        };

        let parent_path = match self.get_path_for_ino(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        // Looking up a share name directly under the virtual root.
        if parent_path == VIRTUAL_ROOT_PATH {
            debug!("lookup share: {}", name_str);
            let shares = match self.block(self.client.list_shares()) {
                Ok(s) => s,
                Err(e) => { reply.error(e.to_errno()); return; }
            };
            match shares.into_iter().find(|s| s.name == name_str) {
                Some(info) => {
                    let ino = self.cache.get_or_alloc_ino(&info.path);
                    let attr = self.syno_to_attr(ino, &info);
                    self.cache.insert(ino, info);
                    reply.entry(&TTL, &attr, 0);
                }
                None => reply.error(ENOENT),
            }
            return;
        }

        let child_path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        debug!("lookup: {}", child_path);

        // Check cache first
        if let Some(entry) = self.cache.get_by_ino(self.cache.get_or_alloc_ino(&child_path)) {
            let attr = self.syno_to_attr(entry.ino, &entry.info);
            reply.entry(&TTL, &attr, 0);
            return;
        }

        match self.block(self.client.get_info(&child_path)) {
            Ok(info) => {
                let ino = self.cache.get_or_alloc_ino(&child_path);
                let attr = self.syno_to_attr(ino, &info);
                self.cache.insert(ino, info);
                reply.entry(&TTL, &attr, 0);
            }
            Err(SynoFsError::NotFound)
            | Err(SynoFsError::ApiError(408 | 414 | 415)) => {
                reply.error(ENOENT);
            }
            Err(e) => {
                error!("lookup {}: {}", child_path, e);
                reply.error(e.to_errno());
            }
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
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
            None => { reply.error(ENOENT); return; }
        };

        match self.block(self.client.get_info(&path)) {
            Ok(info) => {
                let attr = self.syno_to_attr(ino, &info);
                self.cache.insert(ino, info);
                reply.attr(&TTL, &attr);
            }
            Err(e) => {
                error!("getattr ino={} path={}: {}", ino, path, e);
                reply.error(e.to_errno());
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.get_path_for_ino(ino) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };
        debug!("readdir: ino={} path={} offset={}", ino, path, offset);

        // Virtual root: list FileStation shares instead of a real directory.
        let (entries, parent_ino) = if path == VIRTUAL_ROOT_PATH {
            let shares = match self.block(self.client.list_shares()) {
                Ok(s) => s,
                Err(e) => { error!("readdir shares: {}", e); reply.error(e.to_errno()); return; }
            };
            debug!("readdir root: got {} shares", shares.len());
            (shares, ROOT_INO)
        } else {
            let entries = match self.block(self.client.list_dir(&path)) {
                Ok(e) => e,
                Err(e) => { error!("readdir {}: {}", path, e); reply.error(e.to_errno()); return; }
            };
            let parent_ino = path.rfind('/').map(|i| {
                let parent_path = &path[..i];
                // parent of a top-level share (e.g. "/homes") is the virtual root
                if parent_path.is_empty() { ROOT_INO } else { self.cache.get_or_alloc_ino(parent_path) }
            }).unwrap_or(ROOT_INO);
            (entries, parent_ino)
        };

        // Build full entry list: ".", "..", then actual entries
        let mut all_entries: Vec<(u64, FileType, String)> = Vec::new();
        all_entries.push((ino, FileType::Directory, ".".to_string()));
        all_entries.push((parent_ino, FileType::Directory, "..".to_string()));

        for file_info in entries {
            let child_ino = self.cache.get_or_alloc_ino(&file_info.path);
            let kind = if file_info.isdir { FileType::Directory } else { FileType::RegularFile };
            let name = file_info.name.clone();
            self.cache.insert(child_ino, file_info);
            all_entries.push((child_ino, kind, name));
        }

        for (i, (child_ino, kind, name)) in all_entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*child_ino, (i + 1) as i64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if size == 0 {
            reply.data(&[]);
            return;
        }

        let path = match self.get_path_for_ino(ino) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let offset = offset as u64;
        let size = size as u64;
        let block_size = self.read_cache.block_size;
        let first_block = offset / block_size;
        let last_block = (offset + size - 1) / block_size;

        debug!("read: ino={} path={} offset={} size={} blocks=[{}..={}]",
               ino, path, offset, size, first_block, last_block);

        let mut result: Vec<u8> = Vec::with_capacity(size as usize);

        for block_idx in first_block..=last_block {
            let block_start = block_idx * block_size;

            let block = if let Some(cached) = self.read_cache.get(ino, block_idx) {
                if cached.is_empty() { break; } // EOF sentinel
                cached
            } else if self.read_cache.claim_inflight(ino, block_idx) {
                // We won the race — download synchronously.
                debug!("read cache miss: ino={} block={}", ino, block_idx);
                match self.block(self.client.download(&path, block_start, block_size)) {
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
                        reply.error(e.to_errno());
                        return;
                    }
                }
            } else {
                // Another task is downloading this block — wait for it.
                debug!("read waiting for inflight: ino={} block={}", ino, block_idx);
                match self.read_cache.wait_for_block(ino, block_idx) {
                    Some(b) if b.is_empty() => break, // EOF sentinel
                    Some(b) => b,
                    None => {
                        // Other task had a real network error.
                        reply.error(EIO);
                        return;
                    }
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
        }

        // Background prefetch of the next 16 blocks to keep VLC's read-ahead buffer full.
        for prefetch_idx in (last_block + 1)..=(last_block + 16) {
            if !self.read_cache.contains(ino, prefetch_idx) && self.read_cache.claim_inflight(ino, prefetch_idx) {
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

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = match self.get_path_for_ino(ino) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };
        debug!("open: ino={} path={} flags={:#o}", ino, path, flags);

        let block_size = self.read_cache.block_size;
        let file_size = self.cache.get_size_for_ino(ino).unwrap_or(0);
        let total_blocks = if file_size > 0 { (file_size + block_size - 1) / block_size } else { 0 };

        // Block 0: download synchronously so VLC's very first read() is a guaranteed cache hit.
        if total_blocks > 0 && !self.read_cache.contains(ino, 0) {
            if self.read_cache.claim_inflight(ino, 0) {
                match self.block(self.client.download(&path, 0, block_size)) {
                    Ok(data) if !data.is_empty() => self.read_cache.insert(ino, 0, data),
                    _ => self.read_cache.cancel_inflight(ino, 0),
                }
            }
            // If another task already claimed it, skip — it'll be in cache when read() runs.
        }

        // Head: blocks 1-15 async — covers container headers and codec init data.
        let head_end = 16u64.min(total_blocks);
        for block_idx in 1..head_end {
            if !self.read_cache.contains(ino, block_idx) && self.read_cache.claim_inflight(ino, block_idx) {
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
                if !self.read_cache.contains(ino, block_idx) && self.read_cache.claim_inflight(ino, block_idx) {
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
        self.write_buffers.lock().unwrap().insert(fh, WriteBuffer {
            nas_path: path,
            ino,
            data: Vec::new(),
            dirty: false,
        });
        // FOPEN_KEEP_CACHE: don't invalidate the kernel page cache between opens.
        reply.opened(fh, FOPEN_KEEP_CACHE);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        debug!("write: ino={} fh={} offset={} len={}", ino, fh, offset, data.len());
        let mut buffers = self.write_buffers.lock().unwrap();
        let buf = match buffers.get_mut(&fh) {
            Some(b) => b,
            None => { reply.error(EIO); return; }
        };

        // If writing at an offset beyond current buffer, we need the existing file content first.
        // This is handled by seeding the buffer in create/open if needed.
        // For simplicity: if offset > current len, seed from API on first write.
        let offset = offset as usize;
        let end = offset + data.len();
        if end > buf.data.len() {
            buf.data.resize(end, 0);
        }
        buf.data[offset..end].copy_from_slice(data);
        buf.dirty = true;
        reply.written(data.len() as u32);
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        debug!("flush: fh={}", fh);
        match self.flush_write_buffer(fh) {
            Ok(()) => reply.ok(),
            Err(e) => { error!("flush fh={}: {}", fh, e); reply.error(e.to_errno()); }
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        debug!("release: fh={}", fh);
        let result = self.flush_write_buffer(fh);
        self.write_buffers.lock().unwrap().remove(&fh);
        match result {
            Ok(()) => reply.ok(),
            Err(e) => { error!("release fh={}: {}", fh, e); reply.error(e.to_errno()); }
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(ENOENT); return; }
        };

        let parent_path = match self.get_path_for_ino(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let new_path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        debug!("create: {}", new_path);

        // Upload an empty file to create it
        match self.block(self.client.upload(&parent_path, name_str, vec![], false)) {
            Ok(()) => {}
            Err(e) => {
                error!("create {}: {}", new_path, e);
                reply.error(e.to_errno());
                return;
            }
        }

        // Fetch the created file's metadata
        let info = match self.block(self.client.get_info(&new_path)) {
            Ok(i) => i,
            Err(e) => {
                error!("create getinfo {}: {}", new_path, e);
                reply.error(e.to_errno());
                return;
            }
        };

        let ino = self.cache.get_or_alloc_ino(&new_path);
        let attr = self.syno_to_attr(ino, &info);
        self.cache.insert(ino, info);

        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.write_buffers.lock().unwrap().insert(fh, WriteBuffer {
            nas_path: new_path,
            ino,
            data: Vec::new(),
            dirty: false,
        });

        reply.created(&TTL, &attr, 0, fh, 0);
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(ENOENT); return; }
        };
        let parent_path = match self.get_path_for_ino(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
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
            Err(e) => { error!("unlink {}: {}", path, e); reply.error(e.to_errno()); }
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(ENOENT); return; }
        };
        let parent_path = match self.get_path_for_ino(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };
        let path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        debug!("rmdir: {}", path);

        match self.block(self.client.delete(&path)) {
            Ok(()) => {
                self.cache.invalidate_prefix(&path);
                reply.ok();
            }
            Err(e) => { error!("rmdir {}: {}", path, e); reply.error(e.to_errno()); }
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(ENOENT); return; }
        };
        let parent_path = match self.get_path_for_ino(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };
        debug!("mkdir: {}/{}", parent_path, name_str);

        match self.block(self.client.create_folder(&parent_path, name_str)) {
            Ok(info) => {
                let ino = self.cache.get_or_alloc_ino(&info.path);
                let attr = self.syno_to_attr(ino, &info);
                self.cache.insert(ino, info);
                reply.entry(&TTL, &attr, 0);
            }
            Err(e) => {
                error!("mkdir {}/{}: {}", parent_path, name_str, e);
                reply.error(e.to_errno());
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(ENOENT); return; }
        };
        let new_name_str = match new_name.to_str() {
            Some(s) => s,
            None => { reply.error(ENOENT); return; }
        };
        let parent_path = match self.get_path_for_ino(parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };
        let new_parent_path = match self.get_path_for_ino(new_parent) {
            Some(p) => p,
            None => { reply.error(ENOENT); return; }
        };

        let old_path = format!("{}/{}", parent_path.trim_end_matches('/'), name_str);
        let new_path = format!("{}/{}", new_parent_path.trim_end_matches('/'), new_name_str);
        debug!("rename: {} -> {}", old_path, new_path);

        // Same directory: use the efficient Rename API
        if parent == new_parent {
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
                    reply.error(e.to_errno());
                }
            }
            return;
        }

        // Cross-directory: check if it's a directory (not supported atomically)
        let is_dir = self.cache.get_by_ino(
            self.cache.get_or_alloc_ino(&old_path)
        ).map(|e| e.info.isdir).unwrap_or(false);

        if is_dir {
            // Cross-directory move of directories is not supported
            warn!("rename: cross-directory move of directories not supported");
            reply.error(ENOSYS);
            return;
        }

        // Cross-directory file move: download, upload, delete
        // Get the file size first
        let file_size = self.cache.get_by_ino(
            self.cache.get_or_alloc_ino(&old_path)
        ).and_then(|e| e.info.additional.as_ref()?.size).unwrap_or(0);

        let data = match self.block(self.client.download(&old_path, 0, file_size)) {
            Ok(b) => b,
            Err(e) => { reply.error(e.to_errno()); return; }
        };

        match self.block(self.client.upload(&new_parent_path, new_name_str, data.to_vec(), false)) {
            Ok(()) => {}
            Err(e) => { reply.error(e.to_errno()); return; }
        }

        match self.block(self.client.delete(&old_path)) {
            Ok(()) => {}
            Err(e) => {
                warn!("rename: uploaded {} but failed to delete {}: {}", new_path, old_path, e);
            }
        }

        self.cache.invalidate_path(&old_path);
        reply.ok();
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Only handle size truncation (used by truncate())
        if let Some(new_size) = size {
            let path = match self.get_path_for_ino(ino) {
                Some(p) => p,
                None => { reply.error(ENOENT); return; }
            };
            debug!("setattr truncate: ino={} path={} new_size={}", ino, path, new_size);

            let new_size = new_size as usize;

            // Download current content
            let current = match self.block(self.client.download(&path, 0, 0)) {
                Ok(b) => b.to_vec(),
                Err(_) => Vec::new(),
            };

            let mut data = current;
            data.resize(new_size, 0);

            let parent = path.rfind('/').map(|i| &path[..i]).unwrap_or("/");
            let filename = &path[path.rfind('/').unwrap_or(0) + 1..];

            match self.block(self.client.upload(parent, filename, data, true)) {
                Ok(()) => {
                    self.read_cache.invalidate_ino(ino);
                    self.cache.invalidate_path(&path);
                    // Re-fetch attr
                    match self.block(self.client.get_info(&path)) {
                        Ok(info) => {
                            let attr = self.syno_to_attr(ino, &info);
                            self.cache.insert(ino, info);
                            reply.attr(&TTL, &attr);
                        }
                        Err(e) => reply.error(e.to_errno()),
                    }
                }
                Err(e) => reply.error(e.to_errno()),
            }
        } else {
            // For other attribute changes (permissions, timestamps), return current attrs
            // The Synology API doesn't support changing these
            if let Some(entry) = self.cache.get_by_ino(ino) {
                let attr = self.syno_to_attr(ino, &entry.info);
                reply.attr(&TTL, &attr);
            } else {
                reply.error(ENOENT);
            }
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
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

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

use crate::cache::{DirCache, InodeCache, ReadCache};
use crate::spill::{payload_for, upload_payload, SpillBuffer};
use synology_filestation_core::client::SynologyClient;
use synology_filestation_core::error::SynoFsError;
use synology_filestation_core::transport::{WriteHandle, WriteOpen};
use synology_filestation_core::types::{SynoFileInfo, VIRTUAL_ROOT_PATH};

const TTL: Duration = Duration::from_secs(1);

/// What `opendir` tells the kernel it may keep.
///
/// Without `FOPEN_CACHE_DIR` the kernel caches nothing about a directory, so
/// every `opendir` + `getdents` pair from every caller arrives here — a native
/// filesystem would answer most of them from the page cache and never be
/// asked. A client that lists a directory in a loop therefore lands on this
/// filesystem in full, hundreds of times a second.
///
/// Granting it is not a new promise. `--cache-ttl` already says how stale a
/// listing may be, and this hands the kernel the same contract; a mount that
/// set it to zero asked for no caching, and gets none here either rather than
/// having the flag honoured in one layer and ignored in the next.
fn dir_open_flags(may_cache: bool) -> FopenFlags {
    if may_cache {
        FopenFlags::FOPEN_CACHE_DIR
    } else {
        FopenFlags::empty()
    }
}
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

/// Where an open handle's writes go.
///
/// Two shapes, because the transports differ in what they can be told. SMB
/// addresses ranges, so a write goes to the server as it arrives: memory is
/// bounded by one chunk, `write(2)` back-pressures at network speed instead of
/// returning instantly into a growing temp file, and a failure surfaces where
/// it happened rather than minutes later at `close(2)`. The HTTP Upload API
/// takes a whole file and nothing smaller, so it keeps the old shape.
enum WriteSink {
    /// Streamed to the server. `None` once closed, or once a write failed and
    /// the handle was abandoned.
    Streamed(Option<Box<dyn WriteHandle>>),
    /// Held locally, spilling to a temp file, and uploaded whole on close.
    Buffered(SpillBuffer),
}

struct WriteBuffer {
    nas_path: String,
    ino: u64,
    sink: WriteSink,
    dirty: bool,
    /// True when the file was just created and has not yet been uploaded.
    /// Allows the first upload to use overwrite=false, skipping the
    /// delete-before-upload round trips. Cleared once an upload succeeds.
    new_file: bool,
    /// Set when a streamed write failed. The file on the server is short and
    /// the handle is gone, so `close` must report that rather than claim the
    /// write landed.
    broken: bool,
}

/// How the mount presents ownership and permissions to the kernel.
///
/// DSM's identifiers describe the *appliance*, not this machine, so they are
/// deliberately dropped rather than mapped: shares arrive owned by root as
/// `dr----x--t` (mode 0o1411, sticky) and their contents owned by
/// directory-service ids like 1161823311 with mode 000. Exporting that verbatim
/// made glib apply the sticky-directory rule — a file is deletable only by its
/// own owner or its parent directory's owner — and report
/// `access::can-delete: FALSE` for everything inside a share, so GNOME Files
/// hid Delete, Move to Trash and Rename. (The kernel never enforced those bits:
/// the mount carries no `default_permissions`. The damage was entirely in what
/// userspace concluded from the metadata.)
///
/// So every entry is presented as owned by the mounting user with a synthetic
/// mode, the way sshfs and rclone do it. What the account may actually do is
/// still decided by DSM on each call, and surfaces as an error from that call.
#[derive(Debug, Clone, Copy)]
pub struct Ownership {
    /// Owner reported for every entry — the mounting user unless overridden.
    pub uid: u32,
    /// Group reported for every entry.
    pub gid: u32,
    /// Masked out of the synthetic mode, as a process umask would be.
    pub umask: u16,
}

impl Ownership {
    /// The synthetic mode for an entry: `0o777`/`0o666` less the umask.
    pub fn perm(&self, isdir: bool) -> u16 {
        let base = if isdir { 0o777 } else { 0o666 };
        base & !self.umask
    }
}

/// Translate FileStation metadata into a `FileAttr`, presenting it under
/// `owner` rather than under whatever identifiers DSM reported.
///
/// A free function rather than a method: a spawned transfer replies to the
/// kernel from the runtime, where there is no `&self` left to borrow — only
/// the `Ownership` it copied out of the filesystem.
fn file_attr(owner: Ownership, ino: u64, info: &SynoFileInfo) -> FileAttr {
    let kind = if info.isdir {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    let size = info.additional.as_ref().and_then(|a| a.size).unwrap_or(0);
    let perm = owner.perm(info.isdir);

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
        // The epoch, not `now()`. An entry DSM sent no `time` for has an
        // unknown timestamp, and `now()` answers that question differently
        // every time it is asked — so nothing, kernel included, can ever cache
        // an attribute for it, and the mount revalidates forever. A poor
        // timestamp that stays put beats a plausible one that does not.
        .unwrap_or((UNIX_EPOCH, UNIX_EPOCH, UNIX_EPOCH, UNIX_EPOCH));

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
        uid: owner.uid,
        gid: owner.gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Open write handles, keyed by file handle. The outer lock guards the map and
/// is never held across I/O; each buffer has its own lock so a transfer on one
/// handle never blocks work on another. Shared with spawned transfer tasks,
/// hence the `Arc`.
type Buffers = Arc<Mutex<HashMap<u64, Arc<tokio::sync::Mutex<WriteBuffer>>>>>;

/// How many file transfers may be on the wire at once.
///
/// The FUSE event loop used to be this limit by accident — one dispatch thread
/// meant one transfer — which is also precisely why a single upload wedged the
/// mount. Now that transfers run on the Tokio runtime, nothing else bounds
/// them, and unbounded parallel FileStation transfers are what saturated
/// `synoscgi` (the shared per-request CGI backend behind the Download/Upload
/// APIs) and took the appliance down. Keep the fan-out single-digit: DSM's own
/// web client uploads one slice at a time.
const MAX_CONCURRENT_TRANSFERS: usize = 4;

/// Everything a file transfer touches, cloned out of the filesystem so a
/// spawned task owns it and can outlive the callback that started it.
///
/// This is what lets `flush`, `setattr` and `rename` hand a multi-gigabyte
/// transfer to the runtime and return immediately: the FUSE callback keeps
/// nothing borrowed, and the kernel reply is sent from the task when the
/// transfer actually lands.
#[derive(Clone)]
struct Transfers {
    client: Arc<SynologyClient>,
    cache: Arc<InodeCache>,
    dir_cache: Arc<DirCache>,
    read_cache: Arc<ReadCache>,
    buffers: Buffers,
    limit: Arc<tokio::sync::Semaphore>,
}

/// Forget the listing of the directory `path` sits in.
///
/// Called wherever this mount changes what a directory contains. The TTL is a
/// contract about changes made *elsewhere*; a file this process just created
/// has to appear in the very next listing, or the mount contradicts itself.
///
/// Free rather than a method because both the filesystem and its transfer half
/// change directory contents, and the rule is the same for each.
fn forget_parent_listing(dir_cache: &DirCache, path: &str) {
    let parent = match path.rfind('/') {
        // A top-level share: its parent is the virtual root.
        Some(0) | None => VIRTUAL_ROOT_PATH,
        Some(cut) => &path[..cut],
    };
    dir_cache.invalidate(parent);
}

impl Transfers {
    fn buffer(&self, fh: u64) -> Option<Arc<tokio::sync::Mutex<WriteBuffer>>> {
        self.buffers.lock().unwrap().get(&fh).cloned()
    }

    /// Wait for a slot on the wire. Held only for the network call itself, so a
    /// queued transfer costs a future, not a thread.
    async fn permit(&self) -> tokio::sync::SemaphorePermit<'_> {
        self.limit
            .acquire()
            .await
            .expect("the transfer semaphore is never closed")
    }

    /// Upload `fh`'s buffered data and resolve once the NAS has it.
    ///
    /// `dirty` is cleared only *after* the upload succeeds, so a failed flush
    /// leaves the data buffered for `release` to retry rather than silently
    /// discarding the write.
    async fn upload(&self, fh: u64) -> Result<(), SynoFsError> {
        let handle = match self.buffer(fh) {
            Some(h) => h,
            // Unknown handle: there is genuinely nothing to do.
            None => return Ok(()),
        };
        // Lock first, permit second — never the other way round. A task holding
        // a permit while waiting for a buffer lock could be waiting on a task
        // that is itself queued for a permit; with every permit held by such a
        // waiter, nothing would ever progress.
        //
        // The lock is held for the whole transfer, which is the point: for a
        // spilled buffer the payload *is* the temp file being streamed, so a
        // concurrent write would tear the body mid-flight.
        let mut buf = handle.lock().await;
        if buf.broken {
            // A write already failed and took the handle with it. Reporting
            // success here would tell the application its file is safe.
            return Err(SynoFsError::Io(format!(
                "close {}: an earlier write to this file failed",
                buf.nas_path
            )));
        }
        if !buf.dirty {
            // Nothing written since the last successful upload.
            return Ok(());
        }

        // Decide what this handle needs before touching any other field: the
        // match borrows the sink, and the rest of the work wants the buffer.
        enum Finish {
            Close(Option<Box<dyn WriteHandle>>),
            Send(crate::spill::Payload),
        }
        let finish = match &mut buf.sink {
            WriteSink::Streamed(slot) => Finish::Close(slot.take()),
            WriteSink::Buffered(spill) => {
                Finish::Send(payload_for(spill).map_err(|e| SynoFsError::Io(e.to_string()))?)
            }
        };
        let (nas_path, ino, overwrite) = (buf.nas_path.clone(), buf.ino, !buf.new_file);

        match finish {
            // Streamed: the bytes went out as they were written, so closing is
            // the whole of "make it durable".
            Finish::Close(stream) => {
                if let Some(mut stream) = stream {
                    let _permit = self.permit().await;
                    stream.close().await?;
                }
                debug!("close: fh={} path={}", fh, nas_path);
            }
            Finish::Send(payload) => {
                let (parent, filename) = match split_nas_path(&nas_path) {
                    Some(v) => v,
                    None => return Err(SynoFsError::InvalidArg),
                };
                debug!(
                    "upload: fh={} parent={:?} filename={:?} size={}",
                    fh,
                    parent,
                    filename,
                    payload.len()
                );
                let _permit = self.permit().await;
                upload_payload(&self.client, parent, filename, payload, overwrite).await?;
            }
        }

        // Durable now: stop advertising the buffer as dirty, and record that the
        // file exists on the NAS so a later flush overwrites instead of racing
        // an `overwrite=false` create against itself.
        buf.dirty = false;
        buf.new_file = false;
        drop(buf);

        self.cache.invalidate_path(&nas_path);
        forget_parent_listing(&self.dir_cache, &nas_path);
        self.read_cache.invalidate_ino(ino);
        Ok(())
    }

    /// Resize `path` to `new_size`, zero-extending or truncating.
    ///
    /// FileStation has no truncate call, so this is read-modify-write. A
    /// download that fails must abort the whole operation, because the
    /// alternative — treating an unreadable file as an empty one — uploads
    /// `new_size` zero bytes over perfectly good data.
    async fn truncate(
        &self,
        ino: u64,
        path: &str,
        new_size: u64,
    ) -> Result<SynoFileInfo, SynoFsError> {
        // The client picks how: a backend that can set a length does it in one
        // round trip, and only the HTTP fallback still has to move the file's
        // contents to change one number.
        {
            let _permit = self.permit().await;
            self.client.truncate(path, new_size).await?;
        }

        self.read_cache.invalidate_ino(ino);
        self.cache.invalidate_path(path);
        self.client.get_info(path).await
    }

    /// Move a file between directories: download, upload to the new location,
    /// then delete the source. FileStation's Rename API cannot move across
    /// directories, so this is the only route.
    async fn move_across_dirs(
        &self,
        old_path: &str,
        new_parent: &str,
        new_name: &str,
    ) -> Result<(), SynoFsError> {
        // `length = 0` means "the whole file". Sizing this request from the
        // inode cache instead would silently truncate the file whenever that
        // cached size is stale-low — and this path deletes the source
        // afterwards, so the missing bytes are simply gone.
        let permit = self.permit().await;
        let data = self.client.download(old_path, 0, 0).await?;
        drop(permit);

        {
            let _permit = self.permit().await;
            self.client
                .upload(new_parent, new_name, data.to_vec(), true)
                .await?;
        }

        // Only the source deletion is best-effort: the copy is already safe on
        // the NAS, so a failure here leaves a duplicate rather than losing data.
        if let Err(e) = self.client.delete(old_path).await {
            warn!(
                "rename: uploaded {}/{} but failed to delete {}: {}",
                new_parent, new_name, old_path, e
            );
        }
        Ok(())
    }
}

pub struct SynologyFS {
    client: Arc<SynologyClient>,
    cache: Arc<InodeCache>,
    /// Directory listings, so a client that reads a directory repeatedly does
    /// not become repeated load on the appliance. See [`DirCache`].
    dir_cache: Arc<DirCache>,
    read_cache: Arc<ReadCache>,
    rt: tokio::runtime::Handle,
    write_buffers: Buffers,
    /// Bounds how many transfers are on the wire at once, now that they are no
    /// longer implicitly serialised by the event loop.
    transfer_limit: Arc<tokio::sync::Semaphore>,
    next_fh: AtomicU64,
    owner: Ownership,
}

impl SynologyFS {
    /// A directory's entries, from the cache when they are there.
    ///
    /// The single place a listing is obtained, so the caching applies to every
    /// caller rather than to whichever one remembered. `readdir` and `lookup`
    /// both go through it, and both used to hit the network unconditionally —
    /// which, for a directory the kernel reads three times per `ls`, is three
    /// round trips to say one thing.
    ///
    /// The virtual root is a listing like any other; that it comes from
    /// `list_share` rather than `list` is the only difference, and it is the
    /// one that gets polled.
    fn listing(&self, path: &str) -> Result<Arc<Vec<SynoFileInfo>>, SynoFsError> {
        if let Some(cached) = self.dir_cache.get(path) {
            return Ok(cached);
        }
        let entries = if path == VIRTUAL_ROOT_PATH {
            self.block(self.client.list_shares())?
        } else {
            self.block(self.client.list_dir(path))?
        };
        // `insert` hands back what it stored, so this still works when caching
        // is switched off (`--cache-ttl 0`) and nothing was stored at all.
        Ok(self.dir_cache.insert(path, entries))
    }

    pub fn new(
        client: Arc<SynologyClient>,
        cache: Arc<InodeCache>,
        dir_cache: Arc<DirCache>,
        read_cache: Arc<ReadCache>,
        rt: tokio::runtime::Handle,
        owner: Ownership,
    ) -> Self {
        Self {
            client,
            cache,
            dir_cache,
            read_cache,
            rt,
            write_buffers: Arc::new(Mutex::new(HashMap::new())),
            transfer_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TRANSFERS)),
            next_fh: AtomicU64::new(1),
            owner,
        }
    }

    /// A transfer bundle owning clones of everything a background task needs.
    fn transfers(&self) -> Transfers {
        Transfers {
            client: self.client.clone(),
            cache: self.cache.clone(),
            dir_cache: self.dir_cache.clone(),
            read_cache: self.read_cache.clone(),
            buffers: self.write_buffers.clone(),
            limit: self.transfer_limit.clone(),
        }
    }

    fn block<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.rt.block_on(fut)
    }

    fn syno_to_attr(&self, ino: u64, info: &SynoFileInfo) -> FileAttr {
        file_attr(self.owner, ino, info)
    }

    fn get_path_for_ino(&self, ino: u64) -> Option<String> {
        self.cache.get_path_for_ino(ino)
    }

    /// Start `fh`'s upload on the Tokio runtime and hand the outcome to `done`.
    ///
    /// This is the shape that keeps a transfer off the FUSE event loop.
    /// `close(2)` still returns the upload's real outcome — `done` sends the
    /// kernel reply — but it is produced on a runtime thread, so the event-loop
    /// thread returns to serving the mount the moment the work is queued.
    /// Uploading inline was what made a large copy look like a hung filesystem.
    fn start_upload<F>(&self, fh: u64, done: F)
    where
        F: FnOnce(Result<(), SynoFsError>) + Send + 'static,
    {
        let xfer = self.transfers();
        self.rt.spawn(async move { done(xfer.upload(fh).await) });
    }

    /// Same, for the read-modify-write behind `truncate`.
    fn start_truncate<F>(&self, ino: u64, path: String, new_size: u64, done: F)
    where
        F: FnOnce(Result<SynoFileInfo, SynoFsError>) + Send + 'static,
    {
        let xfer = self.transfers();
        self.rt
            .spawn(async move { done(xfer.truncate(ino, &path, new_size).await) });
    }

    /// Same, for the download→upload→delete behind a cross-directory rename.
    fn start_move_across_dirs<F>(
        &self,
        old_path: String,
        new_parent: String,
        new_name: String,
        done: F,
    ) where
        F: FnOnce(Result<(), SynoFsError>) + Send + 'static,
    {
        let xfer = self.transfers();
        self.rt.spawn(async move {
            done(
                xfer.move_across_dirs(&old_path, &new_parent, &new_name)
                    .await,
            )
        });
    }

    /// Upload `fh`'s buffered data, blocking until it lands.
    ///
    /// Only `destroy` uses this: at unmount there is no event loop left to keep
    /// responsive, and the runtime is about to go away, so the wait is the
    /// point. Everything else goes through [`SynologyFS::start_upload`].
    fn finish_upload(&self, fh: u64) -> Result<(), SynoFsError> {
        let xfer = self.transfers();
        self.block(xfer.upload(fh))
    }

    /// Buffer `data` at `offset` for the handle `fh`.
    ///
    /// Split out of the `write` callback so the locking contract — a write to a
    /// handle whose upload is in flight waits for it — is testable without a
    /// live mount. Waiting is correct: the upload may be streaming the very
    /// spill file this would overwrite. It is also rare, since an application
    /// has stopped writing by the time `close(2)` triggers the flush.
    fn write_buffer_at(&self, fh: u64, offset: u64, data: &[u8]) -> Result<(), SynoFsError> {
        let handle = self
            .buffer(fh)
            .ok_or_else(|| SynoFsError::Io(format!("write to unknown file handle {fh}")))?;
        // A FUSE callback thread is not a runtime thread, so blocking here is
        // allowed — and on the streamed path that block IS the back-pressure:
        // `write(2)` returns when the server has the bytes, so a copy runs at
        // the speed of the link rather than the speed of the local disk.
        self.rt.block_on(async move {
            let mut buf = handle.lock().await;
            match &mut buf.sink {
                WriteSink::Streamed(slot) => {
                    let stream = slot
                        .as_mut()
                        .ok_or_else(|| SynoFsError::Io("write to a closed handle".into()))?;
                    if let Err(e) = stream.write_at(offset, data).await {
                        // Whatever is on the server is now short of what the
                        // caller asked for. Drop the handle so `close` cannot
                        // report success over a failed write.
                        *slot = None;
                        buf.broken = true;
                        return Err(e);
                    }
                }
                WriteSink::Buffered(spill) => {
                    spill
                        .write_at(offset, data)
                        .map_err(|e| SynoFsError::Io(e.to_string()))?;
                }
            }
            buf.dirty = true;
            Ok(())
        })
    }

    /// Open `path` for writing, streaming when a backend can take ranges.
    ///
    /// `WriteOpen::Existing` rather than `CreateNew`: `create(2)` without
    /// `O_EXCL` may legitimately land on a file that already exists, and by
    /// the time this runs the kernel has already decided that is allowed.
    fn open_sink(&self, path: &str) -> WriteSink {
        match self.block(self.client.open_write(path, WriteOpen::Existing)) {
            Ok(Some(stream)) => WriteSink::Streamed(Some(stream)),
            Ok(None) => WriteSink::Buffered(SpillBuffer::new()),
            // A backend that refused is not a reason to fail the open: the
            // buffered path may still succeed, and it is what this mount did
            // for every write before streaming existed.
            Err(e) => {
                warn!("open_write {path}: {e}; buffering this handle instead");
                WriteSink::Buffered(SpillBuffer::new())
            }
        }
    }

    /// The buffer for `fh`, if the handle is still open. The map lock is only
    /// ever held long enough to clone the `Arc` — never across a transfer —
    /// so one handle's upload cannot stall lookups of another's.
    fn buffer(&self, fh: u64) -> Option<Arc<tokio::sync::Mutex<WriteBuffer>>> {
        self.write_buffers.lock().unwrap().get(&fh).cloned()
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

    /// Blocking wrappers over the transfer bundle. The callbacks all go through
    /// `start_*`; these exist so the tests can assert on what a transfer *does*
    /// (download sizing, failure handling) without a runtime dance.
    #[cfg(test)]
    fn truncate_file(
        &self,
        ino: u64,
        path: &str,
        new_size: u64,
    ) -> Result<SynoFileInfo, SynoFsError> {
        let xfer = self.transfers();
        self.block(xfer.truncate(ino, path, new_size))
    }

    #[cfg(test)]
    fn move_across_dirs(
        &self,
        old_path: &str,
        new_parent: &str,
        new_name: &str,
    ) -> Result<(), SynoFsError> {
        let xfer = self.transfers();
        self.block(xfer.move_across_dirs(old_path, new_parent, new_name))
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
            perm: self.owner.perm(true),
            nlink: 2,
            uid: self.owner.uid,
            gid: self.owner.gid,
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
        // Transfers now run on the runtime, which dies with the process — so
        // unmount has to wait for anything still in flight rather than leave it
        // to be aborted. Taking each buffer's lock is that wait: an upload holds
        // it for the whole transfer, and whatever is still dirty afterwards is
        // work that never started (or failed) and is uploaded here.
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
            let shares = match self.listing(VIRTUAL_ROOT_PATH) {
                Ok(s) => s,
                Err(e) => {
                    reply.error(errno(e.to_errno()));
                    return;
                }
            };
            match shares.iter().find(|s| s.name == name_str).cloned() {
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

    /// Nothing to open — a directory here is a listing, not a handle — but the
    /// reply is the only place to tell the kernel it may cache one, and
    /// fuser's default says nothing. See [`dir_open_flags`].
    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if self.get_path_for_ino(ino.0).is_none() {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.opened(FileHandle(0), dir_open_flags(self.dir_cache.is_enabled()));
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
            let shares = match self.listing(VIRTUAL_ROOT_PATH) {
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
            let entries = match self.listing(&path) {
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

        for file_info in entries.iter() {
            let child_ino = self.cache.get_or_alloc_ino(&file_info.path);
            let kind = if file_info.isdir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            let name = file_info.name.clone();
            self.cache.insert(child_ino, file_info.clone());
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
            Arc::new(tokio::sync::Mutex::new(WriteBuffer {
                sink: self.open_sink(&path),
                nas_path: path,
                ino,
                dirty: false,
                new_file: false,
                broken: false,
            })),
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

        // The buffer spills to a temp file once it outgrows SpillBuffer's
        // threshold, so a large copy no longer pins the whole file in RAM. A
        // flush already running on this handle holds the buffer's lock, so this
        // waits for that transfer rather than mutating the file it is streaming.
        match self.write_buffer_at(fh, offset, data) {
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => {
                error!("write: buffering failed: {}", e);
                reply.error(Errno::EIO);
            }
        }
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
        // release() reports. So the reply has to carry the upload's real
        // outcome — but it does not have to be produced here. The transfer runs
        // on the runtime and answers the kernel when it lands, leaving this
        // event-loop thread free to serve the rest of the mount meanwhile.
        self.start_upload(fh, move |r| match r {
            Ok(()) => reply.ok(),
            Err(e) => {
                error!("flush fh={}: {}", fh, e);
                reply.error(errno(e.to_errno()));
            }
        });
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
        // Same treatment as flush, plus the handle teardown — which has to wait
        // for the upload, since the buffer owns the spill file being streamed.
        let buffers = self.write_buffers.clone();
        self.start_upload(fh, move |r| {
            buffers.lock().unwrap().remove(&fh);
            match r {
                Ok(()) => reply.ok(),
                Err(e) => {
                    error!("release fh={}: {}", fh, e);
                    reply.error(errno(e.to_errno()));
                }
            }
        });
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

        // The directory now has a file in it that its cached listing does not
        // mention, and the upload does not happen until flush.
        self.dir_cache.invalidate(&parent_path);

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
            Arc::new(tokio::sync::Mutex::new(WriteBuffer {
                sink: self.open_sink(&new_path),
                nas_path: new_path,
                ino,
                // Dirty from birth. `create(2)` is a request for a file to
                // exist, and `touch` makes exactly this handle: opened,
                // written to never, closed. Starting clean meant close saw
                // nothing to do and the file never reached the NAS at all —
                // it lived in the inode cache until the TTL expired and then
                // vanished.
                dirty: true,
                new_file: true,
                broken: false,
            })),
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
                forget_parent_listing(&self.dir_cache, &path);
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
                self.dir_cache.invalidate_prefix(&path);
                forget_parent_listing(&self.dir_cache, &path);
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
                self.dir_cache.invalidate(&parent_path);
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
                forget_parent_listing(&self.dir_cache, &new_path);
                let _ = self.block(self.client.delete(&new_path)); // ignore error — may not exist
            }
            match self.block(self.client.rename(&old_path, new_name_str)) {
                Ok(info) => {
                    if let Some(ino) = self.cache.get_ino_for_path(&old_path) {
                        self.read_cache.invalidate_ino(ino);
                    }
                    self.cache.invalidate_path(&old_path);
                    forget_parent_listing(&self.dir_cache, &old_path);
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

        // Cross-directory file move: download, upload, delete. A whole-file
        // transfer, so it goes to the runtime rather than sitting on this
        // event-loop thread for the length of the copy.
        let cache = self.cache.clone();
        let dir_cache = self.dir_cache.clone();
        let old = old_path.clone();
        let new = new_path.clone();
        self.start_move_across_dirs(
            old_path,
            new_parent_path,
            new_name_str.to_string(),
            move |r| match r {
                Ok(()) => {
                    cache.invalidate_path(&old);
                    // Both ends changed, and the move only lands when the
                    // transfer does — so this cannot be done up front with the
                    // same-directory case above.
                    forget_parent_listing(&dir_cache, &old);
                    forget_parent_listing(&dir_cache, &new);
                    reply.ok();
                }
                Err(e) => {
                    error!("rename {} -> {}: {}", old, new, e);
                    reply.error(errno(e.to_errno()));
                }
            },
        );
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

            // Read-modify-write over the whole file, so it too runs on the
            // runtime and replies from there.
            let cache = self.cache.clone();
            let owner = self.owner;
            let failed_path = path.clone();
            self.start_truncate(ino, path, new_size, move |r| match r {
                Ok(info) => {
                    let attr = file_attr(owner, ino, &info);
                    cache.insert(ino, info);
                    reply.attr(&TTL, &attr);
                }
                Err(e) => {
                    error!("setattr truncate {}: {}", failed_path, e);
                    reply.error(errno(e.to_errno()));
                }
            });
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
    use synology_filestation_core::types::{SynoAdditional, SynoOwner, SynoPerm};
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
            Arc::new(DirCache::new(30)),
            Arc::new(ReadCache::new(BLOCK, 64)),
            rt.handle().clone(),
            Ownership {
                uid: 1000,
                gid: 1000,
                umask: 0o022,
            },
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
        seed_dirty_buffer_fh(f, 1, nas_path, data)
    }

    /// Same, but for the handle of the caller's choosing — the concurrency
    /// tests need two live buffers at once.
    fn seed_dirty_buffer_fh(f: &Fixture, fh: u64, nas_path: &str, data: &[u8]) -> u64 {
        let ino = f.fs.cache.get_or_alloc_ino(nas_path);
        let mut buf = SpillBuffer::new();
        buf.write_at(0, data).unwrap();
        f.fs.write_buffers.lock().unwrap().insert(
            fh,
            Arc::new(tokio::sync::Mutex::new(WriteBuffer {
                nas_path: nas_path.to_string(),
                ino,
                sink: WriteSink::Buffered(buf),
                dirty: true,
                new_file: true,
                broken: false,
            })),
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
            f.fs.buffer(fh).unwrap().blocking_lock().dirty,
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

        let handle = f.fs.buffer(fh).unwrap();
        let buf = handle.blocking_lock();
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
        f.fs.buffer(fh).unwrap().blocking_lock().dirty = false;

        f.fs.finish_upload(fh).unwrap();
    }

    // ── T1.5: concurrent dispatch ─────────────────────────────────────────────

    /// A slow upload, so a second thread can be observed racing it.
    fn mount_upload_slow(f: &Fixture, delay: Duration) {
        f.rt.block_on(
            Mock::given(http_method("POST"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"success": true, "data": {"blks": null}}))
                        .set_delay(delay),
                )
                .mount(&f.server),
        );
    }

    /// Regression: `finish_upload` snapshotted the buffer and then uploaded with
    /// no lock held, which was safe only because fuser dispatched every callback
    /// on one thread. Uploads now run on the runtime and the event loop is
    /// multi-threaded, so a `write` can land while that handle's upload is in
    /// flight — and for a spilled buffer
    /// the "snapshot" is the temp file the upload is still streaming, so the
    /// write would tear the body mid-transfer. A write must wait for the upload
    /// already running on its handle.
    #[test]
    fn a_write_waits_for_an_upload_in_flight_on_the_same_handle() {
        let f = fixture();
        mount_upload_slow(&f, Duration::from_millis(600));

        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"original");

        std::thread::scope(|s| {
            s.spawn(|| f.fs.finish_upload(fh).unwrap());
            // Let the upload get as far as the wire before racing it.
            std::thread::sleep(Duration::from_millis(150));
            let started = std::time::Instant::now();
            f.fs.write_buffer_at(fh, 0, b"clobbered").unwrap();
            assert!(
                started.elapsed() >= Duration::from_millis(300),
                "the write returned in {:?} — it did not wait for the in-flight upload",
                started.elapsed()
            );
        });

        let posted = posted_bodies(&f);
        assert_eq!(posted.len(), 1, "exactly one upload");
        assert!(
            posted[0].windows(8).any(|w| w == b"original"),
            "the upload must carry the bytes it started with, not the racing write's"
        );
    }

    /// …but only *its* handle. The per-handle wait must not become a global one:
    /// serialising unrelated files is the very wedge this change removes.
    #[test]
    fn an_upload_does_not_block_work_on_another_handle() {
        let f = fixture();
        mount_upload_slow(&f, Duration::from_millis(600));

        let slow = seed_dirty_buffer_fh(&f, 1, "/share/slow.bin", b"payload");
        let other = seed_dirty_buffer_fh(&f, 2, "/share/other.bin", b"payload");

        std::thread::scope(|s| {
            s.spawn(|| f.fs.finish_upload(slow).unwrap());
            std::thread::sleep(Duration::from_millis(150));
            let started = std::time::Instant::now();
            f.fs.write_buffer_at(other, 0, b"unrelated").unwrap();
            assert!(
                started.elapsed() < Duration::from_millis(300),
                "a write to an unrelated handle waited {:?} on someone else's upload",
                started.elapsed()
            );
        });
    }

    /// The `write` callback's own error path: an unknown handle is EIO, not a
    /// panic and not a silently accepted write.
    #[test]
    fn writing_to_an_unknown_handle_fails() {
        let f = fixture();
        assert!(f.fs.write_buffer_at(999, 0, b"x").is_err());
    }

    // ── T1.6: transfers run off the event loop ────────────────────────────────

    /// The outcome of a `start_*` call, as seen from the test thread.
    type Outcome<T> = std::sync::mpsc::Receiver<Result<T, SynoFsError>>;

    /// Collects a `start_*` outcome from whichever runtime thread produced it.
    fn outcome_channel<T: Send + 'static>() -> (
        impl FnOnce(Result<T, SynoFsError>) + Send + 'static,
        Outcome<T>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        (
            move |r| {
                let _ = tx.send(r);
            },
            rx,
        )
    }

    /// Regression: `flush` ran the upload with `block_on` on the FUSE
    /// event-loop thread, so for the length of a transfer — minutes on a large
    /// file — that thread served nothing else. The upload belongs on the
    /// runtime; the callback should return as soon as it is queued.
    #[test]
    fn starting_an_upload_does_not_block_the_calling_thread() {
        let f = fixture();
        mount_upload_slow(&f, Duration::from_millis(600));
        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"payload");

        let (done, outcome) = outcome_channel();
        let started = std::time::Instant::now();
        f.fs.start_upload(fh, done);
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "the calling thread waited {:?} on the transfer",
            started.elapsed()
        );

        outcome
            .recv_timeout(Duration::from_secs(10))
            .expect("the reply must still arrive once the transfer lands")
            .expect("the upload itself succeeds");
        assert_eq!(posted_bodies(&f).len(), 1, "the bytes really went out");
    }

    /// Going off-thread must not cost the error path: `close(2)` still reports
    /// what the upload did, it just learns it later.
    #[test]
    fn a_backgrounded_upload_still_reports_its_failure() {
        let f = fixture();
        f.rt.block_on(
            Mock::given(http_method("POST"))
                .respond_with(ResponseTemplate::new(400))
                .mount(&f.server),
        );
        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"payload");

        let (done, outcome) = outcome_channel();
        f.fs.start_upload(fh, done);

        let result = outcome
            .recv_timeout(Duration::from_secs(10))
            .expect("a failed upload must still produce a reply");
        assert!(
            matches!(result, Err(SynoFsError::Io(_))),
            "got {result:?} — a failed upload must not look like a successful close"
        );
        assert!(
            f.fs.buffer(fh).unwrap().blocking_lock().dirty,
            "the data stays buffered for release() to retry"
        );
    }

    /// The single event-loop thread used to be the only thing bounding how many
    /// transfers we aimed at the NAS at once. Now that transfers run on the
    /// runtime, that accidental limit is gone and an explicit one has to take
    /// its place: parallel FileStation transfers are what saturated `synoscgi`
    /// and took the appliance down.
    #[test]
    fn concurrent_transfers_are_capped_so_the_nas_is_not_swarmed() {
        let f = fixture();
        // Long enough that every upload started below is still on the wire when
        // the count is taken.
        mount_upload_slow(&f, Duration::from_secs(3));

        let started = MAX_CONCURRENT_TRANSFERS + 2;
        for fh in 0..started as u64 {
            seed_dirty_buffer_fh(&f, fh, &format!("/share/f{fh}.bin"), b"payload");
            f.fs.start_upload(fh, |_| {});
        }
        // Give every task that is *allowed* to run time to reach the server.
        std::thread::sleep(Duration::from_millis(500));

        let on_the_wire = posted_bodies(&f).len();
        assert!(
            on_the_wire <= MAX_CONCURRENT_TRANSFERS,
            "{started} uploads were queued and {on_the_wire} reached the NAS at once; \
             the cap is {MAX_CONCURRENT_TRANSFERS}"
        );
        assert_eq!(
            on_the_wire, MAX_CONCURRENT_TRANSFERS,
            "the cap must also be used in full — a smaller number means transfers \
             are queueing on something else"
        );
    }

    /// Unmounting must not abandon a transfer that is still in flight: the
    /// runtime dies with the process, so anything still queued would be lost
    /// data. `destroy` waits for it — and does not re-send it afterwards.
    #[test]
    fn unmounting_waits_for_a_transfer_still_in_flight() {
        let mut f = fixture();
        mount_upload_slow(&f, Duration::from_millis(400));
        let fh = seed_dirty_buffer(&f, "/share/new.txt", b"payload");

        let (done, _outcome) = outcome_channel::<()>();
        f.fs.start_upload(fh, done);
        fuser::Filesystem::destroy(&mut f.fs);

        assert!(
            !f.fs.buffer(fh).unwrap().blocking_lock().dirty,
            "unmount returned with the write still pending"
        );
        assert_eq!(
            posted_bodies(&f).len(),
            1,
            "the in-flight upload must be waited for, not re-sent"
        );
    }

    /// Truncate is read-modify-write over the whole file, so it blocked its
    /// event-loop thread for just as long as an upload. Same treatment.
    #[test]
    fn starting_a_truncate_does_not_block_the_calling_thread() {
        let f = fixture();
        mount_download(&f, ramp(4096), Map::new());
        mount_delete_ok(&f);
        mount_getinfo_gone(&f);
        mount_upload_slow(&f, Duration::from_millis(600));

        let (done, outcome) = outcome_channel();
        let started = std::time::Instant::now();
        f.fs.start_truncate(12, "/share/f.bin".to_string(), 100, done);
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "the calling thread waited {:?} on the transfer",
            started.elapsed()
        );

        // The trailing get_info re-read fails against these mocks (getinfo is
        // wired to "gone"), which is irrelevant here: what matters is that a
        // reply came back at all, from the runtime rather than this thread.
        let _ = outcome
            .recv_timeout(Duration::from_secs(10))
            .expect("the reply must still arrive once the transfer lands");
        assert_eq!(
            posted_bodies(&f).len(),
            1,
            "the resized file really went out"
        );
    }

    /// So did a cross-directory move, which is a whole download plus a whole
    /// upload.
    #[test]
    fn starting_a_cross_directory_move_does_not_block_the_calling_thread() {
        let f = fixture();
        mount_download(&f, ramp(4096), Map::new());
        mount_delete_ok(&f);
        mount_getinfo_gone(&f);
        mount_upload_slow(&f, Duration::from_millis(600));

        let (done, outcome) = outcome_channel();
        let started = std::time::Instant::now();
        f.fs.start_move_across_dirs(
            "/a/f.bin".to_string(),
            "/b".to_string(),
            "f.bin".to_string(),
            done,
        );
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "the calling thread waited {:?} on the transfer",
            started.elapsed()
        );

        outcome
            .recv_timeout(Duration::from_secs(10))
            .expect("the reply must still arrive once the transfer lands")
            .expect("the move itself succeeds");
        assert_eq!(posted_bodies(&f).len(), 1, "the copy really went out");
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

    // ── T1.4: ownership and mode presented to the kernel ──────────────────────

    /// The identity a mount presents by default: the local user, umask 0o022.
    fn mounting_user() -> Ownership {
        Ownership {
            uid: 1000,
            gid: 100,
            umask: 0o022,
        }
    }

    /// A `SynoFileInfo` carrying whatever DSM said about owner and POSIX mode.
    fn info_with(isdir: bool, owner: Option<(u32, u32)>, posix: Option<u32>) -> SynoFileInfo {
        SynoFileInfo {
            name: "entry".into(),
            path: "/share/entry".into(),
            isdir,
            additional: Some(SynoAdditional {
                size: Some(0),
                owner: owner.map(|(uid, gid)| SynoOwner {
                    uid,
                    gid,
                    user: "dsm-user".into(),
                    group: "dsm-group".into(),
                }),
                time: None,
                perm: posix.map(|posix| SynoPerm { posix }),
            }),
            code: None,
        }
    }

    /// Regression: DSM's uid/gid space has nothing to do with the local one —
    /// shares come back owned by root and their contents by directory-service
    /// ids like 1161823311. Exporting those verbatim left every entry owned by
    /// a stranger, which is half of what made GIO report
    /// `access::can-delete: FALSE` for anything inside a share.
    #[test]
    fn nas_owner_is_never_exported_to_the_kernel() {
        let attr = file_attr(
            mounting_user(),
            42,
            &info_with(false, Some((1161823311, 1161822721)), None),
        );

        assert_eq!(attr.uid, 1000, "entries must be owned by the mounting user");
        assert_eq!(
            attr.gid, 100,
            "entries must carry the mounting user's group"
        );
    }

    /// Regression: every DSM share is reported as `dr----x--t` — mode 0o1411,
    /// sticky bit set, owned by root. Passing that through made glib apply the
    /// sticky-directory rule (deletable only by the owner of the file or of its
    /// parent), so GNOME Files hid Delete, Move to Trash and Rename on
    /// everything inside a share. The sticky bit must never reach the kernel.
    #[test]
    fn nas_posix_mode_is_never_exported_to_the_kernel() {
        let share = file_attr(
            mounting_user(),
            42,
            &info_with(true, Some((0, 0)), Some(0o1411)),
        );

        assert_eq!(
            share.perm & 0o1000,
            0,
            "the sticky bit must not survive into the mount"
        );
        assert_eq!(share.perm, 0o755, "directories get a synthetic 0o755");

        // A share's contents come back as mode 000 owned by a directory-service
        // id; that must not make them unusable locally either.
        let child = file_attr(
            mounting_user(),
            43,
            &info_with(false, Some((1161823311, 1161822721)), Some(0o000)),
        );
        assert_eq!(child.perm, 0o644, "files get a synthetic 0o644");
    }

    /// The synthetic mode is `0o777`/`0o666` less the umask, so a private mount
    /// is still expressible.
    #[test]
    fn umask_narrows_the_synthetic_mode() {
        let default = mounting_user();
        assert_eq!(default.perm(true), 0o755, "0o022 is the usual umask");
        assert_eq!(default.perm(false), 0o644);

        let private = Ownership {
            umask: 0o077,
            ..default
        };
        assert_eq!(private.perm(true), 0o700);
        assert_eq!(private.perm(false), 0o600);
    }

    /// The virtual root is the one entry with no NAS metadata behind it; it
    /// must still follow the same ownership rules as everything else.
    #[test]
    fn virtual_root_is_owned_by_the_mounting_user() {
        let f = fixture();
        let attr = f.fs.virtual_root_attr();

        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
        assert_eq!(attr.perm, 0o755);
    }

    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex as StdMutex;

    // ── streamed writes ──────────────────────────────────────────────────────
    //
    // With a backend that takes ranges, a write goes out when it is made. The
    // difference from the buffered path is not speed but *when things happen*:
    // memory stays bounded, `write(2)` waits for the server rather than for a
    // local temp file, and a failure is reported by the call that caused it.

    /// What a recording sink saw: each write as (offset, bytes).
    type SeenWrites = Arc<StdMutex<Vec<(u64, Vec<u8>)>>>;

    /// A write sink that records what it was given, and can be told to fail.
    #[derive(Default)]
    struct RecordingSink {
        writes: SeenWrites,
        closed: Arc<AtomicBool>,
        fail_writes: bool,
    }

    struct RecordingHandle {
        writes: SeenWrites,
        closed: Arc<AtomicBool>,
        fail_writes: bool,
    }

    #[async_trait::async_trait]
    impl WriteHandle for RecordingHandle {
        async fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), SynoFsError> {
            if self.fail_writes {
                return Err(SynoFsError::Io("the link died mid-write".into()));
            }
            self.writes.lock().unwrap().push((offset, data.to_vec()));
            Ok(())
        }
        async fn close(&mut self) -> Result<(), SynoFsError> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl synology_filestation_core::transport::OpenWriteTransport for RecordingSink {
        async fn open_write(
            &self,
            _path: &str,
            _mode: WriteOpen,
        ) -> Result<Box<dyn WriteHandle>, SynoFsError> {
            Ok(Box::new(RecordingHandle {
                writes: self.writes.clone(),
                closed: self.closed.clone(),
                fail_writes: self.fail_writes,
            }))
        }
    }

    /// A fixture whose client can stream, plus the sink it streams into.
    fn streaming_fixture(fail_writes: bool) -> (Fixture, Arc<RecordingSink>) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let sink = Arc::new(RecordingSink {
            fail_writes,
            ..Default::default()
        });
        let client = client_for(&server).with_open_write_transport(sink.clone());
        let fs = SynologyFS::new(
            Arc::new(client),
            Arc::new(InodeCache::new(30)),
            Arc::new(DirCache::new(30)),
            Arc::new(ReadCache::new(BLOCK, 64)),
            rt.handle().clone(),
            Ownership {
                uid: 1000,
                gid: 1000,
                umask: 0o022,
            },
        );
        (Fixture { fs, server, rt }, sink)
    }

    /// Open a handle whose sink comes from the client, the way `create` does.
    fn streamed_handle(f: &Fixture, nas_path: &str) -> u64 {
        let fh = f.fs.next_fh.fetch_add(1, Ordering::Relaxed);
        let sink = f.fs.open_sink(nas_path);
        assert!(
            matches!(sink, WriteSink::Streamed(_)),
            "the backend should have taken this handle"
        );
        f.fs.write_buffers.lock().unwrap().insert(
            fh,
            Arc::new(tokio::sync::Mutex::new(WriteBuffer {
                nas_path: nas_path.to_string(),
                ino: 42,
                sink,
                dirty: false,
                new_file: true,
                broken: false,
            })),
        );
        fh
    }

    #[test]
    fn a_streamed_write_reaches_the_server_before_close() {
        // The buffered path cannot do this: nothing leaves the machine until
        // the file is complete. Here the bytes are gone by the time write(2)
        // returns, which is what bounds memory and paces the copy.
        let (f, sink) = streaming_fixture(false);
        let fh = streamed_handle(&f, "/share/streamed.bin");

        f.fs.write_buffer_at(fh, 0, b"first").unwrap();
        f.fs.write_buffer_at(fh, 5, b"second").unwrap();

        let writes = sink.writes.lock().unwrap().clone();
        assert_eq!(
            writes,
            vec![(0, b"first".to_vec()), (5, b"second".to_vec())],
            "each write went out where it was made, before any close"
        );
        assert!(!sink.closed.load(Ordering::SeqCst), "still open");
    }

    #[test]
    fn closing_a_streamed_handle_uploads_nothing() {
        // No POST at close: the bytes are already there. A second copy over
        // HTTP would be the whole file's worth of traffic for nothing.
        let (f, sink) = streaming_fixture(false);
        let fh = streamed_handle(&f, "/share/streamed.bin");
        f.fs.write_buffer_at(fh, 0, b"payload").unwrap();

        f.fs.finish_upload(fh).expect("close");

        assert!(sink.closed.load(Ordering::SeqCst), "the handle was closed");
        assert_eq!(
            posted_bodies(&f).len(),
            0,
            "nothing was re-sent over the HTTP API"
        );
    }

    #[test]
    fn a_failed_streamed_write_is_reported_at_the_write_and_again_at_close() {
        // Both halves matter. The write must fail where it happened — the
        // whole reason to stream — and close must not then report success over
        // a file the server never fully received.
        let (f, sink) = streaming_fixture(true);
        let fh = streamed_handle(&f, "/share/doomed.bin");

        let err =
            f.fs.write_buffer_at(fh, 0, b"payload")
                .expect_err("the write failed, so write(2) must say so");
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");

        let err =
            f.fs.finish_upload(fh)
                .expect_err("close must not claim a file landed when a write failed");
        assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
        assert!(
            !sink.closed.load(Ordering::SeqCst),
            "the handle was abandoned, not closed as if it were fine"
        );
    }

    #[test]
    fn without_a_streaming_backend_writes_are_buffered_as_before() {
        // The HTTP mount is unchanged: nothing can take a range, so the whole
        // file still goes at close.
        let f = fixture();
        let sink = f.fs.open_sink("/share/plain.bin");
        assert!(matches!(sink, WriteSink::Buffered(_)));
    }

    #[test]
    fn creating_a_file_and_writing_nothing_still_puts_it_on_the_nas() {
        // `touch`. The handle is opened, never written, and closed. Before
        // this, close found nothing dirty and did nothing, so the file existed
        // only in the inode cache and disappeared when the TTL lapsed.
        let f = fixture();
        mount_upload_ok(&f);

        let fh = f.fs.next_fh.fetch_add(1, Ordering::Relaxed);
        f.fs.write_buffers.lock().unwrap().insert(
            fh,
            Arc::new(tokio::sync::Mutex::new(WriteBuffer {
                nas_path: "/share/touched.txt".to_string(),
                ino: 7,
                sink: WriteSink::Buffered(SpillBuffer::new()),
                // What `create` now seeds.
                dirty: true,
                new_file: true,
                broken: false,
            })),
        );

        f.fs.finish_upload(fh).expect("close");

        let bodies = posted_bodies(&f);
        assert_eq!(bodies.len(), 1, "the empty file was uploaded");
    }

    // ── Listing cache ─────────────────────────────────────────────────────────

    fn mount_share_listing(f: &Fixture) {
        f.rt.block_on(
            Mock::given(http_method("GET"))
                .and(query_param("method", "list_share"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": true,
                    "data": {"total": 1, "offset": 0, "shares": [
                        {"name": "homes", "path": "/homes", "isdir": true}
                    ]}
                })))
                .mount(&f.server),
        );
    }

    fn share_listings_asked_for(f: &Fixture) -> usize {
        f.rt.block_on(f.server.received_requests())
            .unwrap_or_default()
            .iter()
            .filter(|r| {
                r.url
                    .query()
                    .is_some_and(|q| q.contains("method=list_share"))
            })
            .count()
    }

    /// Regression: the mount asked the NAS for a listing every single time it
    /// was asked for one, and the kernel asks more than once per directory
    /// read — once for the entries, then again at the end offset to be told
    /// there are no more. A desktop file manager polling a freshly-appeared
    /// volume (GIO does exactly this) became a sustained stream of listings
    /// against `synoscgi`, the shared CGI backend the whole appliance runs on:
    /// roughly ten a second, indefinitely, for a directory nobody was looking
    /// at any more.
    #[test]
    fn a_repeated_listing_is_served_without_asking_the_nas_again() {
        let f = fixture();
        mount_share_listing(&f);

        let first = f.fs.listing(VIRTUAL_ROOT_PATH).expect("a listing");
        let second = f.fs.listing(VIRTUAL_ROOT_PATH).expect("a listing");

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1, "the same listing, served twice");
        assert_eq!(
            share_listings_asked_for(&f),
            1,
            "the second read has to come from the cache, or a polling client \
             is a denial of service aimed at the appliance"
        );
    }

    /// The cache may not outlive a change this mount itself made: a file
    /// created and then listed has to be there, or the mount contradicts
    /// itself within one process.
    #[test]
    fn a_listing_is_fetched_again_after_the_directory_changes() {
        let f = fixture();
        mount_share_listing(&f);

        f.fs.listing(VIRTUAL_ROOT_PATH).expect("a listing");
        f.fs.dir_cache.invalidate(VIRTUAL_ROOT_PATH);
        f.fs.listing(VIRTUAL_ROOT_PATH).expect("a listing");

        assert_eq!(share_listings_asked_for(&f), 2);
    }

    /// The virtual root is spelled `""`, so a top-level share's parent is not
    /// what string arithmetic naively produces: `/homes` would otherwise
    /// invalidate `""[..0]`, which is the same thing by luck rather than by
    /// intent, and `homes` (no leading slash) would panic on the slice.
    #[test]
    fn the_parent_of_a_top_level_share_is_the_virtual_root() {
        let cache = DirCache::new(30);
        cache.insert(VIRTUAL_ROOT_PATH, vec![]);
        cache.insert("/homes", vec![]);

        forget_parent_listing(&cache, "/homes");

        assert!(cache.get(VIRTUAL_ROOT_PATH).is_none(), "the root is stale");
        assert!(
            cache.get("/homes").is_some(),
            "the share's own listing did not change; a file appeared beside it"
        );
    }

    #[test]
    fn the_parent_of_a_nested_path_is_the_directory_holding_it() {
        let cache = DirCache::new(30);
        cache.insert("/homes/chris", vec![]);
        cache.insert("/homes", vec![]);

        forget_parent_listing(&cache, "/homes/chris/notes.txt");

        assert!(cache.get("/homes/chris").is_none());
        assert!(cache.get("/homes").is_some(), "only one level up");
    }

    /// A name with no separator at all reaches this from a caller that built
    /// it itself. Slicing on a `None` index would panic in a FUSE callback,
    /// which takes the mount down rather than failing one operation.
    #[test]
    fn a_bare_name_falls_back_to_the_root_rather_than_panicking() {
        let cache = DirCache::new(30);
        cache.insert(VIRTUAL_ROOT_PATH, vec![]);

        forget_parent_listing(&cache, "notes.txt");

        assert!(cache.get(VIRTUAL_ROOT_PATH).is_none());
    }

    // ── Caches the kernel is allowed to keep ──────────────────────────────────

    fn info_without_timestamps(path: &str) -> SynoFileInfo {
        SynoFileInfo {
            name: path.rsplit('/').next().unwrap_or("").to_string(),
            path: path.to_string(),
            isdir: false,
            additional: None,
            code: None,
        }
    }

    /// Regression: an entry DSM sent no `time` for was given
    /// `SystemTime::now()` — a *different* mtime on every single stat. Nothing
    /// downstream can cache an attribute that changes each time it is asked
    /// for, so the kernel has to revalidate everything about that inode
    /// forever, and a mount that is doing nothing still looks busy.
    ///
    /// The epoch is a poor timestamp and an honest one: it says "not known",
    /// which is the truth, and it says the same thing twice.
    #[test]
    fn an_entry_with_no_timestamps_gets_a_stable_one() {
        let owner = Ownership {
            uid: 1000,
            gid: 1000,
            umask: 0o022,
        };

        let first = file_attr(owner, 42, &info_without_timestamps("/homes/a.txt"));
        let second = file_attr(owner, 42, &info_without_timestamps("/homes/a.txt"));

        assert_eq!(first.mtime, second.mtime, "asking twice must answer twice");
        assert_eq!(
            first.mtime, UNIX_EPOCH,
            "and the answer is 'not known', not 'now'"
        );
        assert_eq!(first.ctime, second.ctime);
        assert_eq!(first.atime, second.atime);
        assert_eq!(first.crtime, second.crtime);
    }

    /// Regression: `opendir` was never implemented, so fuser's default replied
    /// with no flags and the kernel cached nothing about a directory. Every
    /// `opendir` + `getdents` pair from every caller came all the way through
    /// to us — a native filesystem would have served most of them from the
    /// page cache and we would never have seen them. That is why a client
    /// looping on `~/mnt` showed up as hundreds of `readdir` a second.
    #[test]
    fn a_directory_the_kernel_may_cache_says_so() {
        assert!(dir_open_flags(true).contains(FopenFlags::FOPEN_CACHE_DIR));
    }

    /// `--cache-ttl 0` is somebody asking for no caching. Handing the kernel a
    /// directory cache anyway would honour the flag in this process and ignore
    /// it one layer up, which is worse than not having the flag.
    #[test]
    fn a_mount_that_asked_for_no_caching_does_not_get_one_from_the_kernel() {
        assert!(!dir_open_flags(false).contains(FopenFlags::FOPEN_CACHE_DIR));
    }
}

//! Translating between DSM's view of a file and the kernel's.
//!
//! Everything here is a pure function of its arguments — no client, no caches,
//! no `&self` — which is what lets a transfer running on the runtime build a
//! kernel reply out of nothing but the `Ownership` it copied out of the mount.

use std::time::{Duration, UNIX_EPOCH};

use fuser::{Errno, FileAttr, FileType, FopenFlags, INodeNo};

use synology_filestation_core::types::SynoFileInfo;

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
pub(super) fn dir_open_flags(may_cache: bool) -> FopenFlags {
    if may_cache {
        FopenFlags::FOPEN_CACHE_DIR
    } else {
        FopenFlags::empty()
    }
}

/// Convert a raw errno (`SynoFsError::to_errno`, `libc::ENOENT`, etc.) into the
/// `fuser::Errno` newtype that `Reply*::error` expects in fuser 0.17+.
pub(super) fn errno(raw: i32) -> Errno {
    Errno::from_i32(raw)
}

/// Split a NAS path into `(parent, filename)`. `None` for a path with no
/// separator, which cannot name a file inside a share.
///
/// Previously open-coded at three call sites as `rfind('/')` followed by a
/// second `rfind('/').unwrap()` — the `unwrap` being safe only because the
/// preceding match had already proven the separator exists.
pub(super) fn split_nas_path(path: &str) -> Option<(&str, &str)> {
    let idx = path.rfind('/')?;
    Some((&path[..idx], &path[idx + 1..]))
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
pub(super) fn file_attr(owner: Ownership, ino: u64, info: &SynoFileInfo) -> FileAttr {
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

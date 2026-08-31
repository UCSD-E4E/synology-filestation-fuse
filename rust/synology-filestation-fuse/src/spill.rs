//! A write buffer that stops growing in memory.
//!
//! Every mount backend accumulates a file's writes until close and then hands
//! the result to the upload API. Holding that in a `Vec<u8>` means a 6 GB copy
//! needs 6 GB of RAM (12 GB once the upload clones it for a retry) — which is
//! what wedged the mount: FUSE callbacks queue behind the allocation and every
//! other filesystem operation stalls with it.
//!
//! [`SpillBuffer`] keeps small files exactly as they were — in memory, one
//! allocation, no syscalls — and switches to a temp file once a file grows past
//! `spill_at`. Past that point memory is bounded by the write size, and the
//! upload streams from disk in slices.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use tracing::warn;

use synology_filestation_core::client::SynologyClient;
use synology_filestation_core::error::SynoFsError;

/// How many candidate names a spill tries before giving up. Collisions should
/// be impossible (the sequence number is process-unique), so this only matters
/// if somebody is actively planting files at our candidate paths.
const SPILL_NAME_ATTEMPTS: u32 = 8;

/// Process-wide counter making each buffer's temp name unique without pulling
/// in a random-number dependency. Uniqueness is what create_new needs; it is
/// not a secret, which is why the open refuses to follow an existing path.
static SPILL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_path(dir: &Path, seq: u64, attempt: u32) -> PathBuf {
    dir.join(format!(
        "synofs-write-{}-{seq}-{attempt}.tmp",
        std::process::id()
    ))
}

/// Where spills go: `$TMPDIR` when it is usable, a real directory when it is
/// not.
///
/// `std::env::temp_dir()` is `$TMPDIR`, read fresh on every call — and a
/// `nix develop` shell points it at a directory it deletes on exit. A mount
/// started from such a shell keeps running after it, at which point every
/// spill fails with `ENOENT`: no file over the threshold can be written for
/// the rest of the process's life. The user sees "copying a large file to the
/// NAS returns EIO", with nothing to suggest a temp directory is involved.
///
/// So a temp directory that is not there is stepped over rather than trusted.
/// The fallback is what `temp_dir()` itself would have returned had `$TMPDIR`
/// been unset, so this only ever *widens* where a spill may land.
fn spill_dir() -> PathBuf {
    usable_or_fallback(std::env::temp_dir())
}

/// Split out of [`spill_dir`] so the decision is testable without mutating the
/// process environment, which no test can do safely while others run.
fn usable_or_fallback(candidate: PathBuf) -> PathBuf {
    if candidate.is_dir() {
        return candidate;
    }
    // Log once: a mount that falls back does it for every handle it opens.
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        warn!(
            "temp directory {} does not exist — large writes will spill to {} instead. \
             (A mount started from a `nix develop` shell outlives the directory that \
             shell sets $TMPDIR to.)",
            candidate.display(),
            FALLBACK_SPILL_DIR,
        );
    });
    PathBuf::from(FALLBACK_SPILL_DIR)
}

/// Where to spill when `$TMPDIR` names nothing. On Unix this is what
/// `std::env::temp_dir()` defaults to; on Windows `GetTempPath2` always
/// answers, so the candidate is kept and this is never reached.
#[cfg(unix)]
const FALLBACK_SPILL_DIR: &str = "/tmp";
#[cfg(windows)]
const FALLBACK_SPILL_DIR: &str = ".";

/// Files larger than this are written to a temp file instead of RAM. Sized to
/// cover the overwhelming majority of desktop file writes while capping what a
/// single handle can pin in memory.
pub const DEFAULT_SPILL_AT: usize = 8 * 1024 * 1024;

/// Where a buffer's bytes currently live.
enum Store {
    Memory(Vec<u8>),
    /// An open temp file plus its path, deleted on drop.
    Spilled {
        file: std::fs::File,
        path: PathBuf,
    },
}

pub struct SpillBuffer {
    store: Store,
    /// Process-unique id feeding this buffer's temp-file name.
    seq: u64,
    /// Logical length, tracked separately so a sparse write past the end
    /// extends the buffer the same way in both stores.
    len: u64,
    spill_at: usize,
    /// Directory this buffer spills into. Configurable so the tests can point
    /// it somewhere unusable; every caller uses the process temp directory.
    dir: PathBuf,
}

impl SpillBuffer {
    pub fn new() -> Self {
        Self::with_spill_at(DEFAULT_SPILL_AT)
    }

    pub fn with_spill_at(spill_at: usize) -> Self {
        Self::with_spill_at_in(spill_at, spill_dir())
    }

    pub fn with_spill_at_in(spill_at: usize, dir: PathBuf) -> Self {
        SpillBuffer {
            store: Store::Memory(Vec::new()),
            seq: SPILL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            len: 0,
            spill_at,
            dir,
        }
    }
    /// Current logical length. Used by the WebDAV backend to append, and by the
    /// tests; the FUSE backend writes at explicit offsets and never asks.
    #[allow(dead_code)]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True once the bytes live on disk rather than in memory.
    #[allow(dead_code)]
    pub fn is_spilled(&self) -> bool {
        matches!(self.store, Store::Spilled { .. })
    }

    /// Resize to `new_len`, truncating or zero-extending. Backs WinFsp's
    /// `set_file_size`, which the shell uses to preallocate before a copy.
    #[allow(dead_code)]
    pub fn set_len(&mut self, new_len: u64) -> std::io::Result<()> {
        if matches!(self.store, Store::Memory(_)) && new_len > self.spill_at as u64 {
            self.spill()?;
        }
        match &mut self.store {
            Store::Memory(v) => v.resize(new_len as usize, 0),
            Store::Spilled { file, .. } => file.set_len(new_len)?,
        }
        self.len = new_len;
        Ok(())
    }

    /// Write `data` at `offset`, extending (and zero-filling any gap) as needed.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        let end = offset + data.len() as u64;
        if matches!(self.store, Store::Memory(_)) && end > self.spill_at as u64 {
            self.spill()?;
        }
        match &mut self.store {
            Store::Memory(v) => {
                if end > v.len() as u64 {
                    v.resize(end as usize, 0);
                }
                v[offset as usize..end as usize].copy_from_slice(data);
            }
            Store::Spilled { file, .. } => {
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(data)?;
            }
        }
        self.len = self.len.max(end);
        Ok(())
    }

    /// Read the whole buffer back, from disk if it has spilled.
    ///
    /// Allocates the full length, so callers on the upload path must go through
    /// [`payload_for`], which only reaches for this when the buffer is still in
    /// memory and therefore under the spill threshold. Calling it directly on a
    /// spilled buffer defeats the point of this type.
    pub fn as_bytes(&mut self) -> std::io::Result<Vec<u8>> {
        match &mut self.store {
            Store::Memory(v) => Ok(v.clone()),
            Store::Spilled { file, .. } => {
                let mut out = Vec::with_capacity(self.len as usize);
                file.seek(SeekFrom::Start(0))?;
                file.read_to_end(&mut out)?;
                Ok(out)
            }
        }
    }

    /// The temp file backing a spilled buffer, ready to hand to the streaming
    /// upload. `None` while the buffer still lives in memory.
    pub fn spilled_path(&mut self) -> std::io::Result<Option<&Path>> {
        match &mut self.store {
            Store::Memory(_) => Ok(None),
            Store::Spilled { file, path } => {
                file.flush()?;
                Ok(Some(path.as_path()))
            }
        }
    }

    /// Move the accumulated bytes out of RAM and onto disk.
    fn spill(&mut self) -> std::io::Result<()> {
        // Moved, not cloned: a clone would briefly double the very allocation
        // this type exists to bound. Moved *back* on every failure path below,
        // though — dropping it there emptied the buffer without a word, and
        // the mount then uploaded that emptiness over the destination file.
        let existing = match &mut self.store {
            Store::Memory(v) => std::mem::take(v),
            Store::Spilled { .. } => return Ok(()),
        };
        // create_new, so an occupied name is stepped over rather than
        // truncated. The temp dir is world-writable on Unix, and a predictable
        // name plus create+truncate is how you end up destroying somebody
        // else's file — or, through a symlink they planted, a file of their
        // choosing.
        //
        // 0600 for the same reason in the other direction: this file holds the
        // full contents of whatever the user is writing to the NAS, sitting in
        // a directory every local account can read. The default umask would
        // leave it 0644. (umask only clears bits, so requesting 0600 cannot be
        // widened by it.)
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let mut last_err = None;
        for attempt in 0..SPILL_NAME_ATTEMPTS {
            let path = temp_path(&self.dir, self.seq, attempt);
            match opts.open(&path) {
                Ok(mut file) => match file.write_all(&existing) {
                    Ok(()) => {
                        self.store = Store::Spilled { file, path };
                        return Ok(());
                    }
                    // A half-written spill file is worse than none: leave
                    // nothing behind, and hand the bytes back to the caller's
                    // buffer so the failure costs only this write.
                    Err(e) => {
                        drop(file);
                        let _ = std::fs::remove_file(&path);
                        self.store = Store::Memory(existing);
                        return Err(e);
                    }
                },
                Err(e) => last_err = Some(e),
            }
        }
        self.store = Store::Memory(existing);
        Err(last_err.unwrap_or_else(|| std::io::Error::other("no spill path available")))
    }
}

/// Hand-written so a buffer never prints its contents — the WebDAV file
/// context derives `Debug`, and dumping a multi-gigabyte body into a log line
/// would be its own kind of memory incident.
impl std::fmt::Debug for SpillBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpillBuffer")
            .field("len", &self.len)
            .field("spilled", &self.is_spilled())
            .finish()
    }
}

impl Drop for SpillBuffer {
    fn drop(&mut self) {
        if let Store::Spilled { path, .. } = &self.store {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// What a flush hands to the upload API: bytes for a buffer still in memory, or
/// the temp file a spilled buffer wrote to. The file variant is what keeps a
/// multi-gigabyte write off the heap — the core streams it to the NAS in slices.
pub enum Payload {
    Memory(Vec<u8>),
    File(PathBuf),
}

impl Payload {
    pub fn len(&self) -> u64 {
        match self {
            Payload::Memory(d) => d.len() as u64,
            Payload::File(p) => std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
        }
    }
}

/// Snapshot a write buffer for upload without consuming it — the WinFsp backend
/// depends on the buffer surviving a failed flush so `close` can retry.
///
/// A spilled buffer yields its temp path, so this stays O(1) no matter how large
/// the file is; only an in-memory buffer is copied. The path stays valid as long
/// as the buffer does, which every caller guarantees by holding the buffer until
/// the upload returns.
pub fn payload_for(buf: &mut SpillBuffer) -> std::io::Result<Payload> {
    match buf.spilled_path()? {
        Some(p) => Ok(Payload::File(p.to_path_buf())),
        None => Ok(Payload::Memory(buf.as_bytes()?)),
    }
}

/// Upload a payload, taking the streaming path when the bytes are already on
/// disk. Shared by all three mount backends so they cannot drift apart.
pub async fn upload_payload(
    client: &SynologyClient,
    parent: &str,
    filename: &str,
    payload: Payload,
    overwrite: bool,
) -> Result<(), SynoFsError> {
    match payload {
        Payload::Memory(data) => client.upload(parent, filename, data, overwrite).await,
        Payload::File(path) => {
            client
                .upload_from_path(&path, parent, filename, overwrite)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    /// Regression: the mount is routinely started from a `nix develop` shell,
    /// which sets `$TMPDIR` to a directory it deletes when the shell exits. The
    /// mount outlives the shell, so `std::env::temp_dir()` then names a
    /// directory that is gone — and every spill failed with ENOENT for the rest
    /// of the process's life. No file over the threshold could be written at
    /// all, which is not a temp-directory problem as far as the user is
    /// concerned: it is "copying a large file to the NAS returns EIO".
    #[test]
    fn a_temp_dir_that_no_longer_exists_falls_back_to_one_that_does() {
        let gone = std::env::temp_dir().join("synofs-nix-shell-that-already-exited");
        assert!(!gone.exists(), "the test needs this path to be absent");

        let chosen = usable_or_fallback(gone.clone());

        assert_ne!(chosen, gone, "a directory that is not there cannot be used");
        assert!(chosen.is_dir(), "and the fallback has to actually exist");
    }

    #[test]
    fn a_temp_dir_that_is_there_is_used_as_it_is() {
        let real = std::env::temp_dir();
        assert_eq!(usable_or_fallback(real.clone()), real);
    }

    #[test]
    fn a_buffer_built_the_normal_way_spills_somewhere_real() {
        let mut b = SpillBuffer::with_spill_at(4);
        b.write_at(0, &[1u8; 32])
            .expect("the default spill directory must be usable");
        assert!(b.is_spilled());
    }
    #[test]
    fn small_writes_stay_in_memory() {
        let mut b = SpillBuffer::with_spill_at(1024);
        b.write_at(0, b"hello").unwrap();
        assert!(!b.is_spilled());
        assert_eq!(b.len(), 5);
        assert_eq!(b.as_bytes().unwrap(), b"hello");
        assert!(b.spilled_path().unwrap().is_none());
    }

    #[test]
    fn crossing_the_threshold_spills_to_disk_preserving_content() {
        let mut b = SpillBuffer::with_spill_at(16);
        b.write_at(0, &[1u8; 10]).unwrap();
        assert!(!b.is_spilled(), "still under the threshold");
        b.write_at(10, &[2u8; 20]).unwrap();
        assert!(b.is_spilled(), "crossing it moves the bytes to a file");

        assert_eq!(b.len(), 30);
        let bytes = b.as_bytes().unwrap();
        assert_eq!(&bytes[..10], &[1u8; 10], "pre-spill bytes survive");
        assert_eq!(&bytes[10..], &[2u8; 20]);
    }

    #[test]
    fn spilled_path_points_at_the_written_file() {
        let mut b = SpillBuffer::with_spill_at(4);
        b.write_at(0, &[7u8; 32]).unwrap();
        let path = b.spilled_path().unwrap().unwrap().to_path_buf();
        assert_eq!(std::fs::read(&path).unwrap(), vec![7u8; 32]);
    }

    #[test]
    fn sparse_write_past_the_end_zero_fills() {
        let mut b = SpillBuffer::with_spill_at(1024);
        b.write_at(4, b"xy").unwrap();
        assert_eq!(b.len(), 6);
        assert_eq!(b.as_bytes().unwrap(), vec![0, 0, 0, 0, b'x', b'y']);
    }

    #[test]
    fn overwriting_in_place_works_after_spilling() {
        let mut b = SpillBuffer::with_spill_at(8);
        b.write_at(0, &[9u8; 40]).unwrap();
        b.write_at(4, b"zz").unwrap();
        let bytes = b.as_bytes().unwrap();
        assert_eq!(&bytes[4..6], b"zz");
        assert_eq!(b.len(), 40, "an in-place write does not shrink the file");
    }

    #[test]
    fn temp_file_is_removed_on_drop() {
        let mut b = SpillBuffer::with_spill_at(4);
        b.write_at(0, &[1u8; 32]).unwrap();
        let path = b.spilled_path().unwrap().unwrap().to_path_buf();
        assert!(path.exists());
        drop(b);
        assert!(
            !path.exists(),
            "a dropped buffer leaves no temp file behind"
        );
    }

    #[test]
    fn payload_for_small_buffer_carries_the_bytes() {
        let mut b = SpillBuffer::with_spill_at(1024);
        b.write_at(0, b"inline").unwrap();
        match payload_for(&mut b).unwrap() {
            Payload::Memory(d) => assert_eq!(d, b"inline"),
            Payload::File(_) => panic!("an in-memory buffer must not go out as a file"),
        }
    }

    #[test]
    fn payload_for_spilled_buffer_points_at_the_temp_file() {
        let mut b = SpillBuffer::with_spill_at(4);
        b.write_at(0, &[3u8; 64]).unwrap();
        match payload_for(&mut b).unwrap() {
            Payload::File(p) => {
                assert_eq!(std::fs::read(&p).unwrap(), vec![3u8; 64]);
                assert_eq!(payload_for(&mut b).unwrap().len(), 64);
            }
            Payload::Memory(_) => panic!("a spilled buffer must go out as a file"),
        }
    }

    #[test]
    fn payload_for_leaves_the_buffer_usable() {
        // WinFsp's flush retries from close() on failure, so snapshotting must
        // not consume the buffer.
        let mut b = SpillBuffer::with_spill_at(4);
        b.write_at(0, &[1u8; 32]).unwrap();
        let _ = payload_for(&mut b).unwrap();
        b.write_at(32, &[2u8; 8]).unwrap();
        assert_eq!(b.len(), 40);
        assert_eq!(payload_for(&mut b).unwrap().len(), 40);
    }

    #[test]
    fn set_len_truncates_and_extends_in_memory() {
        let mut b = SpillBuffer::with_spill_at(1024);
        b.write_at(0, b"abcdef").unwrap();
        b.set_len(3).unwrap();
        assert_eq!(b.as_bytes().unwrap(), b"abc");
        b.set_len(5).unwrap();
        assert_eq!(b.as_bytes().unwrap(), b"abc\0\0", "extension zero-fills");
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn set_len_truncates_a_spilled_buffer() {
        let mut b = SpillBuffer::with_spill_at(4);
        b.write_at(0, &[8u8; 64]).unwrap();
        b.set_len(10).unwrap();
        assert_eq!(b.len(), 10);
        assert_eq!(b.as_bytes().unwrap(), vec![8u8; 10]);
        let path = b.spilled_path().unwrap().unwrap().to_path_buf();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            10,
            "the temp file shrinks with the buffer"
        );
    }

    #[test]
    fn concurrent_buffers_get_distinct_temp_files() {
        let mut a = SpillBuffer::with_spill_at(4);
        let mut b = SpillBuffer::with_spill_at(4);
        a.write_at(0, &[1u8; 16]).unwrap();
        b.write_at(0, &[2u8; 16]).unwrap();
        let pa = a.spilled_path().unwrap().unwrap().to_path_buf();
        let pb = b.spilled_path().unwrap().unwrap().to_path_buf();
        assert_ne!(pa, pb, "two live buffers must not share a temp file");
        assert_eq!(std::fs::read(&pa).unwrap(), vec![1u8; 16]);
        assert_eq!(std::fs::read(&pb).unwrap(), vec![2u8; 16]);
    }

    /// Regression: the spill file was created with the process umask (0644 on a
    /// typical desktop) in a world-readable temp directory. Every file over the
    /// spill threshold written through the mount was therefore readable by any
    /// other local user for the duration of the copy. The existing care around
    /// not *clobbering* a planted file said nothing about who can read ours.
    #[cfg(unix)]
    #[test]
    fn spilled_temp_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let mut b = SpillBuffer::with_spill_at(4);
        b.write_at(0, b"confidential payload large enough to spill")
            .unwrap();
        let path = b.spilled_path().unwrap().unwrap().to_path_buf();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "spill file must be owner-only, got {mode:04o}");
    }

    /// Regression: `spill` moved the in-memory bytes out of the store *before*
    /// it knew it had a file to put them in, so a temp file it could not create
    /// took the buffer's contents with it — silently. The handle was then an
    /// empty buffer that still called itself dirty, and the mount uploaded
    /// exactly that over the destination: a multi-megabyte copy landed on the
    /// NAS as a zero-byte file. A spill that cannot happen must fail the write
    /// and leave the buffer exactly as it found it.
    #[test]
    fn a_spill_that_cannot_open_its_file_keeps_the_bytes_it_already_had() {
        let dir = std::env::temp_dir().join("synofs-spill-dir-that-does-not-exist");
        assert!(!dir.exists(), "the test needs this path to be absent");

        let mut b = SpillBuffer::with_spill_at_in(8, dir);
        b.write_at(0, b"precious").unwrap();

        let err = b
            .write_at(8, &[1u8; 64])
            .expect_err("there is nowhere to spill to, so the write must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "got {err:?}");

        assert!(!b.is_spilled(), "the buffer is still in memory");
        assert_eq!(b.len(), 8, "the failed write did not extend the buffer");
        assert_eq!(
            b.as_bytes().unwrap(),
            b"precious",
            "the bytes written before the failed spill are still there"
        );
    }

    #[test]
    fn spill_does_not_clobber_an_occupied_candidate_path() {
        // The temp dir is world-writable on Unix, so a predictable name opened
        // with create+truncate would let another user pre-place a file (or a
        // symlink to one) and have us destroy it. Spilling must step over an
        // occupied name, not truncate it.
        let mut b = SpillBuffer::with_spill_at(4);
        let occupied = temp_path(&b.dir, b.seq, 0);
        std::fs::write(&occupied, b"precious").unwrap();

        b.write_at(0, &[6u8; 16]).unwrap();
        let used = b.spilled_path().unwrap().unwrap().to_path_buf();

        assert_ne!(used, occupied, "spill must skip the occupied candidate");
        assert_eq!(
            std::fs::read(&occupied).unwrap(),
            b"precious",
            "the pre-existing file is left untouched"
        );
        std::fs::remove_file(&occupied).ok();
    }
}

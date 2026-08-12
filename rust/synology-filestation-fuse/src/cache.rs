use bytes::Bytes;
use moka::sync::Cache;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use synology_filestation_core::types::{InodeEntry, SynoFileInfo};

#[cfg(test)]
fn make_file_info(path: &str) -> SynoFileInfo {
    SynoFileInfo {
        name: path.rsplit('/').next().unwrap_or("").to_string(),
        path: path.to_string(),
        isdir: false,
        additional: None,
        code: None,
    }
}

pub struct InodeCache {
    next_ino: RwLock<u64>,
    /// ino → InodeEntry with TTL eviction
    by_ino: Cache<u64, Arc<InodeEntry>>,
    /// lowercase(path) → ino  (never TTL-evicted; invalidated manually on mutations)
    path_to_ino: RwLock<HashMap<String, u64>>,
    /// ino → original-case path  (never TTL-evicted; source of truth for path strings)
    ino_to_path: RwLock<HashMap<u64, String>>,
}

impl InodeCache {
    pub fn new(ttl_secs: u64) -> Self {
        let by_ino = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();
        Self {
            next_ino: RwLock::new(2), // 1 is reserved for root
            by_ino,
            path_to_ino: RwLock::new(HashMap::new()),
            ino_to_path: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the existing inode for `path`, or allocates a new one.
    pub fn get_or_alloc_ino(&self, path: &str) -> u64 {
        let key = path.to_lowercase();
        {
            let map = self.path_to_ino.read().unwrap();
            if let Some(&ino) = map.get(&key) {
                return ino;
            }
        }
        let mut next = self.next_ino.write().unwrap();
        // Double-check after acquiring write lock
        let mut map = self.path_to_ino.write().unwrap();
        if let Some(&ino) = map.get(&key) {
            return ino;
        }
        let ino = *next;
        *next += 1;
        map.insert(key, ino);
        ino
    }

    /// Insert or refresh a cache entry.
    pub fn insert(&self, ino: u64, info: SynoFileInfo) {
        let path = info.path.clone();
        let entry = Arc::new(InodeEntry {
            ino,
            path: path.clone(),
            info,
        });
        self.by_ino.insert(ino, entry);
        let key = path.to_lowercase();
        self.path_to_ino.write().unwrap().insert(key, ino);
        self.ino_to_path.write().unwrap().insert(ino, path);
    }

    /// Seed inode 1 for the root directory.
    pub fn seed_root(&self, info: SynoFileInfo) {
        let path = info.path.clone();
        let entry = Arc::new(InodeEntry {
            ino: 1,
            path: path.clone(),
            info,
        });
        self.by_ino.insert(1, entry);
        let key = path.to_lowercase();
        self.path_to_ino.write().unwrap().insert(key, 1);
        self.ino_to_path.write().unwrap().insert(1, path);
    }

    /// Look up a cached entry by inode.
    pub fn get_by_ino(&self, ino: u64) -> Option<Arc<InodeEntry>> {
        self.by_ino.get(&ino)
    }

    /// Look up the path for a given inode (even if metadata is evicted).
    pub fn get_path_for_ino(&self, ino: u64) -> Option<String> {
        // Prefer the live metadata cache (freshest data).
        if let Some(entry) = self.by_ino.get(&ino) {
            return Some(entry.path.clone());
        }
        // Fall back to ino_to_path which stores the original-case path permanently.
        self.ino_to_path.read().unwrap().get(&ino).cloned()
    }

    /// Remove all entries whose path starts with `prefix` (after mutations).
    pub fn invalidate_prefix(&self, prefix: &str) {
        let lower = prefix.to_lowercase();
        let mut map = self.path_to_ino.write().unwrap();
        let mut itp = self.ino_to_path.write().unwrap();
        let to_remove: Vec<String> = map
            .keys()
            .filter(|k| k.starts_with(&lower))
            .cloned()
            .collect();
        for path in &to_remove {
            if let Some(&ino) = map.get(path) {
                self.by_ino.invalidate(&ino);
                itp.remove(&ino);
            }
            map.remove(path);
        }
    }

    /// Remove a specific path and its metadata from the cache.
    pub fn invalidate_path(&self, path: &str) {
        let key = path.to_lowercase();
        let mut map = self.path_to_ino.write().unwrap();
        if let Some(&ino) = map.get(&key) {
            self.by_ino.invalidate(&ino);
            self.ino_to_path.write().unwrap().remove(&ino);
            map.remove(&key);
        }
    }

    /// Return the inode for `path` if it is already known, without allocating a new one.
    pub fn get_ino_for_path(&self, path: &str) -> Option<u64> {
        let key = path.to_lowercase();
        self.path_to_ino.read().unwrap().get(&key).copied()
    }

    /// Return the file size for `ino` from the metadata cache, if available.
    pub fn get_size_for_ino(&self, ino: u64) -> Option<u64> {
        self.by_ino
            .get(&ino)
            .and_then(|entry| entry.info.additional.as_ref()?.size)
    }
}

// ---------------------------------------------------------------------------
// Block-level read cache for file data
// ---------------------------------------------------------------------------

/// Size of each cached block in bytes (256 KiB).
pub const READ_BLOCK_SIZE: u64 = 256 * 1024;

/// How long a reader waits on somebody else's in-flight block before giving up
/// and reporting failure. Comfortably longer than a slow block download (the
/// core's own request timeout is 30 s) but finite, so a claim that is never
/// released cannot wedge a FUSE worker thread for the life of the mount.
pub const BLOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// A cache of file data split into fixed-size blocks.
///
/// Key: `(ino, block_index)` — `block_index = byte_offset / READ_BLOCK_SIZE`.
/// Blocks are evicted after 5 minutes of idle time or when the capacity
/// limit is reached.  Explicit invalidation is available via [`invalidate_ino`].
pub struct ReadCache {
    blocks: Cache<(u64, u64), Bytes>,
    /// Tracks which block indices are cached for each inode so we can do
    /// targeted invalidation when a file is written or deleted.
    ino_blocks: RwLock<HashMap<u64, HashSet<u64>>>,
    /// Blocks currently being downloaded (prefetch or sync).  A block in this
    /// set will appear in `blocks` once the download completes.  Used to avoid
    /// issuing duplicate HTTP requests for the same block.
    in_flight: std::sync::Mutex<HashSet<(u64, u64)>>,
    pub block_size: u64,
}

impl ReadCache {
    /// `max_blocks` = total capacity in blocks (= cache_bytes / block_size).
    pub fn new(block_size: u64, max_blocks: u64) -> Self {
        let blocks = Cache::builder()
            .max_capacity(max_blocks)
            .time_to_idle(Duration::from_secs(300))
            .build();
        Self {
            blocks,
            ino_blocks: RwLock::new(HashMap::new()),
            in_flight: std::sync::Mutex::new(HashSet::new()),
            block_size,
        }
    }

    pub fn get(&self, ino: u64, block_idx: u64) -> Option<Bytes> {
        self.blocks.get(&(ino, block_idx))
    }

    pub fn insert(&self, ino: u64, block_idx: u64, data: Bytes) {
        self.blocks.insert((ino, block_idx), data);
        self.ino_blocks
            .write()
            .unwrap()
            .entry(ino)
            .or_default()
            .insert(block_idx);
        self.in_flight.lock().unwrap().remove(&(ino, block_idx));
    }

    pub fn contains(&self, ino: u64, block_idx: u64) -> bool {
        self.blocks.contains_key(&(ino, block_idx))
    }

    /// Returns `true` if this call wins the race to download the block.
    /// Returns `false` if another task already claimed it — the caller should
    /// wait on [`wait_for_block`] instead.
    pub fn claim_inflight(&self, ino: u64, block_idx: u64) -> bool {
        self.in_flight.lock().unwrap().insert((ino, block_idx))
    }

    /// Mark a failed download so other waiters don't spin forever.
    pub fn cancel_inflight(&self, ino: u64, block_idx: u64) {
        self.in_flight.lock().unwrap().remove(&(ino, block_idx));
    }

    /// Spin-wait (5 ms polls) until the block appears in cache or the
    /// in-flight marker is gone (meaning the download failed).
    /// Returns the cached bytes on success, `None` on failure.
    ///
    /// Bounded by [`BLOCK_WAIT_TIMEOUT`]: the owner of an in-flight claim is
    /// responsible for clearing it, but a task that dies without doing so (a
    /// panicking prefetch, a runtime shut down mid-download) would otherwise
    /// strand every waiter here forever — and these waiters are FUSE worker
    /// threads, so the whole mount stops answering. Giving up returns `None`,
    /// which the caller already handles as "that download failed".
    pub fn wait_for_block(&self, ino: u64, block_idx: u64) -> Option<Bytes> {
        self.wait_for_block_until(ino, block_idx, BLOCK_WAIT_TIMEOUT)
    }

    /// [`wait_for_block`](Self::wait_for_block) with an explicit deadline, so
    /// the timeout path is testable without stalling the suite.
    fn wait_for_block_until(&self, ino: u64, block_idx: u64, timeout: Duration) -> Option<Bytes> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(data) = self.blocks.get(&(ino, block_idx)) {
                return Some(data);
            }
            if !self.in_flight.lock().unwrap().contains(&(ino, block_idx)) {
                // Download finished (or failed) without populating the cache.
                return self.blocks.get(&(ino, block_idx));
            }
            if Instant::now() >= deadline {
                // The claim owner never published a block and never released the
                // claim. Drop the stale marker so the next reader re-downloads
                // instead of inheriting the same dead wait.
                self.in_flight.lock().unwrap().remove(&(ino, block_idx));
                tracing::warn!(
                    "read cache: abandoned in-flight block ino={ino} idx={block_idx} after {:?}",
                    timeout
                );
                return self.blocks.get(&(ino, block_idx));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Evict a single cached block (e.g. a stale EOF sentinel).
    pub fn invalidate_block(&self, ino: u64, block_idx: u64) {
        self.blocks.invalidate(&(ino, block_idx));
        if let Some(set) = self.ino_blocks.write().unwrap().get_mut(&ino) {
            set.remove(&block_idx);
        }
    }

    /// Evict all cached blocks for `ino` (call after writing or deleting a file).
    pub fn invalidate_ino(&self, ino: u64) {
        let indices = self.ino_blocks.write().unwrap().remove(&ino);
        if let Some(set) = indices {
            for idx in set {
                self.blocks.invalidate(&(ino, idx));
                self.in_flight.lock().unwrap().remove(&(ino, idx));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // InodeCache tests
    // -----------------------------------------------------------------------

    #[test]
    fn inode_alloc_is_stable() {
        let cache = InodeCache::new(30);
        let a = cache.get_or_alloc_ino("/share/file.txt");
        let b = cache.get_or_alloc_ino("/share/file.txt");
        assert_eq!(a, b);
    }

    #[test]
    fn inode_alloc_is_case_insensitive() {
        let cache = InodeCache::new(30);
        let a = cache.get_or_alloc_ino("/Share/File.txt");
        let b = cache.get_or_alloc_ino("/share/file.txt");
        assert_eq!(a, b);
    }

    #[test]
    fn different_paths_get_different_inodes() {
        let cache = InodeCache::new(30);
        let a = cache.get_or_alloc_ino("/share/a.txt");
        let b = cache.get_or_alloc_ino("/share/b.txt");
        assert_ne!(a, b);
    }

    #[test]
    fn insert_and_get_by_ino() {
        let cache = InodeCache::new(30);
        let info = make_file_info("/share/hello.txt");
        let ino = cache.get_or_alloc_ino("/share/hello.txt");
        cache.insert(ino, info.clone());
        let entry = cache.get_by_ino(ino).unwrap();
        assert_eq!(entry.ino, ino);
        assert_eq!(entry.path, "/share/hello.txt");
    }

    #[test]
    fn seed_root_uses_inode_1() {
        let cache = InodeCache::new(30);
        let info = make_file_info("");
        cache.seed_root(info);
        let entry = cache.get_by_ino(1).unwrap();
        assert_eq!(entry.ino, 1);
    }

    #[test]
    fn get_path_for_ino_returns_correct_path() {
        let cache = InodeCache::new(30);
        let info = make_file_info("/share/doc.pdf");
        let ino = cache.get_or_alloc_ino("/share/doc.pdf");
        cache.insert(ino, info);
        assert_eq!(
            cache.get_path_for_ino(ino).as_deref(),
            Some("/share/doc.pdf")
        );
    }

    #[test]
    fn get_ino_for_path_is_case_insensitive() {
        let cache = InodeCache::new(30);
        let ino = cache.get_or_alloc_ino("/Share/File.TXT");
        assert_eq!(cache.get_ino_for_path("/share/file.txt"), Some(ino));
    }

    #[test]
    fn invalidate_path_removes_entry() {
        let cache = InodeCache::new(30);
        let info = make_file_info("/share/temp.txt");
        let ino = cache.get_or_alloc_ino("/share/temp.txt");
        cache.insert(ino, info);
        cache.invalidate_path("/share/temp.txt");
        assert!(cache.get_by_ino(ino).is_none());
        assert!(cache.get_ino_for_path("/share/temp.txt").is_none());
    }

    #[test]
    fn invalidate_prefix_removes_matching_entries() {
        let cache = InodeCache::new(30);
        for name in &["a.txt", "b.txt", "c.txt"] {
            let path = format!("/share/{}", name);
            let ino = cache.get_or_alloc_ino(&path);
            cache.insert(ino, make_file_info(&path));
        }
        let other_ino = cache.get_or_alloc_ino("/other/file.txt");
        cache.insert(other_ino, make_file_info("/other/file.txt"));

        cache.invalidate_prefix("/share/");

        assert!(cache.get_ino_for_path("/share/a.txt").is_none());
        assert!(cache.get_ino_for_path("/share/b.txt").is_none());
        assert!(cache.get_ino_for_path("/share/c.txt").is_none());
        // Entry outside the prefix is untouched.
        assert!(cache.get_ino_for_path("/other/file.txt").is_some());
    }

    #[test]
    fn get_size_for_ino_returns_size() {
        use synology_filestation_core::types::SynoAdditional;
        let cache = InodeCache::new(30);
        let mut info = make_file_info("/share/video.mp4");
        info.additional = Some(SynoAdditional {
            size: Some(1234567),
            owner: None,
            time: None,
            perm: None,
        });
        let ino = cache.get_or_alloc_ino("/share/video.mp4");
        cache.insert(ino, info);
        assert_eq!(cache.get_size_for_ino(ino), Some(1234567));
    }

    #[test]
    fn get_size_returns_none_when_not_cached() {
        let cache = InodeCache::new(30);
        assert!(cache.get_size_for_ino(999).is_none());
    }

    // -----------------------------------------------------------------------
    // ReadCache tests
    // -----------------------------------------------------------------------

    #[test]
    fn read_cache_insert_and_get() {
        let rc = ReadCache::new(1024, 16);
        let data = Bytes::from_static(b"hello world");
        rc.insert(1, 0, data.clone());
        assert_eq!(rc.get(1, 0).unwrap(), data);
    }

    #[test]
    fn read_cache_contains() {
        let rc = ReadCache::new(1024, 16);
        assert!(!rc.contains(1, 0));
        rc.insert(1, 0, Bytes::from_static(b"x"));
        assert!(rc.contains(1, 0));
    }

    #[test]
    fn claim_inflight_grants_exclusive_access() {
        let rc = ReadCache::new(1024, 16);
        assert!(rc.claim_inflight(1, 0)); // first caller wins
        assert!(!rc.claim_inflight(1, 0)); // second caller loses
    }

    #[test]
    fn cancel_inflight_releases_slot() {
        let rc = ReadCache::new(1024, 16);
        assert!(rc.claim_inflight(1, 0));
        rc.cancel_inflight(1, 0);
        assert!(rc.claim_inflight(1, 0)); // slot is free again
    }

    #[test]
    fn wait_for_block_returns_data_after_insert() {
        let rc = Arc::new(ReadCache::new(1024, 16));
        assert!(rc.claim_inflight(1, 0));

        let rc2 = rc.clone();
        let handle = std::thread::spawn(move || rc2.wait_for_block(1, 0));

        std::thread::sleep(Duration::from_millis(20));
        rc.insert(1, 0, Bytes::from_static(b"payload"));

        let result = handle.join().unwrap();
        assert_eq!(result.unwrap(), Bytes::from_static(b"payload"));
    }

    #[test]
    fn wait_for_block_returns_none_after_cancel() {
        let rc = Arc::new(ReadCache::new(1024, 16));
        assert!(rc.claim_inflight(1, 0));

        let rc2 = rc.clone();
        let handle = std::thread::spawn(move || rc2.wait_for_block(1, 0));

        std::thread::sleep(Duration::from_millis(20));
        rc.cancel_inflight(1, 0);

        let result = handle.join().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn wait_for_block_returns_empty_bytes_as_eof_sentinel() {
        let rc = Arc::new(ReadCache::new(1024, 16));
        assert!(rc.claim_inflight(1, 5));

        let rc2 = rc.clone();
        let handle = std::thread::spawn(move || rc2.wait_for_block(1, 5));

        std::thread::sleep(Duration::from_millis(20));
        rc.insert(1, 5, Bytes::new()); // EOF sentinel

        let result = handle.join().unwrap();
        assert_eq!(result, Some(Bytes::new()));
    }

    /// Regression: the claim owner can die without ever publishing the block or
    /// releasing the claim (a panicking prefetch task, a runtime torn down
    /// mid-download). Before this bound, every waiter looped on a 5 ms sleep
    /// forever — and the waiters are FUSE worker threads, so the mount stopped
    /// answering entirely. The wait must give up and report failure.
    #[test]
    fn wait_for_block_gives_up_on_an_abandoned_claim() {
        let rc = ReadCache::new(1024, 16);
        assert!(rc.claim_inflight(1, 0));
        // Nobody will ever insert() or cancel_inflight() — the owner is gone.
        let start = Instant::now();
        let result = rc.wait_for_block_until(1, 0, Duration::from_millis(50));
        assert!(result.is_none(), "an abandoned claim must not yield data");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "wait must be bounded, took {:?}",
            start.elapsed()
        );
    }

    /// Giving up must also clear the stale marker, otherwise the next reader
    /// inherits the same dead claim and waits out the timeout all over again
    /// instead of just downloading the block.
    #[test]
    fn abandoning_a_claim_frees_it_for_the_next_reader() {
        let rc = ReadCache::new(1024, 16);
        assert!(rc.claim_inflight(2, 7));
        assert!(rc
            .wait_for_block_until(2, 7, Duration::from_millis(50))
            .is_none());
        assert!(
            rc.claim_inflight(2, 7),
            "the abandoned claim must be released so a fresh download can start"
        );
    }

    /// The bound must not cut short a download that is merely slow: a block
    /// published before the deadline is still returned.
    #[test]
    fn wait_for_block_still_returns_a_slow_but_successful_download() {
        let rc = Arc::new(ReadCache::new(1024, 16));
        assert!(rc.claim_inflight(3, 0));

        let rc2 = rc.clone();
        let handle =
            std::thread::spawn(move || rc2.wait_for_block_until(3, 0, Duration::from_secs(30)));

        std::thread::sleep(Duration::from_millis(30));
        rc.insert(3, 0, Bytes::from_static(b"slow payload"));

        assert_eq!(
            handle.join().unwrap(),
            Some(Bytes::from_static(b"slow payload"))
        );
    }

    #[test]
    fn invalidate_ino_removes_all_blocks() {
        let rc = ReadCache::new(1024, 16);
        rc.insert(1, 0, Bytes::from_static(b"block0"));
        rc.insert(1, 1, Bytes::from_static(b"block1"));
        rc.insert(2, 0, Bytes::from_static(b"other_ino"));

        rc.invalidate_ino(1);

        assert!(!rc.contains(1, 0));
        assert!(!rc.contains(1, 1));
        assert!(rc.contains(2, 0)); // other ino untouched
    }

    #[test]
    fn invalidate_ino_clears_inflight_markers() {
        let rc = ReadCache::new(1024, 16);
        // Insert a block so ino_blocks tracks it, then re-claim it as in-flight
        // (simulates a concurrent re-download starting just before invalidation).
        rc.insert(1, 0, Bytes::from_static(b"data"));
        rc.claim_inflight(1, 0);
        rc.invalidate_ino(1);
        // The in-flight marker should have been cleared along with the cached block.
        assert!(rc.claim_inflight(1, 0));
    }
}

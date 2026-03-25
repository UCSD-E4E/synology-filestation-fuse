use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use bytes::Bytes;
use moka::sync::Cache;
use crate::types::{InodeEntry, SynoFileInfo};

pub struct InodeCache {
    next_ino: RwLock<u64>,
    /// ino → InodeEntry with TTL eviction
    by_ino: Cache<u64, Arc<InodeEntry>>,
    /// path → ino mapping (not TTL-evicted; invalidated manually on mutations)
    path_to_ino: RwLock<HashMap<String, u64>>,
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
        let entry = Arc::new(InodeEntry { ino, path: path.clone(), info });
        self.by_ino.insert(ino, entry);
        let key = path.to_lowercase();
        let mut map = self.path_to_ino.write().unwrap();
        map.insert(key, ino);
    }

    /// Seed inode 1 for the root directory.
    pub fn seed_root(&self, info: SynoFileInfo) {
        let path = info.path.clone();
        let entry = Arc::new(InodeEntry { ino: 1, path: path.clone(), info });
        self.by_ino.insert(1, entry);
        let key = path.to_lowercase();
        let mut map = self.path_to_ino.write().unwrap();
        map.insert(key, 1);
    }

    /// Look up a cached entry by inode.
    pub fn get_by_ino(&self, ino: u64) -> Option<Arc<InodeEntry>> {
        self.by_ino.get(&ino)
    }

    /// Look up the path for a given inode (even if metadata is evicted).
    pub fn get_path_for_ino(&self, ino: u64) -> Option<String> {
        // First check the live metadata cache
        if let Some(entry) = self.by_ino.get(&ino) {
            return Some(entry.path.clone());
        }
        // Fall back to the path_to_ino map (reverse lookup)
        let map = self.path_to_ino.read().unwrap();
        for (path, &mapped_ino) in map.iter() {
            if mapped_ino == ino {
                return Some(path.clone());
            }
        }
        None
    }

    /// Remove all entries whose path starts with `prefix` (after mutations).
    pub fn invalidate_prefix(&self, prefix: &str) {
        let lower = prefix.to_lowercase();
        let mut map = self.path_to_ino.write().unwrap();
        let to_remove: Vec<String> = map
            .keys()
            .filter(|k| k.starts_with(&lower))
            .cloned()
            .collect();
        for path in &to_remove {
            if let Some(&ino) = map.get(path) {
                self.by_ino.invalidate(&ino);
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
            map.remove(&key);
        }
    }

    /// Return the inode for `path` if it is already known, without allocating a new one.
    pub fn get_ino_for_path(&self, path: &str) -> Option<u64> {
        let key = path.to_lowercase();
        self.path_to_ino.read().unwrap().get(&key).copied()
    }
}

// ---------------------------------------------------------------------------
// Block-level read cache for file data
// ---------------------------------------------------------------------------

/// Size of each cached block in bytes (1 MiB).
pub const READ_BLOCK_SIZE: u64 = 1024 * 1024;

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
            block_size,
        }
    }

    pub fn get(&self, ino: u64, block_idx: u64) -> Option<Bytes> {
        self.blocks.get(&(ino, block_idx))
    }

    pub fn insert(&self, ino: u64, block_idx: u64, data: Bytes) {
        self.blocks.insert((ino, block_idx), data);
        self.ino_blocks.write().unwrap()
            .entry(ino).or_default()
            .insert(block_idx);
    }

    pub fn contains(&self, ino: u64, block_idx: u64) -> bool {
        self.blocks.contains_key(&(ino, block_idx))
    }

    /// Evict all cached blocks for `ino` (call after writing or deleting a file).
    pub fn invalidate_ino(&self, ino: u64) {
        let indices = self.ino_blocks.write().unwrap().remove(&ino);
        if let Some(set) = indices {
            for idx in set {
                self.blocks.invalidate(&(ino, idx));
            }
        }
    }
}

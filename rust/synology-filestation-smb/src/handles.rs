//! Open read handles, kept between reads.
//!
//! The transport used to issue an SMB2 CREATE and a CLOSE around *every* block
//! read. At 256 KiB a block that is three round trips to move 256 KiB, and the
//! mount asks for blocks by the dozen — so a file the kernel's own SMB client
//! reads with one CREATE and a pipeline of READs cost us three round trips per
//! block, serialised.
//!
//! A handle is worth keeping, but not forever: an open handle is state on the
//! appliance, and a cached one goes stale if the file changes underneath. So
//! this is a bounded LRU with explicit invalidation, and the transport closes
//! whatever falls out of it.
//!
//! # Closing is deferred, never skipped
//!
//! `FileReader::close` consumes the reader, so a handle can only be closed once
//! nothing is reading through it — and dropping one without closing leaks it on
//! the server until the session ends. An eviction that lands mid-read therefore
//! parks the handle in [`defer`](HandleCache::defer) instead of dropping it, and
//! [`take_free`](HandleCache::take_free) hands it back when the last reader has
//! finished with it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// How many open read handles to keep. Each is a file open on the appliance,
/// so this is a small number rather than "as many as we have seen".
pub(crate) const MAX_CACHED_HANDLES: usize = 64;

struct State<H> {
    /// Keys in use order, least-recently-used first.
    order: Vec<String>,
    handles: HashMap<String, Arc<H>>,
    /// Evicted while somebody was still reading through them.
    deferred: Vec<Arc<H>>,
}

/// A bounded, least-recently-used cache of open handles keyed by logical path.
pub(crate) struct HandleCache<H> {
    capacity: usize,
    state: Mutex<State<H>>,
}

impl<H> HandleCache<H> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(State {
                order: Vec::new(),
                handles: HashMap::new(),
                deferred: Vec::new(),
            }),
        }
    }

    /// The handle for `path`, if one is open. Counts as a use.
    pub(crate) fn get(&self, path: &str) -> Option<Arc<H>> {
        let mut state = self.state.lock().unwrap();
        let handle = state.handles.get(path).cloned()?;
        state.touch(path);
        Some(handle)
    }

    /// Keep `handle` for `path`, returning whatever that displaced — a handle
    /// already open on the same path, and the least recently used one if the
    /// cache is now over capacity. The caller closes what comes back.
    pub(crate) fn insert(&self, path: &str, handle: Arc<H>) -> Vec<Arc<H>> {
        let mut displaced = Vec::new();
        // Capacity zero is caching switched off. Handing the handle straight
        // back keeps the "one open handle per cached path" invariant true at
        // zero as well, rather than making it a special case everywhere else.
        if self.capacity == 0 {
            return vec![handle];
        }
        let mut state = self.state.lock().unwrap();
        if let Some(old) = state.handles.insert(path.to_string(), handle) {
            displaced.push(old);
        }
        state.touch(path);
        while state.handles.len() > self.capacity {
            let oldest = state.order.remove(0);
            if let Some(evicted) = state.handles.remove(&oldest) {
                displaced.push(evicted);
            }
        }
        displaced
    }

    /// Forget the handle for exactly `path`.
    pub(crate) fn invalidate(&self, path: &str) -> Vec<Arc<H>> {
        let mut state = self.state.lock().unwrap();
        state.order.retain(|k| k != path);
        state.handles.remove(path).into_iter().collect()
    }

    /// Forget every handle at or under `prefix` — a directory that moved or
    /// went away takes its files' handles with it.
    pub(crate) fn invalidate_prefix(&self, prefix: &str) -> Vec<Arc<H>> {
        let mut state = self.state.lock().unwrap();
        let doomed: Vec<String> = state
            .handles
            .keys()
            .filter(|k| under(k, prefix))
            .cloned()
            .collect();
        state.order.retain(|k| !under(k, prefix));
        doomed
            .into_iter()
            .filter_map(|k| state.handles.remove(&k))
            .collect()
    }

    /// Forget everything, e.g. because the session behind the handles is gone.
    pub(crate) fn clear(&self) -> Vec<Arc<H>> {
        let mut state = self.state.lock().unwrap();
        state.order.clear();
        state.handles.drain().map(|(_, h)| h).collect()
    }

    /// Park a handle the caller could not close because a read still held it.
    pub(crate) fn defer(&self, handle: Arc<H>) {
        self.state.lock().unwrap().deferred.push(handle);
    }

    /// Parked handles nothing is reading through any more.
    pub(crate) fn take_free(&self) -> Vec<Arc<H>> {
        let mut state = self.state.lock().unwrap();
        // `1` is this collection's own reference: nobody else holds it.
        let mut free = Vec::new();
        state.deferred.retain(|h| {
            if Arc::strong_count(h) == 1 {
                free.push(h.clone());
                false
            } else {
                true
            }
        });
        free
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().unwrap().handles.len()
    }

    #[cfg(test)]
    fn deferred_len(&self) -> usize {
        self.state.lock().unwrap().deferred.len()
    }
}

impl<H> State<H> {
    /// Move `path` to the most-recently-used end.
    fn touch(&mut self, path: &str) {
        self.order.retain(|k| k != path);
        self.order.push(path.to_string());
    }
}

/// Is `path` `prefix` itself, or something inside it?
///
/// The separator check is what keeps `/s/dir2` from being swept away with
/// `/s/dir`.
fn under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    path == prefix || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for a `FileReader`: identity is all the cache needs.
    #[derive(Debug, PartialEq, Eq)]
    struct Handle(&'static str);

    fn cache() -> HandleCache<Handle> {
        HandleCache::new(3)
    }

    fn put(c: &HandleCache<Handle>, path: &str, tag: &'static str) -> Vec<Arc<Handle>> {
        c.insert(path, Arc::new(Handle(tag)))
    }

    #[test]
    fn a_handle_that_was_put_in_comes_back_out() {
        let c = cache();
        assert!(put(&c, "/s/a.mov", "a").is_empty());
        assert_eq!(c.get("/s/a.mov").as_deref(), Some(&Handle("a")));
    }

    #[test]
    fn a_path_never_seen_has_no_handle() {
        let c = cache();
        assert!(c.get("/s/nothing.mov").is_none());
    }

    /// The whole point: a second read of the same file reuses the open handle
    /// rather than paying another CREATE.
    #[test]
    fn a_repeated_read_finds_the_handle_still_open() {
        let c = cache();
        put(&c, "/s/a.mov", "a");
        assert!(c.get("/s/a.mov").is_some());
        assert!(c.get("/s/a.mov").is_some());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn going_over_capacity_evicts_the_least_recently_used() {
        let c = cache();
        put(&c, "/s/a", "a");
        put(&c, "/s/b", "b");
        put(&c, "/s/c", "c");
        let evicted = put(&c, "/s/d", "d");

        assert_eq!(evicted.len(), 1);
        assert_eq!(*evicted[0], Handle("a"), "`a` was the oldest");
        assert!(c.get("/s/a").is_none());
        assert!(c.get("/s/d").is_some());
        assert_eq!(c.len(), 3);
    }

    /// A file being streamed must not be evicted by the files being skimmed
    /// around it.
    #[test]
    fn a_handle_that_keeps_being_used_is_not_the_one_evicted() {
        let c = cache();
        put(&c, "/s/a", "a");
        put(&c, "/s/b", "b");
        put(&c, "/s/c", "c");
        c.get("/s/a"); // `a` is in use, `b` is now the oldest
        let evicted = put(&c, "/s/d", "d");

        assert_eq!(*evicted[0], Handle("b"));
        assert!(c.get("/s/a").is_some());
    }

    #[test]
    fn reopening_a_path_displaces_the_handle_it_had() {
        let c = cache();
        put(&c, "/s/a", "first");
        let displaced = put(&c, "/s/a", "second");

        assert_eq!(displaced.len(), 1);
        assert_eq!(*displaced[0], Handle("first"), "the old handle must close");
        assert_eq!(c.get("/s/a").as_deref(), Some(&Handle("second")));
        assert_eq!(c.len(), 1, "one path, one handle");
    }

    #[test]
    fn invalidating_a_path_hands_its_handle_back() {
        let c = cache();
        put(&c, "/s/a", "a");
        put(&c, "/s/b", "b");

        let dropped = c.invalidate("/s/a");

        assert_eq!(dropped.len(), 1);
        assert_eq!(*dropped[0], Handle("a"));
        assert!(c.get("/s/a").is_none());
        assert!(c.get("/s/b").is_some(), "an unrelated file is untouched");
    }

    #[test]
    fn invalidating_an_absent_path_is_not_an_error() {
        let c = cache();
        assert!(c.invalidate("/s/gone").is_empty());
    }

    /// A directory that was renamed or deleted takes its files with it.
    #[test]
    fn invalidating_a_prefix_takes_the_whole_directory() {
        let c = cache();
        put(&c, "/s/dir/a", "a");
        put(&c, "/s/dir/b", "b");
        put(&c, "/s/other/c", "c");

        let mut dropped = c.invalidate_prefix("/s/dir");
        dropped.sort_by_key(|h| h.0);

        assert_eq!(dropped.len(), 2);
        assert_eq!(*dropped[0], Handle("a"));
        assert_eq!(*dropped[1], Handle("b"));
        assert!(c.get("/s/other/c").is_some());
    }

    /// `/s/dir2` is not inside `/s/dir`, however much it looks like it.
    #[test]
    fn a_prefix_stops_at_a_path_separator() {
        let c = cache();
        put(&c, "/s/dir/a", "a");
        put(&c, "/s/dir2/b", "b");

        let dropped = c.invalidate_prefix("/s/dir");

        assert_eq!(dropped.len(), 1);
        assert_eq!(*dropped[0], Handle("a"));
        assert!(c.get("/s/dir2/b").is_some());
    }

    /// The directory itself, named exactly, goes too.
    #[test]
    fn a_prefix_matches_the_directory_itself() {
        let c = cache();
        put(&c, "/s/dir", "d");
        let dropped = c.invalidate_prefix("/s/dir");
        assert_eq!(dropped.len(), 1);
    }

    #[test]
    fn clearing_hands_back_everything() {
        let c = cache();
        put(&c, "/s/a", "a");
        put(&c, "/s/b", "b");

        assert_eq!(c.clear().len(), 2);
        assert_eq!(c.len(), 0);
        assert!(c.get("/s/a").is_none());
    }

    /// Capacity zero is caching switched off: a handle is handed straight back
    /// to be closed, and nothing is ever found later.
    #[test]
    fn zero_capacity_keeps_nothing() {
        let c = HandleCache::new(0);
        let evicted = put(&c, "/s/a", "a");
        assert_eq!(evicted.len(), 1);
        assert!(c.get("/s/a").is_none());
        assert_eq!(c.len(), 0);
    }

    // ── deferred closing ──────────────────────────────────────────────────

    /// A handle evicted mid-read cannot be closed yet — closing consumes it,
    /// and a reader still holds it. It must not simply be dropped: that leaks
    /// the open file on the appliance until the session ends.
    #[test]
    fn a_handle_still_being_read_is_not_free_to_close() {
        let c = cache();
        let held = Arc::new(Handle("busy"));
        c.defer(held.clone()); // `held` stands in for the in-flight reader

        assert!(c.take_free().is_empty(), "somebody is still reading it");
        assert_eq!(c.deferred_len(), 1);
    }

    #[test]
    fn a_deferred_handle_comes_back_once_the_reader_is_done() {
        let c = cache();
        let held = Arc::new(Handle("busy"));
        c.defer(held.clone());
        assert!(c.take_free().is_empty());

        drop(held); // the read finished

        let free = c.take_free();
        assert_eq!(free.len(), 1);
        assert_eq!(*free[0], Handle("busy"));
        assert_eq!(c.deferred_len(), 0, "and it is not handed out twice");
    }

    #[test]
    fn free_and_busy_deferred_handles_are_told_apart() {
        let c = cache();
        let busy = Arc::new(Handle("busy"));
        c.defer(busy.clone());
        c.defer(Arc::new(Handle("free")));

        let free = c.take_free();

        assert_eq!(free.len(), 1);
        assert_eq!(*free[0], Handle("free"));
        assert_eq!(c.deferred_len(), 1, "the busy one waits its turn");
    }
}

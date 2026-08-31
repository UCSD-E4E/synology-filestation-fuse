//! Reads: block assembly out of the read cache, and directory listings.

use super::*;

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

//! Ownership, mode and attribute translation as the kernel sees it.

use fuser::FopenFlags;

use super::*;

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

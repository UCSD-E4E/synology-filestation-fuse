# synology-fuse

A FUSE filesystem driver that mounts a [Synology FileStation](https://www.synology.com/en-global/dsm/feature/file_station) share as a local directory on Linux and macOS. Written in Rust.

## Features

- Browse and navigate directories
- Read and write files
- Create and delete files and directories
- Rename files (same-directory) and move files (cross-directory)
- Truncate files via `setattr`
- Metadata cache with configurable TTL to reduce API round-trips
- Block-level read cache (default 256 MiB) with background prefetch for smooth streaming playback
- Interactive password prompt with hidden input when password is not set via flag or environment variable
- Uses `rustls` — no OpenSSL dependency required

## Requirements

### System

| Platform | Requirement |
|---|---|
| Linux | FUSE support (`/dev/fuse`); `libfuse3-3` runtime (Ubuntu/Debian) |
| macOS (kext) | [macFUSE](https://macfuse.io) 4.0+ — requires allowing a system extension in Recovery Mode |
| macOS (FSKit) | [macFUSE](https://macfuse.io) 5.0+ and macOS 15.4+ — one-time approval in System Settings → Privacy & Security → Extensions; no Recovery Mode required |

All platforms require a Synology NAS running DSM with FileStation API enabled.

### Build

- Rust toolchain (1.70+) — install via [rustup](https://rustup.rs)
- Linux: `libfuse3-dev` (Ubuntu/Debian) or `fuse3-devel` (Fedora/RHEL)
- macOS: macFUSE 5.0+ (`brew install --cask macfuse`)

```bash
# Ubuntu / Debian
sudo apt-get install libfuse3-dev

# Fedora / RHEL
sudo dnf install fuse3-devel

# macOS (requires Homebrew)
brew install --cask macfuse
```

## Building

```bash
cargo build --release
```

The binary will be at `target/release/synology-filestation-fuse`.

## Usage

```bash
synology-filestation-fuse --host <NAS_HOST> -u <USERNAME> [OPTIONS] <MOUNTPOINT>
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `<MOUNTPOINT>` | Local directory to mount on | *(required)* |
| `--host <HOST>` | NAS hostname or IP address | *(required)* |
| `-u, --username` | NAS account username | *(required)* |
| `-p, --password` | NAS account password (or `SYNO_PASSWORD` env var; prompted with hidden input if omitted) | *(optional)* |
| `--otp <CODE>` | TOTP code for 2FA (or `SYNO_OTP` env var); prompted interactively if omitted and 2FA is enabled | *(optional)* |
| `--port <PORT>` | API port | `5001` |
| `--https` | Use HTTPS | `true` |
| `--cache-ttl <SECS>` | Metadata cache TTL in seconds | `30` |
| `--read-cache-mb <MiB>` | Read cache size in MiB for file data blocks | `256` |
| `--log-level <LEVEL>` | Log level (`error`, `warn`, `info`, `debug`, `trace`) | `info` |
| `--fskit` | *(macOS only)* Use macFUSE FSKit backend — no kernel extension approval needed; requires macOS 15.4+ and macFUSE 5.0+; mount point must be inside `/Volumes` | `false` |

### Examples

```bash
# Mount — password will be prompted securely if not supplied
mkdir -p /mnt/nas
synology-filestation-fuse --host 192.168.1.100 -u admin /mnt/nas
# Password: ********

# Pass password via flag
synology-filestation-fuse --host 192.168.1.100 -u admin -p mypassword /mnt/nas

# Pass password via environment variable
export SYNO_PASSWORD=mypassword
synology-filestation-fuse --host nas.local -u admin /mnt/nas

# With two-factor authentication (TOTP code passed directly)
synology-filestation-fuse --host 192.168.1.100 -u admin --otp 123456 /mnt/nas

# With 2FA via environment variable
SYNO_OTP=123456 synology-filestation-fuse --host 192.168.1.100 -u admin /mnt/nas

# With 2FA enabled but no code supplied — will prompt interactively:
#   Two-factor authentication code: ______
synology-filestation-fuse --host 192.168.1.100 -u admin /mnt/nas

# Mount over plain HTTP (DSM default HTTP port)
synology-filestation-fuse --host 192.168.1.100 --port 5000 --no-https -u admin /mnt/nas

# Larger read cache for smoother playback of large video files
synology-filestation-fuse --host nas.local -u admin --read-cache-mb 512 /mnt/nas

# Enable debug logging
synology-filestation-fuse --host nas.local -u admin --log-level debug /mnt/nas

# Unmount (Linux)
fusermount -u /mnt/nas

# Unmount (macOS)
umount /mnt/nas

# macOS with FSKit backend (macFUSE 5.0+, macOS 15.4+).
# Mount point must be inside /Volumes.
# First use: approve the macFUSE extension in
#   System Settings → Privacy & Security → Extensions → File System Extensions
# then restart. No Recovery Mode required.
mkdir /Volumes/nas
synology-filestation-fuse --host nas.local -u admin --fskit /Volumes/nas
# Unmount
umount /Volumes/nas
```

## Architecture

```
synology-fuse/
└── src/
    ├── main.rs     CLI argument parsing, Tokio runtime setup, fuser::mount2
    ├── fs.rs       fuser::Filesystem trait implementation (all FUSE operations)
    ├── client.rs   Async Synology FileStation HTTP API client
    ├── cache.rs    Inode ↔ path metadata cache + block-level read cache
    ├── types.rs    Serde types for API JSON responses
    └── error.rs    Synology API error code → POSIX errno translation
```

### Virtual root

The mountpoint root (inode 1) is a synthetic directory that does not correspond to any real path on the NAS. Reading it calls `SYNO.FileStation.List list_share` to enumerate all shares the authenticated account can see. Each share appears as a subdirectory.

### Sync/async bridge

The FUSE dispatch loop (inside `fuser::mount2`) is synchronous and single-threaded. All Synology API calls are async via `reqwest`. The driver bridges these by holding a `tokio::runtime::Handle` and calling `handle.block_on(future)` inside each FUSE callback. A multi-thread Tokio runtime is used so that background prefetch tasks can run on worker threads while the FUSE thread is blocked on a foreground download.

### Read cache

File data is cached in fixed-size 256 KiB blocks using a `moka` LRU cache (default capacity 256 MiB). On `open()`, the first block is downloaded synchronously (guaranteeing an immediate cache hit on the first `read()`) and the next 15 blocks plus the last 4 blocks are prefetched asynchronously in the background. During `read()`, the next 16 blocks are prefetched. An in-flight deduplication mechanism prevents multiple concurrent HTTP requests for the same block. The read cache is invalidated on write, rename, or delete.

### Write buffering

The Synology Upload API requires the complete file body as a single multipart upload; it does not support partial or streaming writes. As a result:

- Write data is accumulated in an in-memory buffer per open file handle.
- The buffer is flushed to the NAS on `flush()` or `release()`.
- Overwriting an existing file deletes it first, then re-uploads the new content.
- Large file writes consume proportional memory.

### Metadata cache

File and directory metadata is cached in a `moka` TTL cache (default 30 seconds). This reduces API calls for repeated `stat`/`readdir` operations. Mutation operations (create, delete, rename) immediately invalidate the relevant cache entries.

## Known Limitations

- **macOS FSKit backend is experimental.** Performance is lower than the kernel extension path and some operations may be unreliable. Requires macOS 15.4+ and macFUSE 5.0+. Mount point must be inside `/Volumes`.
- **Cross-directory directory moves are not supported.** Moving a directory to a different parent returns `ENOSYS`. Only same-directory renames use the efficient `SYNO.FileStation.Rename` API.
- **Cross-directory file moves are not atomic.** They are implemented as download → upload → delete. A failure mid-sequence may leave data duplicated or missing.
- **Large files require large in-memory write buffers.** Writing to a file buffers the entire file content in process memory until the file is closed or flushed.
- **Overwriting a file is not atomic.** The existing file is deleted before the new content is uploaded; a crash between those two steps would result in data loss.
- **Inode numbers are not stable across remounts.** Inodes are allocated in-memory and reset on each mount.
- **No support for symlinks, hard links, or special files.**
- **Permissions and timestamps are read-only.** `chmod`, `chown`, and `utimens` will appear to succeed but changes are not persisted to the NAS.

## Synology API Reference

All requests go to `/webapi/entry.cgi` (authentication uses `/webapi/auth.cgi`). The driver uses the following API methods:

| Operation | API | Method |
|---|---|---|
| Login | `SYNO.API.Auth` | `login` |
| Logout | `SYNO.API.Auth` | `logout` |
| List shares | `SYNO.FileStation.List` | `list_share` |
| List directory | `SYNO.FileStation.List` | `list` |
| Get file info | `SYNO.FileStation.List` | `getinfo` |
| Download file | `SYNO.FileStation.Download` | `download` |
| Upload file | `SYNO.FileStation.Upload` | `upload` |
| Delete | `SYNO.FileStation.Delete` | `delete` |
| Create folder | `SYNO.FileStation.CreateFolder` | `create` |
| Rename | `SYNO.FileStation.Rename` | `rename` |

## Contributing

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Commit messages determine the next version number automatically via [release-please](https://github.com/googleapis/release-please):

| Commit prefix | Example | Version bump |
|---|---|---|
| `fix:` | `fix: handle HTTP 416 as EOF` | patch (`0.1.0` → `0.1.1`) |
| `feat:` | `feat: add read cache` | minor (`0.1.0` → `0.2.0`) |
| `feat!:` or `BREAKING CHANGE:` footer | `feat!: change CLI flag names` | major (`0.1.0` → `1.0.0`) |

Other prefixes (`docs:`, `chore:`, `refactor:`, `test:`, etc.) do not trigger a release.

When a qualifying commit lands on `main`, release-please opens a PR that bumps the version in `Cargo.toml` and updates `CHANGELOG.md`. Merging that PR creates a GitHub release and tag.

## License

MIT

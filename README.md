# synology-fuse

A filesystem driver that mounts a [Synology FileStation](https://www.synology.com/en-global/dsm/feature/file_station) share as a local directory. Written in Rust.

- **Linux** — FUSE via the `fuser` crate
- **macOS** — local WebDAV proxy; no kernel extension required

## Features

- Browse and navigate directories
- Read and write files
- Create and delete files and directories
- Rename files (same-directory) and move files (cross-directory)
- Interactive password prompt with hidden input when password is not set via flag or environment variable
- 2FA / TOTP support
- Uses `rustls` — no OpenSSL dependency required
- **Linux:** metadata cache with configurable TTL; block-level read cache (default 256 MiB) with background prefetch
- **macOS:** no kernel extension; uses macOS's built-in WebDAV filesystem support

## Requirements

### System

- **Linux:** kernel with FUSE support (`/dev/fuse`) and `libfuse3` runtime (`libfuse3-3` on Ubuntu/Debian)
- **macOS:** macOS 10.15+ (no third-party kernel extension needed)
- A Synology NAS running DSM with FileStation API enabled

### Build

- Rust toolchain (1.70+) — install via [rustup](https://rustup.rs)
- **Linux only:** `libfuse3-dev` (Ubuntu/Debian) or `fuse3-devel` (Fedora/RHEL)

```bash
# Ubuntu / Debian
sudo apt-get install libfuse3-dev

# Fedora / RHEL
sudo dnf install fuse3-devel
```

macOS requires no additional build dependencies.

### Linux FUSE configuration (allow_other)

By default, a FUSE mount is only accessible to the user who created it.
The driver attempts to enable `allow_other` so that other users (and root) can
also access the mount. On Ubuntu 24.04 and other distributions that ship
`fusermount3`, this requires `user_allow_other` to be set in `/etc/fuse.conf`.

If that option is not present, the driver falls back to mounting **without**
`allow_other` and logs a warning — the mount still works for the mounting user.

To enable access for all users, edit `/etc/fuse.conf` and uncomment (or add) the
`user_allow_other` line:

```bash
# /etc/fuse.conf
# Allow non-root users to specify the allow_other or allow_root mount options
user_allow_other
```

You can do this in one command:

```bash
# If the line exists but is commented out, uncomment it;
# otherwise append it (handles fresh installs where the line is absent).
if grep -qE '^[[:space:]]*user_allow_other' /etc/fuse.conf 2>/dev/null; then
    : # already enabled — nothing to do
elif grep -qE '^#[[:space:]]*user_allow_other' /etc/fuse.conf 2>/dev/null; then
    sudo sed -i 's/^#[[:space:]]*user_allow_other/user_allow_other/' /etc/fuse.conf
else
    echo 'user_allow_other' | sudo tee -a /etc/fuse.conf
fi
```

After saving the file, remount and all users will be able to access the share.

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
| `<MOUNTPOINT>` | Directory to mount on. On macOS must be under `/Volumes/` (e.g. `/Volumes/nas`) | *(required)* |
| `--host <HOST>` | NAS hostname or IP address | *(required)* |
| `-u, --username` | NAS account username | *(required)* |
| `-p, --password` | NAS account password (or `SYNO_PASSWORD` env var; prompted with hidden input if omitted) | *(optional)* |
| `--otp <CODE>` | TOTP code for 2FA (or `SYNO_OTP` env var); prompted interactively if omitted and 2FA is enabled | *(optional)* |
| `--port <PORT>` | API port | `5001` |
| `--https` | Use HTTPS | `true` |
| `--cache-ttl <SECS>` | Metadata cache TTL in seconds *(Linux only)* | `30` |
| `--read-cache-mb <MiB>` | Read cache size in MiB *(Linux only)* | `256` |
| `--log-level <LEVEL>` | Log level (`error`, `warn`, `info`, `debug`, `trace`) | `info` |

### Examples

```bash
# Mount — password will be prompted securely if not supplied
# Linux
mkdir -p /mnt/nas
synology-filestation-fuse --host 192.168.1.100 -u admin /mnt/nas

# macOS (mountpoint must be under /Volumes/)
synology-filestation-fuse --host 192.168.1.100 -u admin /Volumes/nas
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

# Linux: larger read cache for smoother playback of large video files
synology-filestation-fuse --host nas.local -u admin --read-cache-mb 512 /mnt/nas

# Enable debug logging
synology-filestation-fuse --host nas.local -u admin --log-level debug /mnt/nas

# Unmount (Linux)
fusermount -u /mnt/nas

# Unmount (macOS — or eject in Finder)
diskutil unmount /Volumes/nas
```

## Architecture

```
synology-fuse/
└── src/
    ├── main.rs     CLI argument parsing, Tokio runtime, platform dispatch
    ├── client.rs   Async Synology FileStation HTTP API client
    ├── types.rs    Serde types for API JSON responses
    ├── error.rs    Synology API error code → POSIX errno translation
    ├── fs.rs       fuser::Filesystem trait (Linux FUSE backend)
    ├── cache.rs    Inode ↔ path metadata cache + block-level read cache (Linux)
    └── webdav.rs   dav_server::DavFileSystem trait (macOS WebDAV backend)
```

### Virtual root

The mountpoint root is a synthetic directory that does not correspond to any real path on the NAS. Reading it calls `SYNO.FileStation.List list_share` to enumerate all shares the authenticated account can see. Each share appears as a subdirectory.

### macOS WebDAV backend

On macOS the binary starts a local HTTP server (`127.0.0.1:<random port>`) that speaks WebDAV, then calls the macOS built-in `mount_webdav` to attach it at the requested mountpoint. This uses Apple's own `webdavfs` kernel support — no third-party kernel extension is required. The process exits cleanly on Ctrl-C or when the volume is ejected from Finder.

WebDAV operations map to FileStation API calls:

| WebDAV | FileStation |
|---|---|
| `PROPFIND /` | `list_share` |
| `PROPFIND /path` | `getinfo` + `list` |
| `GET /path` (Range) | `download` |
| `PUT /path` | `upload` |
| `DELETE /path` | `delete` |
| `MKCOL /path` | `CreateFolder` |
| `MOVE` (same dir) | `rename` |
| `MOVE` (cross dir) | `download` → `upload` → `delete` |

### Linux FUSE backend

The FUSE dispatch loop (inside `fuser::mount2`) is synchronous. All Synology API calls are async via `reqwest`. The driver bridges these by holding a `tokio::runtime::Handle` and calling `handle.block_on(future)` inside each FUSE callback.

File data is cached in fixed-size 256 KiB blocks using a `moka` LRU cache (default 256 MiB). Background prefetch of the next 16 blocks keeps streaming reads smooth.

### Write buffering (both platforms)

The Synology Upload API requires the complete file body as a single multipart upload. Write data is accumulated in an in-memory buffer per open file handle and flushed to the NAS on close. Large file writes consume proportional memory.

## Known Limitations

- **Cross-directory directory moves are not supported.** Moving a directory to a different parent returns `ENOSYS`. Only same-directory renames use the efficient `SYNO.FileStation.Rename` API.
- **Cross-directory file moves are not atomic.** They are implemented as download → upload → delete. A failure mid-sequence may leave data duplicated or missing.
- **Large files require large in-memory write buffers.** Writing to a file buffers the entire file content in process memory until the file is closed or flushed.
- **Overwriting a file is not atomic.** The existing file is deleted before the new content is uploaded; a crash between those two steps would result in data loss.
- **No support for symlinks, hard links, or special files.**
- **Linux only:** Inode numbers are not stable across remounts. Permissions and timestamps are read-only (`chmod`, `chown`, `utimens` appear to succeed but are not persisted).

## Synology API Reference

All requests go to `/webapi/entry.cgi` (authentication uses `/webapi/auth.cgi`).

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

# synology-fuse

A FUSE filesystem driver that mounts a [Synology FileStation](https://www.synology.com/en-global/dsm/feature/file_station) share as a local directory on Linux. Written in Rust.

## Features

- Browse and navigate directories
- Read and write files
- Create and delete files and directories
- Rename files (same-directory) and move files (cross-directory)
- Truncate files via `setattr`
- Metadata cache with configurable TTL to reduce API round-trips
- Uses `rustls` — no OpenSSL dependency required

## Requirements

### System

- Linux with FUSE support (`/dev/fuse`)
- `libfuse3` runtime library (`libfuse3-3` on Ubuntu/Debian)
- A Synology NAS running DSM with FileStation API enabled

### Build

- Rust toolchain (1.70+) — install via [rustup](https://rustup.rs)
- `libfuse3-dev` (Ubuntu/Debian) or `fuse3-devel` (Fedora/RHEL)

```bash
# Ubuntu / Debian
sudo apt-get install libfuse3-dev

# Fedora / RHEL
sudo dnf install fuse3-devel
```

## Building

```bash
cargo build --release
```

The binary will be at `target/release/synology-fuse`.

## Usage

```bash
synology-fuse --host <NAS_HOST> -u <USERNAME> -p <PASSWORD> [OPTIONS] <MOUNTPOINT>
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `<MOUNTPOINT>` | Local directory to mount on | *(required)* |
| `--host <HOST>` | NAS hostname or IP address | *(required)* |
| `-u, --username` | NAS account username | *(required)* |
| `-p, --password` | NAS account password | *(required, or `SYNO_PASSWORD` env var)* |
| `--otp <CODE>` | TOTP code for 2FA (or `SYNO_OTP` env var); prompted interactively if omitted and 2FA is enabled | *(optional)* |
| `--port <PORT>` | API port | `5001` |
| `--https` | Use HTTPS | `true` |
| `--cache-ttl <SECS>` | Metadata cache TTL in seconds | `30` |
| `--log-level <LEVEL>` | Log level (`error`, `warn`, `info`, `debug`, `trace`) | `info` |

### Examples

```bash
# Mount all shares (the mountpoint will list every share you have access to)
mkdir -p /mnt/nas
synology-fuse --host 192.168.1.100 -u admin -p mypassword /mnt/nas
ls /mnt/nas          # shows all shares, e.g. homes  photo  video  backup
cd /mnt/nas/homes    # browse into a share

# With two-factor authentication (TOTP code passed directly)
synology-fuse --host 192.168.1.100 -u admin -p mypassword --otp 123456 /mnt/nas

# With 2FA via environment variable
SYNO_OTP=123456 synology-fuse --host 192.168.1.100 -u admin -p mypassword /mnt/nas

# With 2FA enabled but no code supplied — will prompt interactively:
#   Two-factor authentication code: ______
synology-fuse --host 192.168.1.100 -u admin -p mypassword /mnt/nas

# Use an environment variable for the password
export SYNO_PASSWORD=mypassword
synology-fuse --host nas.local -u admin /mnt/nas

# Mount over plain HTTP (DSM default HTTP port)
synology-fuse --host 192.168.1.100 --port 5000 --no-https \
  -u admin -p mypassword /mnt/nas

# Enable debug logging
synology-fuse --host nas.local -u admin -p mypassword \
  --log-level debug /mnt/nas

# Unmount
fusermount -u /mnt/nas
```

## Architecture

```
synology-fuse/
└── src/
    ├── main.rs     CLI argument parsing, Tokio runtime setup, fuser::mount2
    ├── fs.rs       fuser::Filesystem trait implementation (all FUSE operations)
    ├── client.rs   Async Synology FileStation HTTP API client
    ├── cache.rs    Inode ↔ path bidirectional cache with TTL eviction
    ├── types.rs    Serde types for API JSON responses
    └── error.rs    Synology API error code → POSIX errno translation
```

### Sync/async bridge

The FUSE dispatch loop (inside `fuser::mount2`) is synchronous and single-threaded. All Synology API calls are async via `reqwest`. The driver bridges these by holding a `tokio::runtime::Handle` and calling `handle.block_on(future)` inside each FUSE callback. A multi-thread Tokio runtime is used to avoid deadlocks — the calling thread blocks while the Tokio worker pool handles I/O.

### Write buffering

The Synology Upload API requires the complete file body as a multipart upload; it does not support partial or streaming writes. As a result:

- Write data is accumulated in an in-memory buffer per open file handle.
- The buffer is flushed to the NAS on `flush()` or `release()`.
- Large file writes consume proportional memory.

### Metadata cache

File and directory metadata is cached in a `moka` TTL cache (default 30 seconds). This reduces API calls for repeated `stat`/`readdir` operations. Mutation operations (create, delete, rename) immediately invalidate the relevant cache entries.

## Known Limitations

- **Cross-directory directory moves are not supported.** Moving a directory to a different parent returns `ENOSYS`. The Synology API has no atomic move primitive; only same-directory renames use the efficient `SYNO.FileStation.Rename` API.
- **Cross-directory file moves are not atomic.** They are implemented as download → upload → delete. A failure mid-sequence may leave data duplicated or missing.
- **Large files require large in-memory buffers.** Writes to a file buffer the entire file content in process memory until the file is closed or flushed.
- **Inode numbers are not stable across remounts.** Inodes are allocated in-memory and reset on each mount.
- **No support for symlinks, hard links, or special files.**
- **Permissions and timestamps are read-only.** `chmod`, `chown`, and `touch` will appear to succeed but changes are not persisted to the NAS.

## Synology API Reference

All requests go to `/webapi/entry.cgi` (authentication uses `/webapi/auth.cgi`). The driver uses the following API methods:

| Operation | API | Method |
|---|---|---|
| Login | `SYNO.API.Auth` | `login` |
| Logout | `SYNO.API.Auth` | `logout` |
| List directory | `SYNO.FileStation.List` | `list` |
| Get file info | `SYNO.FileStation.List` | `getinfo` |
| Download file | `SYNO.FileStation.Download` | `download` |
| Upload file | `SYNO.FileStation.Upload` | `upload` |
| Delete | `SYNO.FileStation.Delete` | `delete` |
| Create folder | `SYNO.FileStation.CreateFolder` | `create` |
| Rename | `SYNO.FileStation.Rename` | `rename` |

## License

MIT

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a cross-platform filesystem driver that mounts a Synology FileStation NAS share as a local directory. The core driver is written in **Rust**; an optional desktop GUI uses **.NET 10 / Avalonia**. Platform backends: Linux (FUSE via `fuser`), macOS (WebDAV via `dav-server`), Windows (WinFsp via `winfsp` crate).

## Build Commands

### Rust CLI

```bash
cargo build --release
cargo test
cargo fmt --check
cargo clippy
```

On Windows, build from a **Developer Command Prompt for VS** — Git for Windows ships a `link.exe` that shadows MSVC's linker. See `.cargo/config.toml` for context and the fix if linker issues arise.

### .NET GUI

```bash
dotnet publish SynologyFuse.Gui -c Release -r win-x64 -p:SelfContained=true
dotnet publish SynologyFuse.Gui -c Release -r linux-x64 -p:SelfContained=true
dotnet publish SynologyFuse.Gui -c Release -r osx-arm64 -p:SelfContained=true
dotnet test SynologyFuse.Tests --verbosity normal
dotnet format SynologyFuse.Gui
```

### Windows Installer (WiX 4)

```powershell
# One-time tool setup
dotnet tool install --global wix
wix extension add WixToolset.Bal.wixext
wix extension add WixToolset.Util.wixext

# Build MSI
msbuild SynologyFuse.Installer\SynologyFuse.Installer.wixproj

# Build full bundle (MSI + WinFsp bootstrapper)
.\SynologyFuse.Installer\Build-Bundle.ps1
```

## Architecture

### Data Flow

```
CLI (main.rs) or GUI (MountService.cs → subprocess)
    → Tokio runtime
    → SynologyClient (src/client.rs) — async HTTP to FileStation API
    → Platform backend (dispatched in main.rs):
        Linux:   src/fs.rs      (fuser FUSE callbacks, sync→async bridge)
        macOS:   src/webdav.rs  (local HTTP server, mounted via Finder)
        Windows: src/winfs.rs   (WinFsp callbacks, sync→async bridge)
    → OS filesystem layer → user applications
```

### Rust Components (`src/`)

| File | Role |
|------|------|
| `main.rs` | CLI parsing (clap), interactive prompts, platform dispatch |
| `client.rs` | Async HTTP client — all FileStation API calls, session/SID management, 2FA |
| `types.rs` | Serde structs for API responses (`SynoFileInfo`, `SynoResponse<T>`, etc.) |
| `error.rs` | Maps Synology API error codes → POSIX errno / Windows NTSTATUS |
| `fs.rs` | Linux FUSE backend; uses `runtime.block_on()` for each FUSE callback |
| `cache.rs` | Linux only — `InodeCache` (TTL metadata), `ReadCache` (LRU block cache, 256 KiB blocks, prefetch) |
| `webdav.rs` | macOS WebDAV backend; directory moves are download→upload→delete |
| `winfs.rs` | Windows WinFsp backend; in-memory write buffers flushed atomically on close |

### .NET GUI (`SynologyFuse.Gui/`)

MVVM pattern (Avalonia 11). `MountService.cs` launches the Rust CLI as a subprocess and streams its stdout/stderr. It detects when the CLI pauses for OTP input and injects the code. `SettingsService.cs` persists config to platform-specific app-data directories.

### Caching (Linux Only)

- **`InodeCache`**: inode↔path bidirectional map with 30 s TTL (configurable via `--cache-ttl`)
- **`ReadCache`**: fixed-size block cache (default 256 MiB, `--read-cache-mb`); background prefetch of next 16 blocks

## Known Limitations

- Cross-directory directory moves are not supported
- Cross-directory file moves are not atomic (download → upload → delete)
- Write buffers are held entirely in memory until file close
- No symlinks, hard links, or special files
- Linux: inode numbers are not stable; permissions/timestamps are read-only

## Release Process

Uses [release-please](https://github.com/googleapis/release-please-action) on the `main` branch. Commit messages follow **Conventional Commits** (`fix:` → patch, `feat:` → minor, `feat!:` → major). CI runs on all three platforms for every push/PR (`.github/workflows/rust.yml`).

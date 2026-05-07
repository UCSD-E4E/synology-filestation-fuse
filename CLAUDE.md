# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a cross-platform filesystem driver that mounts a Synology FileStation NAS share as a local directory. The core driver is written in **Rust**; an optional desktop GUI uses **.NET 10 / Avalonia**. Platform backends: Linux (FUSE via `fuser`), macOS (WebDAV via `dav-server`), Windows (WinFsp via `winfsp` crate).

## Repository layout

The repo is a **Cargo workspace** with two crates plus the existing .NET projects:

```
rust/synology-filestation-core/    # Pure HTTP client (no FS code, no platform deps)
rust/synology-filestation-fuse/    # CLI + FUSE/WebDAV/WinFsp backends
SynologyFuse.Gui/                  # Avalonia desktop GUI
SynologyFuse.{Mac,Deb}Installer/   # macOS .pkg / Debian .deb builders
SynologyFuse.Installer/            # Windows MSI/bundle builder (WiX 4)
```

## Build Commands

### Rust CLI

```bash
cargo build --release -p synology-filestation-fuse
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

On Windows, build from a **Developer Command Prompt for VS** — Git for Windows ships a `link.exe` that shadows MSVC's linker. See `rust/synology-filestation-fuse/.cargo/config.toml` for context and the fix if linker issues arise.

### .NET GUI

```bash
dotnet publish SynologyFuse.Gui -c Release -r win-x64 -p:SelfContained=true
dotnet publish SynologyFuse.Gui -c Release -r linux-x64 -p:SelfContained=true
dotnet publish SynologyFuse.Gui -c Release -r osx-arm64 -p:SelfContained=true
dotnet test SynologyFuse.Tests --verbosity normal
dotnet format SynologyFuse.Gui
```

### macOS Installer (pkgbuild / productbuild)

```bash
# One-time: Xcode Command Line Tools (provides pkgbuild, productbuild, iconutil)
xcode-select --install

# Build .pkg (--build also compiles Rust CLI and publishes .NET GUI)
./SynologyFuse.MacInstaller/Build-Installer.sh --build

# Explicit version or Intel target
./SynologyFuse.MacInstaller/Build-Installer.sh --build --version 1.0.0 --arch x86_64
```

Key files in `SynologyFuse.MacInstaller/`:
- `Build-Installer.sh` — assembles `.app` bundle, runs `pkgbuild` + `productbuild`
- `Info.plist` — `.app` bundle template (`__VERSION__` / `__GUI_BINARY__` substituted at build time)
- `distribution.xml` — installer UI config (welcome screen, license, macOS 12+ requirement)
- `scripts/postinstall` — symlinks CLI to `/usr/local/bin/` after payload is placed

### Debian/Ubuntu Package (.deb)

```bash
# One-time: dpkg-dev (provides dpkg-deb)
sudo apt-get install dpkg-dev

# Build .deb (--build also compiles Rust CLI and publishes .NET GUI)
./SynologyFuse.DebInstaller/Build-Package.sh --build

# Explicit version or arm64 target
./SynologyFuse.DebInstaller/Build-Package.sh --build --version 1.0.0 --arch arm64
```

Key files in `SynologyFuse.DebInstaller/`:
- `Build-Package.sh` — stages the payload tree, writes `DEBIAN/control`, runs `dpkg-deb`
- `scripts/postinst` — refreshes icon and desktop-entry caches after install
- `scripts/prerm` — placeholder pre-removal hook

The package installs:
- CLI binary → `/usr/bin/synology-filestation-fuse`
- GUI and .NET runtime → `/opt/SynologyFuse/`
- Desktop launcher → `/usr/share/applications/synologyfuse.desktop`
- Icon → `/usr/share/icons/hicolor/256x256/apps/synologyfuse.png`

Runtime dependency: `libfuse3-3`

### Windows Installer (WiX 4)

```powershell
# One-time tool setup
dotnet tool install --global wix --version 6.0.2

# Build MSI
.\SynologyFuse.Installer\Build-Installer.ps1 -Version 1.0.0

# Build full bundle (MSI + WinFsp bootstrapper)
.\SynologyFuse.Installer\Build-Bundle.ps1
```

## Architecture

### Data Flow

```
CLI (main.rs) or GUI (MountService.cs → subprocess)
    → Tokio runtime
    → SynologyClient (rust/synology-filestation-core/src/client.rs) — async HTTP
    → Platform backend (dispatched in main.rs):
        Linux:   rust/synology-filestation-fuse/src/fs.rs       (fuser FUSE callbacks)
        macOS:   rust/synology-filestation-fuse/src/webdav.rs   (local HTTP, mounted via Finder)
        Windows: rust/synology-filestation-fuse/src/winfs.rs    (WinFsp callbacks)
    → OS filesystem layer → user applications
```

### Rust core (`rust/synology-filestation-core/src/`)

| File | Role |
|------|------|
| `lib.rs`    | Module declarations + re-exports of the public surface |
| `client.rs` | Async HTTP client — all FileStation API calls, session/SID management, 2FA |
| `types.rs`  | Serde structs for API responses (`SynoFileInfo`, `SynoResponse<T>`, etc.) |
| `error.rs`  | `SynoFsError` enum + Linux errno mapping (used by FUSE backend) |

### FUSE binary (`rust/synology-filestation-fuse/src/`)

| File | Role |
|------|------|
| `main.rs`   | CLI parsing (clap), interactive prompts, platform dispatch |
| `fs.rs`     | Linux FUSE backend; uses `runtime.block_on()` for each FUSE callback |
| `cache.rs`  | Linux only — `InodeCache` (TTL metadata), `ReadCache` (LRU block cache, 256 KiB blocks, prefetch) |
| `webdav.rs` | macOS WebDAV backend; directory moves are download→upload→delete |
| `winfs.rs`  | Windows WinFsp backend; in-memory write buffers flushed atomically on close |

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

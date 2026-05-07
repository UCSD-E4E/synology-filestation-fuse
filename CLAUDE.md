# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a cross-platform filesystem driver that mounts a Synology FileStation NAS share as a local directory. The core driver is written in **Rust**; an optional desktop GUI uses **.NET 10 / Avalonia**. Platform backends: Linux (FUSE via `fuser`), macOS (WebDAV via `dav-server`), Windows (WinFsp via `winfsp` crate). A **Python binding** (PyO3, see `python/synology_filestation/`) exposes the FileStation HTTP client surface as a `pip install`-able package — drop-in replacement for the `synology-api` PyPI package's FileStation operations, with typed exceptions, atomic downloads, and transparent SID-expiry recovery.

## Repository layout

The repo is a **Cargo workspace** with three crates plus the existing .NET projects:

```
rust/synology-filestation-core/    # Pure HTTP client (no FS code, no platform deps)
rust/synology-filestation-fuse/    # Existing CLI + FUSE/WebDAV/WinFsp backends
python/synology_filestation/       # PyO3 bindings (cdylib) — Python wheel builds
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

### Python bindings (uv) — run from `python/synology_filestation/`

```bash
uv sync --group dev      # install deps + build wheel
uv run pytest -v         # run the binding test suite
maturin build --release  # produce a Linux wheel under target/wheels/
```

`uv sync` invokes maturin under the hood, so a fresh `import synology_filestation` works after a sync. The Rust core's tests cover the auto-relogin / atomic-download contract; the pytest suite verifies the Python-facing exception hierarchy and ergonomics.

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
CLI (main.rs) or GUI (MountService.cs → subprocess) or Python (Client/AsyncClient)
    → Tokio runtime
    → SynologyClient (rust/synology-filestation-core/src/client.rs) — async HTTP
    → Platform backend (dispatched in main.rs) OR PyO3 binding:
        Linux:   rust/synology-filestation-fuse/src/fs.rs       (fuser FUSE callbacks)
        macOS:   rust/synology-filestation-fuse/src/webdav.rs   (local HTTP, mounted via Finder)
        Windows: rust/synology-filestation-fuse/src/winfs.rs    (WinFsp callbacks)
        Python:  python/synology_filestation/src/lib.rs         (PyO3 _native module)
    → OS filesystem / user Python code
```

### Rust core (`rust/synology-filestation-core/src/`)

| File | Role |
|------|------|
| `lib.rs`    | Module declarations + re-exports of the public surface |
| `client.rs` | Async HTTP client — all FileStation API calls, session/SID management, 2FA, auto-relogin, atomic `download_to_path` |
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

### Python bindings (`python/synology_filestation/`)

| File | Role |
|------|------|
| `src/lib.rs` | PyO3 `_native` module: `Client` (sync, blocks on a per-instance Tokio runtime), `AsyncClient` (via `pyo3-async-runtimes`), typed exception hierarchy |
| `synology_filestation/__init__.py` | Re-exports the sync surface (`Client`, exceptions) |
| `synology_filestation/aio.py`      | Re-exports `AsyncClient` |
| `synology_filestation/fsspec.py`   | `SynologyFileSystem(AsyncFileSystem)` — fsspec backend registered as protocol `synofs` (opt-in via `pip install synology-filestation[fsspec]`) |
| `tests/`                           | pytest + pytest-httpserver — covers atomic download, SID-expiry recovery, exception mapping, fsspec sync+async surface |

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

Uses [release-please](https://github.com/googleapis/release-please-action) on the `main` branch. Commit messages follow **Conventional Commits** (`fix:` → patch, `feat:` → minor, `feat!:` → major).

The repo has **three release-please packages** linked together via the `linked-versions` plugin (so they always bump to the same version, but each ships its own changelog and tag):

| Package | Tag prefix | Artifacts on release |
|---|---|---|
| `rust/synology-filestation-core`  | `synology-filestation-core-v...`  | (Cargo.toml bump only) |
| `rust/synology-filestation-fuse`  | `synology-filestation-fuse-v...`  | `.deb`, `.pkg`, `.msi`, `*-Setup.exe` |
| `python/synology_filestation`     | `synology_filestation-v...`       | `*.whl` (manylinux 2_34, x86_64) |

CI workflows:

| File | Trigger | Purpose |
|---|---|---|
| `.github/workflows/rust.yml`           | every push / PR        | clippy, build, test for the rust crates + .deb/.pkg/.msi smoke builds |
| `.github/workflows/python.yml`         | every push             | pytest matrix (Python 3.10–3.13) for the bindings |
| `.github/workflows/maturin.yml`        | every push             | manylinux wheel smoke build |
| `.github/workflows/release-please.yml` | tag (or workflow_dispatch) | release-please PRs and per-package artifact uploads |

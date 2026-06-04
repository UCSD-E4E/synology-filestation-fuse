#!/usr/bin/env bash
# =============================================================================
# Build-Package.sh
#
# SYNOPSIS
#   Builds the SynologyFuse Debian package (.deb).
#
# DESCRIPTION
#   Produces SynologyFuse-<Version>_<arch>.deb — a native Debian/Ubuntu package
#   that installs:
#     • The CLI binary at /usr/bin/synology-filestation-fuse
#     • The GUI and its runtime files at /opt/SynologyFuse/
#     • A .desktop launcher at /usr/share/applications/synologyfuse.desktop
#     • A PNG icon at /usr/share/icons/hicolor/256x256/apps/synologyfuse.png
#
#   Runtime dependency: libfuse3-3  (satisfied on any FUSE 3–capable distro)
#
#   One-time prerequisites:
#     sudo apt-get install dpkg-dev
#     # Rust toolchain and .NET 10 SDK must also be installed
#
#   Run from the repo root (or any directory), having already built:
#     cargo build --release -p synology-filestation-fuse
#     dotnet publish SynologyFuse.Gui -c Release -r linux-x64 -p:SelfContained=true
#
#   Or pass --build to have this script run those steps automatically.
#
# USAGE
#   ./SynologyFuse.DebInstaller/Build-Package.sh [OPTIONS]
#
# OPTIONS
#   --version <ver>    Version string to embed (default: read from Cargo.toml)
#   --arch <arch>      Target architecture: amd64 or arm64 (default: amd64)
#   --out-dir <dir>    Directory to write the .deb to (default: script directory)
#   --build            Also build Rust CLI and publish .NET GUI before packaging
#
# EXAMPLE
#   ./SynologyFuse.DebInstaller/Build-Package.sh --build
#   ./SynologyFuse.DebInstaller/Build-Package.sh --build --version 1.0.0 --arch arm64
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

VERSION=""
ARCH="amd64"
OUT_DIR="${SCRIPT_DIR}"
DO_BUILD=false

# ── Parse arguments ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --arch)    ARCH="$2";    shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --build)   DO_BUILD=true; shift  ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Read version from Cargo.toml if not specified. The repo is a Cargo
# workspace as of 0.1.16 — the [workspace] root has no version, so we read
# it from the FUSE crate's manifest instead.
if [[ -z "${VERSION}" ]]; then
    VERSION=$(grep '^version' "${REPO_ROOT}/rust/synology-filestation-fuse/Cargo.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')
fi

# Map Debian arch name to .NET runtime identifier and Rust target triple
case "${ARCH}" in
    amd64) DOTNET_RID="linux-x64" ;;
    arm64) DOTNET_RID="linux-arm64" ;;
    *)
        echo "Error: unsupported architecture '${ARCH}'. Use amd64 or arm64." >&2
        exit 1
        ;;
esac

CLI_BINARY="synology-filestation-fuse"
GUI_PROJECT="SynologyFuse.Gui"
GUI_BINARY="SynologyFuse.Gui"
PACKAGE_NAME="synologyfuse"

GUI_PUBLISH_DIR="${REPO_ROOT}/${GUI_PROJECT}/bin/Release/net10.0/${DOTNET_RID}/publish"
RUST_RELEASE_DIR="${REPO_ROOT}/target/release"

DEB_FILE="${OUT_DIR}/${PACKAGE_NAME}-${VERSION}_${ARCH}.deb"

echo "Building SynologyFuse v${VERSION} Debian package (${ARCH})"
echo "  Package:    ${PACKAGE_NAME}"
echo "  Output:     ${DEB_FILE}"
echo ""

# ── Prerequisite checks ───────────────────────────────────────────────────────

if ! command -v dpkg-deb &>/dev/null; then
    echo "Error: 'dpkg-deb' not found. Install it with:" >&2
    echo "  sudo apt-get install dpkg-dev" >&2
    exit 1
fi

# ── Optionally build binaries ─────────────────────────────────────────────────

if [[ "${DO_BUILD}" == true ]]; then
    echo "Building Rust CLI (release)..."
    cargo build --release -p synology-filestation-fuse --manifest-path "${REPO_ROOT}/Cargo.toml"

    echo "Publishing .NET GUI (${DOTNET_RID})..."
    dotnet publish "${REPO_ROOT}/${GUI_PROJECT}" \
        -c Release \
        -r "${DOTNET_RID}" \
        -p:SelfContained=true \
        --nologo -v minimal
    echo ""
fi

# ── Verify build artifacts ────────────────────────────────────────────────────

if [[ ! -f "${RUST_RELEASE_DIR}/${CLI_BINARY}" ]]; then
    echo "Error: CLI binary not found at '${RUST_RELEASE_DIR}/${CLI_BINARY}'." >&2
    echo "  Run 'cargo build --release -p synology-filestation-fuse' first, or pass --build." >&2
    exit 1
fi

if [[ ! -d "${GUI_PUBLISH_DIR}" ]]; then
    echo "Error: GUI publish output not found at '${GUI_PUBLISH_DIR}'." >&2
    echo "  Run 'dotnet publish ${GUI_PROJECT} -c Release -r ${DOTNET_RID} -p:SelfContained=true' first," >&2
    echo "  or pass --build." >&2
    exit 1
fi

# ── Staging directory ─────────────────────────────────────────────────────────

STAGE_DIR="$(mktemp -d)"
cleanup() { rm -rf "${STAGE_DIR}"; }
trap cleanup EXIT

# ── Compute installed size (in KiB) ──────────────────────────────────────────

CLI_SIZE=$(du -sk "${RUST_RELEASE_DIR}/${CLI_BINARY}" | awk '{print $1}')
GUI_SIZE=$(du -sk "${GUI_PUBLISH_DIR}" | awk '{print $1}')
INSTALLED_SIZE=$(( CLI_SIZE + GUI_SIZE ))

# ── DEBIAN control directory ──────────────────────────────────────────────────

DEBIAN_DIR="${STAGE_DIR}/DEBIAN"
mkdir -p "${DEBIAN_DIR}"

cat > "${DEBIAN_DIR}/control" <<EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Engineers for Exploration <e4e@ucsd.edu>
Installed-Size: ${INSTALLED_SIZE}
Depends: libfuse3-3
Section: utils
Priority: optional
Homepage: https://github.com/UCSD-E4E/synology-filestation-fuse
Description: Synology FileStation FUSE filesystem driver
 Mounts a Synology FileStation NAS share as a local directory.
 Provides a CLI tool and an optional Avalonia desktop GUI.
 Uses FUSE 3 (no root required after initial configuration).
EOF

cp "${SCRIPT_DIR}/scripts/postinst" "${DEBIAN_DIR}/postinst"
cp "${SCRIPT_DIR}/scripts/prerm"    "${DEBIAN_DIR}/prerm"
chmod 0755 "${DEBIAN_DIR}/postinst" "${DEBIAN_DIR}/prerm"

# ── Install CLI binary ────────────────────────────────────────────────────────

install -Dm755 "${RUST_RELEASE_DIR}/${CLI_BINARY}" \
    "${STAGE_DIR}/usr/bin/${CLI_BINARY}"

# ── Install GUI and its runtime ───────────────────────────────────────────────

GUI_DEST="${STAGE_DIR}/opt/SynologyFuse"
mkdir -p "${GUI_DEST}"
cp -R "${GUI_PUBLISH_DIR}/"* "${GUI_DEST}/"
chmod +x "${GUI_DEST}/${GUI_BINARY}"

# The GUI calls the Rust core directly through this native library; the
# resolver in NativeMethods.cs looks for it beside the GUI executable.
FFI_LIB="libsynology_filestation_ffi.so"
if [[ ! -f "${RUST_RELEASE_DIR}/${FFI_LIB}" ]]; then
    echo "Error: FFI library not found at '${RUST_RELEASE_DIR}/${FFI_LIB}'." >&2
    echo "Build it first: cargo build --release -p synology-filestation-ffi" >&2
    exit 1
fi
install -Dm755 "${RUST_RELEASE_DIR}/${FFI_LIB}" "${GUI_DEST}/${FFI_LIB}"

# ── Desktop entry ─────────────────────────────────────────────────────────────

install -Dm644 /dev/stdin \
    "${STAGE_DIR}/usr/share/applications/synologyfuse.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=SynologyFuse
Comment=Mount a Synology FileStation share as a local directory
Exec=/opt/SynologyFuse/${GUI_BINARY}
Icon=synologyfuse
Terminal=false
Categories=Network;FileManager;
Keywords=synology;nas;fuse;mount;
StartupWMClass=${GUI_BINARY}
EOF

# ── Icon ──────────────────────────────────────────────────────────────────────

PNG_ICON="${REPO_ROOT}/${GUI_PROJECT}/Assets/app.png"
if [[ -f "${PNG_ICON}" ]]; then
    install -Dm644 "${PNG_ICON}" \
        "${STAGE_DIR}/usr/share/icons/hicolor/256x256/apps/synologyfuse.png"
fi

# ── Build .deb ────────────────────────────────────────────────────────────────

echo "Running dpkg-deb..."
mkdir -p "${OUT_DIR}"
dpkg-deb --build --root-owner-group "${STAGE_DIR}" "${DEB_FILE}"

# Trap handles staging cleanup.

SIZE=$(du -sh "${DEB_FILE}" | awk '{print $1}')
echo ""
echo "Package ready: ${DEB_FILE} (${SIZE})"

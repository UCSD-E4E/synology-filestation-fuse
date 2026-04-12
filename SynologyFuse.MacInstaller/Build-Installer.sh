#!/usr/bin/env bash
# =============================================================================
# Build-Installer.sh
#
# SYNOPSIS
#   Builds the SynologyFuse macOS installer (.pkg).
#
# DESCRIPTION
#   Produces SynologyFuse-<Version>.pkg — a native macOS installer that:
#     • Installs SynologyFuse.app to /Applications/
#     • Symlinks the CLI to /usr/local/bin/synology-filestation-fuse
#
#   One-time prerequisites:
#     xcode-select --install      (provides pkgbuild, productbuild, iconutil)
#     # Rust toolchain and .NET 10 SDK must also be installed
#
#   Run from the repo root (or any directory), having already built:
#     cargo build --release
#     dotnet publish SynologyFuse.Gui -c Release -r osx-arm64 -p:SelfContained=true
#
#   Or pass --build to have this script run those steps automatically.
#
# USAGE
#   ./SynologyFuse.MacInstaller/Build-Installer.sh [OPTIONS]
#
# OPTIONS
#   --version <ver>    Version string to embed (default: read from Cargo.toml)
#   --arch <arch>      Target architecture: arm64 or x86_64 (default: arm64)
#   --out-dir <dir>    Directory to write the .pkg to (default: script directory)
#   --build            Also build Rust CLI and publish .NET GUI before packaging
#
# EXAMPLE
#   ./SynologyFuse.MacInstaller/Build-Installer.sh --build
#   ./SynologyFuse.MacInstaller/Build-Installer.sh --build --version 1.0.0
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

VERSION=""
ARCH="arm64"
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

# Read version from Cargo.toml if not specified
if [[ -z "${VERSION}" ]]; then
    VERSION=$(grep '^version' "${REPO_ROOT}/Cargo.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')
fi

DOTNET_RID="osx-${ARCH}"
APP_NAME="SynologyFuse"
CLI_BINARY="synology-filestation-fuse"
GUI_PROJECT="SynologyFuse.Gui"
GUI_BINARY="SynologyFuse.Gui"
BUNDLE_ID="edu.ucsd.e4e.synologyfuse"

GUI_PUBLISH_DIR="${REPO_ROOT}/${GUI_PROJECT}/bin/Release/net10.0/${DOTNET_RID}/publish"
RUST_RELEASE_DIR="${REPO_ROOT}/target/release"

COMPONENT_PKG="${SCRIPT_DIR}/${APP_NAME}-component.pkg"
PRODUCT_PKG="${OUT_DIR}/${APP_NAME}-${VERSION}.pkg"

echo "Building SynologyFuse v${VERSION} macOS installer (${ARCH})"
echo "  Bundle ID:  ${BUNDLE_ID}"
echo "  Output:     ${PRODUCT_PKG}"
echo ""

# ── Prerequisite checks ───────────────────────────────────────────────────────

for cmd in pkgbuild productbuild; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '${cmd}' not found. Install Xcode Command Line Tools:" >&2
        echo "  xcode-select --install" >&2
        exit 1
    fi
done

# ── Optionally build binaries ─────────────────────────────────────────────────

if [[ "${DO_BUILD}" == true ]]; then
    echo "Building Rust CLI (release)..."
    cargo build --release --manifest-path "${REPO_ROOT}/Cargo.toml"

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
    echo "  Run 'cargo build --release' first, or pass --build." >&2
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
cleanup() { rm -rf "${STAGE_DIR}" "${COMPONENT_PKG}"; }
trap cleanup EXIT

APP_CONTENTS="${STAGE_DIR}/${APP_NAME}.app/Contents"
mkdir -p "${APP_CONTENTS}/MacOS"
mkdir -p "${APP_CONTENTS}/Resources"

# ── Assemble .app bundle ──────────────────────────────────────────────────────

echo "Assembling ${APP_NAME}.app..."

# Copy all GUI publish output into MacOS/
cp -R "${GUI_PUBLISH_DIR}/"* "${APP_CONTENTS}/MacOS/"

# Place CLI binary beside the GUI executable so MountService.FindBinary()
# finds it at the "deployed layout" path without needing PATH.
cp "${RUST_RELEASE_DIR}/${CLI_BINARY}" "${APP_CONTENTS}/MacOS/"
chmod +x "${APP_CONTENTS}/MacOS/${CLI_BINARY}"
chmod +x "${APP_CONTENTS}/MacOS/${GUI_BINARY}"

# Convert PNG icon to .icns (skipped gracefully if iconutil or PNG unavailable)
PNG_ICON="${REPO_ROOT}/${GUI_PROJECT}/Assets/app.png"
if [[ -f "${PNG_ICON}" ]] && command -v iconutil &>/dev/null; then
    echo "Converting icon to .icns..."
    ICONSET="${STAGE_DIR}/AppIcon.iconset"
    mkdir -p "${ICONSET}"
    for sz in 16 32 128 256 512; do
        sips -z $sz $sz                 "${PNG_ICON}" --out "${ICONSET}/icon_${sz}x${sz}.png"       >/dev/null
        sips -z $((sz * 2)) $((sz * 2)) "${PNG_ICON}" --out "${ICONSET}/icon_${sz}x${sz}@2x.png"    >/dev/null
    done
    iconutil -c icns -o "${APP_CONTENTS}/Resources/AppIcon.icns" "${ICONSET}"
fi

# Stamp Info.plist with version and executable name
sed "s/__VERSION__/${VERSION}/g; s/__GUI_BINARY__/${GUI_BINARY}/g" \
    "${SCRIPT_DIR}/Info.plist" > "${APP_CONTENTS}/Info.plist"

# ── Build component package ───────────────────────────────────────────────────

echo "Running pkgbuild..."
pkgbuild \
    --root          "${STAGE_DIR}" \
    --install-location "/Applications" \
    --identifier    "${BUNDLE_ID}" \
    --version       "${VERSION}" \
    --scripts       "${SCRIPT_DIR}/scripts" \
    "${COMPONENT_PKG}"

# ── Build final product archive ───────────────────────────────────────────────

echo "Running productbuild..."
mkdir -p "${OUT_DIR}"
productbuild \
    --distribution "${SCRIPT_DIR}/distribution.xml" \
    --package-path "${SCRIPT_DIR}" \
    --resources    "${SCRIPT_DIR}/resources" \
    "${PRODUCT_PKG}"

# Trap handles staging and component pkg cleanup.

SIZE=$(du -sh "${PRODUCT_PKG}" | awk '{print $1}')
echo ""
echo "Installer ready: ${PRODUCT_PKG} (${SIZE})"

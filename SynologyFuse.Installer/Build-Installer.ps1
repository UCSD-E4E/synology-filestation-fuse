<#
.SYNOPSIS
    Builds the SynologyFuse Windows MSI installer.

.DESCRIPTION
    Produces SynologyFuse-<Version>.msi by compiling Package.wxs with the
    wix CLI tool.

    One-time setup:
        dotnet tool install --global wix

    Run from the repo root before calling this script:
        cargo build -r
        dotnet publish SynologyFuse.Gui -c Release -r win-x64 -p:SelfContained=true

.PARAMETER Version
    Version string to embed in the MSI (default: 0.1.2).

.PARAMETER OutDir
    Directory to write the MSI to (default: same directory as this script).

.EXAMPLE
    .\SynologyFuse.Installer\Build-Installer.ps1
    .\SynologyFuse.Installer\Build-Installer.ps1 -Version 1.0.0
#>
param(
    [string]$Version  = "0.1.2",
    [string]$OutDir   = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot    = (Resolve-Path "$PSScriptRoot\..").Path
$RustBin     = Join-Path $RepoRoot "target\release"
$GuiPublish  = Join-Path $RepoRoot "SynologyFuse.Gui\bin\Release\net10.0\win-x64\publish"
$WxsFile     = Join-Path $PSScriptRoot "Package.wxs"
$OutFile     = Join-Path $OutDir "SynologyFuse-$Version.msi"

# ── Verify prerequisites ──────────────────────────────────────────────────────

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "wix CLI not found. Install it with: dotnet tool install --global wix"
}

$CliExe = Join-Path $RustBin "synology-filestation-fuse.exe"
if (-not (Test-Path $CliExe)) {
    throw "Rust CLI not found at '$CliExe'. Build it first: cargo build -r"
}

if (-not (Test-Path $GuiPublish)) {
    throw "GUI publish output not found at '$GuiPublish'. " +
          "Publish it first: dotnet publish SynologyFuse.Gui -c Release -r win-x64 -p:SelfContained=true"
}

# ── Build ─────────────────────────────────────────────────────────────────────

Write-Host "Building SynologyFuse v$Version installer..."
Write-Host "  CLI:  $CliExe"
Write-Host "  GUI:  $GuiPublish"
Write-Host "  Out:  $OutFile"

wix build $WxsFile `
    -d "Version=$Version" `
    -d "RustBin=$RustBin" `
    -d "GuiPublishDir=$GuiPublish" `
    -o $OutFile

if ($LASTEXITCODE -ne 0) {
    throw "wix build failed (exit code $LASTEXITCODE)"
}

$size = (Get-Item $OutFile).Length / 1MB
Write-Host ("Installer ready: {0} ({1:F1} MB)" -f $OutFile, $size)

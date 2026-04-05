<#
.SYNOPSIS
    Builds the SynologyFuse Windows bundle installer (EXE).

.DESCRIPTION
    Produces SynologyFuse-<Version>-Setup.exe — a Burn bootstrapper that
    installs WinFsp (if not already present) then SynologyFuse.

    One-time setup:
        dotnet tool install --global wix
        wix extension add -g WixToolset.Bal.wixext/6.0.2

    Run from the repo root before calling this script:
        cargo build -r
        dotnet publish SynologyFuse.Gui -c Release -r win-x64 -p:SelfContained=true
        msbuild SynologyFuse.Installer\SynologyFuse.Installer.wixproj

.PARAMETER Version
    Version string to embed (default: 0.1.2).

.PARAMETER WinFspVersion
    WinFsp release to download if not already cached (default: 2.1.25156).

.PARAMETER WinFspSha256
    Expected SHA-256 hash (hex) of the WinFsp MSI. Must be updated together with
    WinFspVersion. Default is the published hash for winfsp-2.1.25156.msi.

.PARAMETER OutDir
    Directory to write the EXE to (default: same directory as this script).

.EXAMPLE
    .\SynologyFuse.Installer\Build-Bundle.ps1
    .\SynologyFuse.Installer\Build-Bundle.ps1 -Version 1.0.0
#>
param(
    [string]$Version       = "0.0.0",
    [string]$WinFspVersion = "2.1.25156",
    # Pinned SHA-256 for winfsp-2.1.25156.msi (update when bumping WinFspVersion).
    # Source: https://github.com/winfsp/winfsp/releases/tag/v2.1
    [string]$WinFspSha256  = "073A70E00F77423E34BED98B86E600DEF93393BA5822204FAC57A29324DB9F7A",
    [string]$OutDir        = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot        = (Resolve-Path "$PSScriptRoot\..").Path
$RedistDir       = Join-Path $PSScriptRoot "redist"
$WinFspInstaller = Join-Path $RedistDir "winfsp.msi"
$SynologyFuseMsi = Join-Path $PSScriptRoot "SynologyFuse-$Version.msi"
$BundleProj      = Join-Path $PSScriptRoot "Bundle.wixproj"
$OutFile         = Join-Path $OutDir "SynologyFuse-$Version-Setup.exe"

# ── Verify prerequisites ──────────────────────────────────────────────────────

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet CLI not found. Install the .NET SDK from https://dotnet.microsoft.com/"
}

if (-not (Test-Path $SynologyFuseMsi)) {
    throw "SynologyFuse MSI not found at '$SynologyFuseMsi'. " +
          "Build it first: msbuild SynologyFuse.Installer\SynologyFuse.Installer.wixproj"
}

# ── Download WinFsp installer if needed ──────────────────────────────────────

if (-not (Test-Path $WinFspInstaller)) {
    $WinFspMajorMinor = $WinFspVersion -replace '\.\d+$', ''  # "2.1.25156" -> "2.1"
    $WinFspUrl = "https://github.com/winfsp/winfsp/releases/download/v$WinFspMajorMinor/winfsp-$WinFspVersion.msi"

    Write-Host "Downloading WinFsp $WinFspVersion..."
    Write-Host "  From: $WinFspUrl"
    Write-Host "  To:   $WinFspInstaller"

    $null = New-Item -ItemType Directory -Force -Path $RedistDir
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        Invoke-WebRequest -Uri $WinFspUrl -OutFile $WinFspInstaller -UseBasicParsing
    } else {
        Invoke-WebRequest -Uri $WinFspUrl -OutFile $WinFspInstaller
    }

    $actualHash = (Get-FileHash -Path $WinFspInstaller -Algorithm SHA256).Hash
    if ($actualHash -ne $WinFspSha256.ToUpper()) {
        Remove-Item $WinFspInstaller -Force
        throw "WinFsp installer SHA-256 mismatch.`n" +
              "  Expected: $($WinFspSha256.ToUpper())`n" +
              "  Actual:   $actualHash`n" +
              "The downloaded file has been removed. " +
              "Verify -WinFspSha256 matches the release at https://github.com/winfsp/winfsp/releases/tag/v$WinFspMajorMinor"
    }
    Write-Host "  SHA-256 verified."
    Write-Host "  Done."
} else {
    Write-Host "Using cached WinFsp installer: $WinFspInstaller"
    $actualHash = (Get-FileHash -Path $WinFspInstaller -Algorithm SHA256).Hash
    if ($actualHash -ne $WinFspSha256.ToUpper()) {
        throw "Cached WinFsp installer SHA-256 mismatch.`n" +
              "  Expected: $($WinFspSha256.ToUpper())`n" +
              "  Actual:   $actualHash`n" +
              "Remove '$WinFspInstaller' and retry."
    }
    Write-Host "  SHA-256 verified."
}

# ── Build bundle ──────────────────────────────────────────────────────────────

Write-Host "Building SynologyFuse v$Version bundle..."
Write-Host "  WinFsp: $WinFspInstaller"
Write-Host "  MSI:    $SynologyFuseMsi"
Write-Host "  Out:    $OutFile"

$BundleOutDir = Join-Path $PSScriptRoot "bundle-out"

dotnet build $BundleProj `
    -c Release `
    /p:Version=$Version `
    /p:WinFspInstaller=$WinFspInstaller `
    /p:SynologyFuseMsi=$SynologyFuseMsi `
    /p:OutputPath="$BundleOutDir\" `
    /p:IntermediateOutputPath="$BundleOutDir\obj\"

if ($LASTEXITCODE -ne 0) {
    throw "dotnet build failed (exit code $LASTEXITCODE)"
}

$builtExe = Get-ChildItem $BundleOutDir -Recurse -Filter "*.exe" | Select-Object -First 1
if (-not $builtExe) {
    throw "Bundle EXE not found in '$BundleOutDir' after build"
}

$null = New-Item -ItemType Directory -Force (Split-Path $OutFile)
Move-Item $builtExe.FullName $OutFile -Force
Remove-Item $BundleOutDir -Recurse -Force -ErrorAction SilentlyContinue

$size = (Get-Item $OutFile).Length / 1MB
Write-Host ("Bundle ready: {0} ({1:F1} MB)" -f $OutFile, $size)

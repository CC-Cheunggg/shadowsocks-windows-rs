$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$version = "0.14.1"
$archiveUrl = "https://www.wintun.net/builds/wintun-$version.zip"
$archiveSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$dllSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
$licenseSha256 = "183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$resourceDirectory = Join-Path $repositoryRoot "src-tauri/resources/wintun"
$outputDirectory = Join-Path $resourceDirectory "amd64"
$licenseDestination = Join-Path $resourceDirectory "WINTUN-LICENSE.txt"
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wintun-fetch-" + [Guid]::NewGuid())
$archivePath = Join-Path $temporaryRoot "wintun.zip"
$expandedPath = Join-Path $temporaryRoot "expanded"

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing
    $actualArchiveHash = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLowerInvariant()
    if ($actualArchiveHash -ne $archiveSha256) {
        throw "Official Wintun archive SHA-256 mismatch."
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $expandedPath
    $sourceDll = Join-Path $expandedPath "wintun/bin/amd64/wintun.dll"
    $sourceLicense = Join-Path $expandedPath "wintun/LICENSE.txt"
    $actualDllHash = (Get-FileHash -Algorithm SHA256 -Path $sourceDll).Hash.ToLowerInvariant()
    if ($actualDllHash -ne $dllSha256) {
        throw "Official Wintun AMD64 DLL SHA-256 mismatch."
    }
    if (-not (Test-Path -LiteralPath $sourceLicense -PathType Leaf)) {
        throw "Official Wintun Prebuilt Binaries License is missing from the archive."
    }
    $actualLicenseHash = (Get-FileHash -Algorithm SHA256 -Path $sourceLicense).Hash.ToLowerInvariant()
    if ($actualLicenseHash -ne $licenseSha256) {
        throw "Official Wintun Prebuilt Binaries License SHA-256 mismatch."
    }

    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    Copy-Item -LiteralPath $sourceDll -Destination (Join-Path $outputDirectory "wintun.dll") -Force
    Copy-Item -LiteralPath $sourceLicense -Destination $licenseDestination -Force
    Write-Host "Verified Wintun $version AMD64 DLL and original binary license at $resourceDirectory"
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Binary
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-Dumpbin {
    $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
    $vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio/Installer/vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw "vswhere.exe is unavailable; cannot inspect PE imports."
    }

    $installationPath = (
        & $vswhere `
            -latest `
            -products "*" `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath |
            Select-Object -First 1
    )
    if ([string]::IsNullOrWhiteSpace($installationPath)) {
        throw "A Visual Studio installation with the x64 VC tools was not found."
    }

    $pattern = Join-Path `
        $installationPath `
        "VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"
    $candidate = Get-ChildItem -Path $pattern -File |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($null -eq $candidate) {
        throw "dumpbin.exe was not found under the selected Visual Studio installation."
    }

    return $candidate.FullName
}

$dumpbin = Resolve-Dumpbin
$forbiddenPattern = (
    '(?i)^(?:vcruntime|msvcp|concrt|msvcr|msvcm|vccorlib|vcomp|vcamp)' +
    '[a-z0-9_]*\.dll$' +
    '|^(?:mfc|mfcm|atl)\d+[a-z0-9_]*\.dll$' +
    '|^libomp\d+[a-z0-9_.-]*\.dll$' +
    '|^api-ms-win-crt-[a-z0-9-]+\.dll$' +
    '|^ucrtbase(?:d)?\.dll$'
)

foreach ($inputPath in $Binary) {
    $resolved = Resolve-Path -LiteralPath $inputPath
    $extension = [System.IO.Path]::GetExtension($resolved.Path)
    if ($extension -ine ".exe" -and $extension -ine ".dll") {
        throw "Expected a Windows PE executable or DLL, got: $($resolved.Path)"
    }

    $output = @(& $dumpbin /NOLOGO /IMPORTS $resolved.Path 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed for $($resolved.Path) with exit code $LASTEXITCODE."
    }

    $outputText = $output -join "`n"
    $targetName = [System.IO.Path]::GetFileName($resolved.Path)
    $imports = @(
        foreach ($match in [regex]::Matches(
            $outputText,
            '(?i)\b[A-Za-z0-9_.-]+\.dll\b'
        )) {
            if ($match.Value -ine $targetName) {
                $match.Value
            }
        }
    ) | Sort-Object -Unique
    if ($imports.Count -eq 0) {
        throw "No PE imports were parsed for $($resolved.Path)."
    }

    $forbidden = @($imports | Where-Object { $_ -match $forbiddenPattern })
    if ($forbidden.Count -ne 0) {
        throw (
            "$($resolved.Path) dynamically imports Microsoft CRT DLLs: " +
            ($forbidden -join ", ")
        )
    }

    Write-Host "Verified no dynamic Microsoft CRT imports in $($resolved.Path)."
}

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$MainBinary,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$NetworkRecoverBinary,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$WintunSmokeBinary
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-PeSubsystem {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "PE file is missing or is not a file: $Path"
    }

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $stream = [System.IO.File]::Open(
        $resolved,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    $reader = [System.IO.BinaryReader]::new($stream)

    try {
        $fileLength = $stream.Length
        if ($fileLength -lt 0x40) {
            throw "File is truncated before the DOS header is complete: $resolved"
        }

        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "DOS MZ signature is missing: $resolved"
        }

        $stream.Position = 0x3C
        $peOffset = [long]($reader.ReadUInt32())
        if ($peOffset -lt 0x40 -or $peOffset -gt ($fileLength - 24)) {
            throw "PE header offset does not contain a complete PE/COFF header: $resolved"
        }

        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "PE signature is missing: $resolved"
        }

        $optionalHeaderOffset = $peOffset + 24
        $stream.Position = $peOffset + 20
        $optionalHeaderSize = [long]($reader.ReadUInt16())
        if ($optionalHeaderSize -lt 70) {
            throw (
                "PE optional header is too small to contain the Subsystem field " +
                "(declared $optionalHeaderSize bytes): $resolved"
            )
        }
        if ($optionalHeaderOffset -gt ($fileLength - $optionalHeaderSize)) {
            throw (
                "PE optional header extends beyond the end of the file " +
                "(declared $optionalHeaderSize bytes): $resolved"
            )
        }

        $stream.Position = $optionalHeaderOffset
        $optionalHeaderMagic = $reader.ReadUInt16()
        if (
            $optionalHeaderMagic -ne 0x010B -and
            $optionalHeaderMagic -ne 0x020B
        ) {
            throw (
                "Unsupported PE optional-header magic " +
                ("0x{0:X4}" -f $optionalHeaderMagic) +
                ": $resolved"
            )
        }

        # IMAGE_OPTIONAL_HEADER32 and IMAGE_OPTIONAL_HEADER64 place the
        # Subsystem field at the same byte offset.
        $stream.Position = $optionalHeaderOffset + 68
        return $reader.ReadUInt16()
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

$expectations = @(
    @{
        Path = $MainBinary
        Name = "desktop application"
        Subsystem = 2
        Label = "Windows GUI"
    },
    @{
        Path = $NetworkRecoverBinary
        Name = "network recovery helper"
        Subsystem = 3
        Label = "Windows console"
    },
    @{
        Path = $WintunSmokeBinary
        Name = "Wintun smoke helper"
        Subsystem = 3
        Label = "Windows console"
    }
)

foreach ($expectation in $expectations) {
    $actual = Get-PeSubsystem -Path $expectation.Path
    if ($actual -ne $expectation.Subsystem) {
        throw (
            "$($expectation.Name) PE subsystem is $actual; expected " +
            "$($expectation.Subsystem) ($($expectation.Label))."
        )
    }

    Write-Host (
        "Verified $($expectation.Name) PE subsystem " +
        "$actual ($($expectation.Label))."
    )
}

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [string]$OutputRoot = (Join-Path $PSScriptRoot "recovered"),

    [int]$FetchBudget = 2000000,

    [int]$CallbackLimit = 200,

    [switch]$ReuseTrace,

    [switch]$ReuseHandlers,

    [switch]$SkipReadable,

    [switch]$SkipAudit
)

$ErrorActionPreference = "Stop"
Get-Command uv -ErrorAction Stop | Out-Null

$sourcePath = (Resolve-Path -LiteralPath $Source).Path
$outputPath = [IO.Path]::GetFullPath($OutputRoot)
$stem = [IO.Path]::GetFileNameWithoutExtension($sourcePath)
$summaryPath = Join-Path $outputPath "artifacts\summaries\$stem.json"

Push-Location $PSScriptRoot
try {
    $recoverArgs = @(
        "run", "--no-project", "--with", "lupa", "--with", "luaparser",
        "python", "-m", "tools.recover_script",
        $sourcePath,
        "--output-root", $outputPath,
        "--fetch-budget", $FetchBudget,
        "--callback-limit", $CallbackLimit
    )
    if ($ReuseTrace) {
        $recoverArgs += "--reuse-trace"
    }
    if ($ReuseHandlers) {
        $recoverArgs += "--reuse-handlers"
    }

    & uv @recoverArgs
    if ($LASTEXITCODE -ne 0) {
        throw "recover_script failed with exit code $LASTEXITCODE"
    }

    if (-not $SkipReadable) {
        & uv run --no-project --with lupa --with luaparser python -m tools.luraph_readable `
            $summaryPath --output-root $outputPath
        if ($LASTEXITCODE -ne 0) {
            throw "luraph_readable failed with exit code $LASTEXITCODE"
        }
    }

    if (-not $SkipAudit) {
        & uv run --no-project --with lupa --with luaparser python -m tools.audit_recovery `
            (Join-Path $outputPath "artifacts\summaries")
        if ($LASTEXITCODE -ne 0) {
            throw "audit_recovery failed with exit code $LASTEXITCODE"
        }

        if (-not $SkipReadable) {
            & uv run --no-project python -m tools.audit_readable `
                (Join-Path $outputPath "artifacts\readable")
            if ($LASTEXITCODE -ne 0) {
                throw "audit_readable failed with exit code $LASTEXITCODE"
            }
        }
    }
}
finally {
    Pop-Location
}

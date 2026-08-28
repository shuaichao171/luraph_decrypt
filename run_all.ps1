[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDirectory,

    [string]$OutputRoot = (Join-Path $PSScriptRoot "recovered"),

    [int]$FetchBudget = 2000000,

    [int]$CallbackLimit = 200,

    [switch]$ReuseTrace,

    [switch]$ReuseHandlers
)

$ErrorActionPreference = "Stop"
$sourcePath = (Resolve-Path -LiteralPath $SourceDirectory).Path
$outputPath = [IO.Path]::GetFullPath($OutputRoot)
$sources = @(Get-ChildItem -LiteralPath $sourcePath -Filter "*.lua" -File |
    Sort-Object Name)

if ($sources.Count -eq 0) {
    throw "No .lua files found in $sourcePath"
}

foreach ($file in $sources) {
    $singleArgs = @{
        Source = $file.FullName
        OutputRoot = $outputPath
        FetchBudget = $FetchBudget
        CallbackLimit = $CallbackLimit
        SkipReadable = $true
        SkipAudit = $true
    }
    if ($ReuseTrace) {
        $singleArgs.ReuseTrace = $true
    }
    if ($ReuseHandlers) {
        $singleArgs.ReuseHandlers = $true
    }
    & (Join-Path $PSScriptRoot "run_recovery.ps1") @singleArgs
}

Push-Location $PSScriptRoot
try {
    $summaryDirectory = Join-Path $outputPath "artifacts\summaries"
    $summaries = @(Get-ChildItem -LiteralPath $summaryDirectory `
        -Filter "*.json" -File | Sort-Object Name | ForEach-Object FullName)

    & uv run --no-project --with lupa --with luaparser python -m tools.luraph_readable `
        @summaries --output-root $outputPath
    if ($LASTEXITCODE -ne 0) {
        throw "luraph_readable failed with exit code $LASTEXITCODE"
    }

    & uv run --no-project --with lupa --with luaparser python -m tools.audit_recovery `
        $summaryDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "audit_recovery failed with exit code $LASTEXITCODE"
    }

    & uv run --no-project python -m tools.audit_readable `
        (Join-Path $outputPath "artifacts\readable")
    if ($LASTEXITCODE -ne 0) {
        throw "audit_readable failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

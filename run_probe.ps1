[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [Parameter(Mandatory = $true)]
    [string]$Fixture,

    [string]$Environment,

    [Parameter(Mandatory = $true)]
    [string]$InstructionUpvalue,

    [Parameter(Mandatory = $true)]
    [string]$EnvironmentUpvalue,

    [int]$FetchBudget = 2000000,

    [int]$EventLimit = 10000,

    [int]$CallbackLimit = 20,

    [int[]]$Program = @(),

    [switch]$Full,

    [switch]$KeepDebugEvents
)

$ErrorActionPreference = "Stop"
Get-Command uv -ErrorAction Stop | Out-Null

$sourcePath = (Resolve-Path -LiteralPath $Source).Path
$fixturePath = (Resolve-Path -LiteralPath $Fixture).Path
$fixtureBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($fixturePath))

if ($Environment) {
    $environmentPath = (Resolve-Path -LiteralPath $Environment).Path
    $environmentBase64 = [Convert]::ToBase64String(
        [IO.File]::ReadAllBytes($environmentPath)
    )
}
else {
    $environmentBase64 = "e30="
}

$probeArgs = @(
    "run", "--no-project", "--with", "lupa", "--with", "luaparser",
    "python", "-m", "tools.probe_business",
    $sourcePath,
    "--fixture", $fixtureBase64,
    "--environment", $environmentBase64,
    "--fetch-budget", $FetchBudget,
    "--event-limit", $EventLimit,
    "--callback-limit", $CallbackLimit,
    "--instruction-upvalue", $InstructionUpvalue,
    "--environment-upvalue", $EnvironmentUpvalue
)
foreach ($programId in $Program) {
    $probeArgs += @("--program", $programId)
}
if ($Full) {
    $probeArgs += "--full"
}
if ($KeepDebugEvents) {
    $probeArgs += "--keep-debug-events"
}

Push-Location $PSScriptRoot
try {
    & uv @probeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "probe_business failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$env:PYTHONDONTWRITEBYTECODE = "1"
Get-Command uv -ErrorAction Stop | Out-Null

Push-Location $PSScriptRoot
try {
    & uv run --no-project --with pytest --with lupa --with luaparser python -m pytest -q -p no:cacheprovider
    if ($LASTEXITCODE -ne 0) {
        throw "pytest failed with exit code $LASTEXITCODE"
    }

    & uv run --no-project --with ruff ruff check --no-cache tools tests
    if ($LASTEXITCODE -ne 0) {
        throw "ruff failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

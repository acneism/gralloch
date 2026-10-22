param([switch]$Yara)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here
try {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found. Install Rust from https://rustup.rs and the MSVC C++ Build Tools, then re-run."
    }

    $featArgs = @()
    if ($Yara) { $featArgs = @('--features', 'yara') }

    Write-Host "Building gralloch-mcp (release)..." -ForegroundColor Cyan
    & cargo build --release @featArgs
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }

    $exe = Join-Path $here 'target\release\gralloch-mcp.exe'
    if (-not (Test-Path $exe)) { throw "expected build output not found: $exe" }

    $binDir = Join-Path (Split-Path -Parent $here) 'bin'
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    Copy-Item $exe (Join-Path $binDir 'gralloch-mcp.exe') -Force
    Write-Host "OK: gralloch-mcp.exe -> $binDir" -ForegroundColor Green
}
finally {
    Pop-Location
}

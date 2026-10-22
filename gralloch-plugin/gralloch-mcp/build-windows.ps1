<#
  Builds gralloch-mcp.exe and copies it into the plugin's bin/ directory.

  Prerequisites:
    - Rust toolchain via rustup:  https://rustup.rs
    - MSVC C++ Build Tools (Visual Studio Build Tools, "Desktop development
      with C++"), providing the x86_64-pc-windows-msvc linker.

  Usage:
    .\build-windows.ps1          # light MVP build (no YARA)
    .\build-windows.ps1 -Yara    # also compile the yara-x engine (heavier)
#>
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

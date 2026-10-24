param([switch]$Yara)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here
try {
    # Make the toolchain reachable even if PATH is not set up in this shell. The
    # GNU target needs the MinGW linker's dlltool.exe to link windows-sys/getrandom.
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
        if (Test-Path -LiteralPath (Join-Path $cargoBin 'cargo.exe')) { $env:PATH = "$cargoBin;$env:PATH" }
    }
    if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
        $cands = @()
        if ($env:MINGW_DIR) { $cands += (Join-Path $env:MINGW_DIR 'bin') }
        $cands += (Join-Path $env:USERPROFILE 'mingw\mingw64\bin')
        $cands += 'C:\msys64\mingw64\bin'
        foreach ($d in $cands) {
            if (Test-Path -LiteralPath (Join-Path $d 'gcc.exe')) {
                $env:PATH = "$d;$env:PATH"
                Write-Host "Using MinGW toolchain: $d" -ForegroundColor DarkGray
                break
            }
        }
    }

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found. Install Rust from https://rustup.rs (GNU: rustup default stable-x86_64-pc-windows-gnu) or put it on PATH, then re-run."
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

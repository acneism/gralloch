param(
    [Parameter(Mandatory = $true)][string]$CaseDir,
    [string]$UpxExe = $env:UPX_EXE,
    [int]$TimeoutSec = 300
)

$ErrorActionPreference = 'Stop'

$casePath = (Resolve-Path $CaseDir).Path
$caseJson = Join-Path $casePath 'case.json'
if (-not (Test-Path $caseJson)) { throw "case.json not found in $casePath (run case_new first)" }
$case = Get-Content -Raw $caseJson | ConvertFrom-Json
$sample = Join-Path $casePath $case.stored_sample
if (-not (Test-Path $sample)) { throw "stored sample not found: $sample" }

$artifacts = Join-Path $casePath 'artifacts'
New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
$unpackJson = Join-Path $artifacts 'unpack.json'

if (-not $UpxExe -and (Get-Command upx -ErrorAction SilentlyContinue)) {
    $UpxExe = (Get-Command upx).Source
}
if (-not $UpxExe -or -not (Test-Path $UpxExe)) {
    throw "upx not found. Install upx (https://github.com/upx/upx/releases) and pass -UpxExe or set `$env:UPX_EXE."
}

function Invoke-Upx([string[]]$UpxArgs) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $UpxExe @UpxArgs 2>&1 | ForEach-Object { "$_" }
        return [pscustomobject]@{ Code = $LASTEXITCODE; Out = ($out -join ' ').Trim() }
    } finally {
        $ErrorActionPreference = $old
    }
}

function Write-Unpack($obj) {

    $json = $obj | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($unpackJson, $json, (New-Object System.Text.UTF8Encoding($false)))
}

$inHash = (Get-FileHash -Algorithm SHA256 $sample).Hash.ToLower()
$base = @{
    schema_version = '0.1.0'
    generated_by   = 'run-unpack.ps1'
    input          = @{ stored_sample = $case.stored_sample; sha256 = $inHash; size = (Get-Item $sample).Length }
}

$isUpx = ((Invoke-Upx @('-t', $sample)).Code -eq 0)

if (-not $isUpx) {
    Write-Unpack ($base + @{
        success = $false
        method  = 'none'
        packer  = 'not UPX (unknown or runtime packer)'
        reason  = 'No static unpacker applies. Runtime/memory-dump unpacking executes the sample and must run inside the VM.'
        next    = 'stage 5: dynamic unpack in the VM (Frida / x64dbg), then re-triage.'
    })
    Write-Host "Not statically unpackable (not UPX). Route: stage 5 dynamic unpack in the VM." -ForegroundColor Yellow
    Write-Host "Wrote $unpackJson"
    return
}

$unpackedDir = Join-Path $artifacts 'unpacked'
New-Item -ItemType Directory -Force -Path $unpackedDir | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("gralloch_upx_" + [guid]::NewGuid().ToString('N') + '.bin')
Copy-Item $sample $tmp -Force
Set-ItemProperty $tmp -Name IsReadOnly -Value $false
try {
    $outTmp = $tmp.Replace('.bin', '.out.bin')
    $ures = Invoke-Upx @('-d', '-o', $outTmp, $tmp)
    $rc = $ures.Code
    if ($rc -ne 0 -or -not (Test-Path $outTmp)) {
        Write-Unpack ($base + @{
            success = $false
            method  = 'upx-static'
            packer  = 'UPX'
            reason  = "upx -d failed (rc=$rc): $($ures.Out). The stub may be modified; try stage 5."
            next    = 'stage 5: dynamic unpack in the VM, then re-triage.'
        })
        Write-Host "UPX detected but static unpack failed. Route: stage 5." -ForegroundColor Yellow
        return
    }

    $outHash = (Get-FileHash -Algorithm SHA256 $outTmp).Hash.ToLower()
    $dest = Join-Path $unpackedDir ($outHash + '.bin')
    Copy-Item $outTmp $dest -Force
    Set-ItemProperty $dest -Name IsReadOnly -Value $true
    $relOut = 'artifacts/unpacked/' + $outHash + '.bin'
    Write-Unpack ($base + @{
        success = $true
        method  = 'upx-static'
        packer  = 'UPX'
        output  = @{ path = $relOut; sha256 = $outHash; size = (Get-Item $dest).Length }
        note    = 'Unpacked image stored read-only, non-executable. Still untrusted.'
        next    = 'stage 1: run case_new on the output, then triage.'
    })
    Write-Host "OK: UPX unpacked -> $relOut" -ForegroundColor Green
    Write-Host "Next: case_new on that file, then triage. Wrote $unpackJson"
}
finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Remove-Item $tmp.Replace('.bin', '.out.bin') -Force -ErrorAction SilentlyContinue
}

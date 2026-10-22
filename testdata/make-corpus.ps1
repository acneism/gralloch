$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$corpus = Join-Path $here 'corpus'
New-Item -ItemType Directory -Force -Path $corpus | Out-Null

function Pick([string[]]$candidates) {
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

$sys = Join-Path $env:WINDIR 'System32'
$exe = Pick @("$sys\hostname.exe", "$sys\where.exe", "$sys\cmd.exe")
$dll = Pick @("$sys\version.dll", "$sys\kernel32.dll")

if ($exe) { Copy-Item $exe (Join-Path $corpus 'signed_system.exe') -Force; Write-Host "exe  <- $exe" }
else { Write-Warning "no system exe found" }
if ($dll) { Copy-Item $dll (Join-Path $corpus 'signed_system.dll') -Force; Write-Host "dll  <- $dll" }
else { Write-Warning "no system dll found" }

$mz = New-Object byte[] 128
$mz[0] = 0x4D; $mz[1] = 0x5A
[IO.File]::WriteAllBytes((Join-Path $corpus 'mz_only.bin'), $mz)
Write-Host "mz_only.bin written"

if ($exe) {
    $all = [IO.File]::ReadAllBytes($exe)
    $n = [Math]::Min(256, $all.Length)
    [IO.File]::WriteAllBytes((Join-Path $corpus 'truncated.bin'), $all[0..($n-1)])
    Write-Host "truncated.bin written ($n bytes)"
}

$g = New-Object byte[] 1024
(New-Object System.Random).NextBytes($g)
[IO.File]::WriteAllBytes((Join-Path $corpus 'garbage.bin'), $g)
Write-Host "garbage.bin written"

Write-Host "`nCorpus ready: $corpus" -ForegroundColor Green
Get-ChildItem $corpus | Select-Object Name, Length

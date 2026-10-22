<#
  Orchestrates Ghidra headless static analysis for a relab case (stage 3).

  Runs analyzeHeadless to import and auto-analyze the stored sample, then runs
  the ghidra_export.py post-script to dump functions/strings/xrefs JSON into the
  case's artifacts/ghidra/ directory.

  This is STATIC analysis: analyzeHeadless disassembles the sample, it does NOT
  execute it. Safe to run on the host.

  Usage:
    .\run-ghidra-headless.ps1 -CaseDir <case dir> [-GhidraDir <ghidra install>]

  GhidraDir defaults to $env:GHIDRA_INSTALL_DIR.
#>
param(
    [Parameter(Mandatory = $true)][string]$CaseDir,
    [string]$GhidraDir = $env:GHIDRA_INSTALL_DIR,
    [int]$TimeoutSec = 900
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $GhidraDir) {
    throw "Ghidra install not set. Pass -GhidraDir or set GHIDRA_INSTALL_DIR."
}
$analyze = Join-Path $GhidraDir 'support\analyzeHeadless.bat'
if (-not (Test-Path $analyze)) {
    throw "analyzeHeadless.bat not found at $analyze"
}

$casePath = (Resolve-Path $CaseDir).Path
$caseJson = Join-Path $casePath 'case.json'
if (-not (Test-Path $caseJson)) {
    throw "case.json not found in $casePath (run case_new first)"
}
$case = Get-Content -Raw $caseJson | ConvertFrom-Json
$sample = Join-Path $casePath $case.stored_sample
if (-not (Test-Path $sample)) {
    throw "stored sample not found: $sample"
}

$ghidraOut = Join-Path $casePath 'artifacts\ghidra'
New-Item -ItemType Directory -Force -Path $ghidraOut | Out-Null
$projDir = Join-Path $ghidraOut 'project'
New-Item -ItemType Directory -Force -Path $projDir | Out-Null
$exportJson = Join-Path $ghidraOut 'ghidra_export.json'

Write-Host "Ghidra headless: importing $sample (static analysis only)..." -ForegroundColor Cyan
& $analyze `
    $projDir 'relab' `
    -import $sample `
    -scriptPath $scriptDir `
    -postScript 'ghidra_export.py' $exportJson `
    -analysisTimeoutPerFile $TimeoutSec `
    -deleteProject

if ($LASTEXITCODE -ne 0) {
    throw "analyzeHeadless failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path $exportJson)) {
    throw "export did not produce $exportJson"
}
Write-Host "OK: $exportJson" -ForegroundColor Green

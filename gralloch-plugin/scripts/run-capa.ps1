<#
  Runs capa (https://github.com/mandiant/capa) against a gralloch case's stored
  sample and writes the raw capa JSON report to artifacts/capa.json (stage 1
  enrichment).

  This is STATIC analysis: capa disassembles the sample (default vivisect
  backend), it does NOT execute it. Safe to run on the host. The stored sample
  stays read-only with its non-executable .bin name.

  The raw report can be large; do NOT read it wholesale into the model. Run the
  `capa_import` MCP tool afterwards to fold a bounded summary into triage.json
  and write artifacts/capa-summary.json.

  Usage:
    .\run-capa.ps1 -CaseDir <case dir> [-CapaExe <capa.exe>] [-RulesDir <dir>]

  capa resolution order: -CapaExe, then `capa` on PATH, then `python -m capa`.
  -RulesDir (or $env:CAPA_RULES) is only needed if your capa has no bundled rules.
#>
param(
    [Parameter(Mandatory = $true)][string]$CaseDir,
    [string]$CapaExe,
    [string]$RulesDir = $env:CAPA_RULES,
    [int]$TimeoutSec = 600
)

$ErrorActionPreference = 'Stop'

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

$artifacts = Join-Path $casePath 'artifacts'
New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
$outJson = Join-Path $artifacts 'capa.json'
$errLog  = Join-Path $artifacts 'capa.stderr.log'

# Resolve the capa invocation. The standalone capa.exe from the capa GitHub
# releases is preferred: it bundles the rules and signatures. The pip library
# (`flare-capa`) ships WITHOUT embedded rules, so `python -m capa.main` only
# works if a rule set is supplied (-RulesDir / $env:CAPA_RULES).
if (-not $CapaExe -and $env:CAPA_EXE) { $CapaExe = $env:CAPA_EXE }
if ($CapaExe) {
    if (-not (Test-Path $CapaExe)) { throw "capa not found at -CapaExe: $CapaExe" }
    $file = $CapaExe
    $argList = @()
} elseif (Get-Command capa -ErrorAction SilentlyContinue) {
    $file = (Get-Command capa).Source
    $argList = @()
} else {
    $py = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $py) {
        throw "capa not found. Use the standalone capa.exe (bundles rules) via -CapaExe or `$env:CAPA_EXE, or pip install flare-capa."
    }
    $file = $py.Source
    $argList = @('-m', 'capa.main')
}

# -j: JSON to stdout. Format is auto-detected from content, not the .bin name.
$argList += @('-j')
if ($RulesDir) { $argList += @('-r', $RulesDir) }
$argList += @($sample)

Write-Host "capa: analyzing $sample (static disassembly, not executed)..." -ForegroundColor Cyan
$p = Start-Process -FilePath $file -ArgumentList $argList -NoNewWindow -PassThru `
    -RedirectStandardOutput $outJson -RedirectStandardError $errLog
if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    try { $p.Kill() } catch {}
    throw "capa timed out after ${TimeoutSec}s"
}
# Flush async redirection and let ExitCode settle. With -RedirectStandardOutput
# the PassThru object can report a null ExitCode until a blocking wait; the real
# success gate below is "output parses as capa JSON", so a null code is tolerated.
$p.WaitForExit() | Out-Null
$code = try { $p.ExitCode } catch { $null }
$errTail = if (Test-Path $errLog) { (Get-Content $errLog -Tail 15) -join "`n" } else { '' }
if ($null -ne $code -and $code -ne 0) {
    throw "capa failed with exit code $code.`n$errTail"
}
if (-not (Test-Path $outJson) -or (Get-Item $outJson).Length -eq 0) {
    throw "capa produced no output at $outJson.`n$errTail"
}
# Real success gate: output must be a capa JSON report (meta + rules).
try {
    $probe = Get-Content -Raw $outJson | ConvertFrom-Json
    if (-not $probe.meta -or -not $probe.rules) { throw "missing meta/rules" }
} catch {
    throw "capa output is not a valid capa JSON report ($outJson): $_`n$errTail"
}

$size = [math]::Round((Get-Item $outJson).Length / 1KB, 1)
Write-Host "OK: $outJson ($size KB). Next: run the capa_import MCP tool." -ForegroundColor Green

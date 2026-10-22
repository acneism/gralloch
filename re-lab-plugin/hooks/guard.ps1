<#
  relab guard - PreToolUse tripwire for the RE pipeline.

  Runs on every Bash / PowerShell tool call. It DENIES three high-signal,
  clearly dangerous classes and lets everything else pass through to the
  normal permission flow (which, in the malware profile, still asks the user
  to confirm each command - see skills/isolation/SKILL.md):

    C. Weakening host antivirus / Microsoft Defender.
    B. Removing a stored sample's read-only protection, or giving it an
       executable name (rename/copy to .exe/.dll/...).
    A. Executing a stored sample on the host (Start-Process, rundll32, or an
       executable file under a case 'sample\' directory).

  This is defense-in-depth, NOT a sandbox. The real isolation guarantees are:
  the stored sample has no executable extension (<sha256>.bin), it is marked
  read-only, and dynamic analysis happens only inside the VM. This hook is a
  tripwire on top of those.

  Contract (Claude Code hooks): hook input arrives as JSON on stdin. To block,
  print a hookSpecificOutput deny decision and exit 0. To pass through, exit 0
  with no stdout. hooks.json sets onFailure=block so a crash/timeout fails
  CLOSED. High-precision matching keeps false positives (which would block
  legitimate commands) low.
#>

$ErrorActionPreference = 'Stop'

function Deny([string]$reason) {
    $out = [ordered]@{
        hookSpecificOutput = [ordered]@{
            hookEventName            = 'PreToolUse'
            permissionDecision       = 'deny'
            permissionDecisionReason = "relab guard: $reason"
        }
    }
    [Console]::Out.Write(($out | ConvertTo-Json -Compress -Depth 5))
    exit 0
}

try { [Console]::InputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) { exit 0 }

try {
    $payload = $raw | ConvertFrom-Json
} catch {
    # Could not parse hook input: fail closed so nothing runs unexamined.
    Deny 'could not parse hook input; blocking for safety'
}

$cmd = ''
if ($payload.tool_input -and $payload.tool_input.command) {
    $cmd = [string]$payload.tool_input.command
}
if ([string]::IsNullOrWhiteSpace($cmd)) { exit 0 }

$c = $cmd.ToLowerInvariant()

# --- Rule C: antivirus / Defender tampering (independent of any sample) -----
$avPatterns = @(
    'set-mppreference', 'add-mppreference', 'remove-mppreference',
    'disablerealtimemonitoring', 'disablebehaviormonitoring', 'disableioavprotection',
    'disablescriptscanning', 'exclusionpath', 'exclusionextension', 'exclusionprocess',
    'windefend', 'mpcmdrun'
)
foreach ($p in $avPatterns) {
    if ($c.Contains($p)) { Deny "host antivirus/Defender tampering is not allowed ('$p')" }
}

# Does the command reference a case 'sample' directory (either slash style)?
$touchesSample = ($c -match 'sample[\\/]')

if ($touchesSample) {
    # --- Rule B: unprotect / rename the sample into something runnable ------
    if ($c -match 'attrib\s+\S*-r')                { Deny 'removing read-only from a sample is not allowed' }
    if ($c -match 'isreadonly\s*=\s*\$?false')     { Deny 'removing read-only from a sample is not allowed' }
    if ($c -match 'set-itemproperty[^\r\n]*isreadonly') { Deny 'removing read-only from a sample is not allowed' }
    if ($c -match '(rename-item|copy-item|move-item|\bcp\b|\bmv\b)[^\r\n]*\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|cpl|msi|pif)') {
        Deny 'giving a sample an executable name is not allowed'
    }

    # --- Rule A: execute the sample on the host ----------------------------
    $execVerbs = @('start-process','invoke-item','start-job','rundll32','regsvr32','mshta','wscript','cscript','installutil')
    foreach ($v in $execVerbs) {
        if ($c.Contains($v)) { Deny "executing a sample is only allowed inside the VM, not on the host ('$v')" }
    }
    # A stored sample is <sha256>.bin; an executable extension under sample\
    # means someone produced a runnable copy.
    if ($c -match 'sample[\\/][^\r\n"'']*\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|cpl|msi|pif)') {
        Deny 'executing a sample is only allowed inside the VM, not on the host'
    }
}

# No rule matched: let it go to the normal permission flow.
exit 0

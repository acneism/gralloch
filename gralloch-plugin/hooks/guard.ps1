$ErrorActionPreference = 'Stop'

function Deny([string]$reason) {
    $out = [ordered]@{
        hookSpecificOutput = [ordered]@{
            hookEventName            = 'PreToolUse'
            permissionDecision       = 'deny'
            permissionDecisionReason = "gralloch guard: $reason"
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

    Deny 'could not parse hook input; blocking for safety'
}

$cmd = ''
if ($payload.tool_input -and $payload.tool_input.command) {
    $cmd = [string]$payload.tool_input.command
}
if ([string]::IsNullOrWhiteSpace($cmd)) { exit 0 }

$c = $cmd.ToLowerInvariant()

$avPatterns = @(
    'set-mppreference', 'add-mppreference', 'remove-mppreference',
    'disablerealtimemonitoring', 'disablebehaviormonitoring', 'disableioavprotection',
    'disablescriptscanning', 'exclusionpath', 'exclusionextension', 'exclusionprocess',
    'windefend', 'mpcmdrun'
)
foreach ($p in $avPatterns) {
    if ($c.Contains($p)) { Deny "host antivirus/Defender tampering is not allowed ('$p')" }
}

$touchesSample = ($c -match 'sample[\\/]')

if ($touchesSample) {

    if ($c -match 'attrib\s+\S*-r')                { Deny 'removing read-only from a sample is not allowed' }
    if ($c -match 'isreadonly\s*=\s*\$?false')     { Deny 'removing read-only from a sample is not allowed' }
    if ($c -match 'set-itemproperty[^\r\n]*isreadonly') { Deny 'removing read-only from a sample is not allowed' }
    if ($c -match '(rename-item|copy-item|move-item|\bcp\b|\bmv\b)[^\r\n]*\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|cpl|msi|pif)') {
        Deny 'giving a sample an executable name is not allowed'
    }

    $execVerbs = @('start-process','invoke-item','start-job','rundll32','regsvr32','mshta','wscript','cscript','installutil')
    foreach ($v in $execVerbs) {
        if ($c.Contains($v)) { Deny "executing a sample is only allowed inside the VM, not on the host ('$v')" }
    }

    if ($c -match 'sample[\\/][^\r\n"'']*\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|cpl|msi|pif)') {
        Deny 'executing a sample is only allowed inside the VM, not on the host'
    }
}

exit 0

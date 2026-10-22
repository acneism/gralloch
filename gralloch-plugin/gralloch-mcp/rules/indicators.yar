// Baseline capability/indicator rules for gralloch. Generic heuristics that
// produce leads (hypotheses), not verdicts. They may match benign software too.

rule embedded_pe
{
    meta:
        description = "Possible embedded or appended PE image (extra DOS stub)"
        category = "indicator"
    strings:
        $dos = "This program cannot be run in DOS mode"
    condition:
        #dos > 1
}

rule contains_http_url
{
    meta:
        description = "Contains HTTP/HTTPS URL strings"
        category = "indicator"
    strings:
        $u = /https?:\/\/[A-Za-z0-9][A-Za-z0-9.\-]{2,}/ ascii wide
    condition:
        $u
}

rule process_injection_apis
{
    meta:
        description = "References the classic remote process-injection API trio"
        category = "capability"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        all of them
}

rule dynamic_api_resolution
{
    meta:
        description = "Resolves APIs at runtime (LoadLibrary + GetProcAddress)"
        category = "capability"
    strings:
        $a = "LoadLibrary" ascii
        $b = "GetProcAddress" ascii
    condition:
        all of them
}

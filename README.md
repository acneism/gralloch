# re-lab

Isolation-first, semi-automatic **reverse-engineering pipeline for Windows PE**,
delivered as a Claude Code plugin. Claude orchestrates established tools
(Ghidra, capa, Frida, …); a native Rust MCP server does the fast deterministic
work (triage, safe case creation). The pipeline is a thin wrapper over existing
tools, not a new analysis engine.

- **Spec:** [`tz-re-pipeline.md`](tz-re-pipeline.md) (v2.1)
- **Plugin:** [`re-lab-plugin/`](re-lab-plugin/) — manifest, MCP server, skills, commands, hooks
- **Marketplace:** `.claude-plugin/marketplace.json` (repo root is an installable marketplace)
- **Test data:** [`testdata/`](testdata/) — safe corpus tooling + a `pefile` cross-check

## Quick start

```
# in Claude Code
/plugin marketplace add <path-to-this-repo>
/plugin install re-lab@re-lab-marketplace
```

```powershell
# build the native server (needs rustup + MSVC C++ Build Tools)
cd re-lab-plugin\relab-mcp
.\build-windows.ps1
```

Then: `/case-new`, `/triage`, `/static`. See `re-lab-plugin/README.md`.

## Status

| Stage | Component | State |
|---|---|---|
| 0 | case creation (`case_new`) | source done; needs `cargo build` |
| 1 | triage (`triage`) | source done; cross-checked vs `pefile`; needs `cargo build` |
| 3 | Ghidra headless export (`/static`) | scaffolded; needs a Ghidra install |
| — | isolation hook, skills, commands, schemas, marketplace | done and validated |
| 2,4,5,6,7 | unpack / deobf / dynamics / verify / output | per spec, later |

All markdown/JSON/scripts are validated here (`claude plugin validate --strict`,
JSON Schema, hook unit tests, script syntax). The Rust server is written but not
yet compiled on this machine (no toolchain present).

## Safety

Samples are stored read-only without an executable extension; a fail-closed
`PreToolUse` hook blocks host-side execution, read-only removal, and antivirus
tampering; dynamic analysis runs only inside a VM; sample-derived text is treated
as untrusted data. See `tz-re-pipeline.md` section 4 and the `relab-isolation` skill.

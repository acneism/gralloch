# gralloch

Isolation-first, semi-automatic **reverse-engineering pipeline for Windows PE**,
delivered as a Claude Code plugin. Claude orchestrates established tools
(Ghidra, capa, Frida, …); a native Rust MCP server does the fast deterministic
work (triage, safe case creation). The pipeline is a thin wrapper over existing
tools, not a new analysis engine.

- **Spec:** [`tz-re-pipeline.md`](tz-re-pipeline.md) (v2.1)
- **Plugin:** [`gralloch-plugin/`](gralloch-plugin/) — manifest, MCP server, skills, commands, hooks
- **Marketplace:** `.claude-plugin/marketplace.json` (repo root is an installable marketplace)
- **Test data:** [`testdata/`](testdata/) — safe corpus tooling + a `pefile` cross-check

## Quick start

```
# in Claude Code
/plugin marketplace add <path-to-this-repo>
/plugin install gralloch@gralloch-marketplace
```

```powershell
# build the native server (needs rustup + MSVC C++ Build Tools)
cd gralloch-plugin\gralloch-mcp
.\build-windows.ps1
```

Then: `/case-new`, `/triage`, `/static`. See `gralloch-plugin/README.md`.

## Status

| Stage | Component | State |
|---|---|---|
| 0 | case creation (`case_new`) | built & verified end-to-end |
| 1 | triage (`triage`) | built & verified; cross-checked vs `pefile` |
| 1 | capa enrichment (`capa_import` + `/capa`) | built & verified vs capa 10.0.0 |
| 1 | YARA scan (`yara_scan` + `/yara`) | built & verified vs yara-x 1.22 (cargo feature `yara`) |
| 2 | static unpack (`/unpack`, UPX) | built & verified vs upx 5.2.1 (round-trip + re-triage) |
| 3 | Ghidra headless export (`/static`) | scaffolded; needs a Ghidra install |
| 4 | static deobfuscation (`deobfuscate` + `/deobfuscate`) | built & verified (strings, XOR brute, base64) |
| — | isolation hook, skills, commands, schemas, marketplace | done and validated |
| 5,6,7 | dynamics / verify / output | per spec, later |

The Rust server compiles (`rustc 1.99.1`, `x86_64-pc-windows-gnu`) and is
verified end-to-end: `cargo test`, an MCP stdio handshake, and `case_new` →
`triage` → capa (`run-capa.ps1` + `capa_import`) over a real System32 PE. All
markdown/JSON/scripts are validated too (`claude plugin validate --strict`,
JSON Schema, hook unit tests, script syntax).

## Safety

Samples are stored read-only without an executable extension; a fail-closed
`PreToolUse` hook blocks host-side execution, read-only removal, and antivirus
tampering; dynamic analysis runs only inside a VM; sample-derived text is treated
as untrusted data. See `tz-re-pipeline.md` section 4 and the `gralloch-isolation` skill.

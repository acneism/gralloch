# gralloch

Isolation-first, semi-automatic **reverse-engineering pipeline for Windows PE**,
delivered as a Claude Code plugin. Claude orchestrates established tools
(Ghidra, capa, Frida, …); a native Rust MCP server does the fast deterministic
work (triage, safe case creation). The pipeline is a thin wrapper over existing
tools, not a new analysis engine.

- **Plugin:** [`gralloch-plugin/`](gralloch-plugin/) — manifest, MCP server, skills, commands, hooks
- **Marketplace:** `.claude-plugin/marketplace.json` (repo root is an installable marketplace)
- **Test data:** [`testdata/`](testdata/) — safe corpus tooling + a `pefile` cross-check
- **Commands:** [`docs/README.md`](docs/README.md) — every slash command, incl. one-shot `/gralloch <sample>`

## Prerequisites

**Host:** Windows + [Claude Code](https://code.claude.com). Analysis stays on the
host; executing a sample is a VM task (see Safety).

**To build the MCP server (required):**

- A Rust toolchain via [rustup](https://rustup.rs) (built & verified with `rustc 1.99.1`).
- A C linker — either of:
  - **MSVC** — Visual Studio Build Tools, "Desktop development with C++"
    (target `x86_64-pc-windows-msvc`); or
  - **GNU (no admin)** — MinGW-w64 `gcc` on `PATH` (e.g. WinLibs), then
    `rustup default stable-x86_64-pc-windows-gnu`.

  The default build is pure Rust. The optional `yara` feature compiles yara-x,
  which pulls wasmtime + a small C dependency built by the linker above.

**Optional external tools** — each enables one stage; a stage whose tool is
absent is skipped, never fatal:

| Tool | Enables | Notes |
|---|---|---|
| capa standalone `capa.exe` | `/capa` | [capa releases](https://github.com/mandiant/capa/releases); bundles rules+signatures. Verified vs 10.0.0. |
| `upx` | `/unpack` | [upx releases](https://github.com/upx/upx/releases). Verified vs 5.2.1. |
| Ghidra | `/static` | set `GHIDRA_INSTALL_DIR` (or the plugin's config). Ghidra 12.x needs a matching JDK (JDK 25 for 12.2) on `JAVA_HOME`. The export runs as a Java GhidraScript — no Python/Jython needed. |
| Windows analysis VM + Frida | `/dynamics` | VM-only, user-initiated; snapshot active, network off/faked. |

YARA needs no external tool — baseline rules ship in the plugin and run in the
`yara`-feature build.

## 1. Build the server

```powershell
cd gralloch-plugin\gralloch-mcp
.\build-windows.ps1          # default build  -> ..\bin\gralloch-mcp.exe
.\build-windows.ps1 -Yara    # also compile the YARA engine (enables /yara)
```

The one-shot `/gralloch` pipeline and `/yara` expect the `-Yara` build. The exe
lands in `gralloch-plugin/bin/`, where `.mcp.json` points.

## 2. Install the plugin

```
# in Claude Code
/plugin marketplace add <path-to-this-repo>
/plugin install gralloch@gralloch-marketplace
```

The `gralloch` MCP server starts automatically once `bin/gralloch-mcp.exe` exists.

## 3. Configure (once)

Set via `/config`: **Cases root** (a working directory outside the plugin) and,
optionally, **capa executable**, **upx executable**, **Ghidra install dir**.
Details in [`docs/README.md`](docs/README.md#configuration).

## 4. Run

One shot — runs the automatic host stages (case → triage → unpack? → capa →
yara → deobfuscate → report):

```
/gralloch C:\path\to\sample.exe --profile malware
```

Then the stages that need external tooling or the VM, when you have them:

```
/static   <case-dir>            # Ghidra headless export (needs Ghidra)
/dynamics <case-dir>            # Frida trace, inside the VM, on your command
/verify   <case-dir>            # promote hypotheses that have evidence
/gralloch --report <case-dir>   # rebuild report.md with everything folded in
```

Run a single stage directly — `/gralloch --verify <case-dir>`, or any of
`/case-new`, `/triage`, `/capa`, `/yara`, `/unpack`, `/deobfuscate`, `/report`.
All commands are documented in [`docs/README.md`](docs/README.md).

## Status

| Stage | Component | State |
|---|---|---|
| 0 | case creation (`case_new`) | built & verified end-to-end |
| 1 | triage (`triage`) | built & verified; cross-checked vs `pefile` |
| 1 | capa enrichment (`capa_import` + `/capa`) | built & verified vs capa 10.0.0 |
| 1 | YARA scan (`yara_scan` + `/yara`) | built & verified vs yara-x 1.22 (cargo feature `yara`) |
| 2 | static unpack (`/unpack`, UPX) | built & verified vs upx 5.2.1 (round-trip + re-triage) |
| 3 | Ghidra headless export (`/static`) | built & verified vs Ghidra 12.2 (Java export script) |
| 4 | static deobfuscation (`deobfuscate` + `/deobfuscate`) | built & verified (strings, XOR brute, base64) |
| 5 | dynamics: VM trace + `dynamic_import` (`/dynamics`) | built & verified (host imports VM trace; never executes) |
| 6 | verification (`verify` + `/verify`) | built & verified (confirmed⇒evidence; writeback via Ghidra MCP) |
| 7 | output: final report (`report` + `/report`) | built & verified (report.md/json, IOCs, injection-sanitized) |
| — | isolation hook, skills, commands, schemas, marketplace | done and validated |

The Rust server compiles (`rustc 1.99.1`, `x86_64-pc-windows-gnu`) and is
verified end-to-end: `cargo test`, an MCP stdio handshake, and `case_new` →
`triage` → capa (`run-capa.ps1` + `capa_import`) over a real System32 PE. All
markdown/JSON/scripts are validated too (`claude plugin validate --strict`,
JSON Schema, hook unit tests, script syntax).

## Safety

Samples are stored read-only without an executable extension; a fail-closed
`PreToolUse` hook blocks host-side execution, read-only removal, and antivirus
tampering; dynamic analysis runs only inside a VM; sample-derived text is treated
as untrusted data. See the `gralloch-isolation` skill.

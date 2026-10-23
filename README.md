# gralloch

Isolation-first, semi-automatic **reverse-engineering pipeline for Windows PE**,
available as a plugin for [Claude Code](#claude-code) and [Codex](#codex).
The coding agent orchestrates established tools
(Ghidra, capa, Frida, …); a native Rust MCP server does the fast deterministic
work (triage, safe case creation). The pipeline is a thin wrapper over existing
tools, not a new analysis engine.

- **Plugin:** [`gralloch-plugin/`](gralloch-plugin/) — manifest, MCP server, skills, commands, hooks
- **Marketplace:** `.claude-plugin/marketplace.json` (repo root is an installable marketplace)
- **Test data:** [`testdata/`](testdata/) — safe corpus tooling + a `pefile` cross-check
- **Commands:** [`docs/README.md`](docs/README.md) — every slash command, incl. one-shot `/gralloch <sample>`
- **Install and run:** [Claude Code](#claude-code) / [Codex](#codex)

## Installation and launch

Requires Windows, Rust, a C linker, and your chosen coding agent; see
[prerequisites](#prerequisites). Clone the repository once in PowerShell:

```powershell
git clone https://github.com/acneism/gralloch.git
cd gralloch
```

Choose your client below. Both sets of PowerShell commands run from this
repository root.

### Claude Code

**1. Build the server in PowerShell:**

```powershell
.\gralloch-plugin\gralloch-mcp\build-windows.ps1 -Yara
```

**2. Install in Claude Code:**

```text
/plugin marketplace add <absolute-path-to-this-repo>
/plugin install gralloch@gralloch-marketplace
```

**3. Configure:** set **Cases root** outside the repository using `/config`.
Optional tool paths can be configured there too; see
[configuration](docs/README.md#configuration).

**4. Run in a Claude Code chat:**

```text
/gralloch C:\samples\app.exe --profile understand --cases-root C:\analysis\cases
```

Single stages use `/case-new`, `/triage`, `/capa`, `/yara`, `/unpack`, `/static`,
`/deobfuscate`, `/dynamics`, `/verify`, and `/report`. See the
[Claude Code command reference](docs/README.md).

### Codex

**1. Install in PowerShell:**

```powershell
.\scripts\install-codex.ps1 -Yara
```

This builds the server and installs `gralloch@gralloch-codex` through Codex's
plugin manager. Codex CLI with `codex plugin add` must be installed.

**2. Start a new local Codex chat and run:**

```text
$gralloch:gralloch "C:\samples\app.exe" --profile understand --cases-root "C:\analysis\cases"
```

See the [Codex reference](docs/CODEX.md) for configuration, individual stages,
updates, troubleshooting, and validation.

For either client, replace the sample path and cases directory with your own.
The cases directory must be outside the repository. The commands above run the
static pipeline and generate a report; sample execution is a separate VM task.
`-Yara` enables YARA scanning; omit it from either build/install command for a
smaller build without that optional stage.

## Prerequisites

**Host:** Windows + [Claude Code](https://code.claude.com) or Codex CLI with
`codex plugin add`. Analysis stays on the host; executing a sample is a VM task
(see [Safety](#safety)).

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

Samples are stored read-only without an executable extension. In Claude Code,
a fail-closed `PreToolUse` hook blocks host-side execution, read-only removal,
and antivirus tampering; dynamic analysis runs only inside a VM; sample-derived text is treated
as untrusted data. See the `gralloch-isolation` skill.

See [Codex isolation details](docs/CODEX.md#codex-isolation-boundary).

## License

Licensed under the [Mozilla Public License 2.0](LICENSE).

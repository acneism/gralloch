# gralloch

Isolation-first, semi-automatic **reverse-engineering pipeline for Windows PE**,
delivered as a Claude Code plugin, with [Codex support](#codex).
The coding agent orchestrates established tools
(Ghidra, capa, Frida, …); a native Rust MCP server does the fast deterministic
work (triage, safe case creation). The pipeline is a thin wrapper over existing
tools, not a new analysis engine.

- **Plugin:** [`gralloch-plugin/`](gralloch-plugin/) — manifest, MCP server, skills, commands, hooks
- **Marketplace:** `.claude-plugin/marketplace.json` (repo root is an installable marketplace)
- **Test data:** [`testdata/`](testdata/) — safe corpus tooling + a `pefile` cross-check
- **Commands:** [`docs/README.md`](docs/README.md) — every slash command, incl. one-shot `/gralloch <sample>`
- **Codex:** [setup and usage](#codex) — Windows setup, MCP connection, and `$gralloch` skill

## Prerequisites

**Host:** Windows + [Claude Code](https://code.claude.com) or Codex (see
[Codex setup](#codex)). Steps 1–4 below describe Claude Code. Analysis stays on the
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

## Codex

Install the Gralloch plugin once, then invoke its `$gralloch:gralloch` skill from a local
Codex chat in any working directory. The installed package includes the MCP
server, scripts, schemas, and stage guides; it does not depend on the checkout
at runtime. Windows, Codex CLI with `codex plugin add`, and the Rust/linker
prerequisites above are required for installation.

### Install once (Windows)

```powershell
git clone --branch codex-support https://github.com/acneism/gralloch.git
cd gralloch
.\scripts\install-codex.ps1
```

The installer builds the native server, prepares a runtime package, registers
`gralloch-codex` as a local marketplace, and installs `gralloch@gralloch-codex`
using Codex's plugin manager. It leaves unrelated Codex settings intact.
Use `-Yara` to build and install the optional YARA engine, or `-SkipBuild` to
package an executable you have already built. Restart Codex or start a new local
chat after installation. Check installation with:

```powershell
codex plugin list --marketplace gralloch-codex
```

After updating the checkout, rerun the installer (with `-Yara` if wanted) to
rebuild and refresh the installed copy. `-PackageOnly` stages the package without
registering or installing it. The generated `.codex-package/` directory is
ignored by Git and is the local marketplace's package source. Do not register
the Git repository URL as a ready-to-run marketplace: server binaries are built
locally and are not committed.

### Run the command in Codex

In a **Codex chat**, send:

```text
$gralloch:gralloch "C:\samples\app.exe" --profile understand --cases-root "C:\analysis\cases"
```

This starts case creation, triage, applicable static unpacking, optional capa
and YARA, string deobfuscation, and the final report. Missing optional tools are
reported and skipped. Without `--cases-root`, the skill asks for the location
unless `GRALLOCH_CASES_ROOT` supplies one. The profile defaults to `understand`.
Sample execution is a separate VM-only task.

Single-stage examples:

```text
$gralloch:gralloch "C:\samples\app.exe" --triage --cases-root "C:\analysis\cases"
$gralloch:gralloch --static "C:\analysis\cases\<case>"
$gralloch:gralloch --verify "C:\analysis\cases\<case>"
$gralloch:gralloch --report "C:\analysis\cases\<case>"
```

`$gralloch:gralloch` is the installed plugin skill invocation in Codex
(`plugin:skill` namespace), not a PowerShell command. Claude's
`/gralloch` slash command belongs to Claude Code. You can also describe the
requested Gralloch stage in natural language. Cases must be outside the installed
package or source repository. Configure optional tools with `CAPA_EXE`, `UPX_EXE`,
`GHIDRA_INSTALL_DIR`, and `JAVA_HOME` in the environment inherited by Codex, or
supply explicit script parameters.

### Manual project setup (alternative)

For development in the checkout, you can use the repository skill and a
project-local MCP server instead of installing the plugin. Use one connection
method to avoid loading duplicate Gralloch servers. This method requires the
checkout at runtime and only discovers the skill inside that repository.

Install Codex and the Rust/linker prerequisites listed above. From
the repository root:

```powershell
# Optional -Yara enables the built-in YARA scan; omit it for a smaller build.
.\gralloch-plugin\gralloch-mcp\build-windows.ps1 -Yara
.\scripts\setup-codex.ps1 -CasesRoot 'C:\analysis\gralloch-cases'
```

The setup script writes `.codex/config.toml` with absolute paths to the server
and cases root. The cases root must be outside the repository. The file is ignored
by Git; regenerate it after moving the checkout. If configuration already exists,
the script stops without replacing it. To merge manually, use this shape with
your absolute paths (TOML literal strings preserve backslashes):

```toml
[mcp_servers.gralloch]
command = 'C:\src\gralloch\gralloch-plugin\bin\gralloch-mcp.exe'
cwd = 'C:\src\gralloch'
startup_timeout_sec = 20
tool_timeout_sec = 600

[mcp_servers.gralloch.env]
RUST_LOG = "info"
GRALLOCH_CASES_ROOT = 'C:\analysis\gralloch-cases'
```

Open the checkout in Codex as a trusted project and start a new chat. Project MCP
configuration is loaded only for trusted projects. In Codex CLI, run `codex` from
the repository root:

```powershell
codex
```

Use `/mcp` in the CLI to inspect the connection. The `gralloch` server
should expose `case_new`, `triage`, `capa_import`, `yara_scan`, `deobfuscate`,
`dynamic_import`, `verify`, and `report`.

The skill is loaded from `.agents/skills/gralloch/SKILL.md` for chats working in
this checkout. It relies on the shared files in this repository; copying only
the skill folder elsewhere is not a standalone installation.

### Per-project usage

Ask Codex, for example:

```text
$gralloch Analyze C:\samples\example.exe with profile understand.
$gralloch Triage only C:\samples\example.dll.
$gralloch Rebuild the report for C:\analysis\gralloch-cases\<case>.
```

Claude's `/gralloch`, `/triage`, and `/config` are not registered as Codex slash
commands. Request the stage in natural language or invoke `$gralloch`.
Optional tools retain their existing configuration: `CAPA_EXE`, `UPX_EXE`,
`GHIDRA_INSTALL_DIR`, and `JAVA_HOME`; these can also be set in the MCP `env`
table. For wrappers launched by Codex's shell, set the same variables in that
shell or pass the corresponding script parameters explicitly.

### Codex isolation boundary

The Claude `PreToolUse` hook in `gralloch-plugin/hooks` does **not** run in this
Codex integration. `AGENTS.md` and the skill guide behavior, but do not enforce
process isolation. The server still stores imported samples read-only as `.bin`
and does not execute them. Perform all execution, debugging, Frida tracing, and
runtime unpacking inside a dedicated analysis VM with a clean snapshot and
disabled/faked network. Follow the existing
[isolation rules](gralloch-plugin/skills/gralloch-isolation/SKILL.md), including
per-command confirmation for the malware profile. Do not use bypass/automatic
approval modes for malware analysis.

### Troubleshooting

- Installed command missing: check `codex plugin list --marketplace gralloch-codex`,
  ensure the plugin is enabled, and start a new local chat.
- Missing executable: build the server before running setup.
- Missing connection: check project trust, absolute paths, and `/mcp`; restart
  the chat after configuration changes. No `${CLAUDE_PLUGIN_ROOT}` or Claude
  `${user_config.*}` expansion is used by this integration.
- Missing YARA: rebuild with `-Yara`; the other stages work without it.
- Missing optional tools: install/configure them or let Codex skip those stages.
- A cases root outside the checkout may require granting that folder access in
  your Codex environment before writing case data.

Configuration follows the official OpenAI documentation for
[MCP](https://developers.openai.com/codex/mcp),
[skills](https://developers.openai.com/codex/skills), and
[AGENTS.md](https://developers.openai.com/codex/guides/agents-md).

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

The execution-blocking hook above is specific to Claude Code. Codex uses the
same read-only case storage and isolation instructions, but does not load that
hook; see [the Codex isolation boundary](#codex-isolation-boundary).

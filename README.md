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

The installed command works from any working directory. The runtime package
includes its server, scripts, schemas, and stage guides. See
[Codex details](#codex-details) for updates, single-stage commands, and troubleshooting.

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

## Codex details

### Installation and updates

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

### Single-stage commands

Single-stage examples:

```text
$gralloch:gralloch "C:\samples\app.exe" --triage --cases-root "C:\analysis\cases"
$gralloch:gralloch --static "C:\analysis\cases\<case>"
$gralloch:gralloch --verify "C:\analysis\cases\<case>"
$gralloch:gralloch --report "C:\analysis\cases\<case>"
```

The same command supports `--case-new <sample>`, `--capa <case-dir>`,
`--yara <case-dir>`, `--unpack <case-dir>`, and `--deobfuscate <case-dir>`.
To import a trace already produced in the VM, use
`--dynamics <case-dir> --trace <trace.json>`. Without `--trace`, the dynamics
stage provides VM instructions and checks preconditions; it does not execute
the sample on the host. Stage flags are mutually exclusive.

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
- Installed MCP startup fails on Windows: rerun `scripts/install-codex.ps1`.
  The installer resolves the executable path to Codex's installed cache rather
  than relying on runtime expansion of a plugin-root placeholder.
- Missing executable: build the server before running setup.
- Missing connection: check project trust, absolute paths, and `/mcp`; restart
  the chat after configuration changes. No `${CLAUDE_PLUGIN_ROOT}` or Claude
  `${user_config.*}` expansion is used by this integration.
- Missing YARA: rebuild with `-Yara`; the other stages work without it.
- Missing optional tools: install/configure them or let Codex skip those stages.
- A cases root outside the checkout may require granting that folder access in
  your Codex environment before writing case data.

### Validate an installed Codex plugin

Run `python -m unittest discover -s tests -p test_codex_package.py` for packaging
and installation-path regression tests. To test an installed copy through the
actual Codex app-server, including native MCP startup and all eight tool
contracts, run:

```powershell
python tests/check_codex_runtime.py --codex-home '<isolated Codex test profile>' --output '<test output outside this repo>' --sample 'C:\Windows\System32\whoami.exe'
```

Install the plugin into that test profile first. This check does not execute
the PE or start a model turn. capa and dynamic-import inputs in this regression
check are explicitly synthetic parser fixtures; external capa, Ghidra, UPX,
and real VM tracing need separate integration checks. YARA is skipped with an
explicit message if the installed server lacks that feature.

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

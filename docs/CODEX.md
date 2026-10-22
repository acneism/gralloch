# Gralloch with Codex

Codex uses the same Rust MCP server and analysis scripts as Claude Code. This
integration adds a repository skill and project-local MCP configuration. It does
not require installing the Claude plugin or changing global Codex settings.

## Setup (Windows)

Install Codex and the Rust/linker prerequisites listed in the root README. From
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
the repository root; use `/mcp` to inspect the connection. The `gralloch` server
should expose `case_new`, `triage`, `capa_import`, `yara_scan`, `deobfuscate`,
`dynamic_import`, `verify`, and `report`.

The skill is loaded from `.agents/skills/gralloch/SKILL.md` for chats working in
this checkout. It relies on the shared files in this repository; copying only
the skill folder elsewhere is not a standalone installation.

## Usage

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

## Isolation boundary

The Claude `PreToolUse` hook in `gralloch-plugin/hooks` does **not** run in this
Codex integration. `AGENTS.md` and the skill guide behavior, but do not enforce
process isolation. The server still stores imported samples read-only as `.bin`
and does not execute them. Perform all execution, debugging, Frida tracing, and
runtime unpacking inside a dedicated analysis VM with a clean snapshot and
disabled/faked network. Follow the existing
[isolation rules](../gralloch-plugin/skills/gralloch-isolation/SKILL.md), including
per-command confirmation for the malware profile. Do not use bypass/automatic
approval modes for malware analysis.

## Troubleshooting

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

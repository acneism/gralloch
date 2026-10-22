# gralloch (Claude Code plugin)

Isolation-first, semi-automatic reverse-engineering pipeline for **Windows PE**,
packaged as a Claude Code plugin. Claude orchestrates; a native Rust MCP server
(`gralloch-mcp`) does the fast deterministic work. Full spec: `../tz-re-pipeline.md`.

MVP scope: profile `understand`, stages 0-1 (case creation + triage) end-to-end.

## Layout

```
gralloch-plugin/
├── .claude-plugin/plugin.json   # manifest
├── .mcp.json                    # declares the gralloch MCP server (bin/gralloch-mcp.exe)
├── commands/                    # /case-new, /triage
├── skills/                      # gralloch-isolation, gralloch-triage
├── hooks/                       # PreToolUse isolation tripwire (guard.ps1)
├── scripts/                     # external-tool orchestration (Ghidra headless export)
├── schemas/                     # JSON Schema for case.json, triage.json, ghidra-export.json
├── bin/                         # gralloch-mcp.exe goes here (built separately)
└── gralloch-mcp/                   # Rust source for the MCP server
```

## Install

The repository root is a plugin marketplace (`.claude-plugin/marketplace.json`).
In Claude Code:

```
/plugin marketplace add <path-to-this-repo>
/plugin install gralloch@gralloch-marketplace
```

Once the repo is pushed to GitHub, install in one step:

```
/plugin install gralloch --marketplace <owner>/<repo>
```

The `gralloch` MCP server starts automatically.

## Build the server

```powershell
cd gralloch-mcp
.\build-windows.ps1          # produces ..\bin\gralloch-mcp.exe (needs rustup + MSVC C++ Build Tools)
```

Until `bin/gralloch-mcp.exe` exists, the plugin still installs and the hook/skills/
commands work, but the `gralloch` tools (`case_new`, `triage`) are unavailable.

## Validate

```powershell
claude plugin validate .\gralloch-plugin --strict
```

## Safety model (summary)

- Samples are stored read-only, without an executable extension, by `case_new`.
- A `PreToolUse` hook (`hooks/guard.ps1`, fail-closed) denies host-side sample
  execution, read-only removal, and antivirus tampering.
- Dynamic analysis runs only inside the VM. The host does static work only.
- Sample-derived text is treated as untrusted data (prompt-injection aware).

See `skills/gralloch-isolation/SKILL.md` and `tz-re-pipeline.md` section 4.

## Status

| Component | State |
|---|---|
| Plugin scaffold, hook, skills, commands, schemas | done, validated |
| `guard.ps1` isolation hook | done, unit-tested |
| `gralloch-mcp` (`case_new`, `triage`) | source complete; needs `cargo build` to produce the exe |
| Stage 3 Ghidra headless export (`scripts/`, `/static`) | scaffolded; needs a Ghidra install to run |
| capa / YARA rules / unpack / dynamics / writeback | later iterations |

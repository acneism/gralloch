# re-lab (Claude Code plugin)

Isolation-first, semi-automatic reverse-engineering pipeline for **Windows PE**,
packaged as a Claude Code plugin. Claude orchestrates; a native Rust MCP server
(`relab-mcp`) does the fast deterministic work. Full spec: `../tz-re-pipeline.md`.

MVP scope: profile `understand`, stages 0-1 (case creation + triage) end-to-end.

## Layout

```
re-lab-plugin/
├── .claude-plugin/plugin.json   # manifest
├── .mcp.json                    # declares the relab MCP server (bin/relab-mcp.exe)
├── commands/                    # /case-new, /triage
├── skills/                      # relab-isolation, relab-triage
├── hooks/                       # PreToolUse isolation tripwire (guard.ps1)
├── scripts/                     # external-tool orchestration (Ghidra headless export)
├── schemas/                     # JSON Schema for case.json, triage.json, ghidra-export.json
├── bin/                         # relab-mcp.exe goes here (built separately)
└── relab-mcp/                   # Rust source for the MCP server
```

## Install

The repository root is a plugin marketplace (`.claude-plugin/marketplace.json`).
In Claude Code:

```
/plugin marketplace add <path-to-this-repo>
/plugin install re-lab@re-lab-marketplace
```

Once the repo is pushed to GitHub, install in one step:

```
/plugin install re-lab --marketplace <owner>/<repo>
```

The `relab` MCP server starts automatically.

## Build the server

```powershell
cd relab-mcp
.\build-windows.ps1          # produces ..\bin\relab-mcp.exe (needs rustup + MSVC C++ Build Tools)
```

Until `bin/relab-mcp.exe` exists, the plugin still installs and the hook/skills/
commands work, but the `relab` tools (`case_new`, `triage`) are unavailable.

## Validate

```powershell
claude plugin validate .\re-lab-plugin --strict
```

## Safety model (summary)

- Samples are stored read-only, without an executable extension, by `case_new`.
- A `PreToolUse` hook (`hooks/guard.ps1`, fail-closed) denies host-side sample
  execution, read-only removal, and antivirus tampering.
- Dynamic analysis runs only inside the VM. The host does static work only.
- Sample-derived text is treated as untrusted data (prompt-injection aware).

See `skills/relab-isolation/SKILL.md` and `tz-re-pipeline.md` section 4.

## Status

| Component | State |
|---|---|
| Plugin scaffold, hook, skills, commands, schemas | done, validated |
| `guard.ps1` isolation hook | done, unit-tested |
| `relab-mcp` (`case_new`, `triage`) | source complete; needs `cargo build` to produce the exe |
| Stage 3 Ghidra headless export (`scripts/`, `/static`) | scaffolded; needs a Ghidra install to run |
| capa / YARA rules / unpack / dynamics / writeback | later iterations |

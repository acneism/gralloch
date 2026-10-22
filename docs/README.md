# gralloch commands

Slash commands shipped by the `gralloch` plugin (`gralloch-plugin/commands/`).
Each command is an orchestration prompt: it drives the native `gralloch-mcp`
tools and the `scripts/` helpers through one pipeline stage. Every stage treats
sample-derived text (strings, paths, hosts, rule/capability names) as untrusted
data; conclusions stay hypotheses until dynamic evidence confirms them.

## One-shot

| Command | Does |
|---|---|
| `/gralloch <sample.exe> [--profile p] [--cases-root dir]` | Runs the whole automatic host pipeline: case → triage → (unpack) → capa → yara → deobfuscate → report. Stages whose external tool is missing are skipped, not failed. |
| `/gralloch --verify [case-dir]` | Runs only stage 6 verification. |
| `/gralloch --report [case-dir]` | Runs only stage 7 report. |

`/gralloch` is the entry point; the per-stage commands below are for targeted or
manual runs, and for the stages that cannot be automated on the host.

## Per-stage commands

| Stage | Command | Does | Native tool / script |
|---|---|---|---|
| 0 | `/case-new <sample> [profile]` | Create a case: hash the PE, store it read-only as `sample/<sha256>.bin`, write `case.json` + `notes.md`. | `case_new` |
| 1 | `/triage [case-dir]` | Parse the PE (arch, sections+entropy, imports, overlay, packer heuristic) → `triage.json`; recommend a route. | `triage` |
| 1 | `/capa [case-dir]` | capa capability detection (ATT&CK/MBC) → `capa-summary.json`, folded into triage. | `run-capa.ps1` + `capa_import` |
| 1 | `/yara [case-dir]` | YARA scan with the built-in baseline rules → `yara.json`. Needs the `yara`-feature build. | `yara_scan` |
| 2 | `/unpack [case-dir]` | Static UPX unpack on the host (never executes); runtime packers route to the VM. | `run-unpack.ps1` |
| 3 | `/static [case-dir]` | Ghidra headless export of functions/strings/xrefs. Needs a Ghidra install. | `run-ghidra-headless.ps1` + `ghidra_export.py` |
| 4 | `/deobfuscate [case-dir]` | Static deobfuscation: strings, single-byte XOR brute (dictionary-scored), base64 → `deobfuscated.json`. | `deobfuscate` |
| 5 | `/dynamics [case-dir]` | Prepare Frida tracing (VM-only, user-initiated) and import the resulting trace → `dynamic.json`. | `frida_trace.js` + `run-frida.py` (VM) → `dynamic_import` (host) |
| 6 | `/verify [case-dir]` | Validate `hypotheses.json`: a `confirmed` finding must cite evidence that exists; list writeback-ready items. | `verify` |
| 7 | `/report [case-dir]` | Aggregate all artifacts → `report.md` + `report.json`, splitting confirmed vs hypotheses and collecting IOCs. | `report` |

## What is NOT automated (by design)

- **Stage 3 (static / Ghidra)** disassembles but needs a Ghidra install
  (`GHIDRA_INSTALL_DIR`); run `/static`, then `/gralloch --report`.
- **Stage 5 (dynamics / VM)** executes the sample, so it is VM-only and
  user-initiated (active snapshot, network off/faked). The host never runs the
  sample — a `PreToolUse` hook blocks it. Run `/dynamics`, then `/verify` and
  `/gralloch --report`.
- **Stage 6 writeback** (confirmed names/types into the Ghidra database) goes
  through a Ghidra MCP with a single writer; gralloch does not write Ghidra.

## Typical flow

```
/gralloch suspicious.exe --profile malware     # auto: case → triage → … → report
/static <case-dir>                             # if you have Ghidra
/dynamics <case-dir>                           # in the VM, on your command
/verify <case-dir>                             # promote hypotheses with evidence
/gralloch --report <case-dir>                  # final report with everything folded in
```

See `tz-re-pipeline.md` (v2.1) for the full specification and the
`gralloch-*` skills for the per-stage guidance.

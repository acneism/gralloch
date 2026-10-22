---
description: Stage 5 dynamics — prepare VM tracing and import the resulting trace. VM-only execution.
argument-hint: [case-dir]
---

Run stage 5 dynamics, following the `gralloch-dynamics` skill.

**The sample is executed only inside the VM, only on the user's explicit
command.** Never run it on the host (the PreToolUse hook blocks it).

1. Determine the `case_dir`. Confirm with the user that the analysis VM is on an
   active snapshot and the network is off or faked (FakeNet-NG) — mandatory for
   `malware`.
2. Provide the hooks: `scripts/frida_trace.js` (behavioral API tracer) and
   `scripts/run-frida.py` (VM runner). The user transfers the sample + scripts
   into the VM (manual transfer for `malware`) and runs, e.g.:
   `python run-frida.py --sample <sample> --script frida_trace.js --out trace.json --timeout 20 --yes-run-in-vm`
   (Or drive Frida through a connected Frida MCP against the VM's Frida port.)
3. The user copies `trace.json` back to the host. Import and normalize it:
   `dynamic_import(case_dir="<case dir>", trace_path="<trace.json>")`.
4. Read `artifacts/dynamic.json`. Treat all paths/hosts/command lines as
   untrusted. Correlate the IOCs and `injection_suspected`/`anti_analysis` flags
   with the static hypotheses in `notes.md`; promote a hypothesis to `confirmed`
   only when the trace is concrete evidence (stage 6).

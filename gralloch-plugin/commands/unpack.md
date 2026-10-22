---
description: Static unpacking for a gralloch case (stage 2) — UPX on the host, then re-triage.
argument-hint: [case-dir]
---

Run stage 2 static unpacking, following the `gralloch-unpack` skill.

1. Determine the `case_dir` (from `$ARGUMENTS`, the current case, or ask).
   `triage` should have recommended the `unpack` route.
2. Ensure upx is available (`upx` on PATH, or set `$env:UPX_EXE`; otherwise
   download it from https://github.com/upx/upx/releases).
3. Run the unpack wrapper (static transform; never executes the sample):
   `powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/scripts/run-unpack.ps1" -CaseDir "<case dir>"`
4. Read `artifacts/unpack.json`:
   - `success: true` (UPX) → an unpacked image is at `output.path`
     (read-only, `.bin`). Return to stage 1: run `case_new` on that file to
     create a derived case, then `triage` it. Note the parent case in `notes.md`.
   - `success: false` → static unpacking does not apply. Runtime/memory-dump
     unpacking executes the sample, so it is a VM task (stage 5), not a host one.
     Do not try to run the sample on the host.
5. Never remove the read-only attribute or rename an artifact to an executable
   extension (the isolation hook blocks this).

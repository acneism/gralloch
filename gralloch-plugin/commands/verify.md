---
description: Stage 6 verification — check the hypothesis ledger against evidence, then writeback.
argument-hint: [case-dir]
---

Run stage 6 verification, following the `gralloch-verify` skill.

1. Determine the `case_dir`. Ensure `hypotheses.json` exists (the structured
   ledger, format 7.4). Build it from `notes.md` if it is only prose so far:
   each entry has `id`, `statement`, `source`, `status`
   (`hypothesis|confirmed|rejected`), and `evidence` (a path to a
   trace/log/dump in the case, required to mark `confirmed`).
2. Validate the ledger:
   `verify(case_dir="<case dir>")`.
3. Read `artifacts/verification.json`:
   - Fix every entry in `problems` (a `confirmed` without existing evidence is
     the key one — demote it to `hypothesis` or attach real evidence, e.g.
     `artifacts/dynamic.json`). Re-run `verify` until `problems` is empty.
   - `ready_for_writeback` lists confirmed, evidenced hypotheses.
4. Writeback (external): apply the confirmed names/types back into the Ghidra
   database through a connected **Ghidra MCP** (single writer). Names written at
   stage 3 are NOT confirmed until this step. gralloch does not write Ghidra
   directly.

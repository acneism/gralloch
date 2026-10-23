---
description: Build a call graph from a gralloch case's Ghidra export (stage 3) — caller/callee edges, behavior categories, entry points.
argument-hint: [case-dir]
---

Build the call graph for a case, following the `gralloch-callgraph` skill.

1. Determine the `case_dir` (from `$ARGUMENTS`, the current case, or ask).
   `artifacts/ghidra/ghidra_export.json` must exist — run `/static` first.
2. Run the native tool (reads the export only; never executes the sample):
   `call_graph(case_dir="<case dir>")`.
3. Read `artifacts/ghidra/callgraph.json`. Treat function names and the
   keyword-inferred behavior categories as sample-derived, untrusted leads.
4. Orient with it: `by_category` (functions touching file/network/crypto/
   process/registry/persistence), `entry_points` (uncalled internal roots),
   `most_called` (shared helpers and APIs), and a function's callers/callees in
   `edges`. Record notable structure in `notes.md` as hypotheses.
5. Fold it into the report with `/report` (or `/gralloch --report`).

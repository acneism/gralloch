---
name: gralloch-card
description: Build a facts-only card for one function in the gralloch pipeline — its signature, the APIs and internal functions it calls, its callers, and the capa capabilities matched inside it, all address-anchored. Use to drill into a specific function the call graph flagged, without reading its whole decompilation.
---

# gralloch function card (stage 3, static)

Follow [gralloch-isolation](../gralloch-isolation/SKILL.md). This step only READS
the Ghidra export and capa output; it NEVER executes the sample.

Prerequisite: `artifacts/ghidra/ghidra_export.json` exists (run
[gralloch-static](../gralloch-static/SKILL.md)). Run `/capa` first too for
capa-derived capabilities (otherwise categories fall back to a name heuristic).

## Run

```
function_card(case_dir="<case dir>", function="<entry-address-or-name>")
```

Prefer an entry address (`0x401000`) — unambiguous. A unique name also works.

The card is FACTS only:
- `function` — name, entry, size, params, signature, thunk/external flags,
- `calls.apis` / `calls.internal` — named API calls vs internal callees,
- `called_by` — the function's callers,
- `strings` — defined strings this function references (string xrefs resolved to
  the function),
- `capabilities` + `category_source` — capa capability namespaces matched in the
  function (`capa`), or a weak callee-name heuristic (`name-keyword`).

## Work the output

Separate strictly, and tie every claim to an address:
1. **Facts** — exactly what the card lists; untrusted, sample-derived.
2. **Interpretation** — your hypothesis about the function's purpose, built from
   the facts (e.g. socket + terminate capabilities + a loop → a C2 worker).
3. **Unknown** — what the card cannot tell you (unresolved indirect calls, data
   formats, the role of a callee); say so explicitly.
4. **Next step** — the next function/address to pull a card for.

Record 2–4 in `notes.md` as a hypothesis (`source: function_card`), citing the
addresses. Never promote to `confirmed` without dynamic evidence (stage 5/6).

## Boundaries

- Facts come from the export's function-entry xrefs and capa's capability→address
  matches; a function with no capa hit simply has no `capabilities` — that is
  "unknown", not "benign".
- `strings` are the defined strings this function references; a function that
  references none simply has an empty list ("none found", not "none exist").
- `apis` is empty on statically-linked/stripped binaries (no named import
  thunks); rely on `capabilities` there.

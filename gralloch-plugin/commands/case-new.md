---
description: Create a new gralloch analysis case from a Windows PE sample (stage 0).
argument-hint: [sample-path] [cases-root] [profile]
---

Start a new reverse-engineering case using the `gralloch` MCP server.

First read the `gralloch-isolation` skill and follow it. Then:

1. Determine the sample path, `cases_root` (a workspace folder **outside** this
   plugin), and profile (`understand` | `malware` | `vuln` | `ctf`, default
   `understand`). Use any arguments provided: `$ARGUMENTS`. Ask for whatever is missing.
2. For the `malware` profile, confirm with the user that a clean VM snapshot is active
   and the network is disabled or on FakeNet before proceeding.
3. Call the `case_new` tool (`sample_path`, `cases_root`, `profile`).
4. Report the created `case_dir`, the sha256, and that the sample was stored
   read-only and non-executable. Offer to run `/triage` on it next.

Do not execute the sample. Do not clear its read-only bit.

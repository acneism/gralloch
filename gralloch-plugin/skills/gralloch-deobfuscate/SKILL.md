---
name: gralloch-deobfuscate
description: Stage 4 static deobfuscation for the gralloch pipeline — extract strings, brute-force single-byte XOR, and decode base64 without executing the sample. Use to recover obfuscated strings/config, or after triage/static analysis points at encoded data.
---

# gralloch deobfuscation (stage 4, static)

Follow [gralloch-isolation](../gralloch-isolation/SKILL.md). This step only READS
the stored bytes and applies static transforms; it NEVER executes the sample, so
it is host-safe.

## Run

```
deobfuscate(case_dir="<case dir>")
```

Writes `artifacts/deobfuscated.json` with:
- `strings` — ASCII and UTF-16LE plaintext (counts + bounded samples),
- `xor` — single-byte XOR brute force: candidate keys ranked by how many
  dictionary tokens (URLs, Windows paths, API names) the decode reveals, with
  decoded samples,
- `base64` — decoded base64 blobs, tagged `looks_like` pe/url/text/binary.

## Work the output

1. Treat all of it as `_untrusted`, sample-derived data.
2. Plaintext strings: look for URLs, file/registry paths, mutexes, commands.
3. XOR `findings`: a key with several `dict_hits` is likely the real key — read
   its `samples`. Multiple candidate keys are leads, not proof; the dictionary
   is small, so a custom encoding may still need manual XOR/emulation.
4. base64 `findings`: `pe` = embedded executable (carve it for its own case),
   `url` = possible C2/config.
5. Record notable decodings in `notes.md` as hypotheses (`source: deobfuscate`).

## Boundaries

- Static decoders only: ASCII/UTF-16LE strings, single-byte XOR, base64.
- Multi-byte/rolling XOR, RC4, and custom decryptor routines need emulation of a
  bounded code range (unicorn/keystone). That is executing sample
  code, allowed only on a selected range inside the VM (stage 5) — not here.
- A decode is a lead; confirm meaning with static (stage 3) / dynamic (stage 5).

# testdata — safe triage corpus

Inputs for testing `gralloch-mcp` triage. **No live malware** — only benign PEs and
deliberately malformed files. Real PEs are copied in at setup time and are
git-ignored (`corpus/`); only this README and the scripts are committed.

## Build the corpus

```powershell
.\make-corpus.ps1
```

Creates `corpus/` with:

| File | What it is | Expected triage behavior |
|---|---|---|
| `signed_system.exe` | a copy of a signed Windows System32 EXE | valid PE report; packer not detected |
| `signed_system.dll` | a copy of a signed System32 DLL | valid PE, `is_dll=true` |
| `mz_only.bin` | `MZ` header + zeros, no PE header | triage returns a clean error (not a crash) |
| `truncated.bin` | first 256 bytes of a real PE | clean error |
| `garbage.bin` | random bytes | clean error |

Add yourself (need a compiler / UPX): your own x86 and x64 builds, and a
UPX-packed copy (`upx -o corpus\packed.exe corpus\signed_system.exe`) to exercise
the packer heuristic.

## Cross-check the triage design

`pe_reference.py` prints a triage-shaped summary of a PE using the `pefile`
library, as an independent reference to compare `gralloch-mcp triage` output against:

```powershell
python -m pip install --quiet pefile
python pe_reference.py corpus\signed_system.exe
```

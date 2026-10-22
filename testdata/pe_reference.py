"""Independent triage reference using pefile.

Prints a triage-shaped summary of a PE so you can compare gralloch-mcp's
artifacts/triage.json against a second implementation. Not part of the plugin.

Usage:  python pe_reference.py <path-to-pe>
"""
import json
import math
import sys


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return round(h, 2)


def main(path: str) -> int:
    try:
        import pefile
    except ImportError:
        print("pip install pefile", file=sys.stderr)
        return 3

    with open(path, "rb") as f:
        raw = f.read()

    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except Exception as e:  # noqa: BLE001 - mirror gralloch's "clean error" expectation
        print(json.dumps({"error": f"not a valid PE: {e}"}, indent=2))
        return 1

    machine = pe.FILE_HEADER.Machine
    arch = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "arm64"}.get(machine, hex(machine))
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        sections.append(
            {
                "name": name,
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": shannon(s.get_data()),
            }
        )

    imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1", "replace")
            fns = [imp.name.decode("latin-1", "replace") for imp in entry.imports if imp.name]
            imports[dll] = fns
    function_count = sum(len(v) for v in imports.values())

    report = {
        "arch": arch,
        "is_dll": is_dll,
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "section_count": pe.FILE_HEADER.NumberOfSections,
        "overall_entropy": shannon(raw),
        "sections": sections,
        "imports": {
            "dll_count": len(imports),
            "function_count": function_count,
            "dlls": list(imports.keys()),
        },
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))

# gralloch-mcp

Native MCP server (Rust) for the gralloch pipeline. Pure-Rust by default — no
cmake, no C libraries — so the MVP builds with only rustup + the MSVC linker.

## Tools

| Tool | What it does |
|---|---|
| `case_new` | Hash a sample, store it read-only as `sample/<sha256>.bin` (no exec extension), write `case.json` + `notes.md`. Never executes the sample. |
| `triage` | Parse the stored PE: format, arch, sections + entropy, imports/exports, overlay, heuristic packer check; recommend a route. Writes `artifacts/triage.json`. |

## Build (Windows)

```powershell
.\build-windows.ps1          # light MVP build (goblin + hashes + entropy)
.\build-windows.ps1 -Yara    # also compile the yara-x engine (heavier: wasmtime + a C dep, MSRV 1.95)
```

The script copies `gralloch-mcp.exe` to `../bin/`, where `.mcp.json` expects it.

Prerequisites: [rustup](https://rustup.rs) and the MSVC C++ Build Tools
(`x86_64-pc-windows-msvc`). YARA is behind the `yara` cargo feature and off by
default.

## Verify before relying on pinned versions

I wrote this without a local toolchain, so confirm the crate versions and the
couple of library APIs at first build:

```powershell
cargo info rmcp        # confirm the 3.x line is current
cargo info goblin      # confirm the 0.9 line is current; adjust Cargo.toml if not
cargo build --release
cargo test             # entropy/slice/non-PE unit tests
```

Spots most likely to need a tweak if a crate moved: the `rmcp` tool macros in
`src/server.rs` (`#[tool_router]` / `#[tool_handler]` / `Parameters` / `ContentBlock`)
and a few goblin field names in `src/triage.rs` (`optional_header.windows_fields`,
`SectionTable`). The pure-Rust analysis logic (entropy, hashing, packer
heuristic) is toolchain-independent.

## Manual smoke test (no Claude needed)

An MCP stdio server speaks JSON-RPC on stdin/stdout. A quick initialize probe:

```powershell
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' |
  .\target\release\gralloch-mcp.exe
```

You should get a JSON-RPC result naming `gralloch-mcp`. For tool calls, drive it
through Claude Code once the plugin is installed.

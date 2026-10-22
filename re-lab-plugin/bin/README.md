# bin/

The compiled MCP server `relab-mcp.exe` belongs here. `.mcp.json` launches it as
`${CLAUDE_PLUGIN_ROOT}/bin/relab-mcp.exe`.

Build it with `../relab-mcp/build-windows.ps1`, which copies the release binary
here. The binary is git-ignored; ship it via a release/archive artifact per
platform (not committed to the repo).

Note: claude.ai and Cowork refuse a plugin with a top-level `bin/` directory. This
plugin targets Claude Code on Windows; for those hosts, move the executable to
`scripts/` and update `.mcp.json` accordingly.

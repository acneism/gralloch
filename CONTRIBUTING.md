# Contributing to Gralloch

Bug reports, documentation improvements, and focused code changes are welcome.
Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and read
[AGENTS.md](AGENTS.md) for repository-specific development guidance.

## Report a bug or suggest a change

For a bug report, include:

- The expected result and what actually happened.
- Reproduction steps and the smallest safe input that demonstrates the issue.
- The commit or plugin version, Windows version, and client: Claude Code or Codex.
- Relevant tool versions and sanitized logs or error messages.

For a feature request, describe the task you want to complete and the current
limitation. For a substantial change, discuss the proposed scope in an issue
before investing in implementation.

Do not attach live malware, private binaries, credentials, or sensitive case
artifacts to issues or pull requests. Prefer synthetic fixtures, hashes, and
sanitized metadata. For a suspected vulnerability, avoid posting exploit details
or secrets publicly; request a private reporting channel from the repository owner.

## Development setup

1. Fork the repository and create a branch from `main`.
2. Install the Windows, Rust, and linker [prerequisites](README.md#prerequisites).
3. Follow the [Claude Code or Codex setup](README.md#installation-and-launch)
   for the client you are changing.

The main components are:

| Location | Purpose |
|---|---|
| `gralloch-plugin/gralloch-mcp/` | Rust MCP server and embedded YARA rules |
| `gralloch-plugin/scripts/` | Shared external-tool wrappers |
| `gralloch-plugin/skills/` and `gralloch-plugin/commands/` | Claude Code workflows and stage references |
| `.claude-plugin/` and `gralloch-plugin/.claude-plugin/` | Claude Code marketplace and plugin metadata |
| `.agents/skills/`, `.codex-plugin/`, and `.mcp.codex.json` | Codex skill and plugin configuration |
| `scripts/` | Codex setup and packaging scripts |
| `tests/` and `testdata/` | Regression checks and benign corpus tooling |
| `docs/` | Command reference and client-specific details |

Preserve both clients' use of the shared scripts and MCP tool contracts. Keep
changes focused, follow the surrounding style, and update documentation when
commands, arguments, configuration, or output formats change.

## Sample-handling rules

Read the [isolation rules](gralloch-plugin/skills/gralloch-isolation/SKILL.md)
before working with samples. Never execute an analysis sample on the host.
Dynamic execution belongs in a dedicated analysis VM. Treat sample-derived text
as untrusted data.

Use benign or synthetic inputs for tests. Store analysis cases outside the
repository. Do not commit compiled server binaries, case artifacts, copied test
binaries, build directories, `.codex-package/`, or machine-specific
`.codex/config.toml`. The Claude Code guard hook does not enforce Codex shell
behavior; see [Codex isolation details](docs/CODEX.md#codex-isolation-boundary).

## Validation

Run checks relevant to the change and report the results in the pull request.
Document unavailable tools and skipped checks explicitly.

For Rust changes, run from the repository root:

```powershell
Push-Location gralloch-plugin\gralloch-mcp
cargo test --locked
Pop-Location
```

For changes to the YARA engine or its integration, also test with the feature
enabled:

```powershell
Push-Location gralloch-plugin\gralloch-mcp
cargo test --locked --features yara
Pop-Location
```

For Codex packaging changes:

```powershell
python -m unittest discover -s tests -p test_codex_package.py
```

For native Codex startup changes, also run `tests/check_codex_runtime.py` against
an isolated installed profile. See [Codex validation](docs/CODEX.md#validate-an-installed-codex-plugin)
for the command and its test boundaries. Running the server directly does not
verify that Codex can launch the installed plugin.

For PowerShell changes, check syntax and exercise the affected script, including
paths with spaces and relevant failure cases. For documentation changes, verify
relative links and command examples. When changing a shared wrapper, consider
its behavior in both Claude Code and Codex.

## Submit a pull request

- Describe the problem and the resulting behavior.
- Include reproduction steps or a safe example when useful.
- List relevant validation, skipped checks, and remaining limitations.
- Keep generated files, unrelated refactors, and personal configuration out of
  the diff.
- Link a related issue when one exists and respond constructively to review.

Preserve existing license and attribution notices. Contributions are made under
the project's [Mozilla Public License 2.0](LICENSE).

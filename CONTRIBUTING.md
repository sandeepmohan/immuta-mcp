# Contributing

Thanks for your interest in improving this project. A few things about how this
repository works will save you surprises.

## How this repo is maintained

This public repository is a **sanitized snapshot mirror** of a private
development repo. Changes land here as periodic sync commits, not as direct
merges. Practical consequences for you:

- **Your PR will be closed, not merged.** After review, the maintainer
  integrates your change into the private repo, runs the end-to-end smoke
  suite against a live Immuta instance (credentials never touch public CI),
  and publishes the next snapshot. The sync commit carries a
  `Co-authored-by:` trailer with your name and email, so the contribution is
  attributed to you on GitHub. The closing comment links the sync commit that
  shipped your change.
- **Force-pushes or history edits on `main` should never happen** — if you see
  one, it was a publishing mistake; please open an issue.

## Before you open a PR

1. **State the Immuta version you tested against.** Endpoint paths drift
   between self-managed Immuta versions (this repo targets **2026.1.x**, tested
   on 2026.1.4). If your change touches an endpoint path in
   `immuta_queries.py`, say which version(s) you verified it on and how.
2. **Keep API logic in `immuta_queries.py`.** `mcp_server.py` is a thin MCP
   wrapper — new queries are added to `immuta_queries.py` first (as a library
   function returning a Pydantic model, plus a Typer CLI subcommand), then
   exposed as a tool in `mcp_server.py`. Never duplicate HTTP logic in the
   MCP layer.
3. **Endpoint paths live only at `_get(...)`/`_post(...)` call sites** so a
   404 error's `endpoint` field points at the exact line to fix.
4. **No secrets, hostnames, or instance-specific values** — docs and examples
   use placeholders like `<your-mcp-hostname>`.

## What CI checks

Public CI runs on every PR (no secrets, no live Immuta):

- `uv sync` and `python -m py_compile immuta_queries.py mcp_server.py`
- `helm lint` and `helm template` on `deploy/helm`

The live end-to-end verification (every CLI subcommand against a real Immuta,
plus the HTTP-transport probes in [DEPLOYMENT.md](DEPLOYMENT.md) §5) is run by
the maintainer before your change is published.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).

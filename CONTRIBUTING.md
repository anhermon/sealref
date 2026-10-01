# Contributing

Small project; issues and pull requests are welcome.

- Run `python3 -m unittest -v test_sealref` before sending a change. Add a test
  for any behavior change.
- Keep the CLI standard-library only. The MCP server's `mcp` dependency is the
  one exception.
- One rule is not negotiable: no MCP tool and no CLI command may print or return
  a secret value. Changes that add one will not be merged.
- Anything that reads a value is `_`-prefixed in `store.py` and is used only by
  `sealref run`. Keep it that way.
- Nothing may write to stdout in `mcp_server.py`; stdout is the MCP transport.
- Security issues: open a private security advisory on GitHub rather than a
  public issue.

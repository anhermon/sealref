# Changelog

## Unreleased

- Refs now print as `sealref://` by default (previously `vaultlet://`).
  `vaultlet://` refs are still accepted everywhere, and
  `SEALREF_REF_SCHEME=vaultlet` / `--ref-scheme vaultlet` restores the old output.
- `request_secret` / `sealref request`: the "serving on" line goes to stderr, and
  the browser is opened from a helper process with stdin closed and stdout sent
  to stderr. Before, both could write into the MCP server's stdout, which is the
  JSON-RPC channel. `sealref ui` prints its "serving on" line to stderr as well.

- Renamed to **sealref**. New primary command `sealref` and ref scheme
  `sealref://group/key`. Fully backward compatible: the `vaultlet` command,
  `python -m vaultlet[.mcp_server]` and `vaultlet://` refs work unchanged; both
  schemes are accepted everywhere. Refs print as `sealref://`; set
  `SEALREF_REF_SCHEME=vaultlet` or `--ref-scheme vaultlet` to print the legacy
  scheme. Keychain service
  (`vaultlet:<group>`) and `~/.vaultlet` are unchanged (no migration).
  MCP tool names unchanged; server name is `sealref`, or `vaultlet` via the alias.
  `SEALREF_SKIP_KEYCHAIN` added next to `VAULTLET_SKIP_KEYCHAIN`.
- Keychain writes now pass the value to `security -i` on stdin instead of argv,
  so it no longer shows up in `ps`. Values with newlines or NUL are rejected.
- Local page: reject requests with a foreign `Host` (DNS rebinding) or `Origin`,
  and require a custom header on POST and DELETE (CSRF). Fixed unescaped
  query parameters in the page, and validate group and key names on delete.
- `sealref run`: tolerate non-UTF-8 child output, terminate the child on Ctrl-C.
- `~/.vaultlet` is created with mode 0700.
- Docs: new README, threat model, security review, MIT license.

## 0.1.0

- Initial version: Keychain store, `vaultlet run` with output redaction, local
  entry page, MCP server (`list_groups`, `list_keys`, `has_secret`,
  `request_secret`, `usage_hint`).

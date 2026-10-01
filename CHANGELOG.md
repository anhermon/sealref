# Changelog

## Unreleased

- Keychain writes now pass the value to `security -i` on stdin instead of argv,
  so it no longer shows up in `ps`. Values with newlines or NUL are rejected.
- Local page: reject requests with a foreign `Host` (DNS rebinding) or `Origin`,
  and require a custom header on POST and DELETE (CSRF). Fixed unescaped
  query parameters in the page, and validate group and key names on delete.
- `vaultlet run`: tolerate non-UTF-8 child output, terminate the child on Ctrl-C.
- `~/.vaultlet` is created with mode 0700.
- Docs: new README, threat model, security review, MIT license.

## 0.1.0

- Initial version: Keychain store, `vaultlet run` with output redaction, local
  entry page, MCP server (`list_groups`, `list_keys`, `has_secret`,
  `request_secret`, `usage_hint`).

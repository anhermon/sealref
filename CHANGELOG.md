# Changelog

## Unreleased

- Linux and Windows support through the optional `keyring` extra
  (`pip install 'sealref[keyring]'`), plus `sealref set <group> <key>` (hidden
  prompt or stdin) and `sealref` / `vaultlet` console scripts. Only OS keystores
  are accepted (SecretService/libsecret, KWallet, Windows Credential Manager,
  macOS); plaintext/file keyrings and keyring's `fail`/`null` backends are
  refused with no fallback. Keychain approval is macOS-only. Windows has not
  been run.
- Replacing a Keychain secret no longer risks silent loss: a first-time save
  never deletes anything, and a failed replace says whether the previous value
  was kept or deleted.
- The local page refuses request bodies over 64 KiB, and its Quit button ends a
  pending `request_secret` immediately instead of after 300 s.
- `sealref run` exits `128+N` for a child killed by signal N and 127/126 when
  the command cannot be started, instead of a traceback.
- `SEALREF_KEYCHAIN=<file>` selects a keychain file for the macOS backend.
- CI matrix: macOS, Linux (gnome-keyring under dbus-run-session), Windows.

- Security fixes from the 2026-10-17 red-team review (see SECURITY-REVIEW.md):
  - The local page's API needs a per-launch token, carried in the link sealref
    opens. A bookmarked `http://127.0.0.1:8765/` without `#t=...` no longer
    works; open the link `sealref ui` prints.
  - New opt-in **Keychain approval** checkbox: every read of that secret raises
    a macOS dialog. Existing secrets are unchanged until saved again with the box ticked.
  - Values longer than about 2900 bytes, or containing any control character, are rejected.
  - Keychain calls use `/usr/bin/security`; `bin/sealref` runs `python3 -I` and
    handles relative symlinks; the page cannot be framed; the value field has
    spell-check off; failed Keychain deletes keep the index entry.
  - Redaction also catches hex and base64 inside longer encodings (HTTP Basic `user:key`).
  - `run --ref ...=NAME` requires a valid env var name; Keychain read errors exit 2 with a message.
- Refs now print as `sealref://` by default (previously `vaultlet://`).
  `vaultlet://` refs are still accepted everywhere, and
  `SEALREF_REF_SCHEME=vaultlet` / `--ref-scheme vaultlet` restores the old output.
- `request_secret` / `sealref request`: the "serving on" line goes to stderr, and
  the browser is opened from a helper process with stdin closed and stdout sent
  to stderr. Before, both could write into the MCP server's stdout, which is the
  JSON-RPC channel. `sealref ui` prints its "serving on" line to stderr as well.
  If the browser cannot be launched, a note goes to stderr and the request
  still waits for the value.
- The request page banner reads "Your agent needs a secret:" instead of naming
  Claude.
- `--ref-scheme` with an unknown value now reports the flag, not
  `SEALREF_REF_SCHEME`.
- `sealref run` closes the child's output pipe (fixes a ResourceWarning).
- Docs: redaction wording now says it is line-based, covers the raw value and
  its base64 / URL-encoded forms, and that `run` merges the child's stderr into
  stdout. The threat model notes that base64 of the value combined with other
  text (e.g. HTTP Basic `user:key`) is not caught.

- Renamed to **sealref**. New primary command `sealref` and ref scheme
  `sealref://group/key`. Backward compatible on input: the `vaultlet` command,
  `python -m vaultlet[.mcp_server]` and `vaultlet://` refs keep working; both
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

# vaultlet — shared contract (do not change without saying so)

Small personal utility. macOS only. **Zero third-party deps** in the package itself
(stdlib only). The MCP server is the one exception and it is launched via
`uv run --with mcp`, so nothing is installed into the repo.

## The one property that matters

**The agent never sees a secret value.** It sees refs. Values leave the store only
into the environment of a child process spawned by `vaultlet run`, and that child's
stdout/stderr is redacted before it is printed.

There is **no** `get_secret` / `reveal` / `resolve` MCP tool. The absence is the design.
Do not add one. Do not add a CLI command that prints a value to stdout.

This is defense-in-depth against accidental leakage into an agent transcript,
**not** a sandbox against a determined agent. Say that in docs; never claim more.

## Layout

```
~/dev/vaultlet/
  vaultlet/__init__.py
  vaultlet/store.py        # phase 1
  vaultlet/cli.py          # phase 1  (python3 -m vaultlet ...)
  vaultlet/__main__.py     # phase 1  -> cli.main()
  vaultlet/ui.py           # phase 2
  vaultlet/mcp_server.py   # phase 3
  test_vaultlet.py         # phase 1 (stdlib unittest or plain asserts + __main__)
  README.md                # phase 3
  bin/vaultlet             # phase 1: shell shim -> exec python3 -m vaultlet "$@"
```

## Storage

- Index: `~/.vaultlet/index.json`, mode 0600, atomic write (tmp + os.replace).
  Shape: `{"groups": {"<group>": {"keys": {"<key>": {"created": "<iso8601>"}}}}}`
- Values: macOS Keychain, **never** in the index.
  - service = `vaultlet:<group>`, account = `<key>`
  - write: `security add-generic-password -a <key> -s vaultlet:<group> -w <value> -U`
  - read:  `security find-generic-password -a <key> -s vaultlet:<group> -w`
  - delete:`security delete-generic-password -a <key> -s vaultlet:<group>`
  - Verified: non-interactive read succeeds with no GUI prompt.
  - Pass the value via a list arg to `subprocess.run` (never `shell=True`).
    Note the ceiling in a `ponytail:` comment: the value is briefly visible in
    `ps` output of the `security` child. Acceptable for a personal utility.

## Ref format

`vaultlet://<group>/<key>` — this string is what agents hold and pass around.
`store.parse_ref(s) -> (group, key)` raises ValueError on anything else.

## Names

group and key must match `^[A-Za-z0-9_.-]+$`. key additionally must be a valid
env var name when uppercased-as-is — enforce `^[A-Za-z_][A-Za-z0-9_]*$` for keys.
Reject otherwise with a clear error. Validate on every write path (UI + CLI).

## store.py public API (phase 2 and 3 depend on these exact signatures)

```python
list_groups() -> list[str]
list_keys(group: str) -> list[str]              # names only, never values
has(group: str, key: str) -> bool
set_secret(group: str, key: str, value: str) -> str   # returns the ref
delete(group: str, key: str) -> None
delete_group(group: str) -> None
create_group(group: str) -> None
ref(group: str, key: str) -> str
parse_ref(s: str) -> tuple[str, str]
_resolve(group: str, key: str) -> str           # private-by-convention; ONLY cli.run uses it
_resolve_group(group: str) -> dict[str, str]    # same
```

Anything reading a value is `_`-prefixed. Nothing outside `cli.py`'s `run` imports them.

## CLI (`python3 -m vaultlet` / `bin/vaultlet`)

- `vaultlet groups` — list group names
- `vaultlet keys <group>` — list `key  vaultlet://group/key` lines (no values)
- `vaultlet ui [--port N]` — start the UI, print URL, open browser
- `vaultlet request <group> <key> [--reason TEXT]` — start UI focused on that field,
  block until the secret exists (poll store) or timeout (default 300s).
  Prints the ref on success, non-zero exit on timeout. Never prints the value.
- `vaultlet run [--group G]... [--ref vaultlet://g/k[=ENVNAME]]... -- <cmd> [args...]`
  Injects the resolved values into the child env (`--group G` injects every key in G
  under its own name; `--ref` injects one under `ENVNAME` or the key name).
  Streams the child's stdout/stderr **through a redaction filter** and exits with the
  child's exit code.

### Redaction filter (the part that must be right)

Merge child stdout+stderr, read line by line, and before writing each line to our
stdout replace every injected value with `«redacted:<group>/<key>»`. Longest values
first so a value that contains another is replaced correctly. Also redact the
base64 and URL-quoted forms of each value (cheap, catches `curl -u` / auth headers).
Skip values shorter than 4 chars (too noisy to redact usefully) but log a warning
to stderr when one is injected.

`ponytail:` comment the ceiling: line-buffered, so a value split across a line
boundary or emitted without a trailing newline at a chunk edge can slip through.

## UI

- stdlib `http.server` only. **Bind `127.0.0.1`** — never `0.0.0.0`.
- Single page, plain HTML + vanilla JS inline in `ui.py`. Dark/light via
  `prefers-color-scheme`. Minimal, no framework, no CDN.
- Manage groups (create/delete) and key/value pairs (add/update/delete).
- Values are **write-only in the API**: no endpoint ever returns a value.
  The list endpoint returns key names + refs + a fixed `••••••••` mask.
- Each key row has a "copy ref" button (copies `vaultlet://g/k`).
- `?group=G&key=K&reason=...` query params pre-fill and focus the input, showing
  the reason as a banner ("Claude needs a secret: ...").
- Server shuts down on a `POST /api/quit` (used by `request` after success) or Ctrl-C.

## MCP server

- `uv run --with mcp python -m vaultlet.mcp_server`, stdio transport, FastMCP.
- **Nothing may ever be printed to stdout.** All logging to stderr. One stray print
  kills the transport silently.
- Tools, exactly these:
  - `list_groups()` -> group names
  - `list_keys(group)` -> `[{"key":..., "ref":"vaultlet://g/k"}]`
  - `has_secret(group, key)` -> bool
  - `request_secret(group, key, reason)` -> opens the UI focused on that field,
    waits (timeout 300s), returns the **ref**. Never the value.
  - `usage_hint()` -> a short string telling the caller to consume secrets via
    `vaultlet run --group G -- <cmd>` and never to ask the user to paste a secret.
- No tool returns a secret value. No tool named get/read/reveal/resolve exists.

## What cli.py expects from ui.py

`cli.py` imports these lazily (inside the `ui`/`request` handlers, guarded by
`try/except ImportError` so the rest of the CLI works before `ui.py` exists):

```python
def serve(port: int = 8765) -> None:
    """Start the UI server bound to 127.0.0.1:<port>, print the URL, open the
    browser, and block until Ctrl-C or POST /api/quit."""

def serve_until(group: str, key: str, reason: str | None, timeout: int = 300) -> bool:
    """Start the UI server, open the browser to
    ?group=<group>&key=<key>&reason=<reason> (reason omitted if None), and
    block until store.has(group, key) becomes True or `timeout` seconds
    elapse. Shuts the server down before returning. Returns True if the
    secret now exists, False on timeout. Never returns or touches the value."""
```

# Security review

Reviewed by reading all code and exercising the local server and Keychain path.
This is a self-review, not an audit.

## Fixed

| # | Issue | Fix |
|---|---|---|
| 1 | Secret value passed as argv to `security add-generic-password -w`, visible in `ps` while it ran. | Value is sent on stdin to `security -i` (quoted and escaped). Newline and NUL values are rejected. Test asserts the value is not in argv. |
| 2 | Local page had no CSRF or DNS-rebinding protection. A web page could POST text/plain JSON to `127.0.0.1:<port>` (the body parser ignored Content-Type) to overwrite or delete secrets or call `/api/quit`. A rebinding hostname could do the same with full response access. | `Host` must be `127.0.0.1:<port>` or `localhost:<port>`; `Origin`, if present, must match; POST and DELETE require `X-Vaultlet: 1`, which forces a CORS preflight that is never granted. Tests cover each. |
| 3 | Page injected the `key` and `group` URL parameters into an HTML attribute and a CSS selector unescaped (DOM injection through a crafted link). | Escaped; element found by comparing `dataset`. |
| 4 | `DELETE /api/groups/<g>` and `/api/keys/<g>/<k>` did not validate names or URL-decode the path. | Names validated in `store.delete` and `store.delete_group`; path segments unquoted. |
| 5 | `request` built the browser URL from unquoted group and key. | Quoted; key validated. |
| 6 | `~/.vaultlet` created with default umask (0755). | Created 0700. (The index inside was already 0600.) |
| 7 | `vaultlet run` crashed on non-UTF-8 child output and left the child running on Ctrl-C. | `errors="replace"`; terminate on interrupt. |

## Open, by design (see README threat model)

- The agent selects the command run under `vaultlet run`, so it can print or
  exfiltrate the value (`echo $K | rev`, `curl -d "$K"`). Redaction is a guard
  against accident. Mitigation outside this tool: require approval for
  `vaultlet run` in the agent's permission settings.
- Same-user processes can read the Keychain item directly.
- Redaction is line-buffered and covers raw, base64 and URL-quoted forms only.
- `request_secret` returns as soon as `store.has` is true, so requesting a key
  that already exists returns immediately without prompting. `has_secret` is
  checked against the index, not the Keychain, so a manually deleted Keychain
  item still reports as present.
- A misleading `reason` in `request_secret` can socially engineer the user.
- The UI port is predictable (`vaultlet ui` defaults to 8765); `request` uses a
  random port. Any local process can connect to it; the guards above stop
  browsers, not other local programs.
- `list_keys` / `has_secret` disclose which services you have credentials for.

## Logging

The MCP server logs to stderr only; the web server's access log is disabled. No
code path logs values. The only value-bearing path is stdin to `security -i`.

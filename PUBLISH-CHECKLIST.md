# Publish checklist

Nothing below has been done. Remove this file before or right after publishing.

1. Decide the name (see the recommendation in the handoff notes). To rename:
   change the package directory, `bin/vaultlet`, the `vaultlet://` ref scheme
   and Keychain service prefix (this breaks existing stored items; migrate or
   re-enter), docs, and CI. Keeping `vaultlet` is the zero-work option; the
   name is free on GitHub under your account and npm but taken on PyPI.
2. Commit identity: history uses angel.hermon.mail@gmail.com. If you do not
   want that public, set `git config user.email <id>+anhermon@users.noreply.github.com`
   and rewrite: `git rebase --root --exec 'git commit --amend --no-edit --reset-author'`.
3. Review `git log -p` once more and the squash/commit state.
4. Run `VAULTLET_SKIP_KEYCHAIN= python3 -m unittest -v test_vaultlet` locally.
5. Verify the MCP server end to end with Claude Code (`mcp` 1.29.0 is pinned;
   this review could not run the MCP transport).
6. Survey agent-focused secret tools and MCP servers once more and adjust the
   "How it differs" section; it deliberately makes no claims about specific ones.
7. Create the repo (private first if you prefer):
   `gh repo create anhermon/vaultlet --public --description "<see below>" --source . --remote origin`
   (this pushes nothing until `git push -u origin main`).
8. `git push -u origin main`.
9. `gh repo edit --add-topic macos --add-topic keychain --add-topic secrets --add-topic mcp --add-topic mcp-server --add-topic ai-agents --add-topic claude-code --add-topic cli`
10. Enable private vulnerability reporting (Settings > Code security) since
    CONTRIBUTING points there.
11. Confirm the macOS workflow passes. If you want the keychain test in CI, drop
    `VAULTLET_SKIP_KEYCHAIN` and see whether the runner keychain is unlocked.
12. Optionally tag `v0.1.0` and move the Unreleased changelog section under it.

Description: Keychain-backed secrets for coding agents: the agent sees
vaultlet:// refs, never values. macOS, MCP server, local entry form.

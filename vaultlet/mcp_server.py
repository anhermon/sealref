"""MCP server exposing vaultlet to agents over stdio.

HARD RULE: nothing here may ever write to stdout -- stdout is the JSON-RPC
transport for FastMCP's stdio mode. All logging/diagnostics go to stderr.

These tools hand out *refs* (`vaultlet://group/key`), never values. There is
deliberately no get/read/reveal/resolve tool -- that absence is the whole
point of vaultlet. Consume a secret by running a child process through
`vaultlet run --group G -- <cmd>`, which injects it into that child's env
and redacts it from the child's output.
"""
import logging
import sys

from mcp.server.fastmcp import FastMCP

from . import store

logging.basicConfig(stream=sys.stderr, level=logging.INFO)

mcp = FastMCP("vaultlet")

DEFAULT_TIMEOUT = 300


@mcp.tool()
def list_groups() -> list:
    """List all vaultlet secret group names. Groups are just namespaces
    (e.g. "stripe", "github") -- this returns names only, never any values."""
    return store.list_groups()


@mcp.tool()
def list_keys(group: str) -> list:
    """List the keys stored in a vaultlet group, each as {"key", "ref"}.
    Returns pointers only (`vaultlet://group/key`) -- never the underlying
    values. Use a ref with `vaultlet run --ref vaultlet://g/k -- <cmd>` to
    inject the value into a child process's environment when you need it."""
    return [{"key": key, "ref": store.ref(group, key)} for key in store.list_keys(group)]


@mcp.tool()
def has_secret(group: str, key: str) -> bool:
    """Check whether a secret exists at vaultlet://group/key, without ever
    revealing or touching its value. Call this before request_secret to
    avoid prompting the user for something already stored."""
    return store.has(group, key)


@mcp.tool()
def request_secret(group: str, key: str, reason: str) -> str:
    """Ask the user to provide a secret via the vaultlet UI (opens a local
    browser page where they type the value in directly). Never ask the user
    to paste a secret into this chat -- that would put it in the transcript,
    defeating the entire point of vaultlet. This call blocks until the user
    submits the value (or times out after 300s), and returns only the ref
    `vaultlet://group/key` -- never the value itself. Consume the secret
    afterwards with `vaultlet run --group group -- <cmd>`."""
    try:
        from .ui import serve_until
    except ImportError:
        raise RuntimeError(
            "vaultlet ui.py is not available; run `vaultlet request "
            f"{group} {key} --reason {reason!r}` in a shell instead"
        )
    ok = serve_until(group, key, reason, timeout=DEFAULT_TIMEOUT)
    if not ok:
        raise RuntimeError(f"timed out waiting for secret {group}/{key}")
    return store.ref(group, key)


@mcp.tool()
def usage_hint() -> str:
    """Explains how to actually use secrets obtained from this server:
    you only ever hold refs (vaultlet://group/key), never values. Consume
    them by running the target command through
    `vaultlet run --group G -- <cmd>` (or --ref for a single secret), which
    injects the value into that child process's environment and redacts it
    from anything the child prints. Never ask the user to paste a secret
    into chat -- always request_secret to open the UI instead."""
    return (
        "You hold refs (vaultlet://group/key), never secret values -- there is no "
        "tool to read one. To use a secret, run the consuming command through "
        "`vaultlet run --group <group> -- <cmd> [args...]` (injects every key in "
        "that group into the child's env, redacts them from its output) or "
        "`vaultlet run --ref vaultlet://g/k -- <cmd>` for a single secret. "
        "If a secret is missing, call request_secret(group, key, reason) to open "
        "the vaultlet UI for the user to type it in -- never ask the user to "
        "paste a secret value into chat."
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")

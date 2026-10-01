"""Alias: runs the sealref MCP server under the legacy server name "vaultlet"."""
from sealref.mcp_server import mcp  # noqa: F401

if __name__ == "__main__":
    mcp.run(transport="stdio")

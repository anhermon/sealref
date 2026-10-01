"""Compatibility shim: `vaultlet` is the old name of `sealref`.
Keeps `python -m vaultlet[.mcp_server]` and `from vaultlet import store` working."""
import os

os.environ.setdefault("SEALREF_PROG", "vaultlet")
os.environ.setdefault("SEALREF_MCP_NAME", "vaultlet")
from sealref import store  # noqa: E402,F401

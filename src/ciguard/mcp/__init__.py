"""ciguard MCP server (v0.8.0).

Exposes ciguard's scanning capabilities as Model Context Protocol tools any
MCP-compatible client (Claude Desktop, Claude Code, Cursor, VS Code MCP
extensions) can invoke. Distributed as the optional `pip install ciguard[mcp]`
extra.

Launch via `ciguard mcp` (stdio transport — the standard for local MCP
servers). See `server.py` for the tool surface.
"""
from .server import build_server, run_stdio

__all__ = ["build_server", "run_stdio"]

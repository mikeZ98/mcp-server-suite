"""Hardened Model Context Protocol (MCP) server suite."""

from importlib.metadata import version

__all__ = ["__version__"]

__version__: str = version("mcp-server-suite")

"""Console entry point: serve MCP over stdio (logs go to stderr only)."""

import asyncio
import logging
import os
import sys

from mcp_server_suite.core import MCPServer, ToolRegistry, run_stdio

LOG_LEVEL_ENV = "MCP_SERVER_SUITE_LOG_LEVEL"


def _configure_logging() -> None:
    level = os.environ.get(LOG_LEVEL_ENV, "WARNING").upper()
    logging.basicConfig(
        stream=sys.stderr,
        level=level if level in logging.getLevelNamesMapping() else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> int:
    """Run the server until stdin closes or SIGINT/SIGTERM arrives."""
    _configure_logging()
    server = MCPServer(ToolRegistry())
    try:
        asyncio.run(run_stdio(server))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

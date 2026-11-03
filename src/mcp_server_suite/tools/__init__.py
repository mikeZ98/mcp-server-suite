"""Concrete MCP tools and the registry assembled from them."""

import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from mcp_server_suite.core.registry import ToolRegistry
from mcp_server_suite.tools.sql import ReadOnlySqlTool, SqlSettings, enforce_read_only

__all__ = ["ReadOnlySqlTool", "SqlSettings", "enforce_read_only", "open_tool_registry"]

logger = logging.getLogger(__name__)


@asynccontextmanager
async def open_tool_registry(*, sql: SqlSettings | None = None) -> AsyncIterator[ToolRegistry]:
    """Build the registry of configured tools and release their resources on exit.

    ``read_only_sql`` is only registered when a DSN is configured.
    """
    sql_settings = sql if sql is not None else SqlSettings()
    registry = ToolRegistry()
    async with AsyncExitStack() as resources:
        if sql_settings.dsn is not None:
            sql_tool = ReadOnlySqlTool(sql_settings)
            resources.push_async_callback(sql_tool.aclose)
            registry.register(sql_tool.definition())
        else:
            logger.warning("MCP_SQL_DSN is not set; read_only_sql is disabled")
        yield registry

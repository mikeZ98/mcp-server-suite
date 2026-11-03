"""Concrete MCP tools and the registry assembled from them."""

import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from mcp_server_suite.core.registry import ToolRegistry
from mcp_server_suite.tools.fs import SandboxFsReadTool, SandboxSettings
from mcp_server_suite.tools.sql import ReadOnlySqlTool, SqlSettings, enforce_read_only

__all__ = [
    "ReadOnlySqlTool",
    "SandboxFsReadTool",
    "SandboxSettings",
    "SqlSettings",
    "enforce_read_only",
    "open_tool_registry",
]

logger = logging.getLogger(__name__)


@asynccontextmanager
async def open_tool_registry(
    *, sql: SqlSettings | None = None, fs: SandboxSettings | None = None
) -> AsyncIterator[ToolRegistry]:
    """Build the registry of configured tools and release their resources on exit.

    Each tool is registered only when its settings are present: ``read_only_sql``
    needs ``MCP_SQL_DSN``, ``sandbox_fs_read`` needs ``MCP_SAFE_DATA_DIR``.
    """
    sql_settings = sql if sql is not None else SqlSettings()
    fs_settings = fs if fs is not None else SandboxSettings()
    registry = ToolRegistry()
    async with AsyncExitStack() as resources:
        if sql_settings.dsn is not None:
            sql_tool = ReadOnlySqlTool(sql_settings)
            resources.push_async_callback(sql_tool.aclose)
            registry.register(sql_tool.definition())
        else:
            logger.warning("MCP_SQL_DSN is not set; read_only_sql is disabled")
        if fs_settings.safe_data_dir is not None:
            registry.register(SandboxFsReadTool(fs_settings).definition())
        else:
            logger.warning("MCP_SAFE_DATA_DIR is not set; sandbox_fs_read is disabled")
        yield registry

"""Async JSON-RPC 2.0 engine implementing the MCP stdio transport."""

from mcp_server_suite.core.framing import (
    MAX_FRAME_BYTES,
    ByteSink,
    ByteSource,
    FrameReader,
    FrameWriter,
    OversizedFrame,
)
from mcp_server_suite.core.jsonrpc import ErrorCode, JsonRpcError
from mcp_server_suite.core.registry import ToolDefinition, ToolError, ToolRegistry
from mcp_server_suite.core.server import (
    LATEST_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    MCPServer,
    ServerConfig,
)
from mcp_server_suite.core.stdio import install_signal_handlers, open_stdio, run_stdio

__all__ = [
    "LATEST_PROTOCOL_VERSION",
    "MAX_FRAME_BYTES",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "ByteSink",
    "ByteSource",
    "ErrorCode",
    "FrameReader",
    "FrameWriter",
    "JsonRpcError",
    "MCPServer",
    "OversizedFrame",
    "ServerConfig",
    "ToolDefinition",
    "ToolError",
    "ToolRegistry",
    "install_signal_handlers",
    "open_stdio",
    "run_stdio",
]

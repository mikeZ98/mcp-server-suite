"""Strict Pydantic v2 wire contracts for MCP tools and RFC 9457 errors."""

from mcp_server_suite.schemas._base import StrictModel
from mcp_server_suite.schemas.errors import (
    ERROR_TAXONOMY,
    PROBLEM_JSON_MEDIA_TYPE,
    ErrorSpec,
    MCPErrorCode,
    ProblemDetail,
)
from mcp_server_suite.schemas.tools import (
    FS_MAX_BYTES_LIMIT,
    SQL_MAX_ROWS_LIMIT,
    CpuMetrics,
    MemoryMetrics,
    ReadOnlySqlParams,
    SandboxFsReadParams,
    SandboxFsReadResult,
    SqlQueryResult,
    SystemMetricsParams,
    SystemMetricsResult,
    ToolName,
)

__all__ = [
    "ERROR_TAXONOMY",
    "FS_MAX_BYTES_LIMIT",
    "PROBLEM_JSON_MEDIA_TYPE",
    "SQL_MAX_ROWS_LIMIT",
    "CpuMetrics",
    "ErrorSpec",
    "MCPErrorCode",
    "MemoryMetrics",
    "ProblemDetail",
    "ReadOnlySqlParams",
    "SandboxFsReadParams",
    "SandboxFsReadResult",
    "SqlQueryResult",
    "StrictModel",
    "SystemMetricsParams",
    "SystemMetricsResult",
    "ToolName",
]

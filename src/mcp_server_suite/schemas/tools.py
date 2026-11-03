"""Strict input/output contracts for the MCP tools exposed by the suite."""

import codecs
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Final, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from mcp_server_suite.schemas._base import StrictModel

__all__ = [
    "FS_MAX_BYTES_LIMIT",
    "SQL_MAX_ROWS_LIMIT",
    "CpuMetrics",
    "MemoryMetrics",
    "ReadOnlySqlParams",
    "SandboxFsReadParams",
    "SandboxFsReadResult",
    "SqlQueryResult",
    "SystemMetricsParams",
    "SystemMetricsResult",
    "ToolName",
]

SQL_MAX_ROWS_LIMIT: Final = 50
FS_MAX_BYTES_LIMIT: Final = 1_048_576

Percent = Annotated[float, Field(ge=0.0, le=100.0)]
NonNegativeInt = Annotated[int, Field(ge=0)]


class ToolName(StrEnum):
    """Registered MCP tool names."""

    READ_ONLY_SQL = "read_only_sql"
    SANDBOX_FS_READ = "sandbox_fs_read"
    SYSTEM_METRICS = "system_metrics"


def _reject_nul(value: str) -> str:
    if "\x00" in value:
        msg = "NUL bytes are not allowed"
        raise ValueError(msg)
    return value


# ---------------------------------------------------------------------------
# read_only_sql
# ---------------------------------------------------------------------------
class ReadOnlySqlParams(StrictModel):
    """Arguments for ``read_only_sql``."""

    query: Annotated[str, Field(min_length=6, max_length=10_000)]
    max_rows: Annotated[int, Field(ge=1, le=SQL_MAX_ROWS_LIMIT)] = SQL_MAX_ROWS_LIMIT

    @field_validator("query", mode="after")
    @classmethod
    def _check_query(cls, value: str) -> str:
        _reject_nul(value)
        if not value.strip():
            msg = "query must not be blank"
            raise ValueError(msg)
        return value


class SqlQueryResult(StrictModel):
    """Result set returned by ``read_only_sql``."""

    columns: tuple[str, ...]
    rows: Annotated[tuple[tuple[Any, ...], ...], Field(max_length=SQL_MAX_ROWS_LIMIT)]
    row_count: Annotated[int, Field(ge=0, le=SQL_MAX_ROWS_LIMIT)]
    truncated: bool

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        if self.row_count != len(self.rows):
            msg = f"row_count {self.row_count} does not match {len(self.rows)} rows"
            raise ValueError(msg)
        width = len(self.columns)
        for index, row in enumerate(self.rows):
            if len(row) != width:
                msg = f"row {index} has {len(row)} values, expected {width}"
                raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# sandbox_fs_read
# ---------------------------------------------------------------------------
class SandboxFsReadParams(StrictModel):
    """Arguments for ``sandbox_fs_read``.

    Path containment is enforced by the tool via canonical resolution; the schema
    only rejects values that can never be a valid path.
    """

    relative_path: Annotated[str, Field(min_length=1, max_length=4096)]
    encoding: Annotated[str, Field(min_length=1, max_length=64)] = "utf-8"
    max_bytes: Annotated[int, Field(ge=1, le=FS_MAX_BYTES_LIMIT)] = 65_536

    @field_validator("relative_path", mode="after")
    @classmethod
    def _check_path(cls, value: str) -> str:
        return _reject_nul(value)

    @field_validator("encoding", mode="after")
    @classmethod
    def _check_encoding(cls, value: str) -> str:
        try:
            info = codecs.lookup(value)
        except LookupError as exc:
            msg = f"unknown encoding {value!r}"
            raise ValueError(msg) from exc
        # Reject bytes-to-bytes / str-to-str codecs such as base64, zlib or rot13.
        if not getattr(info, "_is_text_encoding", True):
            msg = f"{value!r} is not a text encoding"
            raise ValueError(msg)
        return info.name


class SandboxFsReadResult(StrictModel):
    """File contents returned by ``sandbox_fs_read``.

    ``resolved_path`` is relative to the sandbox root so host paths are never exposed.
    """

    resolved_path: Annotated[str, Field(min_length=1, max_length=4096)]
    content: str
    bytes_read: Annotated[int, Field(ge=0, le=FS_MAX_BYTES_LIMIT)]
    truncated: bool


# ---------------------------------------------------------------------------
# system_metrics
# ---------------------------------------------------------------------------
class SystemMetricsParams(StrictModel):
    """Arguments for ``system_metrics``."""

    include_disk: bool = False


class CpuMetrics(StrictModel):
    """Host CPU utilisation snapshot."""

    utilization_percent: Percent
    core_count: Annotated[int, Field(ge=1)]
    load_average_1m: Annotated[float, Field(ge=0.0)]


class MemoryMetrics(StrictModel):
    """Host virtual-memory snapshot."""

    total_bytes: NonNegativeInt
    available_bytes: NonNegativeInt
    percent_used: Percent

    @model_validator(mode="after")
    def _check_available(self) -> Self:
        if self.available_bytes > self.total_bytes:
            msg = "available_bytes cannot exceed total_bytes"
            raise ValueError(msg)
        return self


class SystemMetricsResult(StrictModel):
    """Structured host health metrics returned by ``system_metrics``."""

    cpu: CpuMetrics
    memory: MemoryMetrics
    disk_percent_used: Percent | None = None
    timestamp_utc: AwareDatetime

    @field_validator("timestamp_utc", mode="after")
    @classmethod
    def _check_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            msg = "timestamp_utc must have a UTC offset of zero"
            raise ValueError(msg)
        return value.astimezone(UTC)

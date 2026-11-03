"""``system_metrics``: host CPU, memory and (optionally) disk telemetry via psutil.

``psutil.cpu_percent`` blocks for its sampling interval, so collection runs in a
worker thread. Readings are clamped into the Phase 2 contract ranges because
some platforms (containers, VMs) can report slightly out-of-range values; the
disk path is configuration, never client input, and is not echoed back.
"""

import asyncio
import math
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final

import psutil
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_server_suite.core.registry import ToolDefinition
from mcp_server_suite.schemas import (
    CpuMetrics,
    MemoryMetrics,
    SystemMetricsParams,
    SystemMetricsResult,
    ToolName,
)

__all__ = ["MetricsSettings", "SystemMetricsTool"]

_PERCENT_MAX: Final = 100.0


class MetricsSettings(BaseSettings):
    """``system_metrics`` settings, read from ``MCP_METRICS_*`` environment variables."""

    model_config = SettingsConfigDict(env_prefix="MCP_METRICS_", extra="forbid", frozen=True)

    enabled: bool = True
    cpu_sample_seconds: Annotated[float, Field(gt=0, le=2.0)] = 0.1
    disk_path: Path = Path("/")

    @field_validator("disk_path", mode="after")
    @classmethod
    def _check_disk_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            msg = "disk_path must be an absolute path"
            raise ValueError(msg)
        return value


def _percent(value: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return min(max(float(value), 0.0), _PERCENT_MAX)


def _non_negative(value: float) -> float:
    return float(value) if math.isfinite(value) and value > 0 else 0.0


class SystemMetricsTool:
    """The ``system_metrics`` tool."""

    def __init__(self, settings: MetricsSettings | None = None) -> None:
        self._settings = settings if settings is not None else MetricsSettings()

    def definition(self) -> ToolDefinition[SystemMetricsParams, SystemMetricsResult]:
        """MCP tool definition for registration."""
        return ToolDefinition(
            name=ToolName.SYSTEM_METRICS,
            title="System metrics",
            description=(
                "Report host health: CPU utilisation, logical core count, 1-minute load "
                "average and memory usage; set include_disk for root-volume usage. "
                "Values are a point-in-time sample with a UTC timestamp."
            ),
            params_model=SystemMetricsParams,
            result_model=SystemMetricsResult,
            handler=self,
            read_only=True,
            open_world=False,
        )

    async def __call__(self, params: SystemMetricsParams) -> SystemMetricsResult:
        return await asyncio.to_thread(self._collect, params.include_disk)

    def _collect(self, include_disk: bool) -> SystemMetricsResult:  # noqa: FBT001
        settings = self._settings
        utilization = psutil.cpu_percent(interval=settings.cpu_sample_seconds)
        cores = psutil.cpu_count(logical=True) or os.cpu_count() or 1
        load_1m = psutil.getloadavg()[0]
        memory = psutil.virtual_memory()
        total = max(int(memory.total), 0)
        disk = (
            _percent(psutil.disk_usage(str(settings.disk_path)).percent) if include_disk else None
        )
        return SystemMetricsResult(
            cpu=CpuMetrics(
                utilization_percent=_percent(utilization),
                core_count=max(int(cores), 1),
                load_average_1m=_non_negative(load_1m),
            ),
            memory=MemoryMetrics(
                total_bytes=total,
                available_bytes=min(max(int(memory.available), 0), total),
                percent_used=_percent(memory.percent),
            ),
            disk_percent_used=disk,
            timestamp_utc=datetime.now(UTC),
        )

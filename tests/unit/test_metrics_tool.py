"""Hermetic tests for ``system_metrics`` (psutil is mocked unless stated otherwise)."""

import asyncio
import json
import logging
import math
import os
from dataclasses import dataclass, field
from datetime import UTC, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import mcp_types
import psutil
import pytest
from pydantic import ValidationError

from mcp_server_suite.core import MCPServer, ToolRegistry
from mcp_server_suite.schemas import SystemMetricsParams, SystemMetricsResult
from mcp_server_suite.tools import MetricsSettings, SystemMetricsTool, open_tool_registry

TIMEOUT = 5.0
GIB = 1024**3


@dataclass
class FakePsutil:
    cpu: float = 37.5
    cores: int | None = 8
    load: tuple[float, float, float] = (1.25, 1.0, 0.75)
    total: int = 16 * GIB
    available: int = 6 * GIB
    mem_percent: float = 62.5
    disk_percent: float = 41.0
    disk_error: BaseException | None = None
    intervals: list[float | None] = field(default_factory=list)
    disk_paths: list[str] = field(default_factory=list)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(psutil, "cpu_percent", self.cpu_percent)
        monkeypatch.setattr(psutil, "cpu_count", self.cpu_count)
        monkeypatch.setattr(psutil, "getloadavg", lambda: self.load)
        monkeypatch.setattr(psutil, "virtual_memory", self.virtual_memory)
        monkeypatch.setattr(psutil, "disk_usage", self.disk_usage)

    def cpu_percent(self, interval: float | None = None) -> float:
        self.intervals.append(interval)
        return self.cpu

    def cpu_count(self, logical: bool = True) -> int | None:
        assert logical is True
        return self.cores

    def virtual_memory(self) -> SimpleNamespace:
        return SimpleNamespace(total=self.total, available=self.available, percent=self.mem_percent)

    def disk_usage(self, path: str) -> SimpleNamespace:
        self.disk_paths.append(path)
        if self.disk_error is not None:
            raise self.disk_error
        return SimpleNamespace(percent=self.disk_percent)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakePsutil:
    backend = FakePsutil()
    backend.install(monkeypatch)
    return backend


@pytest.fixture
def tool() -> SystemMetricsTool:
    return SystemMetricsTool(MetricsSettings(enabled=True, cpu_sample_seconds=0.05))


async def collect(tool: SystemMetricsTool, **kwargs: Any) -> SystemMetricsResult:
    return await asyncio.wait_for(tool(SystemMetricsParams(**kwargs)), TIMEOUT)


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------
async def test_collects_cpu_and_memory(fake: FakePsutil, tool: SystemMetricsTool) -> None:
    result = await collect(tool)
    assert result.cpu.model_dump() == {
        "utilization_percent": 37.5,
        "core_count": 8,
        "load_average_1m": 1.25,
    }
    assert result.memory.model_dump() == {
        "total_bytes": 16 * GIB,
        "available_bytes": 6 * GIB,
        "percent_used": 62.5,
    }
    assert result.disk_percent_used is None
    assert fake.disk_paths == [], "disk is only sampled on request"
    assert fake.intervals == [0.05], "configured sampling interval is used"


async def test_disk_usage_on_request(fake: FakePsutil, tool: SystemMetricsTool) -> None:
    result = await collect(tool, include_disk=True)
    assert result.disk_percent_used == 41.0
    assert fake.disk_paths == ["/"]


async def test_configured_disk_path(fake: FakePsutil, tmp_path: Path) -> None:
    tool = SystemMetricsTool(MetricsSettings(disk_path=tmp_path))
    await collect(tool, include_disk=True)
    assert fake.disk_paths == [str(tmp_path)]


async def test_timestamp_is_aware_utc(fake: FakePsutil, tool: SystemMetricsTool) -> None:
    result = await collect(tool)
    assert result.timestamp_utc.tzinfo is UTC
    assert result.timestamp_utc.utcoffset() == timedelta(0)
    assert json.loads(result.model_dump_json())["timestamp_utc"].endswith("Z")


async def test_result_round_trips_through_strict_schema(
    fake: FakePsutil, tool: SystemMetricsTool
) -> None:
    result = await collect(tool, include_disk=True)
    assert SystemMetricsResult.model_validate_json(result.model_dump_json()) == result


async def test_sampling_runs_in_worker_thread(
    fake: FakePsutil, tool: SystemMetricsTool, monkeypatch: pytest.MonkeyPatch
) -> None:
    offloaded: list[str] = []
    real_to_thread = asyncio.to_thread

    async def spy(func: Any, /, *args: Any, **kwargs: Any) -> Any:
        offloaded.append(func.__name__)
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", spy)
    await collect(tool)
    assert offloaded == ["_collect"]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"cpu": 150.0}, {"utilization_percent": 100.0}),
        ({"cpu": -3.0}, {"utilization_percent": 0.0}),
        ({"cpu": math.nan}, {"utilization_percent": 0.0}),
        ({"load": (-1.0, 0.0, 0.0)}, {"load_average_1m": 0.0}),
        ({"load": (math.inf, 0.0, 0.0)}, {"load_average_1m": 0.0}),
        ({"cores": 0}, {"core_count": os.cpu_count() or 1}),  # 0 means "unknown"
    ],
)
async def test_out_of_range_cpu_readings_are_clamped(
    fake: FakePsutil, tool: SystemMetricsTool, overrides: dict[str, Any], expected: dict[str, Any]
) -> None:
    for name, value in overrides.items():
        setattr(fake, name, value)
    cpu = (await collect(tool)).cpu.model_dump()
    assert cpu | expected == cpu


async def test_memory_readings_are_clamped(fake: FakePsutil, tool: SystemMetricsTool) -> None:
    fake.available = fake.total + GIB  # seen in some containers
    fake.mem_percent = 100.4
    memory = (await collect(tool)).memory
    assert memory.available_bytes == memory.total_bytes
    assert memory.percent_used == 100.0


async def test_disk_percent_is_clamped(fake: FakePsutil, tool: SystemMetricsTool) -> None:
    fake.disk_percent = 100.7
    assert (await collect(tool, include_disk=True)).disk_percent_used == 100.0


async def test_core_count_fallbacks(
    fake: FakePsutil, tool: SystemMetricsTool, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.cores = None
    monkeypatch.setattr(os, "cpu_count", lambda: 6)
    assert (await collect(tool)).cpu.core_count == 6
    monkeypatch.setattr(os, "cpu_count", lambda: None)
    assert (await collect(tool)).cpu.core_count == 1


async def test_all_values_are_non_negative(fake: FakePsutil, tool: SystemMetricsTool) -> None:
    fake.cpu, fake.load, fake.available, fake.mem_percent = -1.0, (-2.0, 0, 0), -5, -1.0
    result = await collect(tool, include_disk=True)
    numbers = [
        result.cpu.utilization_percent,
        result.cpu.load_average_1m,
        result.memory.total_bytes,
        result.memory.available_bytes,
        result.memory.percent_used,
        result.disk_percent_used,
    ]
    assert all(n is not None and n >= 0 for n in numbers)


async def test_real_psutil_backend_produces_valid_metrics() -> None:
    """Unmocked smoke test: reads the local host only, writes nothing."""
    tool = SystemMetricsTool(MetricsSettings(cpu_sample_seconds=0.01))
    result = await collect(tool, include_disk=True)
    assert 0 <= result.cpu.utilization_percent <= 100
    assert result.cpu.core_count >= 1
    assert result.memory.total_bytes > 0
    assert result.disk_percent_used is not None


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_METRICS_ENABLED", raising=False)
    settings = MetricsSettings()
    assert (settings.enabled, settings.cpu_sample_seconds, settings.disk_path) == (
        True,
        0.1,
        Path("/"),
    )


@pytest.mark.parametrize(("raw", "expected"), [("false", False), ("0", False), ("true", True)])
def test_enabled_flag_from_environment(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
) -> None:
    monkeypatch.setenv("MCP_METRICS_ENABLED", raw)
    assert MetricsSettings().enabled is expected


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cpu_sample_seconds": 0},
        {"cpu_sample_seconds": 5},
        {"disk_path": Path("relative")},
        {"unknown": 1},
    ],
)
def test_settings_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MetricsSettings(**kwargs)


async def test_registry_honours_enabled_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    async with open_tool_registry(metrics=MetricsSettings(enabled=True)) as registry:
        assert "system_metrics" in registry
    monkeypatch.setenv("MCP_METRICS_ENABLED", "false")
    async with open_tool_registry() as registry:
        assert "system_metrics" not in registry


# ---------------------------------------------------------------------------
# MCP protocol conformance (through MCPServer)
# ---------------------------------------------------------------------------
class Collector:
    def __init__(self) -> None:
        self.messages: dict[Any, dict[str, Any]] = {}

    async def write(self, data: bytes, /) -> None:
        message = json.loads(data)
        self.messages[message["id"]] = message

    async def aclose(self) -> None:
        return None


async def exchange(tool: SystemMetricsTool, *messages: dict[str, Any]) -> dict[Any, Any]:
    init = {
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}},
    }
    reader = asyncio.StreamReader()
    for message in (init, *messages):
        reader.feed_data(json.dumps(message).encode() + b"\n")
    reader.feed_eof()
    sink = Collector()
    await asyncio.wait_for(
        MCPServer(ToolRegistry([tool.definition()])).serve(reader, sink), TIMEOUT
    )
    return sink.messages


def call(request_id: int, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "system_metrics", "arguments": arguments},
    }


async def test_tools_list_advertises_system_metrics(tool: SystemMetricsTool) -> None:
    responses = await exchange(tool, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    (spec,) = responses[1]["result"]["tools"]
    mcp_types.Tool.model_validate(spec)
    assert spec["name"] == "system_metrics"
    assert spec["annotations"]["readOnlyHint"] is True
    assert spec["inputSchema"]["properties"]["include_disk"]["type"] == "boolean"
    assert spec["outputSchema"]["required"] == ["cpu", "memory", "timestamp_utc"]


async def test_call_over_protocol(fake: FakePsutil, tool: SystemMetricsTool) -> None:
    responses = await exchange(tool, call(1, {"include_disk": True}))
    result = mcp_types.CallToolResult.model_validate(responses[1]["result"])
    assert result.is_error is False
    structured = responses[1]["result"]["structuredContent"]
    assert SystemMetricsResult.model_validate_json(json.dumps(structured)).disk_percent_used == 41.0
    assert structured["timestamp_utc"].endswith("Z")
    assert json.loads(responses[1]["result"]["content"][0]["text"]) == structured


@pytest.mark.parametrize("arguments", [{"include_disk": "true"}, {"include_disk": 1}, {"x": 1}])
async def test_strict_arguments_over_protocol(
    fake: FakePsutil, tool: SystemMetricsTool, arguments: dict[str, Any]
) -> None:
    responses = await exchange(tool, call(1, arguments))
    assert responses[1]["result"]["isError"] is True


async def test_psutil_failure_is_internal_error(
    fake: FakePsutil, tool: SystemMetricsTool, caplog: pytest.LogCaptureFixture
) -> None:
    fake.disk_error = PermissionError("statvfs denied")
    with caplog.at_level(logging.ERROR):
        responses = await exchange(tool, call(1, {"include_disk": True}))
    assert responses[1]["error"]["code"] == -32603
    assert "statvfs" not in json.dumps(responses[1])

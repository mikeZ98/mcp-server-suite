"""Hermetic contract tests for the strict Pydantic v2 schemas."""

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from mcp_server_suite import schemas
from mcp_server_suite.schemas import (
    ERROR_TAXONOMY,
    FS_MAX_BYTES_LIMIT,
    PROBLEM_JSON_MEDIA_TYPE,
    SQL_MAX_ROWS_LIMIT,
    CpuMetrics,
    MCPErrorCode,
    MemoryMetrics,
    ProblemDetail,
    ReadOnlySqlParams,
    SandboxFsReadParams,
    SandboxFsReadResult,
    SqlQueryResult,
    StrictModel,
    SystemMetricsParams,
    SystemMetricsResult,
    ToolName,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _cpu() -> CpuMetrics:
    return CpuMetrics(utilization_percent=12.5, core_count=8, load_average_1m=0.75)


def _memory() -> MemoryMetrics:
    return MemoryMetrics(total_bytes=16_000, available_bytes=4_000, percent_used=75.0)


def _problem(**overrides: Any) -> dict[str, Any]:
    spec = ERROR_TAXONOMY[MCPErrorCode.VALIDATION_ERROR]
    payload: dict[str, Any] = {
        "type": spec.type,
        "title": spec.title,
        "status": spec.status,
        "detail": "max_rows must be <= 50",
        "code": MCPErrorCode.VALIDATION_ERROR,
    }
    payload.update(overrides)
    return payload


# Minimal valid payload for every model, used by the cross-cutting invariant tests.
VALID_PAYLOADS: dict[type[BaseModel], dict[str, Any]] = {
    ReadOnlySqlParams: {"query": "SELECT 1"},
    SqlQueryResult: {"columns": ("a",), "rows": ((1,),), "row_count": 1, "truncated": False},
    SandboxFsReadParams: {"relative_path": "notes/readme.txt"},
    SandboxFsReadResult: {
        "resolved_path": "notes/readme.txt",
        "content": "hi",
        "bytes_read": 2,
        "truncated": False,
    },
    SystemMetricsParams: {},
    CpuMetrics: {"utilization_percent": 1.0, "core_count": 1, "load_average_1m": 0.0},
    MemoryMetrics: {"total_bytes": 10, "available_bytes": 5, "percent_used": 50.0},
    SystemMetricsResult: {"cpu": _cpu(), "memory": _memory(), "timestamp_utc": NOW},
    ProblemDetail: _problem(),
}

MODELS = list(VALID_PAYLOADS)


# ---------------------------------------------------------------------------
# Cross-cutting invariants: extra="forbid", frozen=True, strict=True
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__name__)
def test_model_config_is_fail_closed(model: type[BaseModel]) -> None:
    assert issubclass(model, StrictModel)
    config = model.model_config
    assert config.get("extra") == "forbid"
    assert config.get("frozen") is True
    assert config.get("strict") is True


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__name__)
def test_valid_payload_accepted(model: type[BaseModel]) -> None:
    model(**VALID_PAYLOADS[model])


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__name__)
def test_extra_fields_rejected(model: type[BaseModel]) -> None:
    with pytest.raises(ValidationError) as exc_info:
        model(**VALID_PAYLOADS[model], unexpected="x")
    assert exc_info.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__name__)
def test_instances_are_frozen(model: type[BaseModel]) -> None:
    instance = model(**VALID_PAYLOADS[model])
    field = next(iter(model.model_fields))
    with pytest.raises(ValidationError) as exc_info:
        setattr(instance, field, None)
    assert exc_info.value.errors()[0]["type"] == "frozen_instance"


@pytest.mark.parametrize("model", MODELS, ids=lambda m: m.__name__)
def test_json_round_trip(model: type[BaseModel]) -> None:
    instance = model(**VALID_PAYLOADS[model])
    assert model.model_validate_json(instance.model_dump_json()) == instance


@pytest.mark.parametrize(
    ("model", "field", "value"),
    [
        (ReadOnlySqlParams, "max_rows", "50"),
        (ReadOnlySqlParams, "max_rows", 10.0),
        (ReadOnlySqlParams, "max_rows", True),
        (ReadOnlySqlParams, "query", b"SELECT 1"),
        (SandboxFsReadParams, "max_bytes", "1024"),
        (SandboxFsReadParams, "relative_path", 123),
        (SystemMetricsParams, "include_disk", "true"),
        (SystemMetricsParams, "include_disk", 1),
        (SqlQueryResult, "truncated", 0),
        (SqlQueryResult, "row_count", "1"),
        (SqlQueryResult, "columns", ["a"]),
        (CpuMetrics, "core_count", 8.0),
        (CpuMetrics, "utilization_percent", "12.5"),
        (MemoryMetrics, "total_bytes", "10"),
        (SystemMetricsResult, "timestamp_utc", "2026-01-01T12:00:00Z"),
        (ProblemDetail, "status", "422"),
        (ProblemDetail, "code", "MCP_VALIDATION_ERROR"),
        (ProblemDetail, "invalid_params", ["max_rows"]),
    ],
)
def test_strict_mode_rejects_coercion(model: type[BaseModel], field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        model(**{**VALID_PAYLOADS[model], field: value})


def test_strict_json_input_still_parses_native_json_types() -> None:
    params = ReadOnlySqlParams.model_validate_json('{"query": "SELECT 1", "max_rows": 10}')
    assert params.max_rows == 10
    with pytest.raises(ValidationError):
        ReadOnlySqlParams.model_validate_json('{"query": "SELECT 1", "max_rows": "10"}')


# ---------------------------------------------------------------------------
# read_only_sql
# ---------------------------------------------------------------------------
def test_sql_params_defaults() -> None:
    params = ReadOnlySqlParams(query="SELECT 1")
    assert params.max_rows == SQL_MAX_ROWS_LIMIT == 50


@pytest.mark.parametrize("max_rows", [1, 25, 50])
def test_sql_max_rows_within_limit(max_rows: int) -> None:
    assert ReadOnlySqlParams(query="SELECT 1", max_rows=max_rows).max_rows == max_rows


@pytest.mark.parametrize("max_rows", [0, -1, 51, 10_000])
def test_sql_max_rows_out_of_bounds(max_rows: int) -> None:
    with pytest.raises(ValidationError):
        ReadOnlySqlParams(query="SELECT 1", max_rows=max_rows)


@pytest.mark.parametrize("query", ["", "SEL", "x" * 5, "x" * 10_001, "SELECT\x00 1", "          "])
def test_sql_query_rejected(query: str) -> None:
    with pytest.raises(ValidationError):
        ReadOnlySqlParams(query=query)


def test_sql_query_length_boundaries() -> None:
    assert ReadOnlySqlParams(query="x" * 6).query == "x" * 6
    assert len(ReadOnlySqlParams(query="x" * 10_000).query) == 10_000


def test_sql_result_accepts_fifty_rows() -> None:
    rows = tuple((i, f"name-{i}") for i in range(50))
    result = SqlQueryResult(columns=("id", "name"), rows=rows, row_count=50, truncated=True)
    assert result.row_count == 50
    assert isinstance(result.rows, tuple)
    assert all(isinstance(row, tuple) for row in result.rows)


def test_sql_result_rejects_fifty_one_rows() -> None:
    rows = tuple((i,) for i in range(51))
    with pytest.raises(ValidationError):
        SqlQueryResult(columns=("id",), rows=rows, row_count=51, truncated=True)


def test_sql_result_row_count_must_match_rows() -> None:
    with pytest.raises(ValidationError, match="row_count 2 does not match 1 rows"):
        SqlQueryResult(columns=("a",), rows=((1,),), row_count=2, truncated=False)


def test_sql_result_row_width_must_match_columns() -> None:
    with pytest.raises(ValidationError, match="row 1 has 1 values, expected 2"):
        SqlQueryResult(columns=("a", "b"), rows=((1, 2), (3,)), row_count=2, truncated=False)


def test_sql_result_rejects_list_rows() -> None:
    with pytest.raises(ValidationError):
        SqlQueryResult(columns=("a",), rows=([1],), row_count=1, truncated=False)  # type: ignore[arg-type]


def test_sql_result_empty() -> None:
    result = SqlQueryResult(columns=(), rows=(), row_count=0, truncated=False)
    assert result.model_dump() == {
        "columns": (),
        "rows": (),
        "row_count": 0,
        "truncated": False,
    }


# ---------------------------------------------------------------------------
# sandbox_fs_read
# ---------------------------------------------------------------------------
def test_fs_params_defaults() -> None:
    params = SandboxFsReadParams(relative_path="a.txt")
    assert params.encoding == "utf-8"
    assert params.max_bytes == 65_536


@pytest.mark.parametrize("max_bytes", [1, 65_536, FS_MAX_BYTES_LIMIT])
def test_fs_max_bytes_within_limit(max_bytes: int) -> None:
    params = SandboxFsReadParams(relative_path="a.txt", max_bytes=max_bytes)
    assert params.max_bytes == max_bytes


@pytest.mark.parametrize("max_bytes", [0, -1, FS_MAX_BYTES_LIMIT + 1])
def test_fs_max_bytes_out_of_bounds(max_bytes: int) -> None:
    with pytest.raises(ValidationError):
        SandboxFsReadParams(relative_path="a.txt", max_bytes=max_bytes)


@pytest.mark.parametrize("relative_path", ["", "a" * 4097, "safe\x00/../../etc/passwd"])
def test_fs_relative_path_rejected(relative_path: str) -> None:
    with pytest.raises(ValidationError):
        SandboxFsReadParams(relative_path=relative_path)


@pytest.mark.parametrize(
    ("encoding", "canonical"),
    [("utf-8", "utf-8"), ("UTF8", "utf-8"), ("latin-1", "iso8859-1"), ("ascii", "ascii")],
)
def test_fs_encoding_normalised(encoding: str, canonical: str) -> None:
    assert SandboxFsReadParams(relative_path="a", encoding=encoding).encoding == canonical


@pytest.mark.parametrize("encoding", ["no-such-codec", "base64", "rot13", "zlib"])
def test_fs_encoding_rejected(encoding: str) -> None:
    with pytest.raises(ValidationError):
        SandboxFsReadParams(relative_path="a", encoding=encoding)


def test_fs_result_bytes_read_bounds() -> None:
    SandboxFsReadResult(
        resolved_path="a", content="", bytes_read=FS_MAX_BYTES_LIMIT, truncated=True
    )
    for bad in (-1, FS_MAX_BYTES_LIMIT + 1):
        with pytest.raises(ValidationError):
            SandboxFsReadResult(resolved_path="a", content="", bytes_read=bad, truncated=False)


# ---------------------------------------------------------------------------
# system_metrics
# ---------------------------------------------------------------------------
def test_metrics_params_default() -> None:
    assert SystemMetricsParams().include_disk is False


def test_metrics_result_defaults_disk_to_none() -> None:
    result = SystemMetricsResult(cpu=_cpu(), memory=_memory(), timestamp_utc=NOW)
    assert result.disk_percent_used is None


def test_metrics_cpu_accepts_int_for_float_fields() -> None:
    # Lossless int -> float widening is the only numeric conversion strict mode allows.
    cpu = CpuMetrics(utilization_percent=50, core_count=4, load_average_1m=1)
    assert cpu.utilization_percent == 50


@pytest.mark.parametrize(
    "overrides",
    [
        {"utilization_percent": -0.1},
        {"utilization_percent": 100.1},
        {"utilization_percent": float("nan")},
        {"core_count": 0},
        {"load_average_1m": -1.0},
        {"load_average_1m": float("inf")},
    ],
)
def test_metrics_cpu_bounds(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CpuMetrics(**{**VALID_PAYLOADS[CpuMetrics], **overrides})


@pytest.mark.parametrize(
    "overrides",
    [
        {"total_bytes": -1},
        {"percent_used": 101.0},
        {"total_bytes": 10, "available_bytes": 11},
    ],
)
def test_metrics_memory_bounds(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MemoryMetrics(**{**VALID_PAYLOADS[MemoryMetrics], **overrides})


@pytest.mark.parametrize("disk", [-1.0, 100.5])
def test_metrics_disk_bounds(disk: float) -> None:
    with pytest.raises(ValidationError):
        SystemMetricsResult(cpu=_cpu(), memory=_memory(), disk_percent_used=disk, timestamp_utc=NOW)


def test_metrics_timestamp_must_be_aware() -> None:
    with pytest.raises(ValidationError):
        SystemMetricsResult(
            cpu=_cpu(),
            memory=_memory(),
            timestamp_utc=datetime(2026, 1, 1, 12, 0),
        )


def test_metrics_timestamp_must_be_utc() -> None:
    plus_two = timezone(timedelta(hours=2))
    with pytest.raises(ValidationError, match="UTC offset of zero"):
        SystemMetricsResult(cpu=_cpu(), memory=_memory(), timestamp_utc=NOW.astimezone(plus_two))


def test_metrics_timestamp_normalised_to_utc_tzinfo() -> None:
    zero_offset = timezone(timedelta(0), "Z")
    result = SystemMetricsResult(
        cpu=_cpu(), memory=_memory(), timestamp_utc=NOW.replace(tzinfo=zero_offset)
    )
    assert result.timestamp_utc.tzinfo is UTC


def test_metrics_result_json_serialisation() -> None:
    result = SystemMetricsResult(
        cpu=_cpu(), memory=_memory(), disk_percent_used=42.0, timestamp_utc=NOW
    )
    payload = json.loads(result.model_dump_json())
    assert payload["timestamp_utc"] == "2026-01-01T12:00:00Z"
    assert payload["cpu"] == {
        "utilization_percent": 12.5,
        "core_count": 8,
        "load_average_1m": 0.75,
    }
    assert payload["disk_percent_used"] == 42.0


# ---------------------------------------------------------------------------
# RFC 9457 Problem Details
# ---------------------------------------------------------------------------
def test_error_codes_are_stable() -> None:
    assert {code.value for code in MCPErrorCode} == {
        "MCP_VALIDATION_ERROR",
        "MCP_ACCESS_DENIED",
        "MCP_QUERY_VIOLATION",
        "MCP_EXECUTION_TIMEOUT",
        "MCP_INTERNAL_ERROR",
    }


def test_taxonomy_covers_every_code() -> None:
    assert set(ERROR_TAXONOMY) == set(MCPErrorCode)
    types = [spec.type for spec in ERROR_TAXONOMY.values()]
    assert len(types) == len(set(types))
    jsonrpc_codes = [spec.jsonrpc_code for spec in ERROR_TAXONOMY.values()]
    assert len(jsonrpc_codes) == len(set(jsonrpc_codes))
    assert all(400 <= spec.status <= 599 for spec in ERROR_TAXONOMY.values())


def test_taxonomy_is_read_only() -> None:
    with pytest.raises(TypeError):
        ERROR_TAXONOMY[MCPErrorCode.INTERNAL_ERROR] = ERROR_TAXONOMY[  # type: ignore[index]
            MCPErrorCode.VALIDATION_ERROR
        ]


@pytest.mark.parametrize(
    ("code", "status", "jsonrpc_code"),
    [
        (MCPErrorCode.VALIDATION_ERROR, 422, -32602),
        (MCPErrorCode.ACCESS_DENIED, 403, -32001),
        (MCPErrorCode.QUERY_VIOLATION, 403, -32002),
        (MCPErrorCode.EXECUTION_TIMEOUT, 504, -32003),
        (MCPErrorCode.INTERNAL_ERROR, 500, -32603),
    ],
)
def test_from_code_uses_taxonomy(code: MCPErrorCode, status: int, jsonrpc_code: int) -> None:
    problem = ProblemDetail.from_code(code, "something went wrong")
    assert problem.status == status
    assert problem.type == ERROR_TAXONOMY[code].type
    assert problem.title == ERROR_TAXONOMY[code].title
    assert problem.jsonrpc_code == jsonrpc_code


def test_problem_serialises_as_problem_json() -> None:
    problem = ProblemDetail.from_code(
        MCPErrorCode.QUERY_VIOLATION,
        "DROP statements are not permitted",
        instance="urn:uuid:0b6f3f1e-7c1a-4a6b-9d2e-2f1d6c9a8b7e",
        invalid_params=("query",),
        metadata={"keyword": "DROP"},
    )
    body = problem.to_json_dict()
    assert PROBLEM_JSON_MEDIA_TYPE == "application/problem+json"
    assert body == {
        "type": "urn:mcp-server-suite:problem:query-violation",
        "title": "Query violates the read-only policy",
        "status": 403,
        "detail": "DROP statements are not permitted",
        "code": "MCP_QUERY_VIOLATION",
        "instance": "urn:uuid:0b6f3f1e-7c1a-4a6b-9d2e-2f1d6c9a8b7e",
        "invalid_params": ["query"],
        "metadata": {"keyword": "DROP"},
    }
    json.dumps(body)


def test_problem_omits_absent_instance() -> None:
    body = ProblemDetail.from_code(MCPErrorCode.INTERNAL_ERROR, "boom").to_json_dict()
    assert "instance" not in body
    assert body["invalid_params"] == []
    assert body["metadata"] == {}


def test_problem_round_trips_from_json() -> None:
    problem = ProblemDetail.from_code(
        MCPErrorCode.ACCESS_DENIED, "path escapes sandbox", invalid_params=("relative_path",)
    )
    restored = ProblemDetail.model_validate_json(json.dumps(problem.to_json_dict()))
    assert restored.code is MCPErrorCode.ACCESS_DENIED
    assert restored.invalid_params == ("relative_path",)


def test_problem_metadata_is_immutable() -> None:
    source = {"limit": 50}
    problem = ProblemDetail.from_code(MCPErrorCode.VALIDATION_ERROR, "bad", metadata=source)
    source["limit"] = 0
    assert problem.metadata["limit"] == 50
    with pytest.raises(TypeError):
        problem.metadata["limit"] = 1  # type: ignore[index]


def test_problem_invalid_params_is_tuple() -> None:
    problem = ProblemDetail(**_problem(invalid_params=("max_rows", "query")))
    assert problem.invalid_params == ("max_rows", "query")
    assert isinstance(problem.invalid_params, tuple)


@pytest.mark.parametrize("status", [399, 600, 200])
def test_problem_status_range(status: int) -> None:
    with pytest.raises(ValidationError):
        ProblemDetail(**_problem(status=status))


def test_problem_status_must_match_code() -> None:
    with pytest.raises(ValidationError, match="does not match MCP_VALIDATION_ERROR"):
        ProblemDetail(**_problem(status=500))


def test_problem_type_must_match_code() -> None:
    with pytest.raises(ValidationError, match="type 'about:blank' does not match"):
        ProblemDetail(**_problem(type="about:blank"))


@pytest.mark.parametrize("bad_uri", ["", "has space", "urn:x\n", "<script>"])
def test_problem_type_must_be_uri_reference(bad_uri: str) -> None:
    with pytest.raises(ValidationError):
        ProblemDetail(**_problem(type=bad_uri))


def test_problem_instance_must_be_uri_reference() -> None:
    with pytest.raises(ValidationError):
        ProblemDetail(**_problem(instance="not a uri"))


@pytest.mark.parametrize("field", ["title", "detail"])
def test_problem_text_fields_required(field: str) -> None:
    payload = _problem()
    del payload[field]
    with pytest.raises(ValidationError):
        ProblemDetail(**payload)
    with pytest.raises(ValidationError):
        ProblemDetail(**_problem(**{field: ""}))


def test_problem_unknown_code_rejected() -> None:
    with pytest.raises(ValidationError):
        ProblemDetail.model_validate_json(json.dumps({**_problem(), "code": "MCP_SOMETHING_ELSE"}))


# ---------------------------------------------------------------------------
# Package surface
# ---------------------------------------------------------------------------
def test_tool_names() -> None:
    assert [t.value for t in ToolName] == ["read_only_sql", "sandbox_fs_read", "system_metrics"]


def test_package_exports_are_resolvable() -> None:
    assert len(schemas.__all__) == len(set(schemas.__all__))
    public = {name for name in vars(schemas) if not name.startswith("_")} - {
        "errors",
        "tools",
    }
    assert set(schemas.__all__) == public
    for name in schemas.__all__:
        assert getattr(schemas, name) is not None

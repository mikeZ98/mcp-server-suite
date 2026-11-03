"""Hermetic security tests for ``read_only_sql`` (no database: asyncpg is faked)."""

import asyncio
import json
import logging
import math
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from ipaddress import IPv4Address
from typing import Any
from uuid import UUID

import asyncpg
import mcp_types
import pytest
from pydantic import SecretStr, ValidationError

from mcp_server_suite.core import MCPServer, ToolError, ToolRegistry
from mcp_server_suite.schemas import (
    ERROR_TAXONOMY,
    MCPErrorCode,
    ProblemDetail,
    ReadOnlySqlParams,
    SqlQueryResult,
)
from mcp_server_suite.tools import ReadOnlySqlTool, SqlSettings, open_tool_registry
from mcp_server_suite.tools.sql import create_asyncpg_pool, enforce_read_only

DSN = "postgresql://reader@db.invalid:5432/app"
TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# asyncpg fakes
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FakeAttribute:
    name: str


@dataclass
class FakeConnection:
    columns: tuple[str, ...] = ("id", "name")
    rows: list[tuple[Any, ...]] = field(default_factory=lambda: [(1, "ada"), (2, "grace")])
    prepare_error: BaseException | None = None
    fetch_error: BaseException | None = None
    rollback_error: BaseException | None = None
    calls: list[tuple[Any, ...]] = field(default_factory=list)

    def transaction(self, *, readonly: bool = False) -> "FakeTransaction":
        self.calls.append(("transaction", readonly))
        return FakeTransaction(self)

    async def execute(self, query: str, *args: Any, timeout: float | None = None) -> str:
        self.calls.append(("execute", query, args, timeout))
        return "SELECT 1"

    async def prepare(self, query: str, *, timeout: float | None = None) -> "FakeStatement":
        self.calls.append(("prepare", query, timeout))
        if self.prepare_error is not None:
            raise self.prepare_error
        return FakeStatement(self)

    @property
    def call_names(self) -> list[str]:
        return [call[0] for call in self.calls]


@dataclass
class FakeTransaction:
    conn: FakeConnection

    async def start(self) -> None:
        self.conn.calls.append(("begin",))

    async def rollback(self) -> None:
        self.conn.calls.append(("rollback",))
        if self.conn.rollback_error is not None:
            raise self.conn.rollback_error


@dataclass
class FakeStatement:
    conn: FakeConnection

    def get_attributes(self) -> tuple[FakeAttribute, ...]:
        return tuple(FakeAttribute(name) for name in self.conn.columns)

    async def fetch(self, *args: Any, timeout: float | None = None) -> list[Any]:
        self.conn.calls.append(("fetch", timeout))
        if self.conn.fetch_error is not None:
            raise self.conn.fetch_error
        return list(self.conn.rows)


@dataclass
class FakePool:
    conn: FakeConnection
    acquire_error: BaseException | None = None
    acquire_timeouts: list[float | None] = field(default_factory=list)
    closed: bool = False

    @asynccontextmanager
    async def _acquire(self) -> AsyncIterator[FakeConnection]:
        if self.acquire_error is not None:
            raise self.acquire_error
        yield self.conn

    def acquire(self, *, timeout: float | None = None) -> Any:
        self.acquire_timeouts.append(timeout)
        return self._acquire()

    async def close(self) -> None:
        self.closed = True


@dataclass
class PoolFactory:
    pool: FakePool
    calls: int = 0

    async def __call__(self, settings: SqlSettings) -> FakePool:
        self.calls += 1
        return self.pool


@pytest.fixture
def settings() -> SqlSettings:
    return SqlSettings(dsn=SecretStr(DSN), connect_timeout=2.0, query_timeout=3.0)


@pytest.fixture
def conn() -> FakeConnection:
    return FakeConnection()


@pytest.fixture
def pool(conn: FakeConnection) -> FakePool:
    return FakePool(conn)


@pytest.fixture
def factory(pool: FakePool) -> PoolFactory:
    return PoolFactory(pool)


@pytest.fixture
def tool(settings: SqlSettings, factory: PoolFactory) -> ReadOnlySqlTool:
    return ReadOnlySqlTool(settings, pool_factory=factory)


def violation(query: str, code: MCPErrorCode = MCPErrorCode.QUERY_VIOLATION) -> ProblemDetail:
    with pytest.raises(ToolError) as exc_info:
        enforce_read_only(query)
    problem = exc_info.value.problem
    assert problem.code is code, problem
    assert problem.invalid_params == ("query",)
    return problem


# ---------------------------------------------------------------------------
# AST policy: single statement
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "query",
    [
        "SELECT 1; DROP TABLE users;",
        "SELECT 1; VACUUM;",
        "SELECT 1;DROP TABLE users",
        "select 1; drop table users",
        "SELECT 1; SELECT 2",
        "SELECT * FROM t;\nDELETE FROM t",
        "SELECT 1; COMMIT; DROP TABLE users",
    ],
)
def test_multi_statement_injection_rejected(query: str) -> None:
    problem = violation(query)
    assert problem.detail.startswith("exactly one statement is allowed")
    assert problem.metadata["statements"] >= 2


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("SELECT 'a; DROP TABLE t'", "SELECT 'a; DROP TABLE t' LIMIT 50"),
        ("SELECT 1 /* ; DROP TABLE users */", "SELECT 1 LIMIT 50"),
        ("SELECT 1 -- ; DROP TABLE users", "SELECT 1 LIMIT 50"),
        ("SELECT 1;", "SELECT 1 LIMIT 50"),
        ("SELECT 1;;", "SELECT 1 LIMIT 50"),
    ],
)
def test_semicolons_inside_literals_comments_or_trailing_are_one_statement(
    query: str, expected: str
) -> None:
    assert enforce_read_only(query).sql == expected


# ---------------------------------------------------------------------------
# AST policy: mutation blocker
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "query",
    [
        "INSERT INTO users (name) VALUES ('x')",
        "UPDATE users SET admin = true",
        "DELETE FROM users",
        "ALTER TABLE users ADD COLUMN pwned int",
        "TRUNCATE users",
        "GRANT ALL ON users TO public",
        "REVOKE SELECT ON users FROM reader",
        "COPY users TO '/tmp/users.csv'",
        "COPY users FROM PROGRAM 'id'",
        "CREATE TABLE pwned (a int)",
        "DROP TABLE users",
        "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
        "VACUUM",
        "ANALYZE users",
        "SET search_path TO evil",
        "SET SESSION AUTHORIZATION postgres",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "EXPLAIN ANALYZE DELETE FROM users",
        "DO $$ BEGIN DELETE FROM users; END $$",
        "CALL purge()",
        "PREPARE p AS DELETE FROM users",
        "EXECUTE p",
        "LOCK TABLE users",
        "LISTEN channel",
        "NOTIFY channel",
        "REFRESH MATERIALIZED VIEW v",
        "SHOW search_path",
        "VALUES (1)",
        "TABLE users",
        "(SELECT 1)",
    ],
)
def test_non_select_statements_rejected(query: str) -> None:
    violation(query)


@pytest.mark.parametrize(
    ("query", "node"),
    [
        ("WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d", "Delete"),
        ("WITH i AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM i", "Insert"),
        ("WITH u AS (UPDATE t SET a = 1 RETURNING a) SELECT a FROM u", "Update"),
        (
            "WITH safe AS (SELECT 1), d AS (DELETE FROM users RETURNING id) SELECT * FROM safe",
            "Delete",
        ),
        (
            "SELECT 1 UNION ALL (WITH d AS (DELETE FROM t RETURNING 1) SELECT * FROM d)",
            "Delete",
        ),
        ("SELECT * INTO stolen FROM users", "Into"),
        ("SELECT * FROM users FOR UPDATE", "Lock"),
        ("SELECT * FROM users FOR SHARE", "Lock"),
        ("SELECT * FROM users FOR NO KEY UPDATE SKIP LOCKED", "Lock"),
    ],
)
def test_writes_and_locks_nested_in_select_rejected(query: str, node: str) -> None:
    assert violation(query).metadata["node"] == node


@pytest.mark.parametrize(
    ("query", "function"),
    [
        ("SELECT pg_sleep(10)", "pg_sleep"),
        ("SELECT pg_catalog.pg_sleep(10)", "pg_sleep"),
        ('SELECT "pg_sleep"(10)', "pg_sleep"),
        ("SELECT PG_SLEEP(10)", "pg_sleep"),
        ("SELECT * FROM users WHERE pg_sleep(1) IS NULL", "pg_sleep"),
        ("SELECT dblink_exec('host=x', 'DELETE FROM users')", "dblink_exec"),
        ("SELECT * FROM dblink('host=x', 'SELECT 1') AS t(a int)", "dblink"),
        ("SELECT lo_export(1, '/tmp/x')", "lo_export"),
        ("SELECT pg_terminate_backend(42)", "pg_terminate_backend"),
        ("SELECT pg_cancel_backend(42)", "pg_cancel_backend"),
        ("SELECT set_config('statement_timeout', '0', false)", "set_config"),
        ("SELECT query_to_xml('DELETE FROM users', true, true, '')", "query_to_xml"),
        ("SELECT pg_advisory_lock(1)", "pg_advisory_lock"),
        ("SELECT pg_read_file('/etc/passwd')", "pg_read_file"),
        ("SELECT pg_ls_dir('.')", "pg_ls_dir"),
        ("SELECT pg_reload_conf()", "pg_reload_conf"),
        ("SELECT pg_notify('c', 'x')", "pg_notify"),
    ],
)
def test_side_effecting_functions_rejected(query: str, function: str) -> None:
    assert violation(query).metadata["function"] == function


@pytest.mark.parametrize(
    "query",
    [
        "SELECT count(*) FROM users",
        "SELECT lower(name), now(), current_setting('search_path') FROM users",
        "SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id WHERE o.total > 10",
        "WITH recent AS (SELECT * FROM orders ORDER BY created_at DESC) SELECT * FROM recent",
        "SELECT id FROM a UNION SELECT id FROM b",
        "SELECT id FROM a INTERSECT SELECT id FROM b",
        "SELECT id FROM a EXCEPT SELECT id FROM b",
        "SELECT * FROM (VALUES (1), (2)) AS v(n)",
        "SELECT row_number() OVER (PARTITION BY a ORDER BY b) FROM t",
        "SELECT jsonb_build_object('a', 1)",
    ],
)
def test_read_only_queries_allowed(query: str) -> None:
    enforced = enforce_read_only(query)
    assert enforced.sql.endswith("LIMIT 50")


@pytest.mark.parametrize(
    "query", ["SELEC 1", "SELECT 'unterminated", ";;", "SELECT * FROM", "SELECT (1"]
)
def test_syntax_errors_are_validation_errors(query: str) -> None:
    problem = violation(query, MCPErrorCode.VALIDATION_ERROR)
    assert "\x1b" not in problem.detail, "no terminal escape codes in problem text"


def test_parse_error_reports_position() -> None:
    problem = violation("SELECT * FROM", MCPErrorCode.VALIDATION_ERROR)
    assert problem.detail.startswith("SQL syntax error:")
    assert problem.metadata["line"] == 1


@pytest.mark.parametrize("query", ["SELECT * FROM t WHERE id = $1", "SELECT * FROM t LIMIT $1"])
def test_bind_parameters_rejected(query: str) -> None:
    assert "bind parameters" in violation(query, MCPErrorCode.VALIDATION_ERROR).detail


# ---------------------------------------------------------------------------
# LIMIT enforcement
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("query", "expected_sql", "requested"),
    [
        ("SELECT * FROM users", "SELECT * FROM users LIMIT 50", None),
        ("SELECT * FROM users LIMIT 500", "SELECT * FROM users LIMIT 50", 500),
        ("SELECT * FROM users LIMIT 10", "SELECT * FROM users LIMIT 10", 10),
        ("SELECT * FROM users LIMIT 50", "SELECT * FROM users LIMIT 50", 50),
        ("SELECT * FROM users LIMIT 51", "SELECT * FROM users LIMIT 50", 51),
        ("SELECT * FROM users LIMIT 0", "SELECT * FROM users LIMIT 0", 0),
        ("SELECT * FROM users LIMIT 10 OFFSET 5", "SELECT * FROM users LIMIT 10 OFFSET 5", 10),
        ("SELECT * FROM users LIMIT 999 OFFSET 5", "SELECT * FROM users LIMIT 50 OFFSET 5", 999),
        ("SELECT * FROM users LIMIT ALL", "SELECT * FROM users LIMIT 50", None),
        ("SELECT * FROM users LIMIT NULL", "SELECT * FROM users LIMIT 50", None),
        ("SELECT * FROM users LIMIT -1", "SELECT * FROM users LIMIT 50", None),
        ("SELECT * FROM users LIMIT 10.5", "SELECT * FROM users LIMIT 50", None),
        ("SELECT * FROM users LIMIT 10 + 90", "SELECT * FROM users LIMIT 50", None),
        ("SELECT * FROM users LIMIT (SELECT 1000)", "SELECT * FROM users LIMIT 50", None),
        ("SELECT * FROM users FETCH FIRST 100 ROWS ONLY", "SELECT * FROM users LIMIT 50", 100),
        ("SELECT * FROM users FETCH FIRST 5 ROWS ONLY", "SELECT * FROM users LIMIT 5", 5),
        ("SELECT * FROM users FETCH NEXT 3 ROWS ONLY", "SELECT * FROM users LIMIT 3", 3),
        ("SELECT * FROM users FETCH FIRST ROW ONLY", "SELECT * FROM users LIMIT 1", 1),
        ("SELECT * FROM users FETCH FIRST 5 ROWS WITH TIES", "SELECT * FROM users LIMIT 50", None),
        (
            "SELECT * FROM users FETCH FIRST 5 PERCENT ROWS ONLY",
            "SELECT * FROM users LIMIT 50",
            None,
        ),
        ("SELECT 1 UNION SELECT 2 LIMIT 500", "SELECT 1 UNION SELECT 2 LIMIT 50", 500),
        (
            "SELECT * FROM (SELECT * FROM users LIMIT 1000) AS s",
            "SELECT * FROM (SELECT * FROM users LIMIT 1000) AS s LIMIT 50",
            None,
        ),
    ],
)
def test_limit_enforcement(query: str, expected_sql: str, requested: int | None) -> None:
    enforced = enforce_read_only(query)
    assert enforced.sql == expected_sql
    assert enforced.requested_limit == requested
    assert enforced.row_cap == 50


def test_cap_applied_flag() -> None:
    assert enforce_read_only("SELECT 1").cap_applied
    assert enforce_read_only("SELECT 1 LIMIT 500").cap_applied
    assert not enforce_read_only("SELECT 1 LIMIT 10").cap_applied
    assert not enforce_read_only("SELECT 1 LIMIT 50").cap_applied


@pytest.mark.parametrize(
    ("query", "max_rows", "expected"),
    [
        ("SELECT 1", 5, "SELECT 1 LIMIT 5"),
        ("SELECT 1 LIMIT 20", 5, "SELECT 1 LIMIT 5"),
        ("SELECT 1 LIMIT 3", 5, "SELECT 1 LIMIT 3"),
    ],
)
def test_max_rows_lowers_the_cap(query: str, max_rows: int, expected: str) -> None:
    assert enforce_read_only(query, max_rows=max_rows).sql == expected


@pytest.mark.parametrize("max_rows", [0, 51])
def test_max_rows_bounds(max_rows: int) -> None:
    with pytest.raises(ValueError, match="max_rows"):
        enforce_read_only("SELECT 1", max_rows=max_rows)


@pytest.mark.parametrize(
    "query",
    [
        "SELECT * FROM users",
        "select id from users where name = 'O''Brien' limit 500",
        "WITH x AS (SELECT 1 AS a) SELECT a FROM x UNION SELECT 2",
        "SELECT * FROM users FETCH FIRST 7 ROWS ONLY",
    ],
)
def test_rewrite_is_deterministic_and_idempotent(query: str) -> None:
    first = enforce_read_only(query).sql
    assert enforce_read_only(query).sql == first
    assert enforce_read_only(first).sql == first


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def test_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_SQL_DSN", DSN)
    monkeypatch.setenv("MCP_SQL_QUERY_TIMEOUT", "2.5")
    monkeypatch.setenv("MCP_SQL_POOL_MAX_SIZE", "8")
    settings = SqlSettings()
    assert settings.dsn is not None
    assert settings.dsn.get_secret_value() == DSN
    assert settings.query_timeout == 2.5
    assert settings.pool_max_size == 8
    assert settings.statement_timeout_ms == 2500
    assert DSN not in repr(settings)


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_SQL_DSN", raising=False)
    settings = SqlSettings()
    assert settings.dsn is None
    assert (settings.connect_timeout, settings.query_timeout) == (5.0, 10.0)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dsn": "mysql://x"},
        {"dsn": "host=db user=reader"},
        {"query_timeout": 0},
        {"query_timeout": 301},
        {"connect_timeout": -1},
        {"pool_max_size": 0},
        {"unknown": 1},
    ],
)
def test_settings_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SqlSettings(**kwargs)


def test_settings_are_frozen(settings: SqlSettings) -> None:
    with pytest.raises(ValidationError):
        settings.query_timeout = 1.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Execution (mocked asyncpg)
# ---------------------------------------------------------------------------
async def test_execution_runs_in_read_only_rolled_back_transaction(
    tool: ReadOnlySqlTool, conn: FakeConnection, pool: FakePool
) -> None:
    result = await tool(ReadOnlySqlParams(query="SELECT id, name FROM users LIMIT 10"))
    assert conn.call_names == ["transaction", "begin", "execute", "prepare", "fetch", "rollback"]
    assert conn.calls[0] == ("transaction", True)
    assert conn.calls[2] == (
        "execute",
        "SELECT set_config('statement_timeout', $1, true)",
        ("3000",),
        3.0,
    )
    assert conn.calls[3] == ("prepare", "SELECT id, name FROM users LIMIT 10", 3.0)
    assert conn.calls[4] == ("fetch", 3.0)
    assert pool.acquire_timeouts == [2.0]
    assert result == SqlQueryResult(
        columns=("id", "name"), rows=((1, "ada"), (2, "grace")), row_count=2, truncated=False
    )


async def test_rows_and_columns_are_immutable_tuples(tool: ReadOnlySqlTool) -> None:
    result = await tool(ReadOnlySqlParams(query="SELECT id, name FROM users"))
    assert isinstance(result.columns, tuple)
    assert isinstance(result.rows, tuple)
    assert all(isinstance(row, tuple) for row in result.rows)
    with pytest.raises(ValidationError):
        result.rows = ()  # type: ignore[misc]


async def test_injected_limit_is_what_executes(tool: ReadOnlySqlTool, conn: FakeConnection) -> None:
    await tool(ReadOnlySqlParams(query="SELECT * FROM users -- dump everything"))
    assert conn.calls[3][1] == "SELECT * FROM users LIMIT 50"


async def test_truncated_when_cap_reached(conn: FakeConnection, tool: ReadOnlySqlTool) -> None:
    conn.rows = [(i, f"u{i}") for i in range(50)]
    result = await tool(ReadOnlySqlParams(query="SELECT * FROM users"))
    assert (result.row_count, result.truncated) == (50, True)


async def test_not_truncated_when_users_own_limit_reached(
    conn: FakeConnection, tool: ReadOnlySqlTool
) -> None:
    conn.rows = [(i, f"u{i}") for i in range(10)]
    result = await tool(ReadOnlySqlParams(query="SELECT * FROM users LIMIT 10"))
    assert (result.row_count, result.truncated) == (10, False)


async def test_rows_beyond_cap_are_discarded_defensively(
    conn: FakeConnection, tool: ReadOnlySqlTool
) -> None:
    conn.rows = [(i, "x") for i in range(80)]
    result = await tool(ReadOnlySqlParams(query="SELECT * FROM users", max_rows=5))
    assert (result.row_count, result.truncated) == (5, True)


async def test_empty_result_keeps_columns(conn: FakeConnection, tool: ReadOnlySqlTool) -> None:
    conn.rows = []
    result = await tool(ReadOnlySqlParams(query="SELECT id, name FROM users WHERE false"))
    assert result == SqlQueryResult(columns=("id", "name"), rows=(), row_count=0, truncated=False)


async def test_postgres_values_are_json_safe(conn: FakeConnection, tool: ReadOnlySqlTool) -> None:
    uid = UUID("12345678-1234-5678-1234-567812345678")
    stamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    values: tuple[Any, ...] = (
        None,
        True,
        7,
        "txt",
        1.5,
        math.nan,
        math.inf,
        -math.inf,
        Decimal("12345678901234567890.0001"),
        uid,
        stamp,
        date(2026, 1, 2),
        time(3, 4, 5),
        timedelta(minutes=1, seconds=30),
        b"\x00\xff",
        memoryview(b"ab"),
        [1, [2, 3]],
        {"b": 1, "a": Decimal("2")},
        IPv4Address("10.0.0.1"),
    )
    conn.columns = tuple(f"c{i}" for i in range(len(values)))
    conn.rows = [values]
    result = await tool(ReadOnlySqlParams(query="SELECT * FROM t"))
    assert result.rows[0] == (
        None,
        True,
        7,
        "txt",
        1.5,
        "NaN",
        "Infinity",
        "-Infinity",
        "12345678901234567890.0001",
        "12345678-1234-5678-1234-567812345678",
        "2026-01-02T03:04:05+00:00",
        "2026-01-02",
        "03:04:05",
        90.0,
        "\\x00ff",
        "\\x6162",
        (1, (2, 3)),
        '{"a": "2", "b": 1}',
        "10.0.0.1",
    )
    json.loads(result.model_dump_json())  # strictly valid JSON (no NaN tokens)


async def test_pool_is_created_lazily_once_and_closed(
    tool: ReadOnlySqlTool, factory: PoolFactory, pool: FakePool
) -> None:
    assert factory.calls == 0
    await asyncio.gather(*(tool(ReadOnlySqlParams(query="SELECT 1")) for _ in range(3)))
    assert factory.calls == 1
    await tool.aclose()
    assert pool.closed
    await tool.aclose()


async def test_aclose_without_pool_is_noop(tool: ReadOnlySqlTool, factory: PoolFactory) -> None:
    await tool.aclose()
    assert factory.calls == 0


@pytest.mark.parametrize(
    "query",
    ["SELECT 1; DROP TABLE users;", "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"],
)
async def test_policy_violation_never_touches_the_database(
    tool: ReadOnlySqlTool, factory: PoolFactory, query: str
) -> None:
    with pytest.raises(ToolError):
        await tool(ReadOnlySqlParams(query=query))
    assert factory.calls == 0


@pytest.mark.parametrize(
    ("error", "code", "sqlstate"),
    [
        (
            asyncpg.exceptions.UndefinedTableError('relation "x" does not exist'),
            "VALIDATION",
            "42P01",
        ),
        (asyncpg.exceptions.UndefinedColumnError("column nope"), "VALIDATION", "42703"),
        (asyncpg.exceptions.PostgresSyntaxError("syntax error at or near"), "VALIDATION", "42601"),
        (asyncpg.exceptions.DivisionByZeroError("division by zero"), "VALIDATION", "22012"),
        (asyncpg.exceptions.CardinalityViolationError("more than one row"), "VALIDATION", "21000"),
        (asyncpg.exceptions.QueryCanceledError("canceling statement"), "TIMEOUT", "57014"),
        (asyncpg.exceptions.ReadOnlySQLTransactionError("read-only"), "VIOLATION", "25006"),
        (asyncpg.exceptions.InsufficientPrivilegeError("permission denied"), "DENIED", "42501"),
    ],
)
async def test_query_errors_become_problems(
    conn: FakeConnection,
    tool: ReadOnlySqlTool,
    error: asyncpg.PostgresError,
    code: str,
    sqlstate: str,
) -> None:
    expected = {
        "VALIDATION": MCPErrorCode.VALIDATION_ERROR,
        "TIMEOUT": MCPErrorCode.EXECUTION_TIMEOUT,
        "VIOLATION": MCPErrorCode.QUERY_VIOLATION,
        "DENIED": MCPErrorCode.ACCESS_DENIED,
    }[code]
    conn.fetch_error = error
    with pytest.raises(ToolError) as exc_info:
        await tool(ReadOnlySqlParams(query="SELECT * FROM x"))
    assert exc_info.value.problem.code is expected
    assert exc_info.value.problem.metadata["sqlstate"] == sqlstate
    assert conn.call_names[-1] == "rollback"


@pytest.mark.parametrize(
    "error",
    [
        asyncpg.exceptions.TooManyConnectionsError("too many clients"),
        asyncpg.exceptions.AdminShutdownError("terminating connection"),
        asyncpg.exceptions.DiskFullError("no space"),
    ],
)
async def test_infrastructure_errors_propagate(
    conn: FakeConnection, tool: ReadOnlySqlTool, error: asyncpg.PostgresError
) -> None:
    conn.prepare_error = error
    with pytest.raises(type(error)):
        await tool(ReadOnlySqlParams(query="SELECT 1"))
    assert conn.call_names[-1] == "rollback"


async def test_timeout_propagates_after_rollback(
    conn: FakeConnection, tool: ReadOnlySqlTool
) -> None:
    conn.fetch_error = TimeoutError()
    with pytest.raises(TimeoutError):
        await tool(ReadOnlySqlParams(query="SELECT 1"))
    assert conn.call_names[-1] == "rollback"


async def test_failed_rollback_does_not_mask_result(
    conn: FakeConnection, tool: ReadOnlySqlTool
) -> None:
    conn.rollback_error = asyncpg.exceptions.InterfaceError("connection is closed")
    result = await tool(ReadOnlySqlParams(query="SELECT 1"))
    assert result.row_count == 2


async def test_create_asyncpg_pool_uses_read_only_session_defaults(
    monkeypatch: pytest.MonkeyPatch, settings: SqlSettings
) -> None:
    captured: dict[str, Any] = {}

    async def fake_create_pool(**kwargs: Any) -> FakePool:
        captured.update(kwargs)
        return FakePool(FakeConnection())

    monkeypatch.setattr(asyncpg, "create_pool", fake_create_pool)
    await create_asyncpg_pool(settings)
    assert captured["dsn"] == DSN
    assert captured["min_size"] == 0
    assert captured["timeout"] == 2.0
    assert captured["command_timeout"] == 3.0
    assert captured["server_settings"] == {
        "application_name": "mcp-server-suite",
        "default_transaction_read_only": "on",
        "statement_timeout": "3000",
    }


async def test_create_asyncpg_pool_requires_dsn() -> None:
    with pytest.raises(RuntimeError, match="dsn"):
        await create_asyncpg_pool(SqlSettings(dsn=None))


# ---------------------------------------------------------------------------
# MCP protocol conformance (through MCPServer)
# ---------------------------------------------------------------------------
INIT = {
    "jsonrpc": "2.0",
    "id": "init",
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t"}},
}


def call(request_id: int, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "read_only_sql", "arguments": arguments},
    }


class Collector:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def write(self, data: bytes, /) -> None:
        self.messages.append(json.loads(data))

    async def aclose(self) -> None:
        return None


async def exchange(tool: ReadOnlySqlTool, messages: Iterable[dict[str, Any]]) -> dict[Any, Any]:
    reader = asyncio.StreamReader()
    for message in (INIT, *messages):
        reader.feed_data(json.dumps(message).encode() + b"\n")
    reader.feed_eof()
    sink = Collector()
    server = MCPServer(ToolRegistry([tool.definition()]))
    await asyncio.wait_for(server.serve(reader, sink), TIMEOUT)
    return {message["id"]: message for message in sink.messages}


def tool_problem(response: dict[str, Any], code: MCPErrorCode) -> dict[str, Any]:
    result = mcp_types.CallToolResult.model_validate(response["result"])
    assert result.is_error is True
    assert "structuredContent" not in response["result"]
    (content,) = response["result"]["content"]
    problem = ProblemDetail.model_validate_json(content["text"])
    assert problem.code is code
    data: dict[str, Any] = json.loads(content["text"])
    return data


async def test_tools_list_advertises_read_only_sql(tool: ReadOnlySqlTool) -> None:
    responses = await exchange(tool, [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
    (spec,) = responses[1]["result"]["tools"]
    mcp_types.Tool.model_validate(spec)
    assert spec["name"] == "read_only_sql"
    assert spec["annotations"]["readOnlyHint"] is True
    assert spec["annotations"]["destructiveHint"] is False
    assert spec["inputSchema"]["properties"]["max_rows"]["maximum"] == 50
    assert spec["inputSchema"]["additionalProperties"] is False


async def test_successful_call_returns_structured_content(tool: ReadOnlySqlTool) -> None:
    responses = await exchange(tool, [call(1, {"query": "SELECT id, name FROM users"})])
    result = mcp_types.CallToolResult.model_validate(responses[1]["result"])
    assert result.is_error is False
    assert responses[1]["result"]["structuredContent"] == {
        "columns": ["id", "name"],
        "rows": [[1, "ada"], [2, "grace"]],
        "row_count": 2,
        "truncated": False,
    }


async def test_injection_returns_is_error_problem_details(tool: ReadOnlySqlTool) -> None:
    responses = await exchange(tool, [call(1, {"query": "SELECT 1; DROP TABLE users;"})])
    problem = tool_problem(responses[1], MCPErrorCode.QUERY_VIOLATION)
    spec = ERROR_TAXONOMY[MCPErrorCode.QUERY_VIOLATION]
    assert problem["type"] == spec.type
    assert problem["title"] == spec.title
    assert problem["status"] == 403
    assert problem["code"] == "MCP_QUERY_VIOLATION"
    assert problem["invalid_params"] == ["query"]
    assert problem["detail"] == "exactly one statement is allowed, found 2"


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({"query": "SELECT (1"}, MCPErrorCode.VALIDATION_ERROR),
        ({"query": "SELEC broken"}, MCPErrorCode.QUERY_VIOLATION),
        ({"query": "SELECT 1", "max_rows": 500}, MCPErrorCode.VALIDATION_ERROR),
        ({"query": "SELECT 1", "max_rows": "50"}, MCPErrorCode.VALIDATION_ERROR),
        ({"query": "UPDATE users SET admin = true"}, MCPErrorCode.QUERY_VIOLATION),
    ],
)
async def test_tool_errors_are_in_band(
    tool: ReadOnlySqlTool, arguments: dict[str, Any], code: MCPErrorCode
) -> None:
    responses = await exchange(tool, [call(1, arguments)])
    tool_problem(responses[1], code)


async def test_database_error_is_in_band(conn: FakeConnection, tool: ReadOnlySqlTool) -> None:
    conn.fetch_error = asyncpg.exceptions.UndefinedTableError('relation "nope" does not exist')
    responses = await exchange(tool, [call(1, {"query": "SELECT * FROM nope"})])
    problem = tool_problem(responses[1], MCPErrorCode.VALIDATION_ERROR)
    assert problem["metadata"] == {"sqlstate": "42P01"}
    assert 'relation "nope" does not exist' in problem["detail"]


async def test_driver_timeout_is_in_band(conn: FakeConnection, tool: ReadOnlySqlTool) -> None:
    conn.fetch_error = TimeoutError()
    responses = await exchange(tool, [call(1, {"query": "SELECT 1"})])
    tool_problem(responses[1], MCPErrorCode.EXECUTION_TIMEOUT)


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError("connection refused"),
        asyncpg.exceptions.TooManyConnectionsError("too many clients"),
    ],
)
async def test_infrastructure_crash_is_json_rpc_internal_error(
    pool: FakePool, tool: ReadOnlySqlTool, error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    pool.acquire_error = error
    with caplog.at_level(logging.ERROR):
        responses = await exchange(tool, [call(1, {"query": "SELECT 1"})])
    response = responses[1]
    mcp_types.JSONRPCError.model_validate(response)
    assert response["error"]["code"] == -32603
    assert response["error"]["data"]["code"] == "MCP_INTERNAL_ERROR"
    assert "refused" not in response["error"]["message"]
    assert "too many" not in response["error"]["message"]


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------
async def test_open_tool_registry_registers_sql_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []

    async def fake_aclose(self: ReadOnlySqlTool) -> None:
        closed.append(True)

    monkeypatch.setattr(ReadOnlySqlTool, "aclose", fake_aclose)
    async with open_tool_registry(sql=SqlSettings(dsn=SecretStr(DSN))) as registry:
        assert "read_only_sql" in registry
    assert closed == [True]


async def test_open_tool_registry_skips_sql_without_dsn(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("MCP_SQL_DSN", raising=False)
    with caplog.at_level(logging.WARNING):
        async with open_tool_registry() as registry:
            assert "read_only_sql" not in registry
    assert "MCP_SQL_DSN is not set" in caplog.text

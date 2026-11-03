"""``read_only_sql``: AST-validated, row-capped, read-only PostgreSQL queries.

Defence in depth, outermost first:

1. **AST policy** (:func:`enforce_read_only`): exactly one statement whose root is
   a ``SELECT`` or set operation; no DML/DDL/command node anywhere in the tree
   (catches writes in CTEs); no ``SELECT INTO``, row locks, bind parameters, or
   functions with side effects outside the transaction; ``LIMIT`` rewritten to
   at most ``max_rows``. The SQL sent to the server is regenerated from the
   validated AST (comments dropped) and re-validated.
2. **Transaction**: every query runs in ``BEGIN READ ONLY`` with a local
   ``statement_timeout`` and is always rolled back, which also discards any
   session state a query might have changed via ``set_config``.
3. **Session defaults**: pooled connections start with
   ``default_transaction_read_only=on`` and a ``statement_timeout``.

The database role should still be a least-privilege, read-only role; these
layers are not a substitute for ``GRANT``-level isolation.
"""

import asyncio
import json
import logging
import math
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, suppress
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Annotated, Any, Final, Protocol
from uuid import UUID

import asyncpg
import sqlglot
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from mcp_server_suite.core.registry import ToolDefinition, ToolError
from mcp_server_suite.schemas import (
    SQL_MAX_ROWS_LIMIT,
    MCPErrorCode,
    ProblemDetail,
    ReadOnlySqlParams,
    SqlQueryResult,
    ToolName,
)

__all__ = [
    "EnforcedQuery",
    "ReadOnlySqlTool",
    "SqlSettings",
    "enforce_read_only",
]

logger = logging.getLogger(__name__)

DIALECT: Final = "postgres"

# Node types that must not appear anywhere in the tree. ``Command`` is sqlglot's
# fallback for statements it does not model (VACUUM, DO, CALL, EXPLAIN, ...).
_FORBIDDEN_NODES: Final[tuple[type[exp.Expr], ...]] = (
    exp.DML,
    exp.DDL,
    exp.Drop,
    exp.Alter,
    exp.TruncateTable,
    exp.Grant,
    exp.Revoke,
    exp.Command,
    exp.Set,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Analyze,
    exp.Refresh,
    exp.Pragma,
    exp.Use,
    exp.Execute,
    exp.Into,
    exp.Lock,
)
_BIND_PARAMETERS: Final = (exp.Parameter, exp.Placeholder)

# Functions whose effects escape a rolled-back read-only transaction: dynamic SQL,
# other connections, server files, signals, session-level locks, sleeping.
_FORBIDDEN_FUNCTION_PREFIXES: Final = (
    "dblink",
    "lo_",
    "pg_advisory",
    "pg_try_advisory",
    "pg_cancel_backend",
    "pg_terminate_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_switch_wal",
    "pg_promote",
    "pg_create_",
    "pg_drop_replication_slot",
    "pg_replication_",
    "pg_logical_",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_",
    "pg_stat_file",
    "pg_file_",
    "pg_notify",
    "pg_sleep",
    "set_config",
    "query_to_xml",
    "cursor_to_xml",
)

_SAFE_ROOTS: Final = (exp.Select, exp.SetOperation)
_MAX_DETAIL: Final = 1000


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
class SqlSettings(BaseSettings):
    """Connection settings, read from ``MCP_SQL_*`` environment variables."""

    model_config = SettingsConfigDict(env_prefix="MCP_SQL_", extra="forbid", frozen=True)

    dsn: SecretStr | None = None
    connect_timeout: Annotated[float, Field(gt=0, le=60)] = 5.0
    query_timeout: Annotated[float, Field(gt=0, le=300)] = 10.0
    pool_max_size: Annotated[int, Field(ge=1, le=32)] = 4
    application_name: Annotated[str, Field(min_length=1, max_length=63)] = "mcp-server-suite"

    @field_validator("dsn", mode="after")
    @classmethod
    def _check_dsn(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().startswith(
            ("postgres://", "postgresql://")
        ):
            msg = "dsn must be a postgres:// or postgresql:// URI"
            raise ValueError(msg)
        return value

    @property
    def statement_timeout_ms(self) -> int:
        """Server-side statement timeout, in milliseconds."""
        return math.ceil(self.query_timeout * 1000)


# ---------------------------------------------------------------------------
# AST policy
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class EnforcedQuery:
    """A validated query ready for execution."""

    sql: str
    row_cap: int
    requested_limit: int | None  # literal LIMIT/FETCH count in the original query

    @property
    def cap_applied(self) -> bool:
        """Whether the server cap, not the query's own limit, bounds the result."""
        return self.requested_limit is None or self.requested_limit > self.row_cap


def _violation(detail: str, **metadata: Any) -> ToolError:
    return ToolError(
        ProblemDetail.from_code(
            MCPErrorCode.QUERY_VIOLATION, detail, invalid_params=("query",), metadata=metadata
        )
    )


def _syntax_error(detail: str, **metadata: Any) -> ToolError:
    return ToolError(
        ProblemDetail.from_code(
            MCPErrorCode.VALIDATION_ERROR,
            detail[:_MAX_DETAIL],
            invalid_params=("query",),
            metadata=metadata,
        )
    )


def _parse_single(sql: str) -> exp.Expr:
    try:
        statements = [s for s in sqlglot.parse(sql, read=DIALECT) if s is not None]
    except ParseError as exc:
        first = exc.errors[0] if exc.errors else {}
        raise _syntax_error(
            f"SQL syntax error: {first.get('description', 'unparseable query')}",
            line=first.get("line"),
            column=first.get("col"),
        ) from None
    except TokenError as exc:
        raise _syntax_error(f"SQL syntax error: {exc}") from None
    if not statements:
        raise _syntax_error("query contains no SQL statement")
    if len(statements) > 1:
        raise _violation(
            f"exactly one statement is allowed, found {len(statements)}",
            statements=len(statements),
        )
    return statements[0]


def _function_name(node: exp.Func) -> str:
    return (node.name if isinstance(node, exp.Anonymous) else node.sql_name()).lower()


def _check_tree(root: exp.Expr) -> exp.Query:
    if not isinstance(root, _SAFE_ROOTS):
        raise _violation(
            "only a single SELECT query (optionally with UNION/INTERSECT/EXCEPT) is allowed",
            statement=type(root).__name__,
        )
    for node in root.walk():
        if isinstance(node, _FORBIDDEN_NODES):
            raise _violation(
                f"{type(node).__name__.upper()} is not allowed in a read-only query",
                node=type(node).__name__,
            )
        if isinstance(node, _BIND_PARAMETERS):
            raise _syntax_error("bind parameters are not supported; inline literal values")
        if isinstance(node, exp.Func):
            name = _function_name(node)
            if name.startswith(_FORBIDDEN_FUNCTION_PREFIXES):
                raise _violation(f"function {name}() is not allowed", function=name)
    return root


def _literal_count(limit: exp.Expr) -> int | None:
    """Row count of a LIMIT/FETCH clause, or ``None`` unless it is an exact integer.

    ``PERCENT`` and ``WITH TIES`` can return more rows than the count, so they are
    treated as unbounded and replaced by the cap.
    """
    options = limit.args.get("limit_options")
    if options is not None and (options.args.get("percent") or options.args.get("with_ties")):
        return None
    if isinstance(limit, exp.Fetch):
        count = limit.args.get("count")
        if count is None:  # FETCH FIRST ROW ONLY
            return 1
    else:
        count = limit.expression
    if isinstance(count, exp.Literal) and count.is_int:
        return int(count.this)
    return None


def enforce_read_only(query: str, *, max_rows: int = SQL_MAX_ROWS_LIMIT) -> EnforcedQuery:
    """Validate ``query`` and rewrite its outer LIMIT to at most ``max_rows``.

    A literal ``LIMIT n``/``FETCH FIRST n`` with ``n <= max_rows`` is kept; a larger,
    missing or non-literal one (``ALL``, ``NULL``, expressions, ``WITH TIES``) becomes
    ``LIMIT max_rows``.

    Raises:
        ToolError: ``MCP_QUERY_VIOLATION`` for policy breaches,
            ``MCP_VALIDATION_ERROR`` for unparseable SQL.
    """
    if not 1 <= max_rows <= SQL_MAX_ROWS_LIMIT:
        msg = f"max_rows must be within 1..{SQL_MAX_ROWS_LIMIT}"
        raise ValueError(msg)
    root = _check_tree(_parse_single(query))

    existing = root.args.get("limit")
    requested = _literal_count(existing) if existing is not None else None
    effective = max_rows if requested is None else min(requested, max_rows)
    sql = root.limit(effective, copy=False).sql(dialect=DIALECT, comments=False)

    # The generated text is what runs, so it must pass the same policy.
    _check_tree(_parse_single(sql))
    return EnforcedQuery(sql=sql, row_cap=max_rows, requested_limit=requested)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
class _Attribute(Protocol):
    @property
    def name(self) -> str: ...


class _Statement(Protocol):
    def get_attributes(self) -> Sequence[_Attribute]: ...

    # Signatures mirror asyncpg's API, which takes per-call timeouts.
    async def fetch(self, *args: Any, timeout: float | None = None) -> list[Any]: ...  # noqa: ASYNC109


class _Transaction(Protocol):
    async def start(self) -> None: ...

    async def rollback(self) -> None: ...


class _Connection(Protocol):
    def transaction(self, *, readonly: bool = False) -> _Transaction: ...

    async def execute(self, query: str, *args: Any, timeout: float | None = None) -> str: ...  # noqa: ASYNC109

    async def prepare(self, query: str, *, timeout: float | None = None) -> _Statement: ...  # noqa: ASYNC109


class _Pool(Protocol):
    def acquire(self, *, timeout: float | None = None) -> AbstractAsyncContextManager[Any]: ...

    async def close(self) -> None: ...


type PoolFactory = Callable[[SqlSettings], Awaitable[_Pool]]


async def create_asyncpg_pool(settings: SqlSettings) -> _Pool:
    """Lazily-connecting asyncpg pool with read-only session defaults."""
    if settings.dsn is None:
        msg = "SqlSettings.dsn is not configured"
        raise RuntimeError(msg)
    pool: _Pool = await asyncpg.create_pool(
        dsn=settings.dsn.get_secret_value(),
        min_size=0,
        max_size=settings.pool_max_size,
        timeout=settings.connect_timeout,
        command_timeout=settings.query_timeout,
        server_settings={
            "application_name": settings.application_name,
            "default_transaction_read_only": "on",
            "statement_timeout": str(settings.statement_timeout_ms),
        },
    )
    return pool


def _json_value(value: Any) -> Any:  # noqa: PLR0911 - flat type dispatch
    """Convert a PostgreSQL value to an immutable, strictly JSON-safe Python value."""
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return "NaN" if math.isnan(value) else ("Infinity" if value > 0 else "-Infinity")
    if isinstance(value, Decimal | UUID):
        return str(value)  # Decimal as text keeps full numeric precision
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, bytes | bytearray | memoryview):
        return "\\x" + bytes(value).hex()
    if isinstance(value, list | tuple | asyncpg.Record):
        return tuple(_json_value(item) for item in value)
    if isinstance(value, Mapping):
        return json.dumps({str(k): _json_value(v) for k, v in value.items()}, sort_keys=True)
    return str(value)


_SQLSTATE_CLASSES_FOR_CALLER: Final = frozenset({"21", "22", "42", "0A", "54"})


def _problem_from_postgres(exc: asyncpg.PostgresError) -> ProblemDetail | None:
    """Map query-caused server errors to problems; ``None`` means infrastructure fault."""
    state = exc.sqlstate or ""
    message = str(exc)[:_MAX_DETAIL]
    metadata = {"sqlstate": state}
    if state == "57014":
        return ProblemDetail.from_code(
            MCPErrorCode.EXECUTION_TIMEOUT,
            "query cancelled by statement_timeout",
            metadata=metadata,
        )
    if state == "25006":
        return ProblemDetail.from_code(
            MCPErrorCode.QUERY_VIOLATION,
            f"read-only transaction rejected the query: {message}",
            invalid_params=("query",),
            metadata=metadata,
        )
    if state == "42501":
        return ProblemDetail.from_code(
            MCPErrorCode.ACCESS_DENIED, f"permission denied: {message}", metadata=metadata
        )
    if state[:2] in _SQLSTATE_CLASSES_FOR_CALLER:
        return ProblemDetail.from_code(
            MCPErrorCode.VALIDATION_ERROR,
            f"PostgreSQL rejected the query: {message}",
            invalid_params=("query",),
            metadata=metadata,
        )
    return None


class ReadOnlySqlTool:
    """The ``read_only_sql`` tool bound to a lazily created connection pool."""

    def __init__(self, settings: SqlSettings, *, pool_factory: PoolFactory | None = None) -> None:
        self._settings = settings
        self._pool_factory = pool_factory or create_asyncpg_pool
        self._pool: _Pool | None = None
        self._lock = asyncio.Lock()

    def definition(self) -> ToolDefinition[ReadOnlySqlParams, SqlQueryResult]:
        """MCP tool definition for registration."""
        return ToolDefinition(
            name=ToolName.READ_ONLY_SQL,
            title="Read-only SQL",
            description=(
                "Run one read-only PostgreSQL SELECT query. Write statements, multiple "
                "statements and side-effecting functions are rejected. Results are capped "
                f"at max_rows (<= {SQL_MAX_ROWS_LIMIT}); a larger LIMIT is lowered to the cap."
            ),
            params_model=ReadOnlySqlParams,
            result_model=SqlQueryResult,
            handler=self,
            read_only=True,
            open_world=False,
        )

    async def __call__(self, params: ReadOnlySqlParams) -> SqlQueryResult:
        enforced = enforce_read_only(params.query, max_rows=params.max_rows)
        try:
            columns, records = await self._execute(enforced.sql)
        except asyncpg.PostgresError as exc:
            problem = _problem_from_postgres(exc)
            if problem is None:
                raise
            raise ToolError(problem) from None
        rows = tuple(
            tuple(_json_value(v) for v in record) for record in records[: enforced.row_cap]
        )
        return SqlQueryResult(
            columns=columns,
            rows=rows,
            row_count=len(rows),
            truncated=enforced.cap_applied and len(records) >= enforced.row_cap,
        )

    async def _execute(self, sql: str) -> tuple[tuple[str, ...], list[Any]]:
        settings = self._settings
        pool = await self._get_pool()
        async with pool.acquire(timeout=settings.connect_timeout) as connection:
            conn: _Connection = connection
            transaction = conn.transaction(readonly=True)
            await transaction.start()
            try:
                await conn.execute(
                    "SELECT set_config('statement_timeout', $1, true)",
                    str(settings.statement_timeout_ms),
                    timeout=settings.query_timeout,
                )
                statement = await conn.prepare(sql, timeout=settings.query_timeout)
                columns = tuple(attr.name for attr in statement.get_attributes())
                records = await statement.fetch(timeout=settings.query_timeout)
            finally:
                # Always roll back: nothing is written, and session-level SETs vanish.
                # A failed rollback leaves the connection for the pool to reset.
                with suppress(asyncpg.PostgresError, asyncpg.InterfaceError, OSError):
                    await transaction.rollback()
        return columns, records

    async def _get_pool(self) -> _Pool:
        async with self._lock:
            if self._pool is None:
                self._pool = await self._pool_factory(self._settings)
            return self._pool

    async def aclose(self) -> None:
        """Close the pool if it was ever created."""
        async with self._lock:
            pool, self._pool = self._pool, None
        if pool is not None:
            await pool.close()

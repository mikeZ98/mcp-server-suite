"""Hard per-call deadline for tool execution."""

import asyncio
from collections.abc import Awaitable, Callable

from mcp_server_suite.errors import ToolError
from mcp_server_suite.schemas import MCPErrorCode, ProblemDetail

__all__ = ["run_with_deadline"]


async def run_with_deadline[T](
    operation: Callable[[], Awaitable[T]], deadline_seconds: float, tool_name: str
) -> T:
    """Await ``operation()`` and cancel it if it outlives ``deadline_seconds``.

    The deadline cancels the awaiting task tree immediately (asyncpg queries are
    cancelled server-side). Work already handed to a worker thread cannot be
    interrupted by Python and finishes in the background; the tools keep such
    work bounded (capped reads, short CPU sampling).

    Any ``TimeoutError`` — the deadline itself or one raised inside the tool —
    becomes an in-band ``MCP_EXECUTION_TIMEOUT`` problem.

    Raises:
        ToolError: ``MCP_EXECUTION_TIMEOUT``.
    """
    try:
        async with asyncio.timeout(deadline_seconds) as scope:
            return await operation()
    except TimeoutError:
        hit_deadline = scope.expired()
        detail = (
            f"tool {tool_name!r} exceeded its {deadline_seconds:g}s deadline and was cancelled"
            if hit_deadline
            else f"tool {tool_name!r} timed out"
        )
        raise ToolError(
            ProblemDetail.from_code(
                MCPErrorCode.EXECUTION_TIMEOUT,
                detail,
                metadata={"deadline_seconds": deadline_seconds, "deadline_hit": hit_deadline},
            )
        ) from None

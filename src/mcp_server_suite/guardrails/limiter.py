"""Bounded tool concurrency with a bounded wait for a free slot."""

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp_server_suite.errors import ToolError
from mcp_server_suite.schemas import MCPErrorCode, ProblemDetail

__all__ = ["ConcurrencyLimiter"]


class ConcurrencyLimiter:
    """At most ``max_concurrent`` tool calls run at once; others queue FIFO.

    A queued call that cannot get a slot within ``acquire_timeout`` seconds is
    rejected with a retryable ``MCP_INTERNAL_ERROR`` problem (the in-band
    equivalent of HTTP 503). ``acquire_timeout=0`` rejects immediately when full.
    """

    def __init__(self, max_concurrent: int = 16, acquire_timeout: float = 5.0) -> None:
        if max_concurrent < 1:
            msg = "max_concurrent must be positive"
            raise ValueError(msg)
        if acquire_timeout < 0:
            msg = "acquire_timeout must be non-negative"
            raise ValueError(msg)
        self._max = max_concurrent
        self._acquire_timeout = acquire_timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._in_use = 0
        self._waiting = 0

    @property
    def max_concurrent(self) -> int:
        """Configured slot count."""
        return self._max

    @property
    def in_use(self) -> int:
        """Slots currently held."""
        return self._in_use

    @property
    def waiting(self) -> int:
        """Calls queued for a slot."""
        return self._waiting

    @asynccontextmanager
    async def slot(self, tool_name: str) -> AsyncIterator[None]:
        """Hold one slot for the duration of the ``async with`` block."""
        started = time.monotonic()
        self._waiting += 1
        try:
            async with asyncio.timeout(self._acquire_timeout):
                await self._semaphore.acquire()
        except TimeoutError:
            raise ToolError(self._capacity_problem(tool_name, started)) from None
        finally:
            self._waiting -= 1
        self._in_use += 1
        try:
            yield
        finally:
            self._in_use -= 1
            self._semaphore.release()

    def _capacity_problem(self, tool_name: str, started: float) -> ProblemDetail:
        return ProblemDetail.from_code(
            MCPErrorCode.INTERNAL_ERROR,
            f"server is at capacity ({self._max} concurrent tool calls); "
            f"{tool_name!r} was not started, retry later",
            metadata={
                "reason": "capacity_exhausted",
                "retryable": True,
                "max_concurrent_tools": self._max,
                "waited_seconds": round(time.monotonic() - started, 3),
            },
        )

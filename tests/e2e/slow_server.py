"""E2E helper: the production stdio loop serving one deliberately slow tool.

Lifecycle markers and a leak report are written to stderr so tests can
synchronise on them and assert clean teardown:
``e2e-exit fd_leak=[...] pending_tasks=N``.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Annotated

from pydantic import Field

from mcp_server_suite.core import MCPServer, ServerConfig, ToolDefinition, ToolRegistry, run_stdio
from mcp_server_suite.schemas import StrictModel


class SleepParams(StrictModel):
    seconds: Annotated[float, Field(ge=0, le=120)]


class SleepResult(StrictModel):
    slept: float


def note(message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


async def sleep_tool(params: SleepParams) -> SleepResult:
    note("slow tool started")
    try:
        await asyncio.sleep(params.seconds)
    except asyncio.CancelledError:
        note("slow tool cancelled")
        raise
    return SleepResult(slept=params.seconds)


def open_fds() -> set[int]:
    return {int(entry.name) for entry in Path("/dev/fd").iterdir()}


async def main() -> None:
    grace = float(os.environ.get("E2E_SHUTDOWN_GRACE", "5"))
    registry = ToolRegistry(
        [
            ToolDefinition(
                name="sleep",
                description="Sleep for the requested number of seconds.",
                params_model=SleepParams,
                result_model=SleepResult,
                handler=sleep_tool,
            )
        ]
    )
    before = open_fds()
    await run_stdio(MCPServer(registry, ServerConfig(shutdown_grace_seconds=grace)))
    leaked = sorted(open_fds() - before)
    pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    note(f"e2e-exit fd_leak={leaked} pending_tasks={len(pending)}")


if __name__ == "__main__":
    asyncio.run(main())

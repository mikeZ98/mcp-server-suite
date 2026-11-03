"""End-to-end protocol conformance against the real server process over stdio.

Each test spawns ``python -m mcp_server_suite`` (or the slow-tool helper built on
the same stdio loop) with a minimal environment: a temporary HOME/TMPDIR, a
sandbox directory, no inherited ``MCP_*`` variables and no network access
(no DSN). ``-X dev`` makes the child report unclosed resources, never-awaited
coroutines and destroyed pending tasks on stderr, which every test asserts is
free of such diagnostics.
"""

import asyncio
import json
import os
import signal
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Final

import mcp_types
import pytest

pytestmark = pytest.mark.e2e

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
SLOW_SERVER: Final = Path(__file__).with_name("slow_server.py")
SECRET: Final = "E2E-SECRET-7f3a outside the sandbox"
TIMEOUT: Final = 15.0
STDERR_RED_FLAGS: Final = (
    "Traceback",
    "ResourceWarning",
    "Task was destroyed",
    "was never awaited",
    "Unclosed",
    "Exception ignored",
)


class ServerProcess:
    """A spawned server with line-oriented stdout and a background stderr drain."""

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self.process = process
        self._stderr: list[str] = []
        self._stderr_changed = asyncio.Event()
        self._drain = asyncio.create_task(self._drain_stderr())

    @classmethod
    async def start(cls, args: list[str], env: dict[str, str], cwd: Path) -> "ServerProcess":
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-X",
            "dev",
            "-X",
            f"pycache_prefix={REPO_ROOT / '.cache' / 'pycache'}",
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=cwd,
        )
        return cls(process)

    async def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        while line := await self.process.stderr.readline():
            self._stderr.append(line.decode(errors="replace"))
            self._stderr_changed.set()

    @property
    def stderr(self) -> str:
        return "".join(self._stderr)

    async def wait_for_stderr(self, marker: str) -> None:
        async with asyncio.timeout(TIMEOUT):
            while marker not in self.stderr:
                self._stderr_changed.clear()
                await self._stderr_changed.wait()

    async def send_raw(self, data: bytes) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(data)
        await self.process.stdin.drain()

    async def send(self, *messages: dict[str, Any]) -> None:
        await self.send_raw(b"".join(json.dumps(m).encode() + b"\n" for m in messages))

    async def recv(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = await asyncio.wait_for(self.process.stdout.readline(), TIMEOUT)
        assert line, f"server closed stdout; stderr:\n{self.stderr}"
        assert line.isascii(), "stdout carries ASCII-only JSON frames"
        message: dict[str, Any] = json.loads(line)  # stdout never carries non-JSON
        return message

    async def recv_n(self, count: int) -> list[dict[str, Any]]:
        return [await self.recv() for _ in range(count)]

    async def call(self, request_id: Any, method: str, params: Any = None) -> dict[str, Any]:
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        await self.send(message)
        response = await self.recv()
        assert response["id"] == request_id
        return response

    async def initialize(self, version: str = "2025-11-25") -> dict[str, Any]:
        response = await self.call(
            0,
            "initialize",
            {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "e2e"}},
        )
        await self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return response

    async def close_stdin(self) -> None:
        assert self.process.stdin is not None
        self.process.stdin.close()
        await self.process.stdin.wait_closed()

    async def wait(self) -> int:
        code = await asyncio.wait_for(self.process.wait(), TIMEOUT)
        await asyncio.wait_for(self._drain, TIMEOUT)
        return code

    async def remaining_stdout(self) -> bytes:
        assert self.process.stdout is not None
        return await asyncio.wait_for(self.process.stdout.read(), TIMEOUT)

    def assert_clean_stderr(self) -> None:
        for flag in STDERR_RED_FLAGS:
            assert flag not in self.stderr, f"{flag!r} in server stderr:\n{self.stderr}"

    async def kill(self) -> None:
        if self.process.returncode is None:
            self.process.kill()
            await self.process.wait()
        self._drain.cancel()


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "safe"
    (root / "docs").mkdir(parents=True)
    (root / "notes.txt").write_text("hello e2e")
    (root / "docs" / "guide.md").write_text("# guide")
    (tmp_path / "secret.txt").write_text(SECRET)
    return root


@pytest.fixture
def env(tmp_path: Path, sandbox: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "PYTHONDONTWRITEBYTECODE": "1",
        "MCP_SAFE_DATA_DIR": str(sandbox),
        "MCP_METRICS_CPU_SAMPLE_SECONDS": "0.01",
        "MCP_TOOL_TIMEOUT_SECONDS": "120",
        "MCP_SERVER_SUITE_LOG_LEVEL": "WARNING",
    }


@pytest.fixture
async def server(env: dict[str, str], tmp_path: Path) -> AsyncIterator[ServerProcess]:
    proc = await ServerProcess.start(["-m", "mcp_server_suite"], env, tmp_path)
    try:
        yield proc
    finally:
        await proc.kill()


@pytest.fixture
async def slow_server(env: dict[str, str], tmp_path: Path) -> AsyncIterator[ServerProcess]:
    proc = await ServerProcess.start([str(SLOW_SERVER)], env, tmp_path)
    try:
        yield proc
    finally:
        await proc.kill()


async def start_slow(env: dict[str, str], cwd: Path, grace: float) -> ServerProcess:
    return await ServerProcess.start(
        [str(SLOW_SERVER)], {**env, "E2E_SHUTDOWN_GRACE": str(grace)}, cwd
    )


def tool_call(request_id: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("offered", "negotiated"),
    [("2024-11-05", "2024-11-05"), ("2025-11-25", "2025-11-25"), ("1999-01-01", "2025-11-25")],
)
async def test_full_session_and_version_negotiation(
    server: ServerProcess, offered: str, negotiated: str
) -> None:
    init = await server.initialize(offered)
    result = mcp_types.InitializeResult.model_validate(init["result"])
    assert result.protocol_version == negotiated
    assert result.server_info.name == "mcp-server-suite"

    listed = await server.call(1, "tools/list")
    tools = mcp_types.ListToolsResult.model_validate(listed["result"]).tools
    assert [tool.name for tool in tools] == ["sandbox_fs_read", "system_metrics"]
    assert all(tool.annotations and tool.annotations.read_only_hint for tool in tools)

    assert (await server.call(2, "ping"))["result"] == {}
    await server.close_stdin()
    assert await server.wait() == 0
    assert await server.remaining_stdout() == b""
    server.assert_clean_stderr()


async def test_concurrent_tool_invocations(server: ServerProcess) -> None:
    await server.initialize()
    calls = []
    for i in range(10):
        calls.append(tool_call(100 + i, "system_metrics", {"include_disk": i % 2 == 0}))
        calls.append(tool_call(200 + i, "sandbox_fs_read", {"relative_path": "notes.txt"}))
    await server.send(*calls)
    responses = {r["id"]: r for r in await server.recv_n(len(calls))}
    assert set(responses) == {c["id"] for c in calls}
    for request_id, response in responses.items():
        result = mcp_types.CallToolResult.model_validate(response["result"])
        assert result.is_error is False, response
        structured = response["result"]["structuredContent"]
        if request_id >= 200:
            assert structured["content"] == "hello e2e"
        else:
            assert structured["timestamp_utc"].endswith("Z")
            assert (structured["disk_percent_used"] is None) == (request_id % 2 == 1)
    await server.close_stdin()
    assert await server.wait() == 0
    server.assert_clean_stderr()


async def test_interleaved_malformed_lines_are_survived(server: ServerProcess) -> None:
    await server.initialize()
    await server.send_raw(
        b"{not json\n"
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        b"[1, 2]\n"
        b"\xff\xfe\xfd\n"
        b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
        b'{"jsonrpc":"1.0","id":3,"method":"ping"}\n'
        b'{"jsonrpc":"2.0","method":"notifications/unknown"}\n'
        b'{"jsonrpc":"2.0","id":4,"method":"no/such/method"}\n'
        b'{"jsonrpc":"2.0","id":5,"method":"x\\ud800"}\n'
        b'{"jsonrpc":"2.0","id":6,"method":"ping"}\n'
    )
    responses = await server.recv_n(9)
    codes = [(r["id"], r.get("error", {}).get("code")) for r in responses]
    assert codes == [
        (None, -32700),
        (1, None),
        (None, -32600),
        (None, -32700),
        (2, None),
        (3, -32600),
        (4, -32601),
        (5, -32601),
        (6, None),
    ]
    await server.close_stdin()
    assert await server.wait() == 0
    server.assert_clean_stderr()


async def test_oversized_line_is_rejected_and_session_continues(server: ServerProcess) -> None:
    await server.initialize()
    padding = "A" * (1_048_576 + 512)
    await server.send({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": padding}})
    rejected = await server.recv()
    assert rejected["id"] is None
    assert rejected["error"]["code"] == -32600
    assert rejected["error"]["data"] == {"max_frame_bytes": 1_048_576}
    assert (await server.call(2, "ping"))["result"] == {}
    await server.close_stdin()
    assert await server.wait() == 0


async def test_tool_errors_over_the_wire(server: ServerProcess) -> None:
    await server.initialize()
    await server.send(
        tool_call(1, "sandbox_fs_read", {"relative_path": "../secret.txt"}),
        tool_call(2, "sandbox_fs_read", {"relative_path": "notes" + chr(0x202E) + ".txt"}),
        tool_call(3, "read_only_sql", {"query": "SELECT 1"}),
    )
    responses = {r["id"]: r for r in await server.recv_n(3)}
    denied = json.loads(responses[1]["result"]["content"][0]["text"])
    assert (responses[1]["result"]["isError"], denied["code"]) == (True, "MCP_ACCESS_DENIED")
    sanitized = json.loads(responses[2]["result"]["content"][0]["text"])
    assert sanitized["metadata"]["codepoint"] == "U+202E"
    assert responses[3]["error"]["code"] == -32602, "read_only_sql is not registered without a DSN"
    assert SECRET not in json.dumps(responses)
    await server.close_stdin()
    assert await server.wait() == 0
    server.assert_clean_stderr()


# ---------------------------------------------------------------------------
# Signals and teardown
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
async def test_signal_while_idle_exits_cleanly(server: ServerProcess, signum: int) -> None:
    await server.initialize()  # handlers are installed before the first read
    server.process.send_signal(signum)
    assert await server.wait() in {0, 130}
    server.assert_clean_stderr()


async def test_sigint_drains_in_flight_call_within_grace(
    env: dict[str, str], tmp_path: Path
) -> None:
    proc = await start_slow(env, tmp_path, grace=10)
    try:
        await proc.initialize()
        await proc.send(tool_call(1, "sleep", {"seconds": 0.5}))
        await proc.wait_for_stderr("slow tool started")
        proc.process.send_signal(signal.SIGINT)
        response = await proc.recv()
        assert response["result"]["structuredContent"] == {"slept": 0.5}
        assert await proc.wait() == 0
        assert "e2e-exit fd_leak=[] pending_tasks=0" in proc.stderr
        assert "slow tool cancelled" not in proc.stderr
        proc.assert_clean_stderr()
    finally:
        await proc.kill()


async def test_sigint_cancels_in_flight_call_after_grace(
    env: dict[str, str], tmp_path: Path
) -> None:
    proc = await start_slow(env, tmp_path, grace=0.2)
    try:
        await proc.initialize()
        await proc.send(tool_call(1, "sleep", {"seconds": 60}))
        await proc.wait_for_stderr("slow tool started")
        proc.process.send_signal(signal.SIGINT)
        assert await proc.wait() == 0
        assert "slow tool cancelled" in proc.stderr
        assert await proc.remaining_stdout() == b"", "cancelled request gets no response"
        assert "e2e-exit fd_leak=[] pending_tasks=0" in proc.stderr
        proc.assert_clean_stderr()
    finally:
        await proc.kill()


async def test_second_sigint_forces_shutdown(env: dict[str, str], tmp_path: Path) -> None:
    proc = await start_slow(env, tmp_path, grace=60)
    try:
        await proc.initialize()
        await proc.send(tool_call(1, "sleep", {"seconds": 60}))
        await proc.wait_for_stderr("slow tool started")
        loop = asyncio.get_running_loop()
        started = loop.time()
        proc.process.send_signal(signal.SIGINT)
        await asyncio.sleep(0.2)
        assert proc.process.returncode is None, "first SIGINT drains gracefully"
        proc.process.send_signal(signal.SIGINT)
        assert await proc.wait() == 0
        assert loop.time() - started < 10, "forced shutdown does not wait for the 60s grace"
        assert "slow tool cancelled" in proc.stderr
        assert "e2e-exit fd_leak=[] pending_tasks=0" in proc.stderr
        proc.assert_clean_stderr()
    finally:
        await proc.kill()


async def test_eof_with_idle_slow_server_reports_no_leaks(slow_server: ServerProcess) -> None:
    await slow_server.initialize()
    await slow_server.close_stdin()
    assert await slow_server.wait() == 0
    assert "e2e-exit fd_leak=[] pending_tasks=0" in slow_server.stderr
    slow_server.assert_clean_stderr()

"""Hermetic tests for the JSON-RPC 2.0 / MCP stdio engine.

Sessions run over an in-memory ``asyncio.StreamReader`` and a recording sink;
the stdio tests use short-lived ``os.pipe`` pairs and temp files that are always
closed. Every response is cross-checked against the reference ``mcp_types``
models so the wire format stays protocol-compliant.
"""

import asyncio
import json
import logging
import os
import signal
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

import mcp_types
import pytest

from harness import in_band_problem, run_session, tool_call
from mcp_server_suite import __main__ as entrypoint
from mcp_server_suite.core import (
    LATEST_PROTOCOL_VERSION,
    MAX_FRAME_BYTES,
    SUPPORTED_PROTOCOL_VERSIONS,
    ErrorCode,
    FrameReader,
    FrameWriter,
    JsonRpcError,
    MCPServer,
    OversizedFrame,
    ServerConfig,
    ToolDefinition,
    ToolError,
    ToolRegistry,
    install_signal_handlers,
    run_stdio,
)
from mcp_server_suite.core.jsonrpc import (
    ClientResponse,
    Notification,
    Request,
    parse_message,
)
from mcp_server_suite.schemas import (
    ERROR_TAXONOMY,
    MCPErrorCode,
    ProblemDetail,
    ReadOnlySqlParams,
    SqlQueryResult,
    StrictModel,
    ToolName,
)
from mcp_server_suite.tools import SandboxFsReadTool, SandboxSettings

TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------
class EchoParams(StrictModel):
    text: str


class EchoResult(StrictModel):
    text: str


class RecordingSink:
    """In-memory ``ByteSink`` that decodes each frame onto a queue."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []
        self.messages: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.closed = False

    async def write(self, data: bytes, /) -> None:
        assert data.endswith(b"\n")
        assert data.count(b"\n") == 1, "a frame must be exactly one line"
        self.frames.append(data)
        self.messages.put_nowait(json.loads(data))

    async def aclose(self) -> None:
        self.closed = True


class BrokenSink(RecordingSink):
    async def write(self, _data: bytes, /) -> None:
        raise BrokenPipeError

    async def aclose(self) -> None:
        raise BrokenPipeError


class ChunkSource:
    """``ByteSource`` replaying fixed chunks (exercises frame boundaries)."""

    def __init__(self, *chunks: bytes) -> None:
        self._chunks = list(chunks)

    async def read(self, n: int, /) -> bytes:
        assert n > 0
        return self._chunks.pop(0) if self._chunks else b""


class FailingSource:
    async def read(self, _n: int, /) -> bytes:
        raise ConnectionResetError


class SlowTool:
    """Handler that blocks until released and records cancellation."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def __call__(self, params: EchoParams) -> EchoResult:
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        return EchoResult(text=params.text)


async def _echo(params: EchoParams) -> EchoResult:
    return EchoResult(text=params.text)


async def _boom(params: EchoParams) -> EchoResult:
    raise RuntimeError("secret connection string leaked")


async def _denied(params: EchoParams) -> EchoResult:
    raise ToolError(ProblemDetail.from_code(MCPErrorCode.ACCESS_DENIED, "path escapes sandbox"))


async def _too_slow(params: EchoParams) -> EchoResult:
    raise TimeoutError


async def _wrong_type(params: EchoParams) -> EchoResult:
    return params  # type: ignore[return-value]


async def _sql(params: ReadOnlySqlParams) -> SqlQueryResult:
    return SqlQueryResult(columns=("n",), rows=((params.max_rows,),), row_count=1, truncated=False)


async def _unserialisable(params: ReadOnlySqlParams) -> SqlQueryResult:
    return SqlQueryResult(columns=("x",), rows=((object(),),), row_count=1, truncated=False)


def _echo_tool(name: str, handler: Any, **kwargs: Any) -> ToolDefinition[Any, Any]:
    return ToolDefinition(
        name=name,
        description=f"{name} test tool",
        params_model=EchoParams,
        result_model=EchoResult,
        handler=handler,
        **kwargs,
    )


@pytest.fixture
def slow() -> SlowTool:
    return SlowTool()


@pytest.fixture
def registry(slow: SlowTool) -> ToolRegistry:
    return ToolRegistry(
        [
            _echo_tool("echo", _echo, title="Echo"),
            _echo_tool("slow", slow),
            _echo_tool("boom", _boom),
            _echo_tool("denied", _denied),
            _echo_tool("too_slow", _too_slow),
            _echo_tool("wrong_type", _wrong_type),
            ToolDefinition(
                name="read_only_sql",
                description="fake SQL tool",
                params_model=ReadOnlySqlParams,
                result_model=SqlQueryResult,
                handler=_sql,
            ),
            ToolDefinition(
                name="unserialisable",
                description="returns a value JSON cannot encode",
                params_model=ReadOnlySqlParams,
                result_model=SqlQueryResult,
                handler=_unserialisable,
            ),
        ]
    )


async def eventually(predicate: Callable[[], bool]) -> None:
    """Yield to the loop until ``predicate`` holds (task done-callbacks run a tick late)."""
    for _ in range(100):
        if predicate():
            return
        await asyncio.sleep(0)
    pytest.fail("condition not reached within 100 loop iterations")


def frame(message: dict[str, Any]) -> bytes:
    return json.dumps(message).encode() + b"\n"


def request(request_id: Any, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    return message


INIT_PARAMS = {
    "protocolVersion": LATEST_PROTOCOL_VERSION,
    "capabilities": {},
    "clientInfo": {"name": "pytest", "version": "1.0"},
}


class Session:
    """Drive one ``MCPServer.serve`` over in-memory streams."""

    def __init__(self, server: MCPServer, sink: RecordingSink | None = None) -> None:
        self.server = server
        self.reader = asyncio.StreamReader()
        self.sink = sink or RecordingSink()
        self.task: asyncio.Task[None] | None = None
        self._eof = False

    async def __aenter__(self) -> "Session":
        self.task = asyncio.create_task(self.server.serve(self.reader, self.sink))
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        self.close_input()
        await self.wait_closed()

    def close_input(self) -> None:
        if not self._eof:
            self._eof = True
            self.reader.feed_eof()

    async def wait_closed(self) -> None:
        assert self.task is not None
        await asyncio.wait_for(self.task, TIMEOUT)

    def send_raw(self, data: bytes) -> None:
        self.reader.feed_data(data)

    def send(self, message: dict[str, Any]) -> None:
        self.send_raw(frame(message))

    async def receive(self) -> dict[str, Any]:
        return await asyncio.wait_for(self.sink.messages.get(), TIMEOUT)

    async def call(
        self, request_id: Any, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self.send(request(request_id, method, params))
        return await self.receive()

    async def initialize(self) -> dict[str, Any]:
        response = await self.call(0, "initialize", INIT_PARAMS)
        self.send(notification("notifications/initialized"))
        return response

    async def tool(self, request_id: Any, name: str, arguments: Any) -> dict[str, Any]:
        return await self.call(request_id, "tools/call", {"name": name, "arguments": arguments})

    def assert_silent(self) -> None:
        assert self.sink.messages.empty(), f"unexpected output: {self.sink.messages.get_nowait()}"


@pytest.fixture
async def session(registry: ToolRegistry) -> AsyncIterator[Session]:
    async with Session(MCPServer(registry)) as active:
        yield active


@pytest.fixture
async def ready(session: Session) -> Session:
    await session.initialize()
    return session


def assert_error(response: dict[str, Any], code: int, request_id: Any = None) -> dict[str, Any]:
    mcp_types.JSONRPCError.model_validate(response)
    assert response["id"] == request_id
    assert response["error"]["code"] == code, response
    error: dict[str, Any] = response["error"]
    return error


def assert_problem(response: dict[str, Any], code: MCPErrorCode, request_id: Any) -> dict[str, Any]:
    error = assert_error(response, ERROR_TAXONOMY[code].jsonrpc_code, request_id)
    problem = ProblemDetail.model_validate_json(json.dumps(error["data"]))
    assert problem.code is code
    assert error["message"] == problem.detail
    data: dict[str, Any] = error["data"]
    return data


def assert_tool_problem(
    response: dict[str, Any], code: MCPErrorCode, request_id: Any
) -> dict[str, Any]:
    """A tool execution error: ``isError`` result whose only content is the RFC 9457 problem."""
    mcp_types.JSONRPCResponse.model_validate(response)
    assert response["id"] == request_id
    result = mcp_types.CallToolResult.model_validate(response["result"])
    assert result.is_error is True
    assert "structuredContent" not in response["result"]
    (content,) = response["result"]["content"]
    assert content["type"] == "text"
    problem = ProblemDetail.model_validate_json(content["text"])
    assert problem.code is code
    data: dict[str, Any] = json.loads(content["text"])
    return data


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------
async def _frames(reader: FrameReader) -> list[bytes | OversizedFrame]:
    out: list[bytes | OversizedFrame] = []
    while (item := await reader.read_frame()) is not None:
        out.append(item)
    return out


async def test_frames_split_across_chunks_and_crlf() -> None:
    source = ChunkSource(b'{"a"', b":1}\r\n\n  \n{", b'"b":2}\n', b'{"c":3}')
    assert await _frames(FrameReader(source)) == [b'{"a":1}', b'{"b":2}', b'{"c":3}']


async def test_frame_reader_is_sticky_at_eof() -> None:
    reader = FrameReader(ChunkSource(b"x\n"))
    assert await reader.read_frame() == b"x"
    assert await reader.read_frame() is None
    assert await reader.read_frame() is None


async def test_frame_exactly_at_limit_is_accepted() -> None:
    reader = FrameReader(ChunkSource(b"a" * 16 + b"\n"), max_frame_bytes=16)
    assert await _frames(reader) == [b"a" * 16]


async def test_oversized_line_in_one_chunk_is_reported_then_resyncs() -> None:
    reader = FrameReader(ChunkSource(b"a" * 17 + b"\nok\n"), max_frame_bytes=16)
    assert await _frames(reader) == [OversizedFrame(17), b"ok"]


async def test_oversized_streaming_line_is_dropped_without_buffering() -> None:
    chunks = [b"x" * 10] * 50 + [b"tail\nok\n"]
    reader = FrameReader(ChunkSource(*chunks), max_frame_bytes=16, chunk_size=10)
    assert await _frames(reader) == [OversizedFrame(504), b"ok"]
    assert len(reader._buffer) == 0


async def test_oversized_line_at_eof_without_newline() -> None:
    reader = FrameReader(ChunkSource(b"y" * 40), max_frame_bytes=16, chunk_size=8)
    assert await _frames(reader) == [OversizedFrame(40)]


async def test_unterminated_oversized_tail_at_eof() -> None:
    reader = FrameReader(ChunkSource(b"ok\n" + b"z" * 20), max_frame_bytes=32, chunk_size=64)
    assert await _frames(reader) == [b"ok", b"z" * 20]
    reader = FrameReader(ChunkSource(b"ok\n", b"z" * 20), max_frame_bytes=16, chunk_size=64)
    assert await _frames(reader) == [b"ok", OversizedFrame(20)]


@pytest.mark.parametrize("kwargs", [{"max_frame_bytes": 0}, {"chunk_size": 0}])
def test_frame_reader_rejects_bad_limits(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        FrameReader(ChunkSource(), **kwargs)


async def test_frame_writer_emits_single_ascii_line() -> None:
    sink = RecordingSink()
    writer = FrameWriter(sink)
    await writer.send({"text": "line\nbreak", "word": "\u017c\u00f3\u0142w", "lone": "\ud800"})
    assert sink.frames == [
        b'{"text":"line\\nbreak","word":"\\u017c\\u00f3\\u0142w","lone":"\\ud800"}\n'
    ]
    assert json.loads(sink.frames[0])["word"] == "\u017c\u00f3\u0142w"
    await writer.aclose()
    assert sink.closed


async def test_lone_surrogate_in_request_cannot_crash_the_session(ready: Session) -> None:
    """Regression: echoing an unpaired surrogate used to raise UnicodeEncodeError."""
    ready.send_raw(b'{"jsonrpc":"2.0","id":1,"method":"x\\ud800"}\n')
    response = await ready.receive()
    assert_error(response, ErrorCode.METHOD_NOT_FOUND, 1)
    assert response["error"]["message"] == "Method not found: x\ud800"
    assert (await ready.call(2, "ping"))["id"] == 2


async def test_frame_writer_close_tolerates_broken_sink() -> None:
    await FrameWriter(BrokenSink()).aclose()


async def test_frame_writer_rejects_nan() -> None:
    with pytest.raises(ValueError, match="Out of range float"):
        await FrameWriter(RecordingSink()).send({"x": float("nan")})


def test_default_frame_limit_is_one_mebibyte() -> None:
    assert MAX_FRAME_BYTES == 1024 * 1024


# ---------------------------------------------------------------------------
# JSON-RPC envelope parsing
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw",
    [
        b"\xff\xfe{}",
        b"{not json",
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":NaN}}',
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
        b"[" * 100_000 + b"]" * 100_000,
    ],
    ids=["not-utf8", "truncated", "nan-constant", "duplicate-key", "deep-nesting"],
)
def test_parse_errors(raw: bytes) -> None:
    with pytest.raises(JsonRpcError) as exc_info:
        parse_message(raw)
    assert exc_info.value.code == ErrorCode.PARSE_ERROR
    assert exc_info.value.request_id is None


@pytest.mark.parametrize(
    ("payload", "request_id"),
    [
        ([{"jsonrpc": "2.0", "id": 1, "method": "ping"}], None),
        ("ping", None),
        ({"id": 7, "method": "ping"}, 7),
        ({"jsonrpc": "1.0", "id": "a", "method": "ping"}, "a"),
        ({"jsonrpc": "2.0", "id": 1}, 1),
        ({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}}, 1),
        ({"jsonrpc": "2.0", "id": 1, "method": "ping", "extra": True}, 1),
        ({"jsonrpc": "2.0", "id": 1, "method": ""}, 1),
        ({"jsonrpc": "2.0", "id": 1, "method": 5}, 1),
        ({"jsonrpc": "2.0", "id": None, "method": "ping"}, None),
        ({"jsonrpc": "2.0", "id": True, "method": "ping"}, None),
        ({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}, None),
        ({"jsonrpc": "2.0", "id": [1], "method": "ping"}, None),
    ],
)
def test_invalid_requests(payload: Any, request_id: Any) -> None:
    with pytest.raises(JsonRpcError) as exc_info:
        parse_message(json.dumps(payload).encode())
    assert exc_info.value.code == ErrorCode.INVALID_REQUEST
    assert exc_info.value.request_id == request_id


@pytest.mark.parametrize("params", [[1, 2], None, "x"])
def test_non_object_params_are_invalid_params(params: Any) -> None:
    raw = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping", "params": params})
    with pytest.raises(JsonRpcError) as exc_info:
        parse_message(raw.encode())
    assert exc_info.value.code == ErrorCode.INVALID_PARAMS
    assert exc_info.value.request_id == 3


def test_parse_message_kinds() -> None:
    assert parse_message(frame(request("r1", "ping"))) == Request("r1", "ping", {})
    assert parse_message(frame(notification("n", {"a": 1}))) == Notification("n", {"a": 1})
    assert parse_message(b'{"jsonrpc":"2.0","id":4,"result":{}}') == ClientResponse(4)
    assert parse_message(b'{"jsonrpc":"2.0","id":4,"error":{}}') == ClientResponse(4)


def test_json_rpc_error_from_problem() -> None:
    problem = ProblemDetail.from_code(MCPErrorCode.QUERY_VIOLATION, "DROP is not allowed")
    error = JsonRpcError.from_problem(problem)
    assert error.to_object() == {
        "code": -32002,
        "message": "DROP is not allowed",
        "data": problem.to_json_dict(),
    }
    assert JsonRpcError(ErrorCode.PARSE_ERROR, "x").to_object() == {"code": -32700, "message": "x"}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def test_registry_rejects_duplicates(registry: ToolRegistry) -> None:
    with pytest.raises(ValueError, match="already registered"):
        registry.register(_echo_tool("echo", _echo))


@pytest.mark.parametrize("name", ["", "has space", "x" * 129, "semi;colon"])
def test_tool_name_validation(name: str) -> None:
    with pytest.raises(ValueError, match="invalid tool name"):
        _echo_tool(name, _echo)


def test_registry_container_protocol(registry: ToolRegistry) -> None:
    assert len(registry) == 8
    assert "echo" in registry
    assert "missing" not in registry
    assert registry.get("missing") is None
    assert [tool.name for tool in registry][:2] == ["echo", "slow"]


def test_tool_spec_is_mcp_compliant(registry: ToolRegistry) -> None:
    for spec in registry.specs():
        tool = mcp_types.Tool.model_validate(spec)
        assert spec["inputSchema"]["type"] == "object"
        assert spec["inputSchema"]["additionalProperties"] is False
        assert tool.annotations is not None
    echo = registry.specs()[0]
    assert echo["title"] == "Echo"
    assert echo["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    assert "title" not in registry.specs()[1]


# ---------------------------------------------------------------------------
# Lifecycle & handshake
# ---------------------------------------------------------------------------
async def test_full_handshake(session: Session) -> None:
    init = await session.call(1, "initialize", INIT_PARAMS)
    mcp_types.JSONRPCResponse.model_validate(init)
    result = mcp_types.InitializeResult.model_validate(init["result"])
    assert init["id"] == 1
    assert result.protocol_version == LATEST_PROTOCOL_VERSION
    assert result.server_info.name == "mcp-server-suite"
    assert init["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert session.server.protocol_version == LATEST_PROTOCOL_VERSION

    session.send(notification("notifications/initialized"))
    listed = await session.call("list-1", "tools/list")
    assert session.server.client_ready
    tools = mcp_types.ListToolsResult.model_validate(listed["result"])
    assert [tool.name for tool in tools.tools][:2] == ["echo", "slow"]

    pong = await session.call(2, "ping")
    assert pong == {"jsonrpc": "2.0", "id": 2, "result": {}}
    session.assert_silent()


@pytest.mark.parametrize("version", SUPPORTED_PROTOCOL_VERSIONS)
async def test_supported_versions_are_echoed(session: Session, version: str) -> None:
    response = await session.call(1, "initialize", {**INIT_PARAMS, "protocolVersion": version})
    assert response["result"]["protocolVersion"] == version


async def test_unsupported_version_gets_counter_offer(session: Session) -> None:
    response = await session.call(1, "initialize", {**INIT_PARAMS, "protocolVersion": "1999-01-01"})
    assert response["result"]["protocolVersion"] == LATEST_PROTOCOL_VERSION


async def test_instructions_are_advertised(registry: ToolRegistry) -> None:
    config = ServerConfig(instructions="Read-only tools.", name="suite", version="9.9")
    async with Session(MCPServer(registry, config)) as session:
        result = (await session.initialize())["result"]
    assert result["instructions"] == "Read-only tools."
    assert result["serverInfo"] == {"name": "suite", "version": "9.9"}


@pytest.mark.parametrize(
    ("params", "invalid"),
    [
        ({}, "protocolVersion"),
        ({"protocolVersion": 20251125}, "protocolVersion"),
        ({**INIT_PARAMS, "capabilities": []}, "capabilities"),
        ({**INIT_PARAMS, "clientInfo": "pytest"}, "clientInfo"),
    ],
)
async def test_initialize_param_validation(
    session: Session, params: dict[str, Any], invalid: str
) -> None:
    data = assert_problem(
        await session.call(1, "initialize", params), MCPErrorCode.VALIDATION_ERROR, 1
    )
    assert data["invalid_params"] == [invalid]
    assert session.server.protocol_version is None


async def test_double_initialize_rejected(ready: Session) -> None:
    response = await ready.call(9, "initialize", INIT_PARAMS)
    assert_error(response, ErrorCode.INVALID_REQUEST, 9)


@pytest.mark.parametrize("method", ["tools/list", "tools/call"])
async def test_requests_before_initialize_are_rejected(session: Session, method: str) -> None:
    response = await session.call(1, method, {"name": "echo", "arguments": {"text": "x"}})
    assert assert_error(response, ErrorCode.INVALID_REQUEST, 1)["message"].endswith(
        "not initialized"
    )
    assert (await session.call(2, "ping"))["result"] == {}


async def test_unknown_method_returns_method_not_found(ready: Session) -> None:
    response = await ready.call(5, "resources/list")
    assert assert_error(response, ErrorCode.METHOD_NOT_FOUND, 5)["message"] == (
        "Method not found: resources/list"
    )


async def test_unknown_method_name_is_truncated_in_error(ready: Session) -> None:
    response = await ready.call(5, "x" * 5000)
    assert len(response["error"]["message"]) < 200


# ---------------------------------------------------------------------------
# Resilience: malformed input never stops the loop
# ---------------------------------------------------------------------------
async def test_malformed_json_recovery(ready: Session) -> None:
    ready.send_raw(b'{"jsonrpc": "2.0", "id": 1, "method": \n')
    assert_error(await ready.receive(), ErrorCode.PARSE_ERROR)
    assert (await ready.call(2, "ping"))["id"] == 2


async def test_invalid_request_echoes_readable_id(ready: Session) -> None:
    ready.send({"jsonrpc": "1.0", "id": "abc", "method": "ping"})
    assert_error(await ready.receive(), ErrorCode.INVALID_REQUEST, "abc")


async def test_batch_rejected(ready: Session) -> None:
    ready.send_raw(b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n')
    assert_error(await ready.receive(), ErrorCode.INVALID_REQUEST)


async def test_oversized_payload_rejected_and_loop_survives(registry: ToolRegistry) -> None:
    async with Session(MCPServer(registry, ServerConfig(max_frame_bytes=1024))) as session:
        await session.initialize()
        session.send_raw(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"')
        session.send_raw(b"A" * 5000 + b'"}}\n')
        error = assert_error(await session.receive(), ErrorCode.INVALID_REQUEST)
        assert error["data"] == {"max_frame_bytes": 1024}
        assert (await session.call(2, "ping"))["id"] == 2


async def test_default_limit_rejects_payload_over_one_mebibyte(ready: Session) -> None:
    padding = "A" * MAX_FRAME_BYTES
    ready.send({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": padding}})
    assert_error(await ready.receive(), ErrorCode.INVALID_REQUEST)
    assert (await ready.call(2, "ping"))["id"] == 2


async def test_notifications_and_client_responses_are_never_answered(ready: Session) -> None:
    ready.send(notification("notifications/unknown", {"x": 1}))
    ready.send(notification("notifications/cancelled", {"requestId": 404}))
    ready.send(notification("notifications/cancelled", {"requestId": True}))
    ready.send(notification("notifications/cancelled"))
    ready.send({"jsonrpc": "2.0", "id": 99, "result": {}})
    assert (await ready.call(1, "ping"))["id"] == 1
    ready.assert_silent()


async def test_notification_with_bad_params_reports_null_id(ready: Session) -> None:
    ready.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": [1]})
    assert_error(await ready.receive(), ErrorCode.INVALID_PARAMS)


# ---------------------------------------------------------------------------
# tools/call
# ---------------------------------------------------------------------------
async def test_tool_call_success(ready: Session) -> None:
    response = await ready.tool(1, "echo", {"text": "hello"})
    mcp_types.JSONRPCResponse.model_validate(response)
    result = mcp_types.CallToolResult.model_validate(response["result"])
    assert result.is_error is False
    assert response["result"]["structuredContent"] == {"text": "hello"}
    assert json.loads(response["result"]["content"][0]["text"]) == {"text": "hello"}


async def test_tool_call_with_step2_schema(ready: Session) -> None:
    response = await ready.tool(1, "read_only_sql", {"query": "SELECT 1", "max_rows": 7})
    assert response["result"]["structuredContent"]["rows"] == [[7]]


async def test_tool_call_arguments_default_to_empty(ready: Session) -> None:
    response = await ready.call(1, "tools/call", {"name": "echo"})
    data = assert_tool_problem(response, MCPErrorCode.VALIDATION_ERROR, 1)
    assert data["invalid_params"] == ["text"]


@pytest.mark.parametrize(
    ("arguments", "invalid"),
    [
        ({"query": "SELECT 1", "max_rows": "50"}, ["max_rows"]),
        ({"query": "SELECT 1", "max_rows": 51}, ["max_rows"]),
        ({"query": "SELECT 1", "max_rows": True}, ["max_rows"]),
        ({"query": "SELECT 1", "evil": 1}, ["evil"]),
        ({}, ["query"]),
    ],
)
async def test_tool_argument_validation(
    ready: Session, arguments: dict[str, Any], invalid: list[str]
) -> None:
    response = await ready.tool(3, "read_only_sql", arguments)
    data = assert_tool_problem(response, MCPErrorCode.VALIDATION_ERROR, 3)
    assert data["invalid_params"] == invalid
    assert data["status"] == 422
    assert all(set(err) == {"loc", "type", "msg"} for err in data["metadata"]["errors"])


@pytest.mark.parametrize(
    ("params", "invalid"),
    [
        ({"arguments": {}}, "name"),
        ({"name": 42}, "name"),
        ({"name": "echo", "arguments": ["x"]}, "arguments"),
        ({"name": "nope"}, "name"),
    ],
)
async def test_tool_call_envelope_validation(
    ready: Session, params: dict[str, Any], invalid: str
) -> None:
    response = await ready.call(4, "tools/call", params)
    assert assert_problem(response, MCPErrorCode.VALIDATION_ERROR, 4)["invalid_params"] == [invalid]


async def test_unknown_tool_message(ready: Session) -> None:
    response = await ready.tool(4, "nope", {})
    assert response["error"]["message"] == "Unknown tool: 'nope'"


async def test_tool_error_is_in_band_is_error_result(ready: Session) -> None:
    data = assert_tool_problem(
        await ready.tool(1, "denied", {"text": "x"}), MCPErrorCode.ACCESS_DENIED, 1
    )
    assert data["status"] == 403
    assert data["detail"] == "path escapes sandbox"
    assert data["type"] == ERROR_TAXONOMY[MCPErrorCode.ACCESS_DENIED].type


async def test_timeout_is_in_band_execution_timeout(ready: Session) -> None:
    response = await ready.tool(1, "too_slow", {"text": "x"})
    assert assert_tool_problem(response, MCPErrorCode.EXECUTION_TIMEOUT, 1)["status"] == 504


@pytest.mark.parametrize("tool", ["boom", "wrong_type"])
async def test_unexpected_failure_is_internal_error_without_leak(
    ready: Session, tool: str, caplog: pytest.LogCaptureFixture
) -> None:
    arguments = {"text": "x"}
    with caplog.at_level(logging.ERROR, logger="mcp_server_suite.core.server"):
        response = await ready.tool(1, tool, arguments)
    assert_problem(response, MCPErrorCode.INTERNAL_ERROR, 1)
    assert "secret" not in json.dumps(response)
    assert any(record.exc_info for record in caplog.records)


async def test_unserialisable_result_is_internal_error(ready: Session) -> None:
    response = await ready.tool(1, "unserialisable", {"query": "SELECT 1"})
    assert_problem(response, MCPErrorCode.INTERNAL_ERROR, 1)


async def test_slow_tool_does_not_block_other_requests(ready: Session, slow: SlowTool) -> None:
    ready.send(request("slow-1", "tools/call", {"name": "slow", "arguments": {"text": "late"}}))
    await asyncio.wait_for(slow.started.wait(), TIMEOUT)
    assert ready.server.in_flight == 1
    assert (await ready.call(2, "ping"))["id"] == 2
    assert (await ready.tool(3, "echo", {"text": "fast"}))["id"] == 3
    slow.release.set()
    response = await ready.receive()
    assert response["id"] == "slow-1"
    assert response["result"]["structuredContent"] == {"text": "late"}
    await eventually(lambda: ready.server.in_flight == 0)


async def test_cancelled_notification_aborts_call_without_response(
    ready: Session, slow: SlowTool
) -> None:
    ready.send(request(7, "tools/call", {"name": "slow", "arguments": {"text": "x"}}))
    await asyncio.wait_for(slow.started.wait(), TIMEOUT)
    ready.send(notification("notifications/cancelled", {"requestId": 7, "reason": "user"}))
    await asyncio.wait_for(slow.cancelled.wait(), TIMEOUT)
    assert (await ready.call(8, "ping"))["id"] == 8
    ready.assert_silent()
    await eventually(lambda: ready.server.in_flight == 0)


async def test_cancel_only_matches_exact_id_type(ready: Session, slow: SlowTool) -> None:
    ready.send(request(7, "tools/call", {"name": "slow", "arguments": {"text": "x"}}))
    await asyncio.wait_for(slow.started.wait(), TIMEOUT)
    ready.send(notification("notifications/cancelled", {"requestId": "7"}))
    assert (await ready.call(8, "ping"))["id"] == 8
    assert not slow.cancelled.is_set()
    slow.release.set()
    assert (await ready.receive())["id"] == 7


async def test_duplicate_in_flight_id_rejected(ready: Session, slow: SlowTool) -> None:
    ready.send(request(1, "tools/call", {"name": "slow", "arguments": {"text": "x"}}))
    await asyncio.wait_for(slow.started.wait(), TIMEOUT)
    assert_error(await ready.call(1, "ping"), ErrorCode.INVALID_REQUEST, 1)
    slow.release.set()
    assert (await ready.receive())["id"] == 1


# ---------------------------------------------------------------------------
# Shutdown & teardown
# ---------------------------------------------------------------------------
async def test_eof_cancels_in_flight_work_after_grace(
    registry: ToolRegistry, slow: SlowTool
) -> None:
    server = MCPServer(registry, ServerConfig(shutdown_grace_seconds=0.05))
    async with Session(server) as session:
        await session.initialize()
        session.send(request(1, "tools/call", {"name": "slow", "arguments": {"text": "x"}}))
        await asyncio.wait_for(slow.started.wait(), TIMEOUT)
        session.close_input()
        await session.wait_closed()
        assert slow.cancelled.is_set()
        assert session.sink.closed
        session.assert_silent()
    assert server.in_flight == 0


async def test_eof_waits_for_in_flight_work_within_grace(
    registry: ToolRegistry, slow: SlowTool
) -> None:
    async with Session(MCPServer(registry)) as session:
        await session.initialize()
        session.send(request(1, "tools/call", {"name": "slow", "arguments": {"text": "done"}}))
        await asyncio.wait_for(slow.started.wait(), TIMEOUT)
        session.close_input()
        await asyncio.sleep(0.01)
        assert session.task is not None
        assert not session.task.done()
        slow.release.set()
        await session.wait_closed()
        response = await session.receive()
    assert response["result"]["structuredContent"] == {"text": "done"}


async def test_zero_grace_cancels_immediately(registry: ToolRegistry, slow: SlowTool) -> None:
    async with Session(MCPServer(registry, ServerConfig(shutdown_grace_seconds=0))) as session:
        await session.initialize()
        session.send(request(1, "tools/call", {"name": "slow", "arguments": {"text": "x"}}))
        await asyncio.wait_for(slow.started.wait(), TIMEOUT)
        session.close_input()
        await session.wait_closed()
    assert slow.cancelled.is_set()


async def test_second_shutdown_request_forces_cancellation(
    registry: ToolRegistry, slow: SlowTool
) -> None:
    server = MCPServer(registry, ServerConfig(shutdown_grace_seconds=60))
    async with Session(server) as session:
        await session.initialize()
        session.send(request(1, "tools/call", {"name": "slow", "arguments": {"text": "x"}}))
        await asyncio.wait_for(slow.started.wait(), TIMEOUT)
        server.request_shutdown()
        await asyncio.sleep(0.01)
        assert session.task is not None
        assert not session.task.done(), "first request drains gracefully"
        server.request_shutdown()
        await session.wait_closed()
    assert slow.cancelled.is_set()


async def test_force_before_drain_skips_grace(registry: ToolRegistry, slow: SlowTool) -> None:
    server = MCPServer(registry, ServerConfig(shutdown_grace_seconds=60))
    async with Session(server) as session:
        await session.initialize()
        session.send(request(1, "tools/call", {"name": "slow", "arguments": {"text": "x"}}))
        await asyncio.wait_for(slow.started.wait(), TIMEOUT)
        server.request_shutdown()
        server.request_shutdown()
        await session.wait_closed()
    assert slow.cancelled.is_set()


async def test_shutdown_requested_before_serve(registry: ToolRegistry) -> None:
    server = MCPServer(registry)
    server.request_shutdown()
    sink = RecordingSink()
    await asyncio.wait_for(server.serve(asyncio.StreamReader(), sink), TIMEOUT)
    assert sink.closed


async def test_serve_is_single_use(registry: ToolRegistry) -> None:
    server = MCPServer(registry)
    async with Session(server):
        pass
    with pytest.raises(RuntimeError, match="only be called once"):
        await server.serve(asyncio.StreamReader(), RecordingSink())


async def test_send_outside_session_is_a_programming_error(registry: ToolRegistry) -> None:
    with pytest.raises(RuntimeError, match="no active session"):
        await MCPServer(registry)._send({})


async def test_broken_output_stream_ends_session(registry: ToolRegistry) -> None:
    async with Session(MCPServer(registry), sink=BrokenSink()) as session:
        session.send(request(1, "ping"))
        await session.wait_closed()


async def test_broken_input_stream_ends_session(registry: ToolRegistry) -> None:
    sink = RecordingSink()
    await asyncio.wait_for(MCPServer(registry).serve(FailingSource(), sink), TIMEOUT)
    assert sink.closed


@pytest.mark.parametrize("kwargs", [{"max_frame_bytes": 0}, {"shutdown_grace_seconds": -1.0}])
def test_server_config_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must be"):
        ServerConfig(**kwargs)


# ---------------------------------------------------------------------------
# Stdio transport
# ---------------------------------------------------------------------------
HANDSHAKE = (
    frame(request(1, "initialize", INIT_PARAMS))
    + frame(notification("notifications/initialized"))
    + frame(request(2, "tools/list"))
    + frame(request(3, "tools/call", {"name": "echo", "arguments": {"text": "pipe"}}))
    + frame(request(4, "ping"))
)


@contextmanager
def pipe_pair() -> Iterator[tuple[int, int]]:
    read_fd, write_fd = os.pipe()
    try:
        yield read_fd, write_fd
    finally:
        for fd in (read_fd, write_fd):
            with suppress(OSError):
                os.close(fd)


def _read_all(fd: int) -> bytes:
    chunks = []
    while chunk := os.read(fd, 65_536):
        chunks.append(chunk)
    return b"".join(chunks)


def _responses(data: bytes) -> dict[Any, dict[str, Any]]:
    messages = [json.loads(line) for line in data.splitlines()]
    return {message["id"]: message for message in messages}


def _assert_handshake(responses: dict[Any, dict[str, Any]]) -> None:
    assert set(responses) == {1, 2, 3, 4}
    assert responses[1]["result"]["protocolVersion"] == LATEST_PROTOCOL_VERSION
    assert responses[3]["result"]["structuredContent"] == {"text": "pipe"}
    assert responses[4]["result"] == {}


async def test_run_stdio_over_pipes(registry: ToolRegistry) -> None:
    with pipe_pair() as (in_r, in_w), pipe_pair() as (out_r, out_w):
        os.write(in_w, HANDSHAKE)
        os.close(in_w)
        await asyncio.wait_for(
            run_stdio(MCPServer(registry), stdin_fd=in_r, stdout_fd=out_w), TIMEOUT
        )
        assert os.get_blocking(in_r), "original blocking mode restored"
        assert os.get_blocking(out_w)
        os.close(out_w)
        _assert_handshake(_responses(_read_all(out_r)))


async def test_run_stdio_over_regular_files(registry: ToolRegistry, tmp_path: Path) -> None:
    requests_file = tmp_path / "requests.jsonl"
    responses_file = tmp_path / "responses.jsonl"
    requests_file.write_bytes(HANDSHAKE)
    with requests_file.open("rb") as stdin, responses_file.open("wb") as stdout:
        await asyncio.wait_for(
            run_stdio(MCPServer(registry), stdin_fd=stdin.fileno(), stdout_fd=stdout.fileno()),
            TIMEOUT,
        )
    _assert_handshake(_responses(responses_file.read_bytes()))


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
async def test_signal_triggers_graceful_shutdown(
    registry: ToolRegistry, signum: signal.Signals
) -> None:
    with pipe_pair() as (in_r, in_w), pipe_pair() as (out_r, out_w):
        server = MCPServer(registry)
        task = asyncio.create_task(run_stdio(server, stdin_fd=in_r, stdout_fd=out_w))
        os.write(in_w, frame(request(1, "ping")))
        first = await asyncio.wait_for(asyncio.to_thread(os.read, out_r, 65_536), TIMEOUT)
        assert json.loads(first)["id"] == 1
        signal.raise_signal(signum)
        await asyncio.wait_for(task, TIMEOUT)
    assert signal.getsignal(signum) in {signal.SIG_DFL, signal.default_int_handler}


async def test_print_is_redirected_away_from_stdout(
    registry: ToolRegistry, capsys: pytest.CaptureFixture[str]
) -> None:
    async def noisy(params: EchoParams) -> EchoResult:
        print("stray output")  # noqa: T201
        return EchoResult(text=params.text)

    registry.register(_echo_tool("noisy", noisy))
    with pipe_pair() as (in_r, in_w), pipe_pair() as (out_r, out_w):
        os.write(
            in_w,
            frame(request(1, "initialize", INIT_PARAMS))
            + frame(request(2, "tools/call", {"name": "noisy", "arguments": {"text": "x"}})),
        )
        os.close(in_w)
        await asyncio.wait_for(
            run_stdio(MCPServer(registry), stdin_fd=in_r, stdout_fd=out_w), TIMEOUT
        )
        os.close(out_w)
        assert set(_responses(_read_all(out_r))) == {1, 2}
    assert "stray output" in capsys.readouterr().err


async def test_signal_handler_install_failure_is_tolerated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = asyncio.get_running_loop()

    def unsupported(sig: int, callback: Callable[[], None]) -> None:
        raise NotImplementedError

    monkeypatch.setattr(loop, "add_signal_handler", unsupported)
    remove = install_signal_handlers(loop, lambda: None)
    remove()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def test_main_runs_stdio_server(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[MCPServer] = []

    async def fake_run_stdio(server: MCPServer) -> None:
        seen.append(server)

    monkeypatch.setattr(entrypoint, "run_stdio", fake_run_stdio)
    monkeypatch.setenv(entrypoint.LOG_LEVEL_ENV, "bogus")
    assert entrypoint.main() == 0
    assert len(seen) == 1


def test_main_returns_130_on_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    async def interrupted(server: MCPServer) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(entrypoint, "run_stdio", interrupted)
    assert entrypoint.main() == 130


# ---------------------------------------------------------------------------
# Tool names render as plain strings (regression: ToolName enum repr leaked)
# ---------------------------------------------------------------------------
def test_enum_tool_name_is_stored_as_plain_string() -> None:
    tool = _echo_tool(ToolName.SYSTEM_METRICS, _echo)
    assert type(tool.name) is str
    assert tool.name == "system_metrics"
    assert type(tool.spec["name"]) is str


def test_validation_detail_uses_clean_tool_name() -> None:
    tool = _echo_tool(ToolName.SANDBOX_FS_READ, _echo)
    with pytest.raises(ToolError) as exc_info:
        tool.parse_arguments({})
    problem = exc_info.value.problem
    assert problem.detail == "1 invalid argument(s) for tool 'sandbox_fs_read'"
    assert "ToolName" not in json.dumps(problem.to_json_dict())


async def test_wrong_result_type_message_uses_clean_tool_name() -> None:
    tool = _echo_tool(ToolName.SYSTEM_METRICS, _wrong_type)
    with pytest.raises(TypeError, match=r"^tool 'system_metrics' returned "):
        await tool.invoke({"text": "x"})


def test_duplicate_registration_message_uses_clean_tool_name() -> None:
    registry = ToolRegistry([_echo_tool(ToolName.SYSTEM_METRICS, _echo)])
    with pytest.raises(ValueError, match=r"^tool 'system_metrics' is already registered$"):
        registry.register(_echo_tool(ToolName.SYSTEM_METRICS, _echo))


async def test_real_tool_validation_problem_on_the_wire(tmp_path: Path) -> None:
    tool = SandboxFsReadTool(SandboxSettings(safe_data_dir=tmp_path))
    responses = await run_session(
        ToolRegistry([tool.definition()]),
        tool_call(1, "sandbox_fs_read", {"relative_path": "a.txt", "max_bytes": 0}),
    )
    problem = in_band_problem(responses[1], MCPErrorCode.VALIDATION_ERROR)
    assert problem["detail"] == "1 invalid argument(s) for tool 'sandbox_fs_read'"
    assert problem["invalid_params"] == ["max_bytes"]
    assert "ToolName" not in responses[1]["result"]["content"][0]["text"]

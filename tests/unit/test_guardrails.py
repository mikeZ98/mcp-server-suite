"""Hermetic tests for the guardrail layer: sanitizer, concurrency limiter, deadlines."""

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

import mcp_types
import pytest
from pydantic import ValidationError

from mcp_server_suite.core import MCPServer, ToolDefinition, ToolError, ToolRegistry
from mcp_server_suite.guardrails import (
    ArgumentSanitizer,
    ConcurrencyLimiter,
    Guardrails,
    GuardrailSettings,
    SanitizerLimits,
    find_forbidden_character,
    run_with_deadline,
)
from mcp_server_suite.schemas import MCPErrorCode, ProblemDetail, StrictModel

TIMEOUT = 5.0


def problem_of(exc_info: pytest.ExceptionInfo[ToolError], code: MCPErrorCode) -> ProblemDetail:
    problem = exc_info.value.problem
    assert problem.code is code, problem
    return problem


# ---------------------------------------------------------------------------
# Sanitizer - characters
# ---------------------------------------------------------------------------
FORBIDDEN_CODEPOINTS = [
    0x00, 0x01, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x1B, 0x1F,  # C0
    0x7F, 0x80, 0x85, 0x9F,  # DEL + C1
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi
    0x2066, 0x2067, 0x2068, 0x2069,  # bidi isolates
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,  # zero-width
    0x2028, 0x2029,  # separators
    0xD800, 0xDBFF, 0xDC00, 0xDFFF,  # lone surrogates
]  # fmt: skip
ALLOWED_CODEPOINTS = [
    0x09, 0x0A, 0x0D, 0x20, 0x7E, 0xA0, 0xE9, 0x017C,  # TAB LF CR, printable, Latin
    0x061B, 0x200A, 0x2010, 0x2027, 0x202F, 0x205F, 0x2065, 0x206A,  # range neighbours
    0xFEFE, 0xFF0E, 0x1F389, 0x6F22,  # BMP / astral / CJK
]  # fmt: skip


@pytest.mark.parametrize("codepoint", FORBIDDEN_CODEPOINTS, ids=lambda c: f"U+{c:04X}")
def test_forbidden_characters_rejected(codepoint: int) -> None:
    text = f"SELECT 1 {chr(codepoint)} x"
    assert find_forbidden_character(text) == (9, f"U+{codepoint:04X}")
    with pytest.raises(ToolError) as exc_info:
        ArgumentSanitizer().check({"query": text})
    problem = problem_of(exc_info, MCPErrorCode.VALIDATION_ERROR)
    assert problem.invalid_params == ("query",)
    assert problem.metadata == {
        "reason": "forbidden_character",
        "codepoint": f"U+{codepoint:04X}",
        "index": 9,
    }


@pytest.mark.parametrize("codepoint", ALLOWED_CODEPOINTS, ids=lambda c: f"U+{c:04X}")
def test_ordinary_text_is_allowed(codepoint: int) -> None:
    ArgumentSanitizer().check({"query": f"SELECT '{chr(codepoint)}'"})


def test_problem_detail_never_echoes_the_raw_character() -> None:
    with pytest.raises(ToolError) as exc_info:
        ArgumentSanitizer().check({"query": "a" + chr(0x202E) + "b"})
    body = json.dumps(exc_info.value.problem.to_json_dict(), ensure_ascii=False)
    assert chr(0x202E) not in body


def test_nested_location_is_reported() -> None:
    arguments = {"filters": [{"name": "ok"}, {"name": "bad" + chr(0x07)}]}
    with pytest.raises(ToolError) as exc_info:
        ArgumentSanitizer().check(arguments)
    assert problem_of(exc_info, MCPErrorCode.VALIDATION_ERROR).invalid_params == (
        "filters[1].name",
    )


def test_non_string_scalars_pass_and_arguments_are_not_mutated() -> None:
    arguments: dict[str, Any] = {"n": 1, "f": 1.5, "b": True, "z": None, "s": "line\nbreak"}
    snapshot = json.dumps(arguments)
    ArgumentSanitizer().check(arguments)
    assert json.dumps(arguments) == snapshot


# ---------------------------------------------------------------------------
# Sanitizer - parameter poisoning and structure
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "key",
    [
        "max rows",
        "max_rows ",
        "max" + chr(0x200B) + "_rows",
        "max-rows",
        "1st",
        "",
        "__proto__",
        "__class__",
        "a" * 65,
        "caf" + chr(0xE9),
        "x" + chr(0x00),
    ],
)
def test_poisoned_keys_rejected(key: str) -> None:
    with pytest.raises(ToolError) as exc_info:
        ArgumentSanitizer().check({key: 1})
    problem = problem_of(exc_info, MCPErrorCode.VALIDATION_ERROR)
    assert problem.metadata["reason"] == "invalid_key"
    assert problem.detail.isascii(), "non-ASCII key bytes are escaped in the detail"


def test_poisoned_nested_key_location() -> None:
    with pytest.raises(ToolError) as exc_info:
        ArgumentSanitizer().check({"outer": {"bad key": 1}})
    assert problem_of(exc_info, MCPErrorCode.VALIDATION_ERROR).invalid_params == ("outer.bad key",)


@pytest.mark.parametrize("key", ["max_rows", "_private", "A1", "a" * 64, "query"])
def test_identifier_keys_allowed(key: str) -> None:
    ArgumentSanitizer().check({key: 1})


def _nested(depth: int) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for _ in range(depth - 1):
        value = {"k": value}
    return value


def test_depth_limit() -> None:
    sanitizer = ArgumentSanitizer(SanitizerLimits(max_depth=4))
    sanitizer.check(_nested(4))
    with pytest.raises(ToolError) as exc_info:
        sanitizer.check(_nested(5))
    assert problem_of(exc_info, MCPErrorCode.VALIDATION_ERROR).metadata["reason"] == "max_depth"


def test_depth_counts_lists() -> None:
    sanitizer = ArgumentSanitizer(SanitizerLimits(max_depth=2))
    sanitizer.check({"a": []})
    with pytest.raises(ToolError):
        sanitizer.check({"a": [[]]})


@pytest.mark.parametrize("container", ["list", "dict"])
def test_item_limit(container: str) -> None:
    sanitizer = ArgumentSanitizer(SanitizerLimits(max_items=10))
    ok: Any = list(range(10)) if container == "list" else {f"k{i}": i for i in range(9)}
    big: Any = list(range(11)) if container == "list" else {f"k{i}": i for i in range(11)}
    sanitizer.check({"v": ok} if container == "list" else ok)
    with pytest.raises(ToolError) as exc_info:
        sanitizer.check({"v": big} if container == "list" else big)
    assert problem_of(exc_info, MCPErrorCode.VALIDATION_ERROR).metadata["reason"] == "max_items"


def test_long_locations_are_truncated() -> None:
    deep: dict[str, Any] = {"x": "bad" + chr(0x07)}
    for _ in range(7):
        deep = {"k" * 60: deep}
    with pytest.raises(ToolError) as exc_info:
        ArgumentSanitizer().check(deep)
    (location,) = problem_of(exc_info, MCPErrorCode.VALIDATION_ERROR).invalid_params
    assert len(location) == 256


@pytest.mark.parametrize("kwargs", [{"max_depth": 0}, {"max_items": 0}])
def test_sanitizer_limits_validation(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        SanitizerLimits(**kwargs)


# ---------------------------------------------------------------------------
# Concurrency limiter
# ---------------------------------------------------------------------------
async def test_slot_accounting() -> None:
    limiter = ConcurrencyLimiter(max_concurrent=2, acquire_timeout=1.0)
    assert (limiter.max_concurrent, limiter.in_use, limiter.waiting) == (2, 0, 0)
    async with limiter.slot("t"):
        assert limiter.in_use == 1
        async with limiter.slot("t"):
            assert limiter.in_use == 2
    assert (limiter.in_use, limiter.waiting) == (0, 0)


async def test_saturation_rejects_after_bounded_wait() -> None:
    limiter = ConcurrencyLimiter(max_concurrent=2, acquire_timeout=0.05)
    release = asyncio.Event()

    async def hold() -> None:
        async with limiter.slot("slow"):
            await release.wait()

    holders = [asyncio.create_task(hold()) for _ in range(2)]
    await asyncio.sleep(0)
    assert limiter.in_use == 2
    started = time.monotonic()
    with pytest.raises(ToolError) as exc_info:
        async with limiter.slot("late"):
            pytest.fail("a third slot must not be granted")
    elapsed = time.monotonic() - started
    problem = problem_of(exc_info, MCPErrorCode.INTERNAL_ERROR)
    assert problem.metadata["reason"] == "capacity_exhausted"
    assert problem.metadata["retryable"] is True
    assert problem.metadata["max_concurrent_tools"] == 2
    assert 0.04 <= elapsed < 1.0
    assert limiter.waiting == 0
    release.set()
    await asyncio.gather(*holders)
    assert limiter.in_use == 0


async def test_zero_acquire_timeout_rejects_immediately_only_when_full() -> None:
    limiter = ConcurrencyLimiter(max_concurrent=1, acquire_timeout=0)
    async with limiter.slot("first"):
        with pytest.raises(ToolError):
            async with limiter.slot("second"):
                pytest.fail("must not run")
    async with limiter.slot("after"):
        assert limiter.in_use == 1


async def test_waiters_are_served_fifo() -> None:
    limiter = ConcurrencyLimiter(max_concurrent=1, acquire_timeout=TIMEOUT)
    order: list[int] = []
    gate = asyncio.Event()

    async def worker(index: int) -> None:
        async with limiter.slot("w"):
            order.append(index)
            if index == 0:
                await gate.wait()

    first = asyncio.create_task(worker(0))
    await asyncio.sleep(0)
    queued = []
    for index in range(1, 6):
        queued.append(asyncio.create_task(worker(index)))
        await asyncio.sleep(0)
    assert limiter.waiting == 5
    gate.set()
    await asyncio.wait_for(asyncio.gather(first, *queued), TIMEOUT)
    assert order == [0, 1, 2, 3, 4, 5]


async def test_slot_released_on_exception() -> None:
    limiter = ConcurrencyLimiter(max_concurrent=1, acquire_timeout=0)
    with pytest.raises(RuntimeError):
        async with limiter.slot("x"):
            raise RuntimeError
    async with limiter.slot("x"):
        assert limiter.in_use == 1


async def test_cancelled_waiter_does_not_leak_a_slot() -> None:
    limiter = ConcurrencyLimiter(max_concurrent=1, acquire_timeout=TIMEOUT)
    release = asyncio.Event()

    async def hold() -> None:
        async with limiter.slot("h"):
            await release.wait()

    async def wait_for_slot() -> None:
        async with limiter.slot("w"):
            pytest.fail("cancelled waiter must not run")

    holder = asyncio.create_task(hold())
    await asyncio.sleep(0)
    waiter = asyncio.create_task(wait_for_slot())
    await asyncio.sleep(0)
    assert limiter.waiting == 1
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert limiter.waiting == 0
    release.set()
    await holder
    async with limiter.slot("again"):
        assert limiter.in_use == 1


async def test_cancelled_holder_releases_its_slot() -> None:
    limiter = ConcurrencyLimiter(max_concurrent=1, acquire_timeout=0)
    started = asyncio.Event()

    async def hold() -> None:
        async with limiter.slot("h"):
            started.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(hold())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert limiter.in_use == 0


@pytest.mark.parametrize(("size", "wait"), [(0, 1.0), (1, -0.1)])
def test_limiter_validation(size: int, wait: float) -> None:
    with pytest.raises(ValueError, match="must be"):
        ConcurrencyLimiter(size, wait)


# ---------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------
async def test_deadline_returns_fast_results() -> None:
    async def fast() -> int:
        return 42

    assert await run_with_deadline(fast, 1.0, "fast") == 42


async def test_deadline_cancels_slow_work_promptly() -> None:
    cancelled = asyncio.Event()

    async def slow() -> None:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    started = time.monotonic()
    with pytest.raises(ToolError) as exc_info:
        await asyncio.wait_for(run_with_deadline(slow, 0.05, "slow"), TIMEOUT)
    elapsed = time.monotonic() - started
    problem = problem_of(exc_info, MCPErrorCode.EXECUTION_TIMEOUT)
    assert problem.metadata == {"deadline_seconds": 0.05, "deadline_hit": True}
    assert problem.detail == "tool 'slow' exceeded its 0.05s deadline and was cancelled"
    assert cancelled.is_set()
    assert elapsed < 1.0


async def test_deadline_cancels_the_whole_task_tree() -> None:
    children_cancelled: list[int] = []

    async def child(index: int) -> None:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            children_cancelled.append(index)
            raise

    async def fan_out() -> None:
        async with asyncio.TaskGroup() as group:
            for index in range(3):
                group.create_task(child(index))

    with pytest.raises(ToolError):
        await asyncio.wait_for(run_with_deadline(fan_out, 0.05, "fan_out"), TIMEOUT)
    assert sorted(children_cancelled) == [0, 1, 2]


async def test_inner_timeout_is_reported_without_deadline_flag() -> None:
    async def driver_timeout() -> None:
        raise TimeoutError

    with pytest.raises(ToolError) as exc_info:
        await run_with_deadline(driver_timeout, 10.0, "sql")
    problem = problem_of(exc_info, MCPErrorCode.EXECUTION_TIMEOUT)
    assert problem.metadata["deadline_hit"] is False
    assert problem.detail == "tool 'sql' timed out"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def test_guardrail_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("MAX_CONCURRENT_TOOLS", "TOOL_ACQUIRE_TIMEOUT_SECONDS", "TOOL_TIMEOUT_SECONDS"):
        monkeypatch.delenv(f"MCP_{name}", raising=False)
    settings = GuardrailSettings()
    assert settings.max_concurrent_tools == 16
    assert settings.tool_acquire_timeout_seconds == 5.0
    assert settings.tool_timeout_seconds == 30.0


def test_guardrail_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_MAX_CONCURRENT_TOOLS", "4")
    monkeypatch.setenv("MCP_TOOL_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setenv("MCP_SAFE_DATA_DIR", "/unrelated")  # other MCP_* vars are ignored
    guardrails = Guardrails()
    assert guardrails.limiter.max_concurrent == 4
    assert guardrails.settings.tool_timeout_seconds == 2.5


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_concurrent_tools": 0},
        {"tool_timeout_seconds": 0},
        {"tool_timeout_seconds": 601},
        {"tool_acquire_timeout_seconds": -1},
        {"max_argument_depth": 0},
        {"unknown": 1},
    ],
)
def test_guardrail_settings_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        GuardrailSettings(**kwargs)


# ---------------------------------------------------------------------------
# Integration - every tools/call goes through the guardrails
# ---------------------------------------------------------------------------
class TextParams(StrictModel):
    text: str


class TextResult(StrictModel):
    text: str


class Probe:
    """Tool handler with controllable latency that records calls and cancellations."""

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.calls = 0
        self.cancelled = 0
        self.release = asyncio.Event()
        self.release.set()

    async def __call__(self, params: TextParams) -> TextResult:
        self.calls += 1
        try:
            await self.release.wait()
            await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        return TextResult(text=params.text)


def registry_for(probe: Probe) -> ToolRegistry:
    return ToolRegistry(
        [
            ToolDefinition(
                name="probe",
                description="probe",
                params_model=TextParams,
                result_model=TextResult,
                handler=probe,
            )
        ]
    )


class Collector:
    def __init__(self) -> None:
        self.messages: dict[Any, dict[str, Any]] = {}
        self.arrived = asyncio.Event()

    async def write(self, data: bytes, /) -> None:
        message = json.loads(data)
        self.messages[message["id"]] = message
        self.arrived.set()

    async def aclose(self) -> None:
        return None


INIT = {
    "jsonrpc": "2.0",
    "id": "init",
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}},
}


def call(request_id: int, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "probe", "arguments": arguments},
    }


async def exchange(
    server: MCPServer,
    messages: list[dict[str, Any]],
    *,
    before_eof: Callable[[], Awaitable[None]] | None = None,
) -> dict[Any, dict[str, Any]]:
    reader = asyncio.StreamReader()
    sink = Collector()
    task = asyncio.create_task(server.serve(reader, sink))
    for message in (INIT, *messages):
        reader.feed_data(json.dumps(message).encode() + b"\n")
    if before_eof is not None:
        await before_eof()
    reader.feed_eof()
    await asyncio.wait_for(task, TIMEOUT)
    return sink.messages


def in_band_problem(response: dict[str, Any], code: MCPErrorCode) -> dict[str, Any]:
    result = mcp_types.CallToolResult.model_validate(response["result"])
    assert result.is_error is True
    (content,) = response["result"]["content"]
    problem = ProblemDetail.model_validate_json(content["text"])
    assert problem.code is code
    data: dict[str, Any] = json.loads(content["text"])
    return data


def guardrails(**overrides: Any) -> Guardrails:
    return Guardrails(GuardrailSettings(**overrides))


def test_server_always_has_guardrails() -> None:
    server = MCPServer(ToolRegistry())
    assert isinstance(server._guardrails, Guardrails)


async def test_slow_tool_times_out_in_band_and_is_cancelled() -> None:
    probe = Probe(delay=60)
    server = MCPServer(registry_for(probe), guardrails=guardrails(tool_timeout_seconds=0.05))
    responses = await exchange(server, [call(1, {"text": "x"})])
    problem = in_band_problem(responses[1], MCPErrorCode.EXECUTION_TIMEOUT)
    assert problem["status"] == 504
    assert problem["metadata"]["deadline_hit"] is True
    assert (probe.calls, probe.cancelled) == (1, 1)
    assert server.in_flight == 0


async def test_saturation_through_the_server() -> None:
    probe = Probe()
    probe.release.clear()
    server = MCPServer(
        registry_for(probe),
        guardrails=guardrails(max_concurrent_tools=2, tool_acquire_timeout_seconds=0.05),
    )

    async def saturate_then_release() -> None:
        await asyncio.sleep(0.2)  # third call waits 0.05s and is rejected meanwhile
        probe.release.set()

    responses = await exchange(
        server,
        [call(1, {"text": "a"}), call(2, {"text": "b"}), call(3, {"text": "c"})],
        before_eof=saturate_then_release,
    )
    outcomes = {rid: responses[rid]["result"]["isError"] for rid in (1, 2, 3)}
    assert sorted(outcomes.values()) == [False, False, True]
    (rejected,) = [rid for rid, is_error in outcomes.items() if is_error]
    problem = in_band_problem(responses[rejected], MCPErrorCode.INTERNAL_ERROR)
    assert problem["metadata"]["reason"] == "capacity_exhausted"
    assert probe.calls == 2, "the rejected call never reached the handler"


async def test_sanitizer_rejects_before_the_tool_or_a_slot() -> None:
    probe = Probe()
    gr = guardrails(max_concurrent_tools=1, tool_acquire_timeout_seconds=0)
    server = MCPServer(registry_for(probe), guardrails=gr)
    responses = await exchange(
        server,
        [
            call(1, {"text": "evil" + chr(0x1B) + "[2J"}),
            call(2, {"te" + chr(0x200B) + "xt": "shadow"}),
            call(3, {"text": "x" + chr(0xD800)}),
        ],
    )
    for rid in (1, 2, 3):
        in_band_problem(responses[rid], MCPErrorCode.VALIDATION_ERROR)
    assert probe.calls == 0
    assert gr.limiter.in_use == 0


async def test_lone_surrogate_argument_round_trips_safely() -> None:
    probe = Probe()
    server = MCPServer(registry_for(probe))
    reader = asyncio.StreamReader()
    sink = Collector()
    reader.feed_data(json.dumps(INIT).encode() + b"\n")
    reader.feed_data(
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"probe","arguments":{"text":"\\udfff"}}}\n'
    )
    reader.feed_eof()
    await asyncio.wait_for(server.serve(reader, sink), TIMEOUT)
    problem = in_band_problem(sink.messages[1], MCPErrorCode.VALIDATION_ERROR)
    assert problem["metadata"]["codepoint"] == "U+DFFF"


async def test_queue_wait_does_not_consume_the_execution_deadline() -> None:
    first, second = Probe(delay=0.2), Probe(delay=0.25)
    registry = ToolRegistry(
        [
            ToolDefinition(
                name=name, description=name, params_model=TextParams,
                result_model=TextResult, handler=handler,
            )
            for name, handler in (("first", first), ("second", second))
        ]
    )  # fmt: skip
    gr = guardrails(
        max_concurrent_tools=1, tool_acquire_timeout_seconds=2.0, tool_timeout_seconds=0.4
    )
    server = MCPServer(registry, guardrails=gr)
    messages = [
        {"jsonrpc": "2.0", "id": i, "method": "tools/call",
         "params": {"name": name, "arguments": {"text": name}}}
        for i, name in ((1, "first"), (2, "second"))
    ]  # fmt: skip
    responses = await exchange(server, messages)
    assert responses[1]["result"]["isError"] is False
    # 0.2s queued + 0.25s running exceeds 0.4s, but only the run counts against the deadline.
    assert responses[2]["result"]["isError"] is False


async def test_cancelled_call_frees_its_slot() -> None:
    probe = Probe()
    probe.release.clear()
    gr = guardrails(max_concurrent_tools=1, tool_acquire_timeout_seconds=0)
    server = MCPServer(registry_for(probe), guardrails=gr)

    async def cancel_then_retry(reader_feed: Callable[[dict[str, Any]], None]) -> None:
        await asyncio.sleep(0.05)
        assert gr.limiter.in_use == 1
        reader_feed(
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
        )
        await asyncio.sleep(0.05)
        assert gr.limiter.in_use == 0
        probe.release.set()
        reader_feed(call(2, {"text": "retry"}))
        await asyncio.sleep(0.05)

    reader = asyncio.StreamReader()
    sink = Collector()

    def feed(message: dict[str, Any]) -> None:
        reader.feed_data(json.dumps(message).encode() + b"\n")

    task = asyncio.create_task(server.serve(reader, sink))
    feed(INIT)
    feed(call(1, {"text": "x"}))
    await cancel_then_retry(feed)
    reader.feed_eof()
    await asyncio.wait_for(task, TIMEOUT)
    assert 1 not in sink.messages, "cancelled request gets no response"
    assert sink.messages[2]["result"]["structuredContent"] == {"text": "retry"}
    assert probe.cancelled == 1

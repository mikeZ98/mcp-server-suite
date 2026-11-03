"""MCP request dispatcher and connection lifecycle over a framed byte stream."""

import asyncio
import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from typing import Any, Final

from mcp_server_suite import __version__
from mcp_server_suite.core.framing import (
    MAX_FRAME_BYTES,
    ByteSink,
    ByteSource,
    Frame,
    FrameReader,
    FrameWriter,
    OversizedFrame,
)
from mcp_server_suite.core.jsonrpc import (
    ErrorCode,
    JsonObject,
    JsonRpcError,
    Notification,
    Request,
    RequestId,
    failure,
    is_request_id,
    parse_message,
    success,
)
from mcp_server_suite.core.registry import ToolError, ToolRegistry
from mcp_server_suite.schemas import MCPErrorCode, ProblemDetail

__all__ = [
    "LATEST_PROTOCOL_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "MCPServer",
    "ServerConfig",
]

logger = logging.getLogger(__name__)

# Revisions negotiated through the ``initialize`` handshake, newest first.
SUPPORTED_PROTOCOL_VERSIONS: Final = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
LATEST_PROTOCOL_VERSION: Final = SUPPORTED_PROTOCOL_VERSIONS[0]

_PRE_INIT_METHODS: Final = frozenset({"initialize", "ping"})
_ECHO_LIMIT: Final = 128


@dataclass(frozen=True, slots=True, kw_only=True)
class ServerConfig:
    """Static server identity and transport limits."""

    name: str = "mcp-server-suite"
    version: str = __version__
    instructions: str | None = None
    max_frame_bytes: int = MAX_FRAME_BYTES
    shutdown_grace_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.max_frame_bytes < 1:
            msg = "max_frame_bytes must be positive"
            raise ValueError(msg)
        if self.shutdown_grace_seconds < 0:
            msg = "shutdown_grace_seconds must be non-negative"
            raise ValueError(msg)


def _invalid_params(detail: str, *names: str) -> JsonRpcError:
    return JsonRpcError.from_problem(
        ProblemDetail.from_code(MCPErrorCode.VALIDATION_ERROR, detail, invalid_params=names)
    )


class MCPServer:
    """Serve one MCP session: dispatch requests until EOF or shutdown, then drain.

    ``initialize``, ``ping`` and ``tools/list`` are answered inline, in arrival
    order. Each ``tools/call`` runs as its own task so slow tools never block the
    read loop, and so it can be cancelled by ``notifications/cancelled`` or at
    shutdown. Cancelled requests get no response, as the MCP spec requires.

    Error reporting follows the MCP split: protocol faults (unknown tool, malformed
    ``tools/call`` envelope) are JSON-RPC errors; tool execution errors (invalid
    arguments, policy violations, timeouts) are ``isError: true`` results carrying
    an RFC 9457 problem; unexpected crashes are JSON-RPC ``-32603``.
    """

    def __init__(self, registry: ToolRegistry, config: ServerConfig | None = None) -> None:
        self._registry = registry
        self._config = config or ServerConfig()
        self._handlers: dict[str, Callable[[Mapping[str, Any]], JsonObject]] = {
            "initialize": self._initialize,
            "ping": self._ping,
            "tools/list": self._list_tools,
        }
        self._shutdown = asyncio.Event()
        self._force = False
        self._drain_scope: asyncio.Timeout | None = None
        self._in_flight: dict[RequestId, asyncio.Task[None]] = {}
        self._writer: FrameWriter | None = None
        self._served = False
        self._protocol_version: str | None = None
        self._client_ready = False

    # ------------------------------------------------------------------ state
    @property
    def protocol_version(self) -> str | None:
        """Negotiated protocol revision, or ``None`` before ``initialize``."""
        return self._protocol_version

    @property
    def client_ready(self) -> bool:
        """Whether ``notifications/initialized`` has been received."""
        return self._client_ready

    @property
    def in_flight(self) -> int:
        """Number of ``tools/call`` requests currently executing."""
        return len(self._in_flight)

    def request_shutdown(self) -> None:
        """Stop reading and drain in-flight calls; a second call cancels them immediately."""
        if not self._shutdown.is_set():
            self._shutdown.set()
            return
        self._force = True
        if self._drain_scope is not None:
            self._drain_scope.reschedule(0)

    # -------------------------------------------------------------- lifecycle
    async def serve(self, source: ByteSource, sink: ByteSink) -> None:
        """Run the session until the input reaches EOF or shutdown is requested."""
        if self._served:
            msg = "MCPServer.serve() can only be called once"
            raise RuntimeError(msg)
        self._served = True
        self._writer = FrameWriter(sink)
        frames = FrameReader(source, max_frame_bytes=self._config.max_frame_bytes)
        try:
            async with asyncio.TaskGroup() as tasks:
                reader = tasks.create_task(self._read_loop(frames, tasks), name="mcp-reader")
                await self._shutdown.wait()
                reader.cancel()
                await self._drain()
        finally:
            await self._writer.aclose()
        logger.info("session closed")

    async def _read_loop(self, frames: FrameReader, tasks: asyncio.TaskGroup) -> None:
        try:
            while (frame := await frames.read_frame()) is not None:
                await self._handle_frame(frame, tasks)
            logger.info("input closed")
        except OSError:
            logger.warning("input stream failed", exc_info=True)
        finally:
            self._shutdown.set()

    async def _drain(self) -> None:
        pending = [task for task in self._in_flight.values() if not task.done()]
        grace = self._config.shutdown_grace_seconds
        if pending and grace > 0 and not self._force:
            try:
                async with asyncio.timeout(grace) as scope:
                    self._drain_scope = scope
                    await asyncio.wait(pending)
            except TimeoutError:
                logger.warning("shutdown grace period over; cancelling in-flight calls")
            finally:
                self._drain_scope = None
        for task in list(self._in_flight.values()):
            task.cancel()

    # --------------------------------------------------------------- dispatch
    async def _handle_frame(self, frame: Frame, tasks: asyncio.TaskGroup) -> None:
        if isinstance(frame, OversizedFrame):
            limit = self._config.max_frame_bytes
            error = JsonRpcError(
                ErrorCode.INVALID_REQUEST,
                f"Invalid request: message exceeds {limit} bytes",
                {"max_frame_bytes": limit},
            )
            await self._send(failure(None, error))
            return
        try:
            message = parse_message(frame)
        except JsonRpcError as error:
            await self._send(failure(error.request_id, error))
            return
        if isinstance(message, Request):
            await self._handle_request(message, tasks)
        elif isinstance(message, Notification):
            self._handle_notification(message)
        else:
            logger.debug("ignoring client response id=%r", message.id)

    async def _handle_request(self, request: Request, tasks: asyncio.TaskGroup) -> None:
        if request.id in self._in_flight:
            error = JsonRpcError(ErrorCode.INVALID_REQUEST, "Invalid request: id already in use")
            await self._send(failure(request.id, error))
            return
        if request.method == "tools/call" and self._protocol_version is not None:
            task = tasks.create_task(self._run_tool_call(request), name=f"tools/call:{request.id}")
            self._in_flight[request.id] = task
            task.add_done_callback(partial(self._forget, request.id))
            return
        try:
            result = self._dispatch(request)
        except JsonRpcError as error:
            await self._send(failure(request.id, error))
        else:
            await self._send(success(request.id, result))

    def _forget(self, request_id: RequestId, task: asyncio.Task[None]) -> None:
        if self._in_flight.get(request_id) is task:
            del self._in_flight[request_id]

    def _dispatch(self, request: Request) -> JsonObject:
        handler = self._handlers.get(request.method)
        if handler is None and request.method != "tools/call":
            raise JsonRpcError(
                ErrorCode.METHOD_NOT_FOUND,
                f"Method not found: {request.method[:_ECHO_LIMIT]}",
            )
        if handler is None or (
            request.method not in _PRE_INIT_METHODS and self._protocol_version is None
        ):
            raise JsonRpcError(ErrorCode.INVALID_REQUEST, "Invalid request: not initialized")
        return handler(request.params)

    def _handle_notification(self, notification: Notification) -> None:
        if notification.method == "notifications/initialized":
            self._client_ready = True
        elif notification.method == "notifications/cancelled":
            request_id = notification.params.get("requestId")
            task = self._in_flight.get(request_id) if is_request_id(request_id) else None
            if task is not None:
                logger.info("cancelling request id=%r", request_id)
                task.cancel()
        else:
            logger.debug("ignoring notification %s", notification.method[:_ECHO_LIMIT])

    async def _send(self, message: JsonObject) -> None:
        if self._writer is None:
            msg = "no active session"
            raise RuntimeError(msg)
        try:
            await self._writer.send(message)
        except OSError:
            logger.warning("output stream failed; shutting down", exc_info=True)
            self._shutdown.set()

    # ---------------------------------------------------------------- methods
    def _initialize(self, params: Mapping[str, Any]) -> JsonObject:
        if self._protocol_version is not None:
            raise JsonRpcError(ErrorCode.INVALID_REQUEST, "Invalid request: already initialized")
        requested = params.get("protocolVersion")
        if not isinstance(requested, str):
            raise _invalid_params('"protocolVersion" must be a string', "protocolVersion")
        for member in ("capabilities", "clientInfo"):
            if not isinstance(params.get(member, {}), dict):
                raise _invalid_params(f'"{member}" must be an object', member)
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
        self._protocol_version = version
        logger.info("initialized: client requested %.32s, using %s", requested, version)
        result: JsonObject = {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self._config.name, "version": self._config.version},
        }
        if self._config.instructions is not None:
            result["instructions"] = self._config.instructions
        return result

    def _ping(self, _params: Mapping[str, Any]) -> JsonObject:
        return {}

    def _list_tools(self, _params: Mapping[str, Any]) -> JsonObject:
        return {"tools": self._registry.specs()}

    async def _run_tool_call(self, request: Request) -> None:
        try:
            result = await self._call_tool(request.params)
        except JsonRpcError as error:
            response = failure(request.id, error)
        else:
            response = success(request.id, result)
        await self._send(response)

    async def _call_tool(self, params: Mapping[str, Any]) -> JsonObject:
        name = params.get("name")
        if not isinstance(name, str):
            raise _invalid_params('"name" must be a string', "name")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise _invalid_params('"arguments" must be an object', "arguments")
        tool = self._registry.get(name)
        if tool is None:
            raise _invalid_params(f"Unknown tool: {name[:_ECHO_LIMIT]!r}", "name")
        try:
            result = await tool.invoke(arguments)
            text = result.model_dump_json()
        except ToolError as exc:
            return _tool_error_result(exc.problem)
        except TimeoutError:
            return _tool_error_result(
                ProblemDetail.from_code(
                    MCPErrorCode.EXECUTION_TIMEOUT, f"Tool {name!r} exceeded its deadline"
                )
            )
        except Exception:
            logger.exception("tool %r failed", name)
            problem = ProblemDetail.from_code(
                MCPErrorCode.INTERNAL_ERROR, f"Tool {name!r} failed unexpectedly"
            )
            raise JsonRpcError.from_problem(problem) from None
        return {
            "content": [{"type": "text", "text": text}],
            # Decoded from the JSON text so both views are identical and strictly JSON-safe.
            "structuredContent": json.loads(text),
            "isError": False,
        }


def _tool_error_result(problem: ProblemDetail) -> JsonObject:
    """Tool execution error, reported in-band so the calling model can self-correct.

    Only the RFC 9457 problem is returned (as JSON text); ``structuredContent`` is
    omitted because it would not conform to the tool's ``outputSchema``.
    """
    return {
        "content": [{"type": "text", "text": json.dumps(problem.to_json_dict())}],
        "isError": True,
    }

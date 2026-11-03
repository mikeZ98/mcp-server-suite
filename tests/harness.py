"""Shared in-memory MCP session harness for tool-level protocol tests."""

import asyncio
import json
from typing import Any, Final

import mcp_types

from mcp_server_suite.core import MCPServer, ServerConfig, ToolRegistry
from mcp_server_suite.guardrails import Guardrails
from mcp_server_suite.schemas import MCPErrorCode, ProblemDetail

TIMEOUT: Final = 5.0
PROTOCOL_VERSION: Final = "2025-11-25"


class Collector:
    """In-memory ``ByteSink`` keeping the latest message per response id."""

    def __init__(self) -> None:
        self.messages: dict[Any, dict[str, Any]] = {}
        self.frames: list[bytes] = []

    async def write(self, data: bytes, /) -> None:
        assert data.endswith(b"\n")
        assert data.isascii(), "frames are ASCII-only JSON"
        self.frames.append(data)
        message = json.loads(data)
        self.messages[message["id"]] = message

    async def aclose(self) -> None:
        return None


def initialize(request_id: Any = "init", version: str = PROTOCOL_VERSION) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t"}},
    }


def request(request_id: Any, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def tool_call(request_id: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return request(request_id, "tools/call", {"name": name, "arguments": arguments})


async def run_session(
    registry: ToolRegistry,
    *messages: dict[str, Any],
    config: ServerConfig | None = None,
    guardrails: Guardrails | None = None,
) -> dict[Any, dict[str, Any]]:
    """Initialize, send ``messages``, close input and return responses by id."""
    reader = asyncio.StreamReader()
    for message in (initialize(), *messages):
        reader.feed_data(json.dumps(message).encode() + b"\n")
    reader.feed_eof()
    sink = Collector()
    server = MCPServer(registry, config, guardrails)
    await asyncio.wait_for(server.serve(reader, sink), TIMEOUT)
    return sink.messages


def in_band_problem(response: dict[str, Any], code: MCPErrorCode) -> dict[str, Any]:
    """Assert an ``isError`` tool result carrying exactly one RFC 9457 problem."""
    result = mcp_types.CallToolResult.model_validate(response["result"])
    assert result.is_error is True
    assert "structuredContent" not in response["result"]
    (content,) = response["result"]["content"]
    assert content["type"] == "text"
    problem = ProblemDetail.model_validate_json(content["text"])
    assert problem.code is code, problem
    data: dict[str, Any] = json.loads(content["text"])
    return data


def structured_result(response: dict[str, Any]) -> dict[str, Any]:
    """Assert a successful tool result and return its ``structuredContent``."""
    result = mcp_types.CallToolResult.model_validate(response["result"])
    assert result.is_error is False
    structured: dict[str, Any] = response["result"]["structuredContent"]
    assert json.loads(response["result"]["content"][0]["text"]) == structured
    return structured

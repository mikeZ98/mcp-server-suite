"""JSON-RPC 2.0 envelope parsing and error objects (MCP subset: no batching)."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Final, NoReturn, Self, TypeGuard

from mcp_server_suite.schemas import ProblemDetail

__all__ = [
    "JSONRPC_VERSION",
    "ClientResponse",
    "ErrorCode",
    "JsonObject",
    "JsonRpcError",
    "Message",
    "Notification",
    "Request",
    "RequestId",
    "failure",
    "is_request_id",
    "parse_message",
    "success",
]

JSONRPC_VERSION: Final = "2.0"

type RequestId = int | str
type JsonObject = dict[str, Any]

_REQUEST_MEMBERS: Final = frozenset({"jsonrpc", "id", "method", "params"})
_RESPONSE_MEMBERS: Final = frozenset({"jsonrpc", "id", "result", "error"})


class ErrorCode(IntEnum):
    """Error codes reserved by the JSON-RPC 2.0 specification."""

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603


@dataclass(frozen=True, slots=True)
class Request:
    """A call that expects a response."""

    id: RequestId
    method: str
    params: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Notification:
    """A one-way message; never answered."""

    method: str
    params: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ClientResponse:
    """A response sent by the client (the server issues no requests, so it is ignored)."""

    id: RequestId | None


type Message = Request | Notification | ClientResponse


class JsonRpcError(Exception):
    """A JSON-RPC error object, raised to abort handling of a single message."""

    def __init__(
        self,
        code: int,
        message: str,
        data: Any = None,
        *,
        request_id: RequestId | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
        self.request_id = request_id

    @classmethod
    def from_problem(cls, problem: ProblemDetail) -> Self:
        """Carry an RFC 9457 problem as ``error.data`` under its taxonomy JSON-RPC code."""
        return cls(problem.jsonrpc_code, problem.detail, problem.to_json_dict())

    def to_object(self) -> JsonObject:
        """Serialise as the ``error`` member of a response."""
        obj: JsonObject = {"code": int(self.code), "message": self.message}
        if self.data is not None:
            obj["data"] = self.data
        return obj


def is_request_id(value: object) -> TypeGuard[RequestId]:
    """MCP request ids are strings or integers; ``null`` and booleans are rejected."""
    return isinstance(value, int | str) and not isinstance(value, bool)


def success(request_id: RequestId, result: JsonObject) -> JsonObject:
    """Build a success response envelope."""
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def failure(request_id: RequestId | None, error: JsonRpcError) -> JsonObject:
    """Build an error response envelope (``id`` is ``null`` when it could not be read)."""
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error.to_object()}


def _reject_constant(name: str) -> NoReturn:
    msg = f"non-standard JSON constant {name}"
    raise ValueError(msg)


def _unique_object(pairs: list[tuple[str, Any]]) -> JsonObject:
    obj: JsonObject = {}
    for key, value in pairs:
        if key in obj:
            msg = f"duplicate key {key!r}"
            raise ValueError(msg)
        obj[key] = value
    return obj


def parse_message(frame: bytes) -> Message:
    """Decode one frame into a typed message.

    Raises:
        JsonRpcError: ``PARSE_ERROR`` for undecodable input, ``INVALID_REQUEST`` or
            ``INVALID_PARAMS`` for well-formed JSON that is not a valid MCP message.
    """
    try:
        text = frame.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonRpcError(ErrorCode.PARSE_ERROR, "Parse error: message is not UTF-8") from exc
    try:
        payload = json.loads(
            text, parse_constant=_reject_constant, object_pairs_hook=_unique_object
        )
    except (ValueError, RecursionError) as exc:
        raise JsonRpcError(ErrorCode.PARSE_ERROR, "Parse error: invalid JSON") from exc
    return _classify(payload)


def _classify(payload: object) -> Message:
    if isinstance(payload, list):
        raise JsonRpcError(ErrorCode.INVALID_REQUEST, "Invalid request: batching is not supported")
    if not isinstance(payload, dict):
        raise JsonRpcError(ErrorCode.INVALID_REQUEST, "Invalid request: expected a JSON object")

    raw_id = payload.get("id")
    request_id: RequestId | None = raw_id if is_request_id(raw_id) else None

    def invalid(reason: str) -> JsonRpcError:
        return JsonRpcError(
            ErrorCode.INVALID_REQUEST, f"Invalid request: {reason}", request_id=request_id
        )

    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise invalid('"jsonrpc" must be "2.0"')

    if "method" not in payload:
        keys = payload.keys()
        is_response = ("result" in keys) != ("error" in keys)
        if "id" in keys and is_response and keys <= _RESPONSE_MEMBERS:
            return ClientResponse(request_id)
        raise invalid('missing "method"')

    unexpected = payload.keys() - _REQUEST_MEMBERS
    if unexpected:
        raise invalid(f"unexpected members {sorted(unexpected)}")

    method = payload["method"]
    if not isinstance(method, str) or not method:
        raise invalid('"method" must be a non-empty string')

    has_id = "id" in payload
    if has_id and request_id is None:
        raise invalid('"id" must be a string or an integer')

    params = payload.get("params", {})
    if not isinstance(params, dict):
        raise JsonRpcError(
            ErrorCode.INVALID_PARAMS, '"params" must be an object', request_id=request_id
        )

    if request_id is None:
        return Notification(method, params)
    return Request(request_id, method, params)

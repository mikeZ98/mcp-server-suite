"""RFC 9457 Problem Details contract and the stable MCP error taxonomy."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Final, Self

from pydantic import Field, field_serializer, field_validator, model_validator

from mcp_server_suite.schemas._base import StrictModel

__all__ = [
    "ERROR_TAXONOMY",
    "PROBLEM_JSON_MEDIA_TYPE",
    "ErrorSpec",
    "MCPErrorCode",
    "ProblemDetail",
]

PROBLEM_JSON_MEDIA_TYPE: Final = "application/problem+json"

_TYPE_URI_PREFIX: Final = "urn:mcp-server-suite:problem:"

# URI reference (RFC 3986): no whitespace, control characters or characters that
# must always be percent-encoded.
_URI_REFERENCE_PATTERN: Final = r"^[^\s\x00-\x1f\x7f<>\"{}|\\^`]+$"


class MCPErrorCode(StrEnum):
    """Stable, machine-readable error codes exposed to MCP clients."""

    VALIDATION_ERROR = "MCP_VALIDATION_ERROR"
    ACCESS_DENIED = "MCP_ACCESS_DENIED"
    QUERY_VIOLATION = "MCP_QUERY_VIOLATION"
    EXECUTION_TIMEOUT = "MCP_EXECUTION_TIMEOUT"
    INTERNAL_ERROR = "MCP_INTERNAL_ERROR"


@dataclass(frozen=True, slots=True)
class ErrorSpec:
    """Canonical Problem Details attributes bound to one error code."""

    type: str
    title: str
    status: int
    jsonrpc_code: int


ERROR_TAXONOMY: Final[Mapping[MCPErrorCode, ErrorSpec]] = MappingProxyType(
    {
        MCPErrorCode.VALIDATION_ERROR: ErrorSpec(
            type=f"{_TYPE_URI_PREFIX}validation-error",
            title="Invalid tool arguments",
            status=422,
            jsonrpc_code=-32602,
        ),
        MCPErrorCode.ACCESS_DENIED: ErrorSpec(
            type=f"{_TYPE_URI_PREFIX}access-denied",
            title="Access to the requested resource is denied",
            status=403,
            jsonrpc_code=-32001,
        ),
        MCPErrorCode.QUERY_VIOLATION: ErrorSpec(
            type=f"{_TYPE_URI_PREFIX}query-violation",
            title="Query violates the read-only policy",
            status=403,
            jsonrpc_code=-32002,
        ),
        MCPErrorCode.EXECUTION_TIMEOUT: ErrorSpec(
            type=f"{_TYPE_URI_PREFIX}execution-timeout",
            title="Tool execution exceeded its deadline",
            status=504,
            jsonrpc_code=-32003,
        ),
        MCPErrorCode.INTERNAL_ERROR: ErrorSpec(
            type=f"{_TYPE_URI_PREFIX}internal-error",
            title="Internal server error",
            status=500,
            jsonrpc_code=-32603,
        ),
    }
)


class ProblemDetail(StrictModel):
    """RFC 9457 Problem Details object with an MCP-specific ``code`` extension member.

    ``type`` and ``status`` must agree with :data:`ERROR_TAXONOMY` for ``code`` so a
    single code can never be reported with conflicting HTTP semantics.
    """

    type: Annotated[str, Field(min_length=1, max_length=2048, pattern=_URI_REFERENCE_PATTERN)]
    title: Annotated[str, Field(min_length=1, max_length=200)]
    status: Annotated[int, Field(ge=400, le=599)]
    detail: Annotated[str, Field(min_length=1, max_length=4096)]
    code: MCPErrorCode
    instance: Annotated[
        str | None, Field(default=None, max_length=2048, pattern=_URI_REFERENCE_PATTERN)
    ]
    invalid_params: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...] = ()
    metadata: Mapping[str, Any] = Field(default_factory=lambda: MappingProxyType({}))

    @field_validator("metadata", mode="after")
    @classmethod
    def _freeze_metadata(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return MappingProxyType(dict(value))

    @field_serializer("metadata")
    def _serialize_metadata(self, value: Mapping[str, Any]) -> dict[str, Any]:
        return dict(value)

    @model_validator(mode="after")
    def _check_taxonomy(self) -> Self:
        spec = ERROR_TAXONOMY[self.code]
        if self.status != spec.status:
            msg = f"status {self.status} does not match {self.code} (expected {spec.status})"
            raise ValueError(msg)
        if self.type != spec.type:
            msg = f"type {self.type!r} does not match {self.code} (expected {spec.type!r})"
            raise ValueError(msg)
        return self

    @classmethod
    def from_code(
        cls,
        code: MCPErrorCode,
        detail: str,
        *,
        instance: str | None = None,
        invalid_params: tuple[str, ...] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Self:
        """Build a problem whose ``type``, ``title`` and ``status`` come from the taxonomy."""
        spec = ERROR_TAXONOMY[code]
        return cls(
            type=spec.type,
            title=spec.title,
            status=spec.status,
            detail=detail,
            code=code,
            instance=instance,
            invalid_params=invalid_params,
            metadata=dict(metadata or {}),
        )

    @property
    def jsonrpc_code(self) -> int:
        """JSON-RPC 2.0 error code carrying this problem in an error response."""
        return ERROR_TAXONOMY[self.code].jsonrpc_code

    def to_json_dict(self) -> dict[str, Any]:
        """Serialise as an ``application/problem+json`` body (``None`` members omitted)."""
        return self.model_dump(mode="json", exclude_none=True)

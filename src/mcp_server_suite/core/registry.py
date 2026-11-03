"""Typed tool definitions and the registry the server dispatches ``tools/call`` to."""

import json
import re
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from pydantic import ValidationError

from mcp_server_suite.errors import ToolError
from mcp_server_suite.schemas import MCPErrorCode, ProblemDetail, StrictModel

__all__ = ["ToolDefinition", "ToolError", "ToolRegistry"]

_TOOL_NAME_RE: Final = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_MAX_REPORTED_ERRORS: Final = 20


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolDefinition[P: StrictModel, R: StrictModel]:
    """A tool: strict argument model, strict result model and an async handler."""

    name: str
    description: str
    params_model: type[P]
    result_model: type[R]
    handler: Callable[[P], Awaitable[R]]
    title: str | None = None
    read_only: bool = True
    open_world: bool = False
    _spec: dict[str, Any] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Store a plain ``str``: a ``ToolName`` member would otherwise render as its
        # enum repr wherever the name is formatted with ``!r`` (problem details,
        # log lines, error messages).
        object.__setattr__(self, "name", str(self.name))
        if not _TOOL_NAME_RE.fullmatch(self.name):
            msg = f"invalid tool name {self.name!r}"
            raise ValueError(msg)
        spec: dict[str, Any] = {"name": self.name}
        if self.title is not None:
            spec["title"] = self.title
        spec |= {
            "description": self.description,
            "inputSchema": self.params_model.model_json_schema(mode="validation"),
            "outputSchema": self.result_model.model_json_schema(mode="serialization"),
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": not self.read_only,
                "idempotentHint": self.read_only,
                "openWorldHint": self.open_world,
            },
        }
        object.__setattr__(self, "_spec", spec)

    @property
    def spec(self) -> dict[str, Any]:
        """MCP ``Tool`` object as advertised by ``tools/list``."""
        return self._spec

    def parse_arguments(self, arguments: Mapping[str, Any]) -> P:
        """Validate JSON-origin arguments with JSON-mode strict semantics.

        Raises:
            ToolError: ``MCP_VALIDATION_ERROR`` listing the offending parameters.
        """
        try:
            return self.params_model.model_validate_json(json.dumps(arguments))
        except ValidationError as exc:
            raise ToolError(self._validation_problem(exc)) from None

    async def invoke(self, arguments: Mapping[str, Any]) -> R:
        """Validate arguments, run the handler and check the result contract."""
        params = self.parse_arguments(arguments)
        result = await self.handler(params)
        if not isinstance(result, self.result_model):
            msg = (
                f"tool {self.name!r} returned {type(result).__name__}, "
                f"expected {self.result_model.__name__}"
            )
            raise TypeError(msg)
        return result

    def _validation_problem(self, exc: ValidationError) -> ProblemDetail:
        errors = exc.errors(include_url=False, include_context=False, include_input=False)
        reported = errors[:_MAX_REPORTED_ERRORS]
        locations = [
            ".".join(str(part) for part in err["loc"])[:256] or "arguments" for err in reported
        ]
        return ProblemDetail.from_code(
            MCPErrorCode.VALIDATION_ERROR,
            f"{len(errors)} invalid argument(s) for tool {self.name!r}",
            invalid_params=tuple(dict.fromkeys(locations)),
            metadata={
                "errors": [
                    {"loc": loc, "type": err["type"], "msg": err["msg"]}
                    for loc, err in zip(locations, reported, strict=True)
                ]
            },
        )


class ToolRegistry:
    """Name-indexed set of tools; names are unique."""

    def __init__(self, tools: Iterable[ToolDefinition[Any, Any]] = ()) -> None:
        self._tools: dict[str, ToolDefinition[Any, Any]] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: ToolDefinition[Any, Any]) -> None:
        """Add a tool; duplicate names are a programming error."""
        if tool.name in self._tools:
            msg = f"tool {tool.name!r} is already registered"
            raise ValueError(msg)
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDefinition[Any, Any] | None:
        """Look up a tool by name."""
        return self._tools.get(name)

    def specs(self) -> list[dict[str, Any]]:
        """``tools/list`` payload, in registration order."""
        return [tool.spec for tool in self._tools.values()]

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __iter__(self) -> Iterator[ToolDefinition[Any, Any]]:
        return iter(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)

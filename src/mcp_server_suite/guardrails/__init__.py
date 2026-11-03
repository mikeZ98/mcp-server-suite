"""Execution guardrails applied by the server to every ``tools/call``.

Order per call: argument sanitizer -> concurrency slot (bounded wait) ->
deadline-bounded execution. All rejections are in-band RFC 9457 problems.
"""

from collections.abc import Mapping
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_server_suite.guardrails.limiter import ConcurrencyLimiter
from mcp_server_suite.guardrails.sanitizer import (
    ArgumentSanitizer,
    SanitizerLimits,
    find_forbidden_character,
)
from mcp_server_suite.guardrails.timeout import run_with_deadline

if TYPE_CHECKING:
    from mcp_server_suite.core.registry import ToolDefinition
    from mcp_server_suite.schemas import StrictModel

__all__ = [
    "ArgumentSanitizer",
    "ConcurrencyLimiter",
    "GuardrailSettings",
    "Guardrails",
    "SanitizerLimits",
    "find_forbidden_character",
    "run_with_deadline",
]


class GuardrailSettings(BaseSettings):
    """Guardrail limits, read from ``MCP_*`` environment variables."""

    model_config = SettingsConfigDict(env_prefix="MCP_", extra="forbid", frozen=True)

    max_concurrent_tools: Annotated[int, Field(ge=1, le=256)] = 16
    tool_acquire_timeout_seconds: Annotated[float, Field(ge=0, le=60)] = 5.0
    tool_timeout_seconds: Annotated[float, Field(gt=0, le=600)] = 30.0
    max_argument_depth: Annotated[int, Field(ge=1, le=64)] = 8
    max_argument_items: Annotated[int, Field(ge=1, le=100_000)] = 1_000


class Guardrails:
    """Sanitize, rate-limit and deadline-bound a single tool invocation."""

    def __init__(self, settings: GuardrailSettings | None = None) -> None:
        self.settings = settings if settings is not None else GuardrailSettings()
        self.sanitizer = ArgumentSanitizer(
            SanitizerLimits(
                max_depth=self.settings.max_argument_depth,
                max_items=self.settings.max_argument_items,
            )
        )
        self.limiter = ConcurrencyLimiter(
            self.settings.max_concurrent_tools, self.settings.tool_acquire_timeout_seconds
        )

    async def run(
        self, tool: "ToolDefinition[Any, Any]", arguments: Mapping[str, Any]
    ) -> "StrictModel":
        """Run ``tool`` with all guardrails; raises ``ToolError`` on any rejection."""
        self.sanitizer.check(arguments)
        async with self.limiter.slot(tool.name):
            result: StrictModel = await run_with_deadline(
                lambda: tool.invoke(arguments), self.settings.tool_timeout_seconds, tool.name
            )
            return result

"""Structural and character-level screening of tool arguments.

Runs before schema validation for every tool, so no handler ever sees:

* control characters other than TAB/LF/CR (C0, DEL, C1), Unicode bidi overrides
  and isolates (Trojan Source), zero-width/invisible formatting characters,
  line/paragraph separators, or lone UTF-16 surrogates (which cannot be encoded
  and would crash path or driver APIs);
* parameter-poisoning keys: anything that is not a plain identifier (lookalikes
  such as ``max\\u200brows`` or ``max_rows `` cannot shadow a real parameter) or a
  dunder name;
* oversized structures: excessive nesting depth or container size.

Arguments are never rewritten: a violation is rejected, not "cleaned".
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from mcp_server_suite.errors import ToolError
from mcp_server_suite.schemas import MCPErrorCode, ProblemDetail

__all__ = ["ArgumentSanitizer", "SanitizerLimits", "find_forbidden_character"]

# Inclusive code-point ranges that may not appear in any argument string. Built
# from numbers so the source itself contains no invisible characters.
_FORBIDDEN_RANGES: Final = (
    (0x0000, 0x0008),  # C0 controls (TAB 0x09, LF 0x0A allowed)
    (0x000B, 0x000C),  # VT, FF (CR 0x0D allowed)
    (0x000E, 0x001F),  # remaining C0 controls
    (0x007F, 0x009F),  # DEL + C1 controls
    (0x061C, 0x061C),  # Arabic letter mark (bidi)
    (0x200B, 0x200F),  # zero-width space/joiners, LRM, RLM
    (0x2028, 0x2029),  # line / paragraph separators
    (0x202A, 0x202E),  # bidi embeddings and overrides
    (0x2060, 0x2060),  # word joiner
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # zero-width no-break space / BOM
    (0xD800, 0xDFFF),  # lone UTF-16 surrogates
)
_FORBIDDEN_CHARS: Final = re.compile(
    "[" + "".join(f"\\U{low:08X}-\\U{high:08X}" for low, high in _FORBIDDEN_RANGES) + "]"
)
_KEY_RE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


@dataclass(frozen=True, slots=True)
class SanitizerLimits:
    """Structural bounds for one ``arguments`` object."""

    max_depth: int = 8
    max_items: int = 1_000

    def __post_init__(self) -> None:
        if self.max_depth < 1 or self.max_items < 1:
            msg = "sanitizer limits must be positive"
            raise ValueError(msg)


def find_forbidden_character(text: str) -> tuple[int, str] | None:
    """Return ``(index, "U+XXXX")`` of the first forbidden character, if any."""
    match = _FORBIDDEN_CHARS.search(text)
    if match is None:
        return None
    return match.start(), f"U+{ord(match.group()):04X}"


def _reject(location: str, detail: str, **metadata: Any) -> ToolError:
    return ToolError(
        ProblemDetail.from_code(
            MCPErrorCode.VALIDATION_ERROR,
            detail,
            invalid_params=((location or "arguments")[:256],),
            metadata=metadata,
        )
    )


class ArgumentSanitizer:
    """Validate that a decoded JSON ``arguments`` object is safe to hand to a tool."""

    def __init__(self, limits: SanitizerLimits | None = None) -> None:
        self._limits = limits or SanitizerLimits()

    def check(self, arguments: Mapping[str, Any]) -> None:
        """Raise :class:`ToolError` (``MCP_VALIDATION_ERROR``) on the first violation."""
        self._check_value(arguments, "", 1)

    def _check_value(self, value: Any, location: str, depth: int) -> None:
        if isinstance(value, str):
            self._check_text(value, location)
        elif isinstance(value, Mapping):
            self._check_container(value, location, depth)
            for key, item in value.items():
                self._check_key(key, location)
                self._check_value(item, f"{location}.{key}" if location else key, depth + 1)
        elif isinstance(value, list):
            self._check_container(value, location, depth)
            for index, item in enumerate(value):
                self._check_value(item, f"{location}[{index}]", depth + 1)

    def _check_container(
        self, value: Mapping[str, Any] | list[Any], location: str, depth: int
    ) -> None:
        if depth > self._limits.max_depth:
            raise _reject(
                location,
                f"arguments nest deeper than {self._limits.max_depth} levels",
                reason="max_depth",
            )
        if len(value) > self._limits.max_items:
            raise _reject(
                location,
                f"container holds {len(value)} items (limit {self._limits.max_items})",
                reason="max_items",
            )

    def _check_key(self, key: str, location: str) -> None:
        if not _KEY_RE.fullmatch(key) or key.startswith("__"):
            shown = key[:64].encode("unicode_escape").decode("ascii")
            raise _reject(
                f"{location}.{shown}" if location else shown,
                f"argument name {shown!r} is not a plain identifier",
                reason="invalid_key",
            )

    def _check_text(self, text: str, location: str) -> None:
        found = find_forbidden_character(text)
        if found is not None:
            index, codepoint = found
            raise _reject(
                location,
                f"argument {location!r} contains forbidden character {codepoint} at index {index}",
                reason="forbidden_character",
                codepoint=codepoint,
                index=index,
            )

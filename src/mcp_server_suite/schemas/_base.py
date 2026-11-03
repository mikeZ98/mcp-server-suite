"""Shared base model for every wire contract in the suite."""

from typing import ClassVar

from pydantic import BaseModel, ConfigDict

__all__ = ["StrictModel"]


class StrictModel(BaseModel):
    """Fail-closed base: unknown keys rejected, no type coercion, immutable instances."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        allow_inf_nan=False,
        str_strip_whitespace=False,
    )

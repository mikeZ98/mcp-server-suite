"""Newline-delimited JSON framing with a hard per-message size limit."""

import asyncio
import json
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Final, Protocol

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "MAX_FRAME_BYTES",
    "ByteSink",
    "ByteSource",
    "Frame",
    "FrameReader",
    "FrameWriter",
    "OversizedFrame",
]

MAX_FRAME_BYTES: Final = 1_048_576
DEFAULT_CHUNK_SIZE: Final = 65_536


class ByteSource(Protocol):
    """Async byte stream; ``read`` returns ``b""`` at EOF (``asyncio.StreamReader`` fits)."""

    async def read(self, n: int, /) -> bytes: ...


class ByteSink(Protocol):
    """Async byte sink whose ``write`` returns once the data is flushed downstream."""

    async def write(self, data: bytes, /) -> None: ...

    async def aclose(self) -> None: ...


@dataclass(frozen=True, slots=True)
class OversizedFrame:
    """Marker for a line that exceeded the limit and was discarded unparsed."""

    size: int


type Frame = bytes | OversizedFrame


class FrameReader:
    """Split a byte stream into newline-terminated frames.

    Memory is bounded by ``max_frame_bytes + chunk_size``: an over-long line is
    dropped as it streams in and reported once as :class:`OversizedFrame`, after
    which reading resumes at the next newline. Blank lines and a trailing ``\\r``
    are ignored; an unterminated final line at EOF is still delivered.
    """

    def __init__(
        self,
        source: ByteSource,
        *,
        max_frame_bytes: int = MAX_FRAME_BYTES,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if max_frame_bytes < 1 or chunk_size < 1:
            msg = "max_frame_bytes and chunk_size must be positive"
            raise ValueError(msg)
        self._source = source
        self._max = max_frame_bytes
        self._chunk_size = chunk_size
        self._buffer = bytearray()
        self._scanned = 0  # bytes of _buffer already searched for a newline
        self._discarded: int | None = None  # bytes dropped from the current oversized line
        self._eof = False

    async def read_frame(self) -> Frame | None:
        """Return the next frame, or ``None`` once the stream is exhausted."""
        while True:
            frame = self._next_buffered()
            if frame is not None:
                return frame
            if self._eof:
                return self._finish()
            chunk = await self._source.read(self._chunk_size)
            if chunk:
                self._buffer += chunk
            else:
                self._eof = True

    def _next_buffered(self) -> Frame | None:
        while (newline := self._buffer.find(b"\n", self._scanned)) >= 0:
            line = bytes(self._buffer[:newline])
            del self._buffer[: newline + 1]
            self._scanned = 0
            if self._discarded is not None:
                size, self._discarded = self._discarded + len(line), None
                return OversizedFrame(size)
            frame = self._accept(line)
            if frame is not None:
                return frame
        if self._discarded is not None:
            self._discarded += len(self._buffer)
            self._buffer.clear()
        elif len(self._buffer) > self._max:
            self._discarded = len(self._buffer)
            self._buffer.clear()
        self._scanned = len(self._buffer)
        return None

    def _accept(self, line: bytes) -> Frame | None:
        if len(line) > self._max:
            return OversizedFrame(len(line))
        line = line.removesuffix(b"\r")
        return line if line.strip() else None

    def _finish(self) -> Frame | None:
        if self._discarded is not None:
            size, self._discarded = self._discarded, None
            return OversizedFrame(size)
        line = bytes(self._buffer)
        self._buffer.clear()
        self._scanned = 0
        return self._accept(line)


class FrameWriter:
    """Serialise messages as single-line JSON frames; concurrent sends never interleave."""

    def __init__(self, sink: ByteSink) -> None:
        self._sink = sink
        self._lock = asyncio.Lock()

    async def send(self, message: Mapping[str, Any]) -> None:
        """Encode and write one message (raises ``OSError`` if the sink is broken).

        Output is ASCII-only JSON: non-ASCII text is ``\\uXXXX``-escaped, so lone
        surrogates echoed from client input can never make encoding fail.
        """
        data = json.dumps(message, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        async with self._lock:
            await self._sink.write(data.encode("ascii") + b"\n")

    async def aclose(self) -> None:
        """Flush and close the sink, tolerating an already-broken stream."""
        async with self._lock:
            with suppress(OSError):
                await self._sink.aclose()

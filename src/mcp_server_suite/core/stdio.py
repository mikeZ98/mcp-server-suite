"""Stdio transport: non-blocking fd streams plus SIGINT/SIGTERM handling."""

import asyncio
import contextlib
import io
import logging
import os
import signal
import stat
import sys
from collections.abc import AsyncIterator, Callable

from mcp_server_suite.core.framing import ByteSink, ByteSource
from mcp_server_suite.core.server import MCPServer

__all__ = ["install_signal_handlers", "open_stdio", "run_stdio"]

logger = logging.getLogger(__name__)

_SHUTDOWN_SIGNALS = (signal.SIGINT, signal.SIGTERM)


class _StreamSink:
    """Pipe/TTY sink backed by an asyncio write transport (honours back-pressure)."""

    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self._writer = writer

    async def write(self, data: bytes, /) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def aclose(self) -> None:
        try:
            await self._writer.drain()
        finally:
            self._writer.close()
            await asyncio.sleep(0)  # let the transport release its file


class _FileSource:
    """Regular-file source (``< requests.jsonl``); reads never block for long."""

    def __init__(self, file: io.FileIO) -> None:
        self._file = file

    async def read(self, n: int, /) -> bytes:
        return await asyncio.to_thread(self._file.read, n) or b""


class _FileSink:
    """Regular-file sink (``> responses.jsonl``)."""

    def __init__(self, file: io.FileIO) -> None:
        self._file = file

    async def write(self, data: bytes, /) -> None:
        await asyncio.to_thread(self._write_all, data)

    def _write_all(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            view = view[self._file.write(view) or 0 :]

    async def aclose(self) -> None:
        self._file.close()


def _is_regular_file(fd: int) -> bool:
    return stat.S_ISREG(os.fstat(fd).st_mode)


@contextlib.asynccontextmanager
async def open_stdio(
    stdin_fd: int = 0, stdout_fd: int = 1
) -> AsyncIterator[tuple[ByteSource, ByteSink]]:
    """Open duplicated, non-blocking streams over ``stdin_fd``/``stdout_fd``.

    The descriptors are duplicated so closing the transport never closes the
    process's own stdio, and their original blocking mode is restored on exit.
    """
    loop = asyncio.get_running_loop()
    blocking = {fd: os.get_blocking(fd) for fd in (stdin_fd, stdout_fd)}
    async with contextlib.AsyncExitStack() as stack:
        for fd, was_blocking in blocking.items():
            stack.callback(os.set_blocking, fd, was_blocking)

        in_file = io.FileIO(os.dup(stdin_fd), "rb")
        stack.callback(in_file.close)
        source: ByteSource
        if _is_regular_file(stdin_fd):
            source = _FileSource(in_file)
        else:
            reader = asyncio.StreamReader()
            read_transport, _ = await loop.connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(reader), in_file
            )
            stack.push_async_callback(asyncio.sleep, 0)
            stack.callback(read_transport.close)
            source = reader

        out_file = io.FileIO(os.dup(stdout_fd), "wb")
        stack.callback(out_file.close)
        sink: ByteSink
        if _is_regular_file(stdout_fd):
            sink = _FileSink(out_file)
        else:
            write_transport, protocol = await loop.connect_write_pipe(
                asyncio.streams.FlowControlMixin, out_file
            )
            sink = _StreamSink(asyncio.StreamWriter(write_transport, protocol, None, loop))
            stack.callback(write_transport.close)

        yield source, sink


def install_signal_handlers(
    loop: asyncio.AbstractEventLoop, callback: Callable[[], None]
) -> Callable[[], None]:
    """Route SIGINT/SIGTERM to ``callback``; returns a function that uninstalls them."""
    installed: list[signal.Signals] = []
    for sig in _SHUTDOWN_SIGNALS:
        try:
            loop.add_signal_handler(sig, callback)
        except (NotImplementedError, RuntimeError, ValueError):
            logger.debug("cannot install handler for %s", sig.name)
        else:
            installed.append(sig)

    def remove() -> None:
        for sig in installed:
            loop.remove_signal_handler(sig)

    return remove


async def run_stdio(server: MCPServer, *, stdin_fd: int = 0, stdout_fd: int = 1) -> None:
    """Serve ``server`` over stdio until EOF or a shutdown signal.

    Stray ``print`` calls are redirected to stderr so they cannot corrupt the
    JSON-RPC stream on stdout.
    """
    remove_handlers = install_signal_handlers(asyncio.get_running_loop(), server.request_shutdown)
    try:
        with contextlib.redirect_stdout(sys.stderr):
            async with open_stdio(stdin_fd, stdout_fd) as (source, sink):
                await server.serve(source, sink)
    finally:
        remove_handlers()

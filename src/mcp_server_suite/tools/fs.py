"""``sandbox_fs_read``: bounded text reads confined to a single directory tree.

Containment is enforced twice:

1. **Canonical resolution** — ``(root / relative_path).resolve()`` follows every
   symlink, and the result must satisfy ``is_relative_to(root)``. Resolution is
   non-strict, so paths outside the sandbox are denied whether or not they
   exist (no existence oracle for the host filesystem).
2. **Race-free open** — the resolved, symlink-free path is then re-opened one
   component at a time relative to a directory fd of the root, with
   ``O_NOFOLLOW`` on every component. A component swapped for a symlink after
   step 1 (TOCTOU) fails with ``ELOOP`` instead of escaping.

The leaf is opened ``O_NONBLOCK`` (a FIFO cannot hang the worker) and its type is
checked with ``fstat`` on the open descriptor: only regular files are read.
Reads happen in a worker thread and never buffer more than ``max_bytes + 1``.
Problem details never contain absolute host paths.
"""

import asyncio
import codecs
import errno
import os
import stat
from pathlib import Path, PurePath
from typing import Any, Final

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_server_suite.core.registry import ToolDefinition, ToolError
from mcp_server_suite.schemas import (
    FS_MAX_BYTES_LIMIT,
    MCPErrorCode,
    ProblemDetail,
    SandboxFsReadParams,
    SandboxFsReadResult,
    ToolName,
)

__all__ = ["SandboxFsReadTool", "SandboxSettings"]

_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_LEAF_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
_READ_CHUNK: Final = 65_536
_ECHO_LIMIT: Final = 256

_SPECIAL_FILE_TYPES: Final = {
    stat.S_IFCHR: "character device",
    stat.S_IFBLK: "block device",
    stat.S_IFIFO: "FIFO",
    stat.S_IFSOCK: "socket",
    stat.S_IFLNK: "symbolic link",
}


class SandboxSettings(BaseSettings):
    """Sandbox location, read from ``MCP_SAFE_DATA_DIR``."""

    model_config = SettingsConfigDict(env_prefix="MCP_", extra="forbid", frozen=True)

    safe_data_dir: Path | None = None

    @field_validator("safe_data_dir", mode="after")
    @classmethod
    def _check_root(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        if not value.is_absolute():
            msg = "safe_data_dir must be an absolute path"
            raise ValueError(msg)
        try:
            resolved = value.resolve(strict=True)
        except (OSError, RuntimeError):
            msg = "safe_data_dir does not exist or cannot be resolved"
            raise ValueError(msg) from None
        if not resolved.is_dir():
            msg = "safe_data_dir must be a directory"
            raise ValueError(msg)
        return resolved


# ---------------------------------------------------------------------------
# Problems
# ---------------------------------------------------------------------------
def _denied(detail: str) -> ToolError:
    return ToolError(
        ProblemDetail.from_code(
            MCPErrorCode.ACCESS_DENIED, detail, invalid_params=("relative_path",)
        )
    )


def _invalid(detail: str, *, param: str = "relative_path", **metadata: Any) -> ToolError:
    return ToolError(
        ProblemDetail.from_code(
            MCPErrorCode.VALIDATION_ERROR, detail, invalid_params=(param,), metadata=metadata
        )
    )


def _problem_for_os_error(exc: OSError, shown: str) -> ToolError:
    """Map expected open() failures to problems; other errors (EIO, ...) are re-raised."""
    code = exc.errno
    if code in {errno.ELOOP, errno.EMLINK}:
        return _denied(f"{shown!r}: symbolic links changed during access")
    if code in {errno.EACCES, errno.EPERM}:
        return _denied(f"{shown!r}: permission denied")
    if code in {errno.ENXIO, errno.EOPNOTSUPP, errno.ENODEV}:
        return _denied(f"{shown!r} is not a regular file")
    if code in {errno.ENOENT, errno.ENOTDIR}:
        return _invalid(f"{shown!r} does not exist")
    if code == errno.ENAMETOOLONG:
        return _invalid(f"{shown!r}: path component is too long")
    raise exc


def check_file_type(mode: int, shown: str) -> None:
    """Allow regular files only; directories are a caller error, devices are denied."""
    if stat.S_ISREG(mode):
        return
    if stat.S_ISDIR(mode):
        raise _invalid(f"{shown!r} is a directory")
    kind = _SPECIAL_FILE_TYPES.get(stat.S_IFMT(mode), "special file")
    raise _denied(f"{shown!r} is a {kind}; only regular files can be read")


# ---------------------------------------------------------------------------
# Resolution and open
# ---------------------------------------------------------------------------
def resolve_candidate(root: Path, relative_path: str) -> Path:
    """Canonical (symlink-free) absolute path for ``relative_path`` under ``root``."""
    return (root / relative_path).resolve(strict=False)


def _is_symlink(name: str, dir_fd: int) -> bool:
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _open_component(name: str, flags: int, dir_fd: int) -> int:
    """``openat`` one component; a symlink always fails with ``ELOOP``.

    Platforms disagree on the errno for ``O_NOFOLLOW`` (+ ``O_DIRECTORY``) on a
    symlink (Linux: ``ELOOP``, macOS: ``ENOTDIR`` for directories), so it is
    normalised here.
    """
    try:
        return os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK, errno.ENOTDIR} and _is_symlink(name, dir_fd):
            raise OSError(errno.ELOOP, "symbolic link in path") from exc
        raise


def open_beneath(root: Path, relative: PurePath) -> int:
    """Open ``root / relative`` without following any symlink in ``relative``.

    Every component is opened with ``O_NOFOLLOW`` relative to its parent's fd,
    so the open cannot leave ``root`` even if the tree changes concurrently.
    """
    *parents, leaf = relative.parts
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parents:
            child = _open_component(part, _DIR_FLAGS, fd)
            os.close(fd)
            fd = child
        return _open_component(leaf, _LEAF_FLAGS, fd)
    finally:
        os.close(fd)


def _read_bounded(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(fd, min(remaining, _READ_CHUNK))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _decode(data: bytes, encoding: str, *, final: bool) -> tuple[str, int]:
    """Strictly decode; a truncated tail may end mid-character, which is dropped."""
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    try:
        text = decoder.decode(data, final=final)
    except UnicodeDecodeError as exc:
        raise _invalid(
            f"content is not valid {encoding} (byte offset {exc.start})",
            param="encoding",
            encoding=encoding,
            offset=exc.start,
        ) from None
    pending, _ = decoder.getstate()
    return text, len(data) - len(pending)


class SandboxFsReadTool:
    """The ``sandbox_fs_read`` tool bound to one sandbox root."""

    def __init__(self, settings: SandboxSettings) -> None:
        if settings.safe_data_dir is None:
            msg = "SandboxSettings.safe_data_dir is not configured"
            raise ValueError(msg)
        self._root = settings.safe_data_dir

    def definition(self) -> ToolDefinition[SandboxFsReadParams, SandboxFsReadResult]:
        """MCP tool definition for registration."""
        return ToolDefinition(
            name=ToolName.SANDBOX_FS_READ,
            title="Sandboxed file read",
            description=(
                "Read a text file inside the server's sandbox directory. relative_path is "
                "resolved against the sandbox root; paths or symlinks leading outside it, "
                "directories and special files are rejected. At most max_bytes "
                f"(<= {FS_MAX_BYTES_LIMIT}) bytes are returned; truncated reports a cut."
            ),
            params_model=SandboxFsReadParams,
            result_model=SandboxFsReadResult,
            handler=self,
            read_only=True,
            open_world=False,
        )

    async def __call__(self, params: SandboxFsReadParams) -> SandboxFsReadResult:
        return await asyncio.to_thread(self._read, params)

    def _read(self, params: SandboxFsReadParams) -> SandboxFsReadResult:
        shown = params.relative_path[:_ECHO_LIMIT]
        try:
            candidate = resolve_candidate(self._root, params.relative_path)
        except (RuntimeError, OSError):  # symlink loop (RuntimeError before Python 3.13)
            raise _invalid(f"{shown!r} cannot be resolved (symbolic link loop)") from None
        if not candidate.is_relative_to(self._root):
            raise _denied(f"{shown!r} resolves outside the sandbox")
        relative = candidate.relative_to(self._root)
        if not relative.parts:
            raise _invalid(f"{shown!r} is a directory")

        try:
            fd = open_beneath(self._root, relative)
        except OSError as exc:
            raise _problem_for_os_error(exc, shown) from None
        try:
            check_file_type(os.fstat(fd).st_mode, shown)
            data = _read_bounded(fd, params.max_bytes + 1)
        finally:
            os.close(fd)

        truncated = len(data) > params.max_bytes
        content, consumed = _decode(data[: params.max_bytes], params.encoding, final=not truncated)
        return SandboxFsReadResult(
            resolved_path=relative.as_posix(),
            content=content,
            bytes_read=consumed,
            truncated=truncated,
        )

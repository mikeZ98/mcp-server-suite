"""Hermetic security tests for ``sandbox_fs_read`` (temporary trees under ``tmp_path``)."""

import asyncio
import errno
import json
import logging
import os
import socket
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any

import mcp_types
import pytest
from pydantic import SecretStr, ValidationError

from mcp_server_suite.core import MCPServer, ToolError, ToolRegistry
from mcp_server_suite.schemas import (
    FS_MAX_BYTES_LIMIT,
    MCPErrorCode,
    ProblemDetail,
    SandboxFsReadParams,
    SandboxFsReadResult,
)
from mcp_server_suite.tools import (
    MetricsSettings,
    SandboxFsReadTool,
    SandboxSettings,
    SqlSettings,
    open_tool_registry,
)
from mcp_server_suite.tools import fs as fs_module
from mcp_server_suite.tools.fs import check_file_type, open_beneath

TIMEOUT = 5.0
SECRET = "TOP SECRET: outside the sandbox"


@dataclass(frozen=True)
class Sandbox:
    root: Path
    outside: Path
    tool: SandboxFsReadTool

    async def read(self, relative_path: str, **kwargs: Any) -> SandboxFsReadResult:
        params = SandboxFsReadParams(relative_path=relative_path, **kwargs)
        return await asyncio.wait_for(self.tool(params), TIMEOUT)

    async def problem(self, relative_path: str, code: MCPErrorCode, **kwargs: Any) -> ProblemDetail:
        with pytest.raises(ToolError) as exc_info:
            await self.read(relative_path, **kwargs)
        problem = exc_info.value.problem
        assert problem.code is code, problem
        body = json.dumps(problem.to_json_dict())
        assert str(self.root) not in body, "absolute sandbox path leaked"
        if str(self.outside) not in relative_path:  # echoing the caller's own input is fine
            assert str(self.outside) not in body, "absolute host path leaked"
        assert SECRET not in body
        return problem


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    """
    safe/
      notes.txt            "hello sandbox"
      docs/guide.md        "# Guide"
      docs/nested/deep.txt "deep"
      docs/up -> ..                         (internal, points at root)
      link_abs -> <safe>/docs/guide.md      (internal, absolute)
      link_rel -> docs/guide.md             (internal, relative)
      escape -> <outside>/secret.txt        (escape, file)
      escape_dir -> <outside>               (escape, directory)
      escape_rel -> ../outside/secret.txt   (escape, relative)
      dangling_out -> <outside>/missing     (escape, dangling)
      loop -> loop                          (self loop)
    outside/secret.txt     SECRET
    """
    root = tmp_path / "safe"
    outside = tmp_path / "outside"
    (root / "docs" / "nested").mkdir(parents=True)
    outside.mkdir()
    (root / "notes.txt").write_text("hello sandbox")
    (root / "docs" / "guide.md").write_text("# Guide")
    (root / "docs" / "nested" / "deep.txt").write_text("deep")
    (outside / "secret.txt").write_text(SECRET)
    (root / "docs" / "up").symlink_to("..")
    (root / "link_abs").symlink_to(root / "docs" / "guide.md")
    (root / "link_rel").symlink_to("docs/guide.md")
    (root / "escape").symlink_to(outside / "secret.txt")
    (root / "escape_dir").symlink_to(outside, target_is_directory=True)
    (root / "escape_rel").symlink_to("../outside/secret.txt")
    (root / "dangling_out").symlink_to(outside / "missing")
    (root / "loop").symlink_to("loop")
    tool = SandboxFsReadTool(SandboxSettings(safe_data_dir=root))
    return Sandbox(root=root.resolve(), outside=outside.resolve(), tool=tool)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
async def test_reads_regular_file(sandbox: Sandbox) -> None:
    result = await sandbox.read("notes.txt")
    assert result == SandboxFsReadResult(
        resolved_path="notes.txt", content="hello sandbox", bytes_read=13, truncated=False
    )


@pytest.mark.parametrize(
    "path", ["docs/nested/deep.txt", "./docs/nested/deep.txt", "docs//nested/./deep.txt"]
)
async def test_nested_and_redundant_paths(sandbox: Sandbox, path: str) -> None:
    result = await sandbox.read(path)
    assert (result.resolved_path, result.content) == ("docs/nested/deep.txt", "deep")


async def test_dotdot_that_stays_inside_is_allowed(sandbox: Sandbox) -> None:
    result = await sandbox.read("docs/nested/../guide.md")
    assert result.resolved_path == "docs/guide.md"


@pytest.mark.parametrize(
    ("path", "resolved"),
    [
        ("link_abs", "docs/guide.md"),
        ("link_rel", "docs/guide.md"),
        ("docs/up/notes.txt", "notes.txt"),
        ("docs/up/docs/up/docs/guide.md", "docs/guide.md"),
    ],
)
async def test_internal_symlinks_are_followed(sandbox: Sandbox, path: str, resolved: str) -> None:
    result = await sandbox.read(path)
    assert result.resolved_path == resolved
    assert not result.resolved_path.startswith("/")


async def test_read_runs_in_worker_thread(
    sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real_to_thread = asyncio.to_thread

    async def spy(func: Any, /, *args: Any, **kwargs: Any) -> Any:
        calls.append(func.__name__)
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", spy)
    await sandbox.read("notes.txt")
    assert calls == ["_read"]


# ---------------------------------------------------------------------------
# Traversal and escapes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        "../outside/secret.txt",
        "../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "foo/../../bar",
        "docs/../../outside/secret.txt",
        "docs/nested/../../../outside/secret.txt",
        "./../outside/secret.txt",
        "docs/up/../../outside/secret.txt",
        "/etc/passwd",
        "//etc/passwd",
        "..",
        "docs/../..",
    ],
)
async def test_traversal_is_denied(sandbox: Sandbox, path: str) -> None:
    problem = await sandbox.problem(path, MCPErrorCode.ACCESS_DENIED)
    assert problem.detail.endswith("resolves outside the sandbox")
    assert problem.invalid_params == ("relative_path",)


async def test_absolute_path_to_outside_file_is_denied(sandbox: Sandbox) -> None:
    await sandbox.problem(str(sandbox.outside / "secret.txt"), MCPErrorCode.ACCESS_DENIED)


async def test_no_existence_oracle_outside_the_sandbox(sandbox: Sandbox) -> None:
    exists = await sandbox.problem("../outside/secret.txt", MCPErrorCode.ACCESS_DENIED)
    missing = await sandbox.problem("../outside/no-such-file", MCPErrorCode.ACCESS_DENIED)
    assert exists.title == missing.title
    assert exists.status == missing.status


@pytest.mark.parametrize(
    "path",
    [
        "escape",
        "escape_rel",
        "escape_dir/secret.txt",
        "dangling_out",
        "docs/../escape",
    ],
)
async def test_symlink_escape_is_denied(sandbox: Sandbox, path: str) -> None:
    await sandbox.problem(path, MCPErrorCode.ACCESS_DENIED)


@pytest.mark.parametrize(
    "path",
    [
        "%2e%2e/outside/secret.txt",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2fetc%2fpasswd",
        "..\\..\\outside\\secret.txt",
        "․․/outside/secret.txt",  # noqa: RUF001 - deliberate homoglyph
        "．．/outside/secret.txt",  # noqa: RUF001 - deliberate homoglyph
        "~/secret.txt",
        "$HOME/secret.txt",
    ],
)
async def test_encoded_or_lookalike_dots_are_literal_names(sandbox: Sandbox, path: str) -> None:
    problem = await sandbox.problem(path, MCPErrorCode.VALIDATION_ERROR)
    assert problem.detail.endswith("does not exist")


def test_nul_byte_rejected_by_schema() -> None:
    with pytest.raises(ValidationError):
        SandboxFsReadParams(relative_path="notes.txt\x00../../etc/passwd")


async def test_symlink_swapped_in_after_resolution_is_denied(
    sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TOCTOU: resolution saw a plain path, but a component is a symlink at open time."""

    def stale_resolution(root: Path, relative_path: str) -> Path:
        return root / "escape_dir" / "secret.txt"  # lexically inside, physically outside

    monkeypatch.setattr(fs_module, "resolve_candidate", stale_resolution)
    problem = await sandbox.problem("whatever", MCPErrorCode.ACCESS_DENIED)
    assert "symbolic links changed" in problem.detail


def test_open_beneath_refuses_symlink_components(sandbox: Sandbox) -> None:
    for relative in ("escape_dir/secret.txt", "escape", "link_rel", "docs/up/notes.txt"):
        with pytest.raises(OSError, match="symbolic link in path") as exc_info:
            open_beneath(sandbox.root, PurePath(relative))
        assert exc_info.value.errno == errno.ELOOP


def test_open_beneath_opens_plain_paths(sandbox: Sandbox) -> None:
    fd = open_beneath(sandbox.root, PurePath("docs/nested/deep.txt"))
    try:
        assert os.read(fd, 100) == b"deep"
    finally:
        os.close(fd)


def test_open_beneath_reports_non_symlink_errors_unchanged(sandbox: Sandbox) -> None:
    with pytest.raises(NotADirectoryError):
        open_beneath(sandbox.root, PurePath("notes.txt/child"))
    with pytest.raises(FileNotFoundError):
        open_beneath(sandbox.root, PurePath("gone/child"))


def test_symlink_probe_treats_vanished_entries_as_non_links(sandbox: Sandbox) -> None:
    fd = os.open(sandbox.root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert fs_module._is_symlink("escape", fd) is True
        assert fs_module._is_symlink("notes.txt", fd) is False
        assert fs_module._is_symlink("vanished", fd) is False
    finally:
        os.close(fd)


async def test_symlink_loop_is_rejected(sandbox: Sandbox) -> None:
    problem = await sandbox.problem("loop", MCPErrorCode.VALIDATION_ERROR)
    assert "loop" in problem.detail


# ---------------------------------------------------------------------------
# File type guards
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", ["docs", "docs/", ".", "docs/nested/..", "docs/up"])
async def test_directories_are_rejected(sandbox: Sandbox, path: str) -> None:
    problem = await sandbox.problem(path, MCPErrorCode.VALIDATION_ERROR)
    assert problem.detail.endswith("is a directory")


async def test_fifo_is_denied_without_blocking(sandbox: Sandbox) -> None:
    fifo = sandbox.root / "pipe"
    os.mkfifo(fifo)
    task = asyncio.ensure_future(sandbox.tool(SandboxFsReadParams(relative_path="pipe")))
    done, _ = await asyncio.wait({task}, timeout=2.0)
    if not done:
        # A blocking open() parks the worker thread until a writer appears; release
        # it so the suite fails cleanly instead of hanging at loop shutdown.
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        with suppress(Exception):
            await task
        pytest.fail("opening a FIFO blocked the worker thread")
    error = task.exception()
    assert isinstance(error, ToolError)
    assert error.problem.code is MCPErrorCode.ACCESS_DENIED
    assert "FIFO" in error.problem.detail


async def test_unix_socket_is_denied(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(sandbox.root)  # relative bind sidesteps the sun_path length limit
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind("sock")
        await sandbox.problem("sock", MCPErrorCode.ACCESS_DENIED)


@pytest.mark.parametrize("device", ["zero", "urandom", "null"])
async def test_character_devices_are_denied(device: str) -> None:
    dev = SandboxFsReadTool(SandboxSettings(safe_data_dir=Path("/dev")))
    with pytest.raises(ToolError) as exc_info:
        await asyncio.wait_for(dev(SandboxFsReadParams(relative_path=device)), TIMEOUT)
    assert exc_info.value.problem.code is MCPErrorCode.ACCESS_DENIED
    assert "character device" in exc_info.value.problem.detail


async def test_symlink_to_device_is_an_escape(sandbox: Sandbox) -> None:
    (sandbox.root / "zero").symlink_to("/dev/zero")
    await sandbox.problem("zero", MCPErrorCode.ACCESS_DENIED)


@pytest.mark.parametrize(
    ("mode", "code", "kind"),
    [
        (stat.S_IFCHR, MCPErrorCode.ACCESS_DENIED, "character device"),
        (stat.S_IFBLK, MCPErrorCode.ACCESS_DENIED, "block device"),
        (stat.S_IFIFO, MCPErrorCode.ACCESS_DENIED, "FIFO"),
        (stat.S_IFSOCK, MCPErrorCode.ACCESS_DENIED, "socket"),
        (stat.S_IFLNK, MCPErrorCode.ACCESS_DENIED, "symbolic link"),
        (0o170000, MCPErrorCode.ACCESS_DENIED, "special file"),  # unknown file type bits
        (stat.S_IFDIR, MCPErrorCode.VALIDATION_ERROR, "directory"),
    ],
)
def test_file_type_classification(mode: int, code: MCPErrorCode, kind: str) -> None:
    with pytest.raises(ToolError) as exc_info:
        check_file_type(mode | 0o644, "x")
    assert exc_info.value.problem.code is code
    assert kind in exc_info.value.problem.detail


def test_regular_file_type_is_allowed() -> None:
    check_file_type(stat.S_IFREG | 0o644, "x")


# ---------------------------------------------------------------------------
# Missing files and OS errors
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path", ["missing.txt", "docs/missing/x.txt", "notes.txt/child", "docs/nested/../../nope"]
)
async def test_missing_file_is_validation_error(sandbox: Sandbox, path: str) -> None:
    problem = await sandbox.problem(path, MCPErrorCode.VALIDATION_ERROR)
    assert problem.detail.endswith("does not exist")
    assert problem.invalid_params == ("relative_path",)


async def test_overlong_component_is_validation_error(sandbox: Sandbox) -> None:
    problem = await sandbox.problem("x" * 300, MCPErrorCode.VALIDATION_ERROR)
    assert "too long" in problem.detail
    assert len(problem.detail) < 400, "echoed path is truncated"


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="root bypasses modes")
async def test_unreadable_file_is_denied(sandbox: Sandbox) -> None:
    locked = sandbox.root / "locked.txt"
    locked.write_text("nope")
    locked.chmod(0)
    try:
        problem = await sandbox.problem("locked.txt", MCPErrorCode.ACCESS_DENIED)
    finally:
        locked.chmod(0o600)
    assert "permission denied" in problem.detail


@pytest.mark.parametrize(
    ("errno_value", "code"),
    [
        (errno.ENXIO, MCPErrorCode.ACCESS_DENIED),
        (errno.EOPNOTSUPP, MCPErrorCode.ACCESS_DENIED),
        (errno.EPERM, MCPErrorCode.ACCESS_DENIED),
        (errno.EMLINK, MCPErrorCode.ACCESS_DENIED),
        (errno.ENOTDIR, MCPErrorCode.VALIDATION_ERROR),
    ],
)
async def test_open_errno_mapping(
    sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch, errno_value: int, code: MCPErrorCode
) -> None:
    def failing_open(root: Path, relative: PurePath) -> int:
        raise OSError(errno_value, os.strerror(errno_value))

    monkeypatch.setattr(fs_module, "open_beneath", failing_open)
    await sandbox.problem("notes.txt", code)


async def test_unexpected_io_error_propagates(
    sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_open(root: Path, relative: PurePath) -> int:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(fs_module, "open_beneath", failing_open)
    with pytest.raises(OSError, match="I/O error"):
        await sandbox.read("notes.txt")


# ---------------------------------------------------------------------------
# Bounded reads and truncation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("size", "max_bytes", "truncated"),
    [(100, 10, True), (100, 99, True), (100, 100, False), (100, 101, False), (0, 1, False)],
)
async def test_truncation(sandbox: Sandbox, size: int, max_bytes: int, truncated: bool) -> None:
    data = bytes(ord("a") + i % 26 for i in range(size))
    (sandbox.root / "data.txt").write_bytes(data)
    result = await sandbox.read("data.txt", max_bytes=max_bytes)
    expected = data[:max_bytes].decode()
    assert (result.content, result.truncated, result.bytes_read) == (
        expected,
        truncated,
        len(expected),
    )


async def test_large_file_reads_at_most_max_bytes_plus_one(
    sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    (sandbox.root / "big.txt").write_bytes(b"x" * (3 * 65_536 + 7))
    requested: list[int] = []
    real_read = os.read

    def counting_read(fd: int, n: int) -> bytes:
        requested.append(n)
        return real_read(fd, n)

    monkeypatch.setattr(os, "read", counting_read)
    result = await sandbox.read("big.txt", max_bytes=100_000)
    assert result.truncated
    assert result.bytes_read == 100_000
    assert sum(requested) == 100_001
    assert max(requested) <= 65_536


async def test_max_bytes_upper_bound_is_one_mebibyte() -> None:
    SandboxFsReadParams(relative_path="a", max_bytes=FS_MAX_BYTES_LIMIT)
    with pytest.raises(ValidationError):
        SandboxFsReadParams(relative_path="a", max_bytes=FS_MAX_BYTES_LIMIT + 1)


async def test_truncation_never_splits_a_multibyte_character(sandbox: Sandbox) -> None:
    (sandbox.root / "pl.txt").write_text("żółw" * 10, encoding="utf-8")  # 2-byte chars
    result = await sandbox.read("pl.txt", max_bytes=5)
    assert result.content == "żó"
    assert result.bytes_read == 4
    assert result.truncated


async def test_invalid_bytes_beyond_the_slice_are_not_decoded(sandbox: Sandbox) -> None:
    (sandbox.root / "mixed.bin").write_bytes(b"clean text" + b"\xff\xfe" * 10)
    result = await sandbox.read("mixed.bin", max_bytes=10)
    assert (result.content, result.truncated) == ("clean text", True)


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("payload", "offset"),
    [(b"\xff\xfe\xfa", 0), (b"ok \xc3\x28 bad", 3), (b"trailing \xe2\x82", 9)],
)
async def test_invalid_utf8_is_validation_error(
    sandbox: Sandbox, payload: bytes, offset: int
) -> None:
    (sandbox.root / "bad.txt").write_bytes(payload)
    problem = await sandbox.problem("bad.txt", MCPErrorCode.VALIDATION_ERROR)
    assert problem.invalid_params == ("encoding",)
    assert problem.metadata == {"encoding": "utf-8", "offset": offset}


async def test_explicit_encodings(sandbox: Sandbox) -> None:
    (sandbox.root / "latin.txt").write_bytes(b"caf\xe9")
    (sandbox.root / "wide.txt").write_bytes("hi ✓".encode("utf-16"))
    assert (await sandbox.read("latin.txt", encoding="latin-1")).content == "café"
    assert (await sandbox.read("wide.txt", encoding="utf-16")).content == "hi ✓"
    await sandbox.problem("latin.txt", MCPErrorCode.VALIDATION_ERROR)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def test_settings_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_SAFE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MCP_SQL_DSN", "postgresql://unrelated")  # other MCP_* vars are ignored
    assert SandboxSettings().safe_data_dir == tmp_path.resolve()


def test_settings_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_SAFE_DATA_DIR", raising=False)
    assert SandboxSettings().safe_data_dir is None


def test_settings_canonicalise_symlinked_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    assert SandboxSettings(safe_data_dir=tmp_path / "alias").safe_data_dir == real.resolve()


@pytest.mark.parametrize("kind", ["relative", "missing", "file"])
def test_settings_reject_invalid_roots(tmp_path: Path, kind: str) -> None:
    (tmp_path / "file.txt").write_text("x")
    value = {
        "relative": Path("data"),
        "missing": tmp_path / "missing",
        "file": tmp_path / "file.txt",
    }[kind]
    with pytest.raises(ValidationError):
        SandboxSettings(safe_data_dir=value)


def test_settings_forbid_extra_fields(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        SandboxSettings(safe_data_dir=tmp_path, unexpected=True)  # type: ignore[call-arg]


def test_tool_requires_configured_root() -> None:
    with pytest.raises(ValueError, match="not configured"):
        SandboxFsReadTool(SandboxSettings(safe_data_dir=None))


# ---------------------------------------------------------------------------
# MCP protocol conformance (through MCPServer)
# ---------------------------------------------------------------------------
class Collector:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def write(self, data: bytes, /) -> None:
        self.messages.append(json.loads(data))

    async def aclose(self) -> None:
        return None


async def exchange(registry: ToolRegistry, *messages: dict[str, Any]) -> dict[Any, Any]:
    init = {
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}},
    }
    reader = asyncio.StreamReader()
    for message in (init, *messages):
        reader.feed_data(json.dumps(message).encode() + b"\n")
    reader.feed_eof()
    sink = Collector()
    await asyncio.wait_for(MCPServer(registry).serve(reader, sink), TIMEOUT)
    return {message["id"]: message for message in sink.messages}


def call(request_id: int, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "sandbox_fs_read", "arguments": arguments},
    }


def tool_problem(response: dict[str, Any], code: MCPErrorCode) -> dict[str, Any]:
    result = mcp_types.CallToolResult.model_validate(response["result"])
    assert result.is_error is True
    assert "structuredContent" not in response["result"]
    (content,) = response["result"]["content"]
    assert ProblemDetail.model_validate_json(content["text"]).code is code
    data: dict[str, Any] = json.loads(content["text"])
    return data


@pytest.fixture
def registry(sandbox: Sandbox) -> ToolRegistry:
    return ToolRegistry([sandbox.tool.definition()])


async def test_tools_list_advertises_sandbox_fs_read(registry: ToolRegistry) -> None:
    responses = await exchange(registry, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    (spec,) = responses[1]["result"]["tools"]
    mcp_types.Tool.model_validate(spec)
    assert spec["name"] == "sandbox_fs_read"
    assert spec["annotations"]["readOnlyHint"] is True
    assert spec["inputSchema"]["properties"]["max_bytes"]["maximum"] == FS_MAX_BYTES_LIMIT


async def test_successful_read_over_protocol(registry: ToolRegistry) -> None:
    responses = await exchange(registry, call(1, {"relative_path": "notes.txt"}))
    assert mcp_types.CallToolResult.model_validate(responses[1]["result"]).is_error is False
    assert responses[1]["result"]["structuredContent"] == {
        "resolved_path": "notes.txt",
        "content": "hello sandbox",
        "bytes_read": 13,
        "truncated": False,
    }


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({"relative_path": "../../etc/passwd"}, MCPErrorCode.ACCESS_DENIED),
        ({"relative_path": "escape"}, MCPErrorCode.ACCESS_DENIED),
        ({"relative_path": "missing.txt"}, MCPErrorCode.VALIDATION_ERROR),
        ({"relative_path": "docs"}, MCPErrorCode.VALIDATION_ERROR),
        ({"relative_path": "notes.txt", "max_bytes": 2_000_000}, MCPErrorCode.VALIDATION_ERROR),
        ({"relative_path": "notes.txt", "encoding": "rot13"}, MCPErrorCode.VALIDATION_ERROR),
    ],
)
async def test_failures_are_in_band_problem_details(
    registry: ToolRegistry, sandbox: Sandbox, arguments: dict[str, Any], code: MCPErrorCode
) -> None:
    responses = await exchange(registry, call(1, arguments))
    problem = tool_problem(responses[1], code)
    assert str(sandbox.root) not in json.dumps(responses[1])
    assert SECRET not in json.dumps(responses[1])
    assert problem["status"] in {403, 422}


async def test_decode_failure_over_protocol(registry: ToolRegistry, sandbox: Sandbox) -> None:
    (sandbox.root / "bin.dat").write_bytes(b"\x89PNG\r\n\x1a\n\xff")
    responses = await exchange(registry, call(1, {"relative_path": "bin.dat"}))
    assert tool_problem(responses[1], MCPErrorCode.VALIDATION_ERROR)["invalid_params"] == [
        "encoding"
    ]


async def test_io_crash_is_json_rpc_internal_error(
    registry: ToolRegistry, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def failing_open(root: Path, relative: PurePath) -> int:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(fs_module, "open_beneath", failing_open)
    with caplog.at_level(logging.ERROR):
        responses = await exchange(registry, call(1, {"relative_path": "notes.txt"}))
    assert responses[1]["error"]["code"] == -32603


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------
async def test_registry_exposes_all_tools(sandbox: Sandbox) -> None:
    async with open_tool_registry(
        sql=SqlSettings(dsn=SecretStr("postgresql://reader@db.invalid/app")),
        fs=SandboxSettings(safe_data_dir=sandbox.root),
        metrics=MetricsSettings(enabled=True),
    ) as registry:
        assert [tool.name for tool in registry] == [
            "read_only_sql",
            "sandbox_fs_read",
            "system_metrics",
        ]


async def test_registry_skips_fs_without_root(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("MCP_SAFE_DATA_DIR", raising=False)
    with caplog.at_level(logging.WARNING):
        async with open_tool_registry() as registry:
            assert "sandbox_fs_read" not in registry
    assert "MCP_SAFE_DATA_DIR is not set" in caplog.text

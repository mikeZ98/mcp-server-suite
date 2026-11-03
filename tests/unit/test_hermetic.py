"""The suite itself is hermetic: no network, no inherited configuration, no stray state."""

import asyncio
import os
import socket
from pathlib import Path

import asyncpg
import pytest
from hypothesis.configuration import storage_directory
from pytest_socket import SocketBlockedError

REPO_ROOT = Path(__file__).resolve().parents[2]

# pytest-socket warns before raising; with ``filterwarnings = error`` that warning
# would itself fail any test touching the network. These probes expect it.
expects_blocked_socket = pytest.mark.filterwarnings("ignore:A test tried to use socket:UserWarning")


def test_socket_blocking_is_enabled_for_the_whole_run(request: pytest.FixtureRequest) -> None:
    assert request.config.getoption("disable_socket") is True


@expects_blocked_socket
@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_ip_sockets_are_blocked(family: socket.AddressFamily, kind: socket.SocketKind) -> None:
    with pytest.raises(SocketBlockedError):
        socket.socket(family, kind)


@expects_blocked_socket
def test_outbound_connections_are_blocked() -> None:
    with pytest.raises(SocketBlockedError):
        socket.create_connection(("192.0.2.1", 5432), timeout=0.1)  # TEST-NET-1, never routed


@expects_blocked_socket
async def test_asyncio_connections_are_blocked() -> None:
    with pytest.raises(SocketBlockedError):
        await asyncio.open_connection("127.0.0.1", 5432)


@expects_blocked_socket
async def test_no_live_postgres_is_reachable() -> None:
    with pytest.raises(SocketBlockedError):
        await asyncpg.connect("postgresql://reader@127.0.0.1:5432/app", timeout=0.5)


def test_unix_sockets_remain_available_for_the_event_loop() -> None:
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"ok")
        assert right.recv(2) == b"ok"


def test_mcp_environment_is_isolated_per_test() -> None:
    assert not [name for name in os.environ if name.startswith("MCP_")]


def test_hypothesis_state_lives_under_cache() -> None:
    directory = storage_directory("examples")
    assert directory.path.is_relative_to(REPO_ROOT / ".cache")
    assert not (REPO_ROOT / ".hypothesis").exists()

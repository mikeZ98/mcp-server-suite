#!/usr/bin/env bash
# Build the container image and verify its runtime security profile.
#
# Usage:
#   scripts/smoke-docker.sh            build and check against a live Docker daemon
#   scripts/smoke-docker.sh --offline  validate Dockerfile and docker-compose.yml only
#
# Environment:
#   SMOKE_IMAGE       image tag to build and test (default: mcp-server-suite:smoke)
#   SMOKE_KEEP_IMAGE  set to 1 to keep the image afterwards
#   PYTHON            interpreter used to parse JSON (default: python3)
#
# Compatible with macOS /bin/bash 3.2 (no mapfile, no associative arrays).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${SMOKE_IMAGE:-mcp-server-suite:smoke}"
PYTHON="${PYTHON:-python3}"
APP_ID=10001
RUN_ID="smoke-$$"
OFFLINE=0

case "${1:-}" in
  "") ;;
  --offline) OFFLINE=1 ;;
  *) echo "usage: $0 [--offline]" >&2; exit 2 ;;
esac

# The same hardening docker-compose.yml applies, for plain `docker run`.
# shellcheck disable=SC2054  # commas separate tmpfs mount options
HARDENED=(
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --network none
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777
  --pids-limit 64
  --memory 256m
)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/smoke-docker.XXXXXX")"
failures=0
created_image=0

cleanup() {
  docker rm -f "$RUN_ID-term" >/dev/null 2>&1 || true
  if ((OFFLINE == 0)); then
    MCP_IMAGE="$IMAGE" docker compose -p "$RUN_ID" down --volumes --remove-orphans \
      >/dev/null 2>&1 || true
  fi
  if ((created_image == 1)) && [[ "${SMOKE_KEEP_IMAGE:-0}" != 1 ]]; then
    docker image rm "$IMAGE" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { printf '  ok    %s\n' "$1"; }
fail() {
  printf '  FAIL  %s\n' "$1" >&2
  failures=$((failures + 1))
}
section() { printf '\n== %s\n' "$1"; }

# expect_eq LABEL EXPECTED ACTUAL
expect_eq() {
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}

# Run a command inside the hardened container, overriding the entrypoint.
in_container() {
  local entrypoint="$1"
  shift
  docker run --rm "${HARDENED[@]}" --entrypoint "$entrypoint" "$IMAGE" "$@"
}

# ---------------------------------------------------------------------------
# Static checks (no daemon required)
# ---------------------------------------------------------------------------
check_static() {
  section "Dockerfile and .dockerignore"
  local line
  # shellcheck disable=SC1003  # the backslash is part of the expected line
  for line in \
    'USER 10001:10001' \
    'STOPSIGNAL SIGTERM' \
    'ENTRYPOINT ["/opt/venv/bin/python", "-m", "mcp_server_suite"]' \
    '    MCP_SAFE_DATA_DIR=/safe_data_dir' \
    '    TMPDIR=/tmp \'; do
    if grep -qxF -- "$line" Dockerfile; then pass "Dockerfile: ${line#    }"; else fail "Dockerfile lacks: $line"; fi
  done
  local images pinned
  images="$(grep -cE '^ARG [A-Z_]+_IMAGE=' Dockerfile || true)"
  pinned="$(grep -cE '^ARG [A-Z_]+_IMAGE=[^ ]+@sha256:[0-9a-f]{64}$' Dockerfile || true)"
  if ((images >= 2 && images == pinned)); then
    pass "Dockerfile: base images pinned by digest"
  else
    fail "Dockerfile: every base image must be pinned by digest ($pinned of $images)"
  fi
  expect_eq ".dockerignore: deny-by-default allowlist" "*" \
    "$(grep -vE '^[[:space:]]*(#|$)' .dockerignore | head -n 1)"

  section "docker-compose.yml"
  if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose plugin is not available"
    return
  fi
  if ! docker compose config --format json >"$WORK/compose.json" 2>"$WORK/compose.err"; then
    fail "docker compose config: $(cat "$WORK/compose.err")"
    return
  fi
  pass "docker compose config parses"
  "$PYTHON" - "$WORK/compose.json" <<'PY' || failures=$((failures + 1))
import json
import sys

service = json.load(open(sys.argv[1]))["services"]["mcp-server"]
limits = service.get("deploy", {}).get("resources", {}).get("limits", {})
reservations = service.get("deploy", {}).get("resources", {}).get("reservations", {})
volumes = [v for v in service.get("volumes", []) if v.get("target") == "/safe_data_dir"]
checks = [
    ("read_only rootfs", service.get("read_only") is True),
    ("runs as 10001:10001", service.get("user") == "10001:10001"),
    ("cap_drop ALL", service.get("cap_drop") == ["ALL"]),
    ("no-new-privileges", "no-new-privileges:true" in service.get("security_opt", [])),
    ("tmpfs on /tmp", any(t.split(":")[0] == "/tmp" for t in service.get("tmpfs", []))),
    ("stdin open, no TTY", service.get("stdin_open") is True and not service.get("tty")),
    ("no network", service.get("network_mode") == "none"),
    ("CPU and memory limits", bool(limits.get("cpus")) and bool(limits.get("memory"))),
    ("CPU and memory reservations", bool(reservations.get("cpus")) and bool(reservations.get("memory"))),
    ("pids limit", bool(limits.get("pids"))),
    (
        "dedicated read-only volume on /safe_data_dir",
        len(volumes) == 1 and volumes[0].get("type") == "volume" and volumes[0].get("read_only") is True,
    ),
    ("stop signal SIGTERM", service.get("stop_signal") == "SIGTERM"),
]
failed = 0
for label, ok in checks:
    print(("  ok    " if ok else "  FAIL  ") + "compose: " + label, file=sys.stdout if ok else sys.stderr)
    failed += not ok
sys.exit(1 if failed else 0)
PY
}

# ---------------------------------------------------------------------------
# Live checks
# ---------------------------------------------------------------------------
write_requests() {
  cat >"$WORK/requests.jsonl" <<'JSON'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke-docker","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"ping"}
{"jsonrpc":"2.0","id":3,"method":"tools/list"}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"system_metrics","arguments":{"include_disk":true}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sandbox_fs_read","arguments":{"relative_path":"../etc/passwd"}}}
JSON
}

# verify_session LABEL STDOUT_FILE STDERR_FILE
verify_session() {
  "$PYTHON" - "$1" "$2" "$3" <<'PY' || failures=$((failures + 1))
import json
import sys

label, out_path, err_path = sys.argv[1:4]
responses = {}
for raw in open(out_path, "rb"):
    message = json.loads(raw)
    responses[message.get("id")] = message
stderr = open(err_path, encoding="utf-8", errors="replace").read()


def tool_names():
    return sorted(tool["name"] for tool in responses[3]["result"]["tools"])


def call(id_):
    return responses[id_]["result"]


checks = [
    ("initialize negotiates 2025-11-25", lambda: responses[1]["result"]["protocolVersion"] == "2025-11-25"),
    ("ping returns an empty result", lambda: responses[2]["result"] == {}),
    ("tools/list exposes the sandbox tools", lambda: tool_names() == ["sandbox_fs_read", "system_metrics"]),
    ("system_metrics succeeds read-only", lambda: call(4)["isError"] is False and "cpu" in call(4)["structuredContent"]),
    (
        "sandbox_fs_read denies traversal",
        lambda: call(5)["isError"] is True and json.loads(call(5)["content"][0]["text"])["code"] == "MCP_ACCESS_DENIED",
    ),
    ("no unexpected responses", lambda: sorted(responses) == [1, 2, 3, 4, 5]),
    ("stderr is free of tracebacks", lambda: "Traceback" not in stderr),
]
failed = 0
for name, check in checks:
    try:
        ok = bool(check())
    except (KeyError, IndexError, TypeError, ValueError):
        ok = False
    print(("  ok    " if ok else "  FAIL  ") + f"{label}: {name}", file=sys.stdout if ok else sys.stderr)
    failed += not ok
if failed and stderr:
    print("  --- server stderr ---\n" + stderr, file=sys.stderr)
sys.exit(1 if failed else 0)
PY
}

check_image_config() {
  section "Image configuration"
  expect_eq "USER" "$APP_ID:$APP_ID" "$(docker image inspect -f '{{.Config.User}}' "$IMAGE")"
  expect_eq "STOPSIGNAL" "SIGTERM" "$(docker image inspect -f '{{.Config.StopSignal}}' "$IMAGE")"
  expect_eq "ENTRYPOINT" "[/opt/venv/bin/python -m mcp_server_suite]" \
    "$(docker image inspect -f '{{.Config.Entrypoint}}' "$IMAGE")"
  local env
  env="$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE")"
  for var in MCP_SAFE_DATA_DIR=/safe_data_dir TMPDIR=/tmp PYTHONSAFEPATH=1; do
    if grep -qxF "$var" <<<"$env"; then pass "ENV $var"; else fail "ENV $var missing"; fi
  done
}

check_runtime_profile() {
  section "Runtime security profile"
  expect_eq "id -u" "$APP_ID" "$(in_container id -u)"
  expect_eq "id -g" "$APP_ID" "$(in_container id -g)"
  expect_eq "/safe_data_dir owner and mode" "$APP_ID:$APP_ID 750" \
    "$(in_container stat -c '%u:%g %a' /safe_data_dir)"

  local path
  for path in /probe /opt/venv/probe /safe_data_dir/probe; do
    if in_container sh -c "touch '$path'" 2>/dev/null; then
      fail "write to $path succeeded"
    else
      pass "write to $path refused"
    fi
  done
  expect_eq "/tmp is writable tmpfs" "ok" \
    "$(in_container sh -c 'echo ok >/tmp/probe && cat /tmp/probe')"

  # shellcheck disable=SC2016  # expanded by the container's shell
  if in_container sh -c \
    'for t in pip pip3 uv uvx apt apt-get dpkg gcc cc make; do command -v "$t" && exit 1; done; exit 0'; then
    pass "no pip, uv, package managers or compilers on PATH"
  else
    fail "build or package tooling present in runtime image"
  fi
  if in_container python -c '
import importlib.util, sys
banned = ("pip", "ensurepip", "setuptools", "pytest", "hypothesis", "mypy", "ruff")
sys.exit(1 if [m for m in banned if importlib.util.find_spec(m)] else 0)'; then
    pass "no pip, ensurepip or dev packages importable"
  else
    fail "pip, ensurepip or dev packages importable"
  fi
  # Audited as root so unreadable directories cannot hide anything.
  local suid
  if suid="$(docker run --rm --read-only --network none --user 0 --entrypoint find "$IMAGE" \
    / -xdev -type f -perm /6000)"; then
    expect_eq "no setuid/setgid binaries" "" "$suid"
  else
    fail "setuid/setgid audit could not run"
  fi
}

check_handshake() {
  section "MCP handshake over container stdio (docker run)"
  write_requests
  local status=0
  docker run --rm -i "${HARDENED[@]}" "$IMAGE" \
    <"$WORK/requests.jsonl" >"$WORK/run.out" 2>"$WORK/run.err" || status=$?
  expect_eq "exit status after EOF" "0" "$status"
  verify_session "docker run" "$WORK/run.out" "$WORK/run.err"

  section "MCP handshake over container stdio (docker compose)"
  status=0
  MCP_IMAGE="$IMAGE" docker compose -p "$RUN_ID" run --rm -T mcp-server \
    <"$WORK/requests.jsonl" >"$WORK/compose.out" 2>"$WORK/compose.err" || status=$?
  expect_eq "exit status after EOF" "0" "$status"
  verify_session "compose" "$WORK/compose.out" "$WORK/compose.err"
}

check_sigterm() {
  section "Graceful stop on SIGTERM"
  mkfifo "$WORK/stdin"
  docker run --name "$RUN_ID-term" -i "${HARDENED[@]}" "$IMAGE" \
    <"$WORK/stdin" >"$WORK/term.out" 2>"$WORK/term.err" &
  local client=$!
  exec 3>"$WORK/stdin"
  head -n 1 "$WORK/requests.jsonl" >&3

  # Wait for the initialize response so the signal handlers are installed.
  local waited=0
  until grep -q '"id":1' "$WORK/term.out" 2>/dev/null; do
    if ((waited >= 300)); then break; fi
    sleep 0.1
    waited=$((waited + 1))
  done
  if ((waited >= 300)); then
    fail "server did not answer initialize within 30 s"
  else
    pass "server answered initialize"
  fi

  docker stop --time 10 "$RUN_ID-term" >/dev/null
  exec 3>&-
  wait "$client" || true
  expect_eq "exit code after docker stop" "0" \
    "$(docker inspect -f '{{.State.ExitCode}}' "$RUN_ID-term")"
  if grep -q Traceback "$WORK/term.err"; then
    fail "traceback on shutdown: $(cat "$WORK/term.err")"
  else
    pass "clean shutdown log"
  fi
}

# ---------------------------------------------------------------------------
check_static

if ((OFFLINE == 0)); then
  if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon unreachable; start one or rerun with --offline." >&2
    exit 2
  fi
  section "Build $IMAGE"
  DOCKER_BUILDKIT=1 docker build --tag "$IMAGE" .
  created_image=1
  check_image_config
  check_runtime_profile
  check_handshake
  check_sigterm
fi

echo
if ((failures > 0)); then
  echo "smoke-docker: $failures check(s) failed" >&2
  exit 1
fi
echo "smoke-docker: all checks passed$( ((OFFLINE == 1)) && echo ' (offline)')"

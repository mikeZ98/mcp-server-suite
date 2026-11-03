# check=error=true
#
# mcp-server-suite: unprivileged, read-only-rootfs container for MCP over stdio.
#
#   docker build -t mcp-server-suite .
#   docker run --rm -i --read-only --cap-drop ALL \
#     --security-opt no-new-privileges:true --tmpfs /tmp \
#     -v mcp-safe-data:/safe_data_dir:ro mcp-server-suite
#
# Base images are pinned by digest; bump each tag and digest together.
ARG PYTHON_IMAGE=python:3.12-slim-trixie@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.7@sha256:240fb85ab0f263ef12f492d8476aa3a2e4e1e333f7d67fbdd923d00a506a516a

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------------------
# Stage 1: builder. Resolves the locked dependency set into /opt/venv.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

# A C toolchain for any dependency without a wheel for the target platform.
# It never leaves this stage. Package versions are fixed by the base image digest.
# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends gcc libc6-dev; \
    rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON_PREFERENCE=only-system \
    UV_PYTHON=/usr/local/bin/python3 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Third-party dependencies first, verified against uv.lock hashes. This layer is
# reused until the lockfile or project metadata change.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-dev --no-install-project --no-editable

# The project itself, installed as a regular (non-editable) wheel so the runtime
# needs nothing from /build.
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

# Fail the build if the package is broken or development tooling leaked in.
RUN set -eux; \
    /opt/venv/bin/python -I -c 'import mcp_server_suite.__main__'; \
    if /opt/venv/bin/python -I -c 'import pytest' 2>/dev/null; then \
      echo 'development dependencies must not be installed' >&2; exit 1; \
    fi

# ---------------------------------------------------------------------------
# Stage 2: runtime. Same base image, so the venv's interpreter symlink and
# compiled extensions match exactly.
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="mcp-server-suite" \
      org.opencontainers.image.description="Hardened MCP server over stdio: read-only SQL, sandboxed file reads, system metrics."

# Unprivileged identity and the sandbox root, then strip the image down:
# - pip and the ensurepip bootstrap that could reinstall it;
# - apt/dpkg tooling (the dpkg status database stays so image scanners can
#   still inventory OS packages);
# - setuid/setgid bits, so no binary can gain privileges.
RUN set -eux; \
    groupadd --system --gid 10001 appuser; \
    useradd --system --uid 10001 --gid appuser --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin appuser; \
    install -d -o appuser -g appuser -m 0750 /safe_data_dir; \
    rm -rf /usr/local/bin/pip /usr/local/bin/pip3* \
      /usr/local/lib/python3.*/site-packages/pip \
      /usr/local/lib/python3.*/site-packages/pip-*.dist-info \
      /usr/local/lib/python3.*/ensurepip; \
    rm -rf /usr/bin/apt /usr/bin/apt-* /usr/bin/dpkg /usr/bin/dpkg-* /usr/sbin/dpkg-* \
      /usr/lib/apt /usr/lib/dpkg /etc/apt /var/lib/apt /var/cache/apt /var/log/*; \
    find / -xdev -type f -perm /6000 -exec chmod a-s {} +

COPY --from=builder --link /opt/venv /opt/venv

# PYTHONSAFEPATH keeps the working directory off sys.path, so nothing in a
# mounted directory can shadow an import. Bytecode is precompiled in the
# builder; the root filesystem is expected to be read-only.
ENV PATH=/opt/venv/bin:$PATH \
    VIRTUAL_ENV=/opt/venv \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONSAFEPATH=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    TMPDIR=/tmp \
    MCP_SAFE_DATA_DIR=/safe_data_dir

WORKDIR /
USER 10001:10001

# The server installs SIGINT/SIGTERM handlers itself, so it runs as PID 1
# without an init shim and drains in-flight calls on `docker stop`.
STOPSIGNAL SIGTERM
# Stdio servers have no endpoint to probe; the MCP client owns liveness.
HEALTHCHECK NONE
ENTRYPOINT ["/opt/venv/bin/python", "-m", "mcp_server_suite"]

#!/usr/bin/env bash
# Enforce 100% branch coverage on the security-critical modules.
#
# Run after the test suite has produced coverage data (pytest runs with --cov);
# the overall >= 95% floor is enforced by pytest-cov itself (fail_under).
# Usage (inside the project environment, e.g. direnv or `uv run`):
#   pytest && scripts/coverage-gate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

readonly CRITICAL=(
  "src/mcp_server_suite/tools/sql.py"
  "src/mcp_server_suite/tools/fs.py"
  "src/mcp_server_suite/guardrails/*"
)

include="$(IFS=,; echo "${CRITICAL[*]}")"
python -m coverage report --fail-under=100 --show-missing --include="$include"

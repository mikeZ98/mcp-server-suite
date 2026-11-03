#!/usr/bin/env bash
# Audit every tracked file against the repository hygiene rules the local
# pre-commit hook applies to staged changes: no cache, virtualenv or secret
# files, and no absolute machine-specific paths in content.
#
# Usage: scripts/audit-hygiene.sh
# Used by the CI attribution-audit job; patterns live in .githooks/_policy.sh.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=../.githooks/_policy.sh
source "$ROOT/.githooks/_policy.sh"
cd "$ROOT"

fail=0

forbidden_paths="$(git ls-files | grep -E "$MCP_FORBIDDEN_PATH_RE" | grep -vE "$MCP_ALLOWED_PATH_RE" || true)"
if [[ -n "$forbidden_paths" ]]; then
  mcp_err "Tracked cache, virtualenv or secret files:"
  sed 's/^/    /' <<<"$forbidden_paths" >&2
  fail=1
fi

path_leaks="$(git grep -nIE "$MCP_PATH_LEAK_RE" || true)"
if [[ -n "$path_leaks" ]]; then
  mcp_err "Tracked content contains absolute local paths:"
  sed 's/^/    /' <<<"$path_leaks" >&2
  fail=1
fi

if ((fail)); then
  mcp_err "Hygiene audit FAILED."
  exit 1
fi
mcp_ok "Hygiene audit passed ($(git ls-files | wc -l | tr -d ' ') tracked file(s) scanned)."

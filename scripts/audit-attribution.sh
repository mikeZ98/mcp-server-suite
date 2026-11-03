#!/usr/bin/env bash
# Audit commits for the sole-contributor identity invariant (author + committer)
# and for tool-generated meta-trailers in commit messages.
#
# Usage: scripts/audit-attribution.sh [<git rev-list args>...]   (default: HEAD)
# Used by .githooks/pre-push locally and by the CI attribution-audit job.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=../.githooks/_policy.sh
source "$ROOT/.githooks/_policy.sh"

(($#)) || set -- HEAD

fail=0
count=0
while IFS= read -r sha; do
  count=$((count + 1))
  IFS=$'\x1f' read -r an ae cn ce <<<"$(git log -1 --format='%an%x1f%ae%x1f%cn%x1f%ce' "$sha")"
  short="${sha:0:12}"
  mcp_check_identity "[$short] Author" "$an" "$ae" || fail=1
  mcp_check_identity "[$short] Committer" "$cn" "$ce" || fail=1
  mcp_check_trailers "$(git log -1 --format='%B' "$sha")" || {
    mcp_err "[$short] message policy violation."
    fail=1
  }
done < <(git rev-list "$@")

if ((fail)); then
  mcp_err "Attribution audit FAILED ($count commit(s) scanned)."
  exit 1
fi
mcp_ok "Attribution audit passed ($count commit(s) scanned)."

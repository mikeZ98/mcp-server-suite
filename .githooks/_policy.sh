# shellcheck shell=bash
# Shared commit policy for git hooks and scripts/audit-attribution.sh:
#   * sole-contributor identity (author + committer),
#   * Conventional Commits subject line,
#   * no tool-generated meta-trailers in commit messages.
# Sourced, never executed. Git ignores this file as a hook (not a hook name).

readonly MCP_ALLOWED_NAME="mikeZ98"
readonly MCP_ALLOWED_EMAIL="145975972+mikeZ98@users.noreply.github.com"

readonly MCP_CONVENTIONAL_RE='^(feat|fix|chore|docs|test|build|ci|refactor|perf|style|revert)(\([a-z0-9._/-]+\))?!?: [^ ].{0,98}$'

# Case-insensitive patterns rejected anywhere in the message body.
readonly MCP_FORBIDDEN_TRAILER_RE='^(co-authored-by|generated-by|signed-off-by-bot):|generated with \[?[a-z ]+\]?\(|🤖'

mcp_err() { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; }
mcp_ok() { printf '\033[32m✔ %s\033[0m\n' "$*" >&2; }

# mcp_check_identity <role> <name> <email>
mcp_check_identity() {
  local role="$1" name="$2" email="$3"
  if [[ "$name" != "$MCP_ALLOWED_NAME" || "$email" != "$MCP_ALLOWED_EMAIL" ]]; then
    mcp_err "$role identity '$name <$email>' violates the sole-contributor invariant."
    mcp_err "Expected: '$MCP_ALLOWED_NAME <$MCP_ALLOWED_EMAIL>'."
    return 1
  fi
}

# mcp_parse_ident <git-var-ident>  →  prints "name<TAB>email"
mcp_parse_ident() {
  sed -E 's/^(.*) <([^>]*)> [0-9]+ [-+][0-9]{4}$/\1\t\2/' <<<"$1"
}

# mcp_clean_message — strip comments and anything below the scissors line.
mcp_clean_message() {
  sed -e '/^# ------------------------ >8 ------------------------$/,$d' -e '/^#/d'
}

# mcp_check_subject <first-line>
mcp_check_subject() {
  local subject="$1"
  case "$subject" in
    Merge\ *|fixup!\ *|squash!\ *|amend!\ *) return 0 ;;
  esac
  if ! grep -qE "$MCP_CONVENTIONAL_RE" <<<"$subject"; then
    mcp_err "Subject is not a Conventional Commit (max 100 chars): '$subject'"
    mcp_err "Format: <type>(<scope>)?: <summary>   types: feat fix chore docs test build ci refactor perf style revert"
    return 1
  fi
}

# mcp_check_trailers <full-message>
mcp_check_trailers() {
  local hits
  hits="$(grep -inE "$MCP_FORBIDDEN_TRAILER_RE" <<<"$1" || true)"
  if [[ -n "$hits" ]]; then
    mcp_err "Commit message contains tool-generated meta-trailers:"
    sed 's/^/    /' <<<"$hits" >&2
    return 1
  fi
}

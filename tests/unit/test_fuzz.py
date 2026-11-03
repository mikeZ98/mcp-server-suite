"""Property-based fuzzing of the security boundaries (Hypothesis).

Every property is checked against an *independent oracle* - Unicode database
properties, ``os.path.realpath``, a fresh sqlglot parse - never against the
implementation's own tables, and every property is two-sided where possible:
dirty input must be rejected *and* clean input must be accepted.
"""

import json
import os
import re
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import sqlglot
from hypothesis import assume, example, given
from hypothesis import strategies as st
from pydantic import ValidationError
from sqlglot import exp

from mcp_server_suite.errors import ToolError
from mcp_server_suite.guardrails import ArgumentSanitizer, SanitizerLimits
from mcp_server_suite.schemas import MCPErrorCode, SandboxFsReadParams
from mcp_server_suite.tools import SandboxFsReadTool, SandboxSettings
from mcp_server_suite.tools.sql import enforce_read_only

# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------
#: Any code point, including lone surrogates (``st.characters`` excludes them).
any_char = st.integers(min_value=0, max_value=0x10FFFF).map(chr)
any_text = st.text(alphabet=any_char, max_size=40)

_NAMED_INVISIBLES = frozenset(
    unicodedata.lookup(name)
    for name in (
        "LEFT-TO-RIGHT MARK",
        "RIGHT-TO-LEFT MARK",
        "ARABIC LETTER MARK",
        "ZERO WIDTH SPACE",
        "ZERO WIDTH NON-JOINER",
        "ZERO WIDTH JOINER",
        "WORD JOINER",
        "ZERO WIDTH NO-BREAK SPACE",
    )
)
_BIDI_CONTROL_CLASSES = frozenset({"LRE", "RLE", "PDF", "LRO", "RLO", "LRI", "RLI", "FSI", "PDI"})
TROJAN = sorted(
    c
    for c in map(chr, range(0x10000))
    if unicodedata.bidirectional(c) in _BIDI_CONTROL_CLASSES or c in _NAMED_INVISIBLES
)


def oracle_forbidden(char: str) -> bool:
    """Independent definition of a dangerous character via the Unicode database."""
    category = unicodedata.category(char)
    if category == "Cc":
        return char not in "\t\n\r"
    return (
        category in {"Cs", "Zl", "Zp"}
        or unicodedata.bidirectional(char) in _BIDI_CONTROL_CLASSES
        or char in _NAMED_INVISIBLES
    )


def test_trojan_alphabet_is_nonempty_and_complete() -> None:
    expected = {chr(cp) for cp in (0x202E, 0x2066, 0x2069, 0x200B, 0xFEFF, 0x200E, 0x061C)}
    assert expected <= set(TROJAN)


# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------
LIMITS = SanitizerLimits(max_depth=4, max_items=6)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")

identifier_keys = st.from_regex(_IDENT, fullmatch=True).filter(lambda k: not k.startswith("__"))
keys = identifier_keys | any_text | st.sampled_from(["__proto__", "max rows", "a-b", "", "x" * 65])
scalars = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | any_text
json_values = st.recursive(
    scalars,
    lambda children: st.lists(children, max_size=8) | st.dictionaries(keys, children, max_size=8),
    max_leaves=30,
)


def oracle_clean(value: Any, depth: int = 1) -> bool:
    if isinstance(value, str):
        return not any(map(oracle_forbidden, value))
    if isinstance(value, dict | list):
        if depth > LIMITS.max_depth or len(value) > LIMITS.max_items:
            return False
        if isinstance(value, dict):
            return all(
                _IDENT.fullmatch(k) is not None
                and not k.startswith("__")
                and oracle_clean(v, depth + 1)
                for k, v in value.items()
            )
        return all(oracle_clean(item, depth + 1) for item in value)
    return True


@given(st.dictionaries(keys, json_values, max_size=8))
@example({"query": "SELECT 1"})
@example({"query": "a" + chr(0x202E) + "b"})
@example({"max" + chr(0x200B) + "rows": 1})
def test_sanitizer_decision_matches_oracle(arguments: dict[str, Any]) -> None:
    sanitizer = ArgumentSanitizer(LIMITS)
    try:
        sanitizer.check(arguments)
    except ToolError as exc:
        assert not oracle_clean(arguments), "clean arguments were rejected"
        problem = exc.problem
        assert problem.code is MCPErrorCode.VALIDATION_ERROR
        body = json.dumps(problem.to_json_dict(), ensure_ascii=False)
        body.encode("utf-8")  # no lone surrogates echoed back
        assert not any(map(oracle_forbidden, body)), "dangerous character echoed in problem"
    else:
        assert oracle_clean(arguments), "dirty arguments were accepted"


@given(
    prefix=st.text(max_size=20),
    trojans=st.lists(st.sampled_from(TROJAN), min_size=1, max_size=4),
    suffix=st.text(max_size=20),
)
def test_trojan_source_sequences_always_rejected(
    prefix: str, trojans: list[str], suffix: str
) -> None:
    payload = prefix + "".join(trojans) + suffix
    with pytest.raises(ToolError) as exc_info:
        ArgumentSanitizer().check({"query": payload})
    assert exc_info.value.problem.metadata["reason"] == "forbidden_character"


@given(st.lists(st.integers(min_value=0xD800, max_value=0xDFFF), min_size=1, max_size=4))
def test_json_surrogate_escapes(units: list[int]) -> None:
    """``\\uD83D\\uDE00`` is a valid pair (decodes to an astral char); anything unpaired fails."""
    document = '{"text": "' + "".join(f"\\u{u:04x}" for u in units) + '"}'
    arguments = json.loads(document)
    decoded_has_surrogate = any(0xD800 <= ord(c) <= 0xDFFF for c in arguments["text"])
    try:
        ArgumentSanitizer().check(arguments)
    except ToolError:
        assert decoded_has_surrogate
    else:
        assert not decoded_has_surrogate


# ---------------------------------------------------------------------------
# SQL policy
# ---------------------------------------------------------------------------
tables = st.sampled_from(["users", "orders", "t", "public.accounts", '"Mixed Case"'])
columns = st.lists(
    st.sampled_from(
        ["*", "id", "name", "count(*)", "lower(name)", "1", "'a;b'", "now()", "id + 1"]
    ),
    min_size=1,
    max_size=3,
).map(", ".join)
wheres = st.sampled_from(
    [
        "",
        " WHERE id > 1",
        " WHERE name = 'x'",
        " WHERE id IN (SELECT id FROM t)",
        " WHERE EXISTS (SELECT 1)",
    ]
)
orders = st.sampled_from(["", " ORDER BY 1", " ORDER BY id DESC NULLS LAST"])
limits = st.one_of(
    st.just(""),
    st.integers(min_value=0, max_value=10**12).map(lambda n: f" LIMIT {n}"),
    st.integers(min_value=0, max_value=200).map(lambda n: f" FETCH FIRST {n} ROWS ONLY"),
    st.sampled_from(
        [
            " LIMIT ALL",
            " LIMIT NULL",
            " LIMIT 10 + 90",
            " LIMIT (SELECT 1000)",
            " FETCH FIRST ROW ONLY",
            " FETCH FIRST 5 ROWS WITH TIES",
            " FETCH FIRST 10 PERCENT ROWS ONLY",
        ]
    ),
)
offsets = st.sampled_from(["", " OFFSET 3"])
simple_selects = st.builds(
    lambda c, t, w, o: f"SELECT {c} FROM {t}{w}{o}", columns, tables, wheres, orders
)
read_only_queries = st.one_of(
    st.builds(lambda s, lim, off: f"{s}{lim}{off}", simple_selects, limits, offsets),
    st.builds(lambda a, b, lim: f"{a} UNION ALL {b}{lim}", simple_selects, simple_selects, limits),
    st.builds(lambda s, lim: f"WITH c AS ({s}) SELECT * FROM c{lim}", simple_selects, limits),
    st.builds(lambda s, lim: f"SELECT * FROM ({s}{lim}) AS sub", simple_selects, limits),
)
decorations: list[Callable[[str], str]] = [
    lambda q: q,
    str.lower,
    lambda q: q + ";",
    lambda q: "/* lead */ " + q,
    lambda q: q + " -- trailing",
    lambda q: "\n\t " + q.replace(" ", "\n  ") + "\n",
]


def outer_limit(sql: str) -> int:
    (root,) = [s for s in sqlglot.parse(sql, read="postgres") if s is not None]
    assert isinstance(root, exp.Select | exp.SetOperation)
    limit = root.args["limit"]
    assert isinstance(limit, exp.Limit), "output always carries a plain LIMIT"
    count = limit.expression
    assert isinstance(count, exp.Literal)
    assert count.is_int
    return int(count.this)


@given(read_only_queries, st.sampled_from(decorations), st.integers(min_value=1, max_value=50))
def test_any_select_gets_a_literal_limit_within_the_cap(
    query: str, decorate: Callable[[str], str], max_rows: int
) -> None:
    enforced = enforce_read_only(decorate(query), max_rows=max_rows)
    limit = outer_limit(enforced.sql)
    assert 0 <= limit <= max_rows
    if enforced.requested_limit is not None:
        assert limit == min(enforced.requested_limit, max_rows)
    assert enforce_read_only(enforced.sql, max_rows=max_rows).sql == enforced.sql


_WRITES = [
    "INSERT INTO t VALUES (1)",
    "UPDATE t SET a = 1",
    "DELETE FROM t",
    "DROP TABLE t",
    "TRUNCATE t",
    "ALTER TABLE t ADD c int",
    "GRANT ALL ON t TO u",
    "REVOKE ALL ON t FROM u",
    "CREATE TABLE x (a int)",
    "COPY t TO '/tmp/x'",
    "VACUUM",
    "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
    "SET search_path = x",
    "COMMIT",
    "DO $$ BEGIN END $$",
    "CALL p()",
    "LOCK TABLE t",
    "REFRESH MATERIALIZED VIEW v",
    "SELECT * INTO x FROM t",
    "SELECT * FROM t FOR UPDATE",
    "SELECT pg_sleep(1)",
    "SELECT dblink_exec('x', 'y')",
    "EXPLAIN ANALYZE DELETE FROM t",
]
_RETURNING = [
    "DELETE FROM t RETURNING *",
    "UPDATE t SET a = 1 RETURNING a",
    "INSERT INTO t VALUES (1) RETURNING *",
]
writes = st.sampled_from(_WRITES)
returning = st.sampled_from(_RETURNING)
attacks = st.one_of(
    writes,
    st.builds(lambda s, w: f"{s}; {w}", simple_selects, writes),
    st.builds(lambda w, s: f"{w}; {s}", writes, simple_selects),
    st.builds(lambda r, s: f"WITH d AS ({r}) {s}", returning, simple_selects),
    st.builds(
        lambda s, r: f"{s} UNION ALL (WITH d AS ({r}) SELECT * FROM d)", simple_selects, returning
    ),
    st.builds(lambda s, w: f"{s}; /* hidden */ {w}; --", simple_selects, writes),
)
casings: list[Callable[[str], str]] = [lambda q: q, str.lower, str.upper, str.swapcase]


@given(attacks, st.sampled_from(casings))
def test_writes_are_never_accepted(attack: str, casing: Callable[[str], str]) -> None:
    with pytest.raises(ToolError) as exc_info:
        enforce_read_only(casing(attack))
    assert exc_info.value.problem.code in {
        MCPErrorCode.QUERY_VIOLATION,
        MCPErrorCode.VALIDATION_ERROR,
    }


@given(st.text(max_size=200), st.integers(min_value=1, max_value=50))
@example("SELECT " + "(" * 2000 + "1" + ")" * 2000, 50)
@example("SELECT 1 " + "UNION SELECT 1 " * 500, 50)
def test_arbitrary_text_fails_closed(text: str, max_rows: int) -> None:
    """Garbage never crashes the policy: it is rejected, or it is a capped SELECT."""
    try:
        enforced = enforce_read_only(text, max_rows=max_rows)
    except ToolError as exc:
        code = exc.problem.code
    else:
        assert outer_limit(enforced.sql) <= max_rows
        return
    assert code in {MCPErrorCode.QUERY_VIOLATION, MCPErrorCode.VALIDATION_ERROR}


# ---------------------------------------------------------------------------
# Filesystem containment
# ---------------------------------------------------------------------------
SECRET = "TOP SECRET: outside the sandbox"


@pytest.fixture(scope="module")
def sandbox(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, SandboxFsReadTool]:
    base = tmp_path_factory.mktemp("fuzz")
    root, outside = base / "safe", base / "outside"
    (root / "docs" / "nested").mkdir(parents=True)
    outside.mkdir()
    (root / "notes.txt").write_text("hello")
    (root / "docs" / "guide.md").write_text("guide")
    (root / "docs" / "nested" / "deep.txt").write_text("deep")
    (outside / "secret.txt").write_text(SECRET)
    (root / "docs" / "up").symlink_to("..")
    (root / "link").symlink_to("docs/guide.md")
    (root / "escape").symlink_to(outside / "secret.txt")
    (root / "escape_dir").symlink_to(outside, target_is_directory=True)
    (root / "loop").symlink_to("loop")
    return root.resolve(), SandboxFsReadTool(SandboxSettings(safe_data_dir=root))


segments = st.one_of(
    st.sampled_from(
        [
            "..", ".", "", "docs", "nested", "notes.txt", "guide.md", "deep.txt", "up", "link",
            "escape", "escape_dir", "secret.txt", "outside", "loop", "%2e%2e", "~", "..\\..",
        ]
    ),
    st.text(alphabet=st.characters(exclude_characters="/\x00"), max_size=6),
)  # fmt: skip
relative_paths = st.builds(
    lambda absolute, parts: ("/" if absolute else "") + "/".join(parts),
    st.booleans(),
    st.lists(segments, min_size=1, max_size=8),
)


def _inside(root: Path, candidate: str) -> bool:
    return os.path.commonpath([str(root), candidate]) == str(root)


def _hits_symlink_loop(root: Path, relative_path: str) -> bool:
    """Loops make ``os.path.realpath`` meaningless (``loop//.`` -> ``/``)."""
    try:
        (root / relative_path).resolve(strict=False)
    except (RuntimeError, OSError):
        return True
    return False


def _check_read(sandbox: tuple[Path, SandboxFsReadTool], relative_path: str) -> None:
    root, tool = sandbox
    try:
        params = SandboxFsReadParams(relative_path=relative_path)
    except ValidationError:
        return  # rejected by the schema (empty, NUL, too long)
    real = os.path.realpath(os.path.join(root, relative_path))  # noqa: PTH118 - independent oracle
    try:
        result = tool._read(params)
    except ToolError as exc:
        problem = exc.problem
        assert problem.code in {MCPErrorCode.ACCESS_DENIED, MCPErrorCode.VALIDATION_ERROR}
        if not _inside(root, real) and not _hits_symlink_loop(root, relative_path):
            assert problem.code is MCPErrorCode.ACCESS_DENIED, (relative_path, problem)
        body = json.dumps(problem.to_json_dict())
        assert str(root) not in body or str(root) in relative_path
        assert SECRET not in body
        return
    assert _inside(root, real), f"escaped the sandbox via {relative_path!r}"
    target = root / result.resolved_path
    assert not target.is_symlink()
    assert target.is_file()
    assert result.content == target.read_text()
    assert SECRET not in result.content


@given(relative_paths)
@example("../outside/secret.txt")
@example("docs/up/../escape")
@example("escape_dir/../safe/notes.txt")
def test_traversal_fuzz_never_escapes(
    sandbox: tuple[Path, SandboxFsReadTool], relative_path: str
) -> None:
    _check_read(sandbox, relative_path)


@given(st.text(alphabet=any_char, min_size=1, max_size=30))
def test_arbitrary_unicode_paths_fail_closed(
    sandbox: tuple[Path, SandboxFsReadTool], relative_path: str
) -> None:
    assume("\x00" not in relative_path)
    _check_read(sandbox, relative_path)

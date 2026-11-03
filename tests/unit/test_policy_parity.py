"""Local git hooks and the CI audits enforce one policy (.githooks/_policy.sh).

Each case is run through both the local gate (commit-msg / pre-commit hook) and
its CI counterpart (scripts/audit-attribution.sh / scripts/audit-hygiene.sh) in
a throwaway repository; the verdicts must agree with each other and with the
expected outcome.
"""

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

OWNER = ("mikeZ98", "145975972+mikeZ98@users.noreply.github.com")
FOREIGN = ("root", "root@localhost")

BASH = shutil.which("bash")
GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(BASH is None or GIT is None, reason="needs bash and git")


class Identity(NamedTuple):
    author: tuple[str, str]
    committer: tuple[str, str]


OWNER_ONLY = Identity(OWNER, OWNER)


def _env(home: Path, identity: Identity) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        HOME=str(home),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_NAME=identity.author[0],
        GIT_AUTHOR_EMAIL=identity.author[1],
        GIT_COMMITTER_NAME=identity.committer[0],
        GIT_COMMITTER_EMAIL=identity.committer[1],
    )
    return env


class Sandbox:
    """A throwaway git repository carrying copies of the real hooks and audits."""

    def __init__(self, root: Path, identity: Identity) -> None:
        self.root = root
        self.env = _env(root.parent, identity)
        shutil.copytree(REPO_ROOT / ".githooks", root / ".githooks")
        (root / "scripts").mkdir()
        for script in ("audit-attribution.sh", "audit-hygiene.sh"):
            shutil.copy2(REPO_ROOT / "scripts" / script, root / "scripts" / script)
        self.git("init", "-q", "-b", "main")

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed argv built from trusted literals
            args, cwd=self.root, env=self.env, capture_output=True, text=True, check=False
        )

    def git(self, *args: str) -> None:
        assert GIT is not None
        result = self.run(GIT, *args)
        assert result.returncode == 0, result.stderr

    def bash(self, script: str, *args: str) -> bool:
        assert BASH is not None
        return self.run(BASH, script, *args).returncode == 0


SandboxFactory = Callable[..., Sandbox]


@pytest.fixture
def make_sandbox(tmp_path: Path) -> SandboxFactory:
    def make(identity: Identity = OWNER_ONLY) -> Sandbox:
        return Sandbox(tmp_path / "repo", identity)

    return make


# ---------------------------------------------------------------------------
# Commit identity and message: commit-msg hook  <->  audit-attribution.sh
# ---------------------------------------------------------------------------
MESSAGE_CASES = [
    ("clean", OWNER_ONLY, "feat(core): add a widget", True),
    ("clean with body", OWNER_ONLY, "fix: handle EOF\n\nDetails here.", True),
    ("merge subject", OWNER_ONLY, "Merge branch 'topic'", True),
    ("foreign author", Identity(FOREIGN, OWNER), "feat: x", False),
    ("foreign committer", Identity(OWNER, FOREIGN), "feat: x", False),
    ("owner name, other email", Identity((OWNER[0], "me@example.com"), OWNER), "feat: x", False),
    ("co-author trailer", OWNER_ONLY, "feat: x\n\nCo-authored-by: A <a@b.c>", False),
    (
        "tool banner",
        OWNER_ONLY,
        "feat: x\n\nGenerated with [Some Tool](https://example.com)",
        False,
    ),
    ("robot emoji", OWNER_ONLY, "feat: x\n\n\N{ROBOT FACE} done", False),
    ("not conventional", OWNER_ONLY, "Update stuff", False),
    ("unknown type", OWNER_ONLY, "feature: add x", False),
    ("subject too long", OWNER_ONLY, "feat: " + "x" * 120, False),
]


@pytest.mark.parametrize(
    ("identity", "message", "allowed"),
    [case[1:] for case in MESSAGE_CASES],
    ids=[case[0] for case in MESSAGE_CASES],
)
def test_commit_msg_hook_and_ci_audit_agree(
    make_sandbox: SandboxFactory, identity: Identity, message: str, allowed: bool
) -> None:
    repo = make_sandbox(identity)
    message_file = repo.root.parent / "COMMIT_EDITMSG"
    message_file.write_text(message + "\n", encoding="utf-8")

    hook_allows = repo.bash(".githooks/commit-msg", str(message_file))
    repo.git("commit", "-q", "--allow-empty", "--no-verify", "-F", str(message_file))
    audit_allows = repo.bash("scripts/audit-attribution.sh", "HEAD")

    assert (hook_allows, audit_allows) == (allowed, allowed)


# ---------------------------------------------------------------------------
# Tracked content: pre-commit hook  <->  audit-hygiene.sh
# ---------------------------------------------------------------------------
def _machine_path(root: str) -> str:
    """A sample absolute machine path, assembled so this file never contains one."""
    return "/".join(("", root, "alice", "project"))


HYGIENE_CASES = [
    ("clean file", "notes.txt", "relative/path is fine\n", True),
    ("env example", ".env.example", "MCP_SQL_DSN=\n", True),
    ("macOS user path", "notes.txt", f"see {_machine_path('Users')}\n", False),
    ("external volume path", "notes.txt", f"see {_machine_path('Volumes')}\n", False),
    ("linux home path", "notes.txt", f"see {_machine_path('home')}\n", False),
    ("dotenv file", ".env", "SECRET=1\n", False),
    ("local envrc", ".envrc.local", "export X=1\n", False),
    ("cache file", ".cache/state.json", "{}\n", False),
    ("venv file", ".venv/pyvenv.cfg", "home = x\n", False),
    ("private key", "deploy.key", "key\n", False),
]


@pytest.mark.parametrize(
    ("path", "content", "allowed"),
    [case[1:] for case in HYGIENE_CASES],
    ids=[case[0] for case in HYGIENE_CASES],
)
def test_pre_commit_hook_and_ci_hygiene_audit_agree(
    make_sandbox: SandboxFactory, path: str, content: str, allowed: bool
) -> None:
    repo = make_sandbox()
    target = repo.root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    repo.git("add", "--force", "--", path)

    hook_allows = repo.bash(".githooks/pre-commit")
    audit_allows = repo.bash("scripts/audit-hygiene.sh")

    assert (hook_allows, audit_allows) == (allowed, allowed)


def test_pre_commit_hook_rejects_foreign_identity(make_sandbox: SandboxFactory) -> None:
    repo = make_sandbox(Identity(FOREIGN, FOREIGN))
    (repo.root / "notes.txt").write_text("ok\n", encoding="utf-8")
    repo.git("add", "notes.txt")
    assert not repo.bash(".githooks/pre-commit")


def test_this_repository_passes_its_own_hygiene_audit() -> None:
    # Commit attribution is audited per push/PR range in CI, where HEAD may be
    # GitHub's synthetic merge commit; tracked content is checked here directly.
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - fixed argv
        [BASH, "scripts/audit-hygiene.sh"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# Workflow invariants
# ---------------------------------------------------------------------------
WORKFLOW_TEXT = WORKFLOW.read_text(encoding="utf-8")
USES = re.findall(r"^\s*(?:-\s+)?uses:\s*(.+?)\s*$", WORKFLOW_TEXT, re.MULTILINE)


def test_workflow_pins_every_action_to_a_commit_sha_with_its_tag() -> None:
    assert USES
    pinned = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40} # v\d+(\.\d+)*$")
    assert [use for use in USES if not pinned.match(use)] == []


def test_workflow_uses_the_same_sha_for_each_action() -> None:
    by_action: dict[str, set[str]] = {}
    for use in USES:
        action, _, ref = use.partition("@")
        by_action.setdefault(action, set()).add(ref)
    assert {action: refs for action, refs in by_action.items() if len(refs) > 1} == {}


def test_workflow_grants_read_only_contents_and_nothing_else() -> None:
    assert re.search(r"^permissions:\n  contents: read\n\n", WORKFLOW_TEXT, re.MULTILINE)
    assert WORKFLOW_TEXT.count("permissions:") == 1
    assert ": write" not in WORKFLOW_TEXT


def test_workflow_runs_the_shared_local_gates() -> None:
    for gate in (
        "scripts/audit-attribution.sh",
        "scripts/audit-hygiene.sh",
        "scripts/coverage-gate.sh",
        "scripts/smoke-docker.sh",
        "HYPOTHESIS_PROFILE: ci",
        "mypy src/ tests/ --strict",
        "bandit -c pyproject.toml -r src/",
    ):
        assert gate in WORKFLOW_TEXT, gate


def test_workflow_never_checks_out_with_persisted_credentials() -> None:
    checkouts = WORKFLOW_TEXT.count("uses: actions/checkout@")
    assert checkouts == WORKFLOW_TEXT.count("persist-credentials: false")


def test_workflow_pins_every_runner_to_a_versioned_image() -> None:
    runners = re.findall(r"^\s*runs-on:\s*(\S+)\s*$", WORKFLOW_TEXT, re.MULTILINE)
    assert runners
    assert [runner for runner in runners if not re.fullmatch(r"ubuntu-\d{2}\.\d{2}", runner)] == []

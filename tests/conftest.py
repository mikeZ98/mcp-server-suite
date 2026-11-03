"""Suite-wide hermetic configuration.

* Hypothesis state (example database, observability) lives under ``./.cache/``
  instead of ``./.hypothesis/``; the path is derived from this file's location.
* ``HYPOTHESIS_PROFILE=ci`` selects a deeper, derandomised fuzzing profile.
* Every test starts without ``MCP_*`` variables so the developer's shell cannot
  change results; tests that need configuration set it explicitly.

Network isolation is enforced by ``--disable-socket`` in ``pyproject.toml``.
"""

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings
from hypothesis.configuration import set_hypothesis_home_dir
from hypothesis.database import DirectoryBasedExampleDatabase

REPO_ROOT = Path(__file__).resolve().parent.parent
HYPOTHESIS_HOME = REPO_ROOT / ".cache" / "hypothesis"

set_hypothesis_home_dir(HYPOTHESIS_HOME)
settings.register_profile(
    "default",
    max_examples=200,
    deadline=None,
    database=DirectoryBasedExampleDatabase(HYPOTHESIS_HOME / "examples"),
    suppress_health_check=[HealthCheck.too_slow],
    print_blob=True,
)
settings.register_profile(
    "ci",
    parent=settings.get_profile("default"),
    max_examples=1_000,
    derandomize=True,
    database=None,
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


@pytest.fixture(autouse=True)
def _isolate_mcp_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [key for key in os.environ if key.startswith("MCP_")]:
        monkeypatch.delenv(name)

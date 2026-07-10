"""Tests for the public ``bounty_hunter_toolkit`` API and CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT))

from bounty_hunter_toolkit import (  # noqa: E402
    PatternMatcher,
    main,
)


def run_module(*args: str) -> subprocess.CompletedProcess:
    """Invoke the package as ``python -m bounty_hunter_toolkit`` from the repo root."""
    return subprocess.run(
        [sys.executable, "-m", "bounty_hunter_toolkit", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )


def test_module_imports_pattern_matcher():
    assert PatternMatcher is not None


def test_module_main_reexported():
    assert callable(main)


def test_pattern_matcher_apply(tmp_path):
    matcher = PatternMatcher()
    f = tmp_path / "conf.yaml"
    f.write_text("data = yaml.load(data)")
    assert matcher.apply("yaml_rce", f) == 0
    assert "safe_load" in f.read_text()


def test_cli_list():
    r = run_module("--list")
    assert r.returncode == 0
    assert "sql_injection" in r.stdout
    assert "zero_amount" in r.stdout


def test_cli_find():
    r = run_module("--find", "sql injection")
    assert r.returncode == 0
    assert "sql_injection" in r.stdout


def test_cli_find_no_match():
    r = run_module("--find", "xyzabc123")
    assert r.returncode == 0
    assert r.stdout == ""


def test_cli_apply(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")')
    r = run_module("--apply", "sql_injection", "--file", str(f))
    assert r.returncode == 0
    assert "?" in f.read_text()


def test_cli_unknown_pattern(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("print('hello')")
    r = run_module("--apply", "nonexistent", "--file", str(f))
    assert r.returncode == 1

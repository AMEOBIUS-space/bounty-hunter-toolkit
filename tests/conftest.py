"""Shared pytest fixtures for the Bounty Hunter Toolkit test suite.

These fixtures expose real-world shaped sample API responses so tests can
validate parsing, reporting, and bounty automation logic without hitting live
endpoints.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_json_fixture(name: str) -> dict:
    """Load and return a JSON fixture from ``tests/fixtures/``.

    Args:
        name: Basename of the ``.json`` fixture file.

    Returns:
        The decoded JSON object.

    Raises:
        FileNotFoundError: If the fixture file does not exist.
        json.JSONDecodeError: If the fixture file is not valid JSON.
    """
    path = FIXTURES_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def github_issue_response() -> dict:
    """Sample GitHub Issues API response for a SQL injection bounty report."""
    return _load_json_fixture("github_issue.json")


@pytest.fixture
def hackerone_report_response() -> dict:
    """Sample HackerOne report API response for a reflected XSS finding."""
    return _load_json_fixture("hackerone_report.json")


@pytest.fixture
def bugcrowd_submission_response() -> dict:
    """Sample Bugcrowd submission API response for an IDOR finding."""
    return _load_json_fixture("bugcrowd_submission.json")

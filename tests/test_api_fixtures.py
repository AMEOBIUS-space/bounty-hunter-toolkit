"""Integration tests for sample bug-bounty API response fixtures.

These tests make sure the fixtures shipped in ``tests/fixtures/`` are valid
JSON, contain the expected top-level fields, and can be used to exercise
reporting or recon logic without network access.
"""

from __future__ import annotations


class TestGitHubIssueFixture:
    """Assertions for the GitHub Issues API response fixture."""

    def test_is_open_bounty_issue(self, github_issue_response: dict) -> None:
        """The fixture should be an open issue with a security label."""
        assert github_issue_response["state"] == "open"
        assert github_issue_response["number"] == 1
        label_names = {label["name"] for label in github_issue_response["labels"]}
        assert "security" in label_names
        assert "bounty" in label_names

    def test_contains_vulnerable_code_snippet(self, github_issue_response: dict) -> None:
        """The issue body should mention a vulnerability that has a fix pattern."""
        body = github_issue_response["body"]
        assert "SQL injection" in body
        assert "cursor.execute" in body

    def test_bounty_amount_in_title_or_body(self, github_issue_response: dict) -> None:
        """The fixture should include a bounty value for reporting tests."""
        combined = f"{github_issue_response['title']}\n{github_issue_response['body']}"
        assert "$100" in combined


class TestHackerOneReportFixture:
    """Assertions for the HackerOne report API response fixture."""

    def test_report_state_and_severity(self, hackerone_report_response: dict) -> None:
        """The report should be a new medium-severity XSS finding."""
        attributes = hackerone_report_response["attributes"]
        assert hackerone_report_response["id"].startswith("h1-")
        assert attributes["state"] == "new"
        assert attributes["title"].lower().startswith("reflected xss")
        assert attributes["severity"]["rating"] == "medium"

    def test_reporter_and_program_present(self, hackerone_report_response: dict) -> None:
        """The report should identify the reporter and the target program."""
        attributes = hackerone_report_response["attributes"]
        assert attributes["reporter"]["username"]
        assert attributes["program"]["handle"] == "acme-corp"
        assert "cross_site_scripting" == attributes["bug_type"]

    def test_bounty_amount_present(self, hackerone_report_response: dict) -> None:
        """The report should include a bounty amount and currency."""
        bounty = hackerone_report_response["attributes"]["bounty"]
        assert bounty["amount"] == 250
        assert bounty["currency"] == "USD"


class TestBugcrowdSubmissionFixture:
    """Assertions for the Bugcrowd submission API response fixture."""

    def test_submission_state_and_severity(self, bugcrowd_submission_response: dict) -> None:
        """The submission should be a medium-severity IDOR."""
        submission = bugcrowd_submission_response["submission"]
        assert submission["title"].lower().startswith("insecure direct object reference")
        assert submission["severity_label"] == "medium"
        assert submission["state"] == "not-validated"

    def test_target_and_researcher_present(self, bugcrowd_submission_response: dict) -> None:
        """The submission should describe the target and the researcher."""
        submission = bugcrowd_submission_response["submission"]
        assert submission["target"]["name"] == "api.example.com"
        assert submission["researcher"]["username"]

    def test_reward_information_present(self, bugcrowd_submission_response: dict) -> None:
        """The submission should include a reward amount and currency."""
        submission = bugcrowd_submission_response["submission"]
        assert submission["reward_amount"] == 150
        assert submission["reward_currency"] == "USD"

# tests/test_webhooks.py

"""GitHub webhook route: signature check, event routing, queued analysis.

The analyzer is always mocked, so nothing reaches GitHub or an LLM.
"""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.analysis import ApprovalRecommendation, CodeAnalysisResult, RiskLevel
from app.routes import webhooks

PR_URL = "https://github.com/octo/repo/pull/42"


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def post(client, secret, event, payload, signature=None):
    body = json.dumps(payload).encode()
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
    headers["X-Hub-Signature-256"] = signature if signature is not None else sign(secret, body)
    return client.post("/webhooks/github", content=body, headers=headers)


def pr_payload(action="opened"):
    return {"action": action, "pull_request": {"number": 42, "html_url": PR_URL}}


def make_result() -> CodeAnalysisResult:
    return CodeAnalysisResult(
        pr_number=42,
        pr_title="Fix thing",
        author="octo",
        repository="octo/repo",
        executive_summary="Looks fine.",
        risk_level=RiskLevel.LOW,
        files_changed=1,
        lines_added=3,
        lines_deleted=1,
        approval_recommendation=ApprovalRecommendation.APPROVE,
        analysis_duration_seconds=0.1,
    )


@pytest.fixture
def github(monkeypatch):
    """Mock PyGithub itself, so the real GitHubMCPService runs without a network."""
    monkeypatch.setenv("SKIP_GITHUB_CONNECTION_TEST", "true")
    client = MagicMock()
    monkeypatch.setattr("app.services.github_mcp.Github", MagicMock(return_value=client))
    return client


@pytest.fixture
def analyzer(monkeypatch, github):
    """Replace the analyzer class used by the background task."""
    instance = MagicMock()
    instance.analyze_pr = AsyncMock(return_value=make_result())
    monkeypatch.setattr(webhooks, "CodeAnalyzerService", MagicMock(return_value=instance))
    return instance


class TestSignature:
    def test_valid_signature_accepted(self, client, webhook_secret):
        assert post(client, webhook_secret, "ping", {"zen": "x"}).status_code == 200

    def test_wrong_secret_rejected(self, client, webhook_secret):
        res = post(client, "other-secret", "ping", {"zen": "x"})
        assert res.status_code == 401

    def test_missing_signature_rejected(self, client, webhook_secret):
        res = client.post(
            "/webhooks/github", json={"zen": "x"}, headers={"X-GitHub-Event": "ping"}
        )
        assert res.status_code == 401

    @pytest.mark.parametrize("header", ["garbage", "sha1=abcd", "sha256", "sha256="])
    def test_malformed_signature_rejected(self, client, webhook_secret, header):
        assert post(client, webhook_secret, "ping", {}, signature=header).status_code == 401

    def test_signature_over_a_different_body_rejected(self, client, webhook_secret):
        sig = sign(webhook_secret, b'{"other": true}')
        assert post(client, webhook_secret, "ping", {"zen": "x"}, signature=sig).status_code == 401

    def test_unit_verify(self, webhook_secret):
        body = b"abc"
        assert webhooks.verify_github_signature(body, sign(webhook_secret, body))
        assert not webhooks.verify_github_signature(body, "sha256=00")
        assert not webhooks.verify_github_signature(body, "")


class TestEvents:
    def test_ping(self, client, webhook_secret):
        res = post(client, webhook_secret, "ping", {"zen": "x"})
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

    @pytest.mark.parametrize("event", ["push", "issues", "issue_comment"])
    def test_other_events_ignored(self, client, webhook_secret, analyzer, event):
        res = post(client, webhook_secret, event, {"action": "opened"})
        assert res.status_code == 200
        assert res.json()["status"] == "ignored"
        analyzer.analyze_pr.assert_not_called()

    def test_invalid_json_body_is_400(self, client, webhook_secret):
        body = b"not json"
        res = client.post(
            "/webhooks/github",
            content=body,
            headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": sign(webhook_secret, body)},
        )
        assert res.status_code == 400


class TestPullRequest:
    @pytest.mark.parametrize("action", ["opened", "synchronize", "reopened"])
    def test_trigger_actions_queue_analysis(self, client, webhook_secret, analyzer, action):
        res = post(client, webhook_secret, "pull_request", pr_payload(action))
        assert res.status_code == 200
        assert res.json()["status"] == "queued"
        assert res.json()["pr_url"] == PR_URL
        # TestClient runs background tasks before returning
        analyzer.analyze_pr.assert_awaited_once_with(PR_URL)

    @pytest.mark.parametrize("action", ["closed", "labeled", "edited", "assigned"])
    def test_other_actions_not_analyzed(self, client, webhook_secret, analyzer, action):
        res = post(client, webhook_secret, "pull_request", pr_payload(action))
        assert res.status_code == 200
        assert res.json()["status"] == "ignored"
        analyzer.analyze_pr.assert_not_called()

    def test_missing_pr_url_is_400(self, client, webhook_secret, analyzer):
        payload = {"action": "opened", "pull_request": {"number": 1}}
        assert post(client, webhook_secret, "pull_request", payload).status_code == 400
        analyzer.analyze_pr.assert_not_called()

    def test_background_failure_does_not_fail_the_webhook(self, client, webhook_secret, analyzer):
        analyzer.analyze_pr.side_effect = RuntimeError("llm down")
        res = post(client, webhook_secret, "pull_request", pr_payload())
        assert res.status_code == 200
        assert res.json()["status"] == "queued"


class TestPostsComment:
    @staticmethod
    def comments(github):
        return github.get_repo.return_value.get_issue.return_value.create_comment

    def test_posts_exactly_one_summary_comment(self, client, webhook_secret, analyzer, github):
        res = post(client, webhook_secret, "pull_request", pr_payload())
        assert res.status_code == 200
        github.get_repo.assert_called_once_with("octo/repo")
        github.get_repo.return_value.get_issue.assert_called_once_with(42)
        self.comments(github).assert_called_once()
        body = self.comments(github).call_args.args[0]
        assert body == webhooks.SummaryFormatter.format_for_github_comment(make_result())

    def test_posting_failure_is_handled_and_not_leaked(
        self, client, webhook_secret, analyzer, github, caplog
    ):
        self.comments(github).side_effect = RuntimeError("boom ghp_SECRETTOKEN")
        res = post(client, webhook_secret, "pull_request", pr_payload())
        assert res.status_code == 200
        assert res.json()["status"] == "queued"
        self.comments(github).assert_called_once()
        assert "Failed to post" in caplog.text
        assert "ghp_SECRETTOKEN" not in caplog.text

    def test_no_comment_when_analysis_fails(self, client, webhook_secret, analyzer, github):
        analyzer.analyze_pr.side_effect = RuntimeError("llm down")
        post(client, webhook_secret, "pull_request", pr_payload())
        self.comments(github).assert_not_called()


class TestCommentGating:
    @staticmethod
    def comments(github):
        return github.get_repo.return_value.get_issue.return_value.create_comment

    def test_empty_secret_reviews_but_does_not_comment(
        self, client, monkeypatch, analyzer, github, caplog
    ):
        monkeypatch.setattr(webhooks.settings, "GITHUB_WEBHOOK_SECRET", "")
        monkeypatch.setattr(webhooks, "_warned_unsigned", False)
        for _ in range(2):  # unsigned, forged-looking request
            res = post(client, "", "pull_request", pr_payload(), signature="sha256=bogus")
            assert res.status_code == 200
        assert analyzer.analyze_pr.await_count == 2
        github.get_repo.assert_not_called()
        self.comments(github).assert_not_called()
        assert caplog.text.count("PR comments are not posted") == 1  # warned once

    def test_valid_signature_with_secret_posts_one_comment(
        self, client, webhook_secret, analyzer, github
    ):
        res = post(client, webhook_secret, "pull_request", pr_payload())
        assert res.status_code == 200
        self.comments(github).assert_called_once()

    def test_oversized_comment_is_truncated(self, client, webhook_secret, analyzer, github, monkeypatch):
        monkeypatch.setattr(
            webhooks.SummaryFormatter, "format_for_github_comment", classmethod(lambda cls, a: "x" * 100000)
        )
        post(client, webhook_secret, "pull_request", pr_payload())
        body = self.comments(github).call_args.args[0]
        assert len(body) <= webhooks.MAX_COMMENT_CHARS < 65536
        assert body.endswith(webhooks.TRUNCATION_NOTE)

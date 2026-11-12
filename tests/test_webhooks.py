# tests/test_webhooks.py

"""GitHub webhook route: signature check, event routing, queued analysis.

The analyzer is always mocked, so nothing reaches GitHub or an LLM.
"""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

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


@pytest.fixture
def analyzer(monkeypatch):
    """Replace the analyzer class used by the background task."""
    instance = MagicMock()
    instance.analyze_pr = AsyncMock()
    instance.analyze_pr.return_value.risk_level.value = "low"
    instance.analyze_pr.return_value.approval_recommendation.value = "approve"
    instance.analyze_pr.return_value.security_findings = []
    instance.analyze_pr.return_value.performance_findings = []
    instance.analyze_pr.return_value.best_practice_findings = []
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

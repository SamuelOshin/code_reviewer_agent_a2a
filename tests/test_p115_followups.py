"""P1-15: review follow-ups from the P1-04 to P1-07 reviews.

One group per item. Nothing here touches the network or a real model.
"""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError
from pydantic_ai.exceptions import ModelHTTPError

from app.core import push_url
from app.core.config import MIN_WEBHOOK_SECRET_LENGTH, Settings
from app.core.errors import RequestTimeoutError
from app.core.push_url import PushUrlRejected, validate_push_url
from app.llm.errors import LLMConfigurationError
from app.llm.pydantic_ai_client import map_error
from app.models.analysis import AnalysisStatus, ApprovalRecommendation
from app.routes import webhooks
from app.services.github_mcp import GitHubMCPError, GitHubMCPService
from app.services.jsonrpc_handler import JSONRPCHandler
from app.services.message_handler import MessageHandler
from tests.test_code_analyzer import make_analyzer, run
from tests.test_webhooks import PR_URL, analyzer, github, pr_payload, sign  # noqa: F401  (fixtures)

GOOD_SECRET = "s" * MIN_WEBHOOK_SECRET_LENGTH
KEY = "k" * 32


def make_settings(**overrides):
    env = {"GITHUB_TOKEN": "x", "GITHUB_WEBHOOK_SECRET": GOOD_SECRET, "API_KEY": KEY}
    env.update(overrides)
    return Settings(_env_file=None, **env)


# --- 1. replayed webhook deliveries ---------------------------------------------------


class TestReplayedDelivery:
    @staticmethod
    def send(client, secret, delivery):
        body = json.dumps(pr_payload()).encode()
        headers = {
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": sign(secret, body),
            "Content-Type": "application/json",
        }
        if delivery:
            headers["X-GitHub-Delivery"] = delivery
        return client.post("/webhooks/github", content=body, headers=headers)

    @pytest.fixture(autouse=True)
    def fresh_cache(self, monkeypatch):
        monkeypatch.setattr(webhooks, "delivery_cache", webhooks.DeliveryCache())

    def test_replayed_delivery_posts_once_with_a_2xx(self, client, webhook_secret, analyzer, github):  # noqa: F811
        first = self.send(client, webhook_secret, "d-1")
        second = self.send(client, webhook_secret, "d-1")
        assert first.status_code == 200 and first.json()["status"] == "queued"
        assert second.status_code == 200 and second.json()["status"] == "duplicate"
        assert analyzer.analyze_pr.await_count == 1
        assert github.get_repo.return_value.get_issue.return_value.create_comment.call_count == 1

    def test_different_delivery_ids_both_run(self, client, webhook_secret, analyzer, github):  # noqa: F811
        self.send(client, webhook_secret, "d-1")
        self.send(client, webhook_secret, "d-2")
        assert analyzer.analyze_pr.await_count == 2

    def test_forged_request_cannot_claim_an_id(self, client, webhook_secret, analyzer, github):  # noqa: F811
        bad = self.send(client, "wrong-secret", "d-1")
        assert bad.status_code == 401
        assert self.send(client, webhook_secret, "d-1").json()["status"] == "queued"

    def test_rejected_payload_does_not_burn_the_id(self, client, webhook_secret, analyzer, github):  # noqa: F811
        payload = {"action": "opened", "pull_request": {"number": 1}}  # no html_url
        body = json.dumps(payload).encode()
        headers = {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "d-9",
                   "X-Hub-Signature-256": sign(webhook_secret, body)}
        assert client.post("/webhooks/github", content=body, headers=headers).status_code == 400
        assert self.send(client, webhook_secret, "d-9").json()["status"] == "queued"

    def test_cache_expires_and_is_bounded(self, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr(webhooks.time, "monotonic", lambda: now[0])
        cache = webhooks.DeliveryCache(ttl_seconds=10, max_entries=2)
        assert not cache.seen_before("a")
        assert cache.seen_before("a")
        now[0] += 11
        assert not cache.seen_before("a")  # expired
        cache.seen_before("b")
        cache.seen_before("c")  # evicts the oldest ("a")
        assert len(cache._seen) <= 2
        assert not cache.seen_before("a")


# --- 2. blocking message/send timeout -------------------------------------------------


class TestBlockingTimeout:
    @staticmethod
    def handler():
        h = MessageHandler.__new__(MessageHandler)
        h.analyzer = MagicMock()
        h._background_tasks = set()
        return h

    @staticmethod
    def message():
        return {"kind": "message", "role": "user", "messageId": "m1",
                "parts": [{"kind": "text", "text": f"review {PR_URL}"}]}

    @pytest.mark.asyncio
    async def test_slow_review_times_out_with_a_clear_error(self, monkeypatch):
        monkeypatch.setattr("app.services.message_handler.settings.A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)
        h = self.handler()

        async def slow(*args, **kwargs):
            await asyncio.sleep(5)

        h._analyze_and_return = slow
        with pytest.raises(RequestTimeoutError, match="did not finish within"):
            await h.handle_message_send(self.message(), {"blocking": True})

    @pytest.mark.asyncio
    async def test_json_rpc_layer_returns_a_timeout_error_not_internal(self, monkeypatch):
        rpc = JSONRPCHandler()

        async def method():
            raise RequestTimeoutError("took too long")

        rpc.register_method("slow", method)
        res = await rpc.handle_request({"jsonrpc": "2.0", "method": "slow", "id": 1})
        assert res["error"]["code"] == -32004
        assert res["error"]["message"] == "took too long"

    @pytest.mark.asyncio
    async def test_fast_review_is_unaffected(self, monkeypatch):
        h = self.handler()
        h._analyze_and_return = AsyncMock(return_value={"kind": "task"})
        assert await h.handle_message_send(self.message(), None) == {"kind": "task"}

    def test_setting_default_and_validator(self):
        assert make_settings().A2A_BLOCKING_TIMEOUT_SECONDS == 300.0
        for bad in (0, -1, 3601):
            with pytest.raises(ValidationError, match="A2A_BLOCKING_TIMEOUT_SECONDS"):
                make_settings(A2A_BLOCKING_TIMEOUT_SECONDS=bad)


# --- 3. parse_pr_url ASCII digits ----------------------------------------------------


class TestParsePrUrl:
    @pytest.fixture
    def service(self, github):  # noqa: F811
        return GitHubMCPService()

    def test_ascii_number_parses(self, service):
        assert service.parse_pr_url("https://github.com/o/r/pull/123") == ("o", "r", 123)

    @pytest.mark.parametrize("digits", ["١٢٣", "１２３", "१२३"])  # Arabic-Indic, fullwidth, Devanagari
    def test_non_ascii_digits_are_rejected(self, service, digits):
        with pytest.raises(GitHubMCPError):
            service.parse_pr_url(f"https://github.com/o/r/pull/{digits}")

    def test_a2a_extraction_ignores_non_ascii_digit_urls(self):
        h = MessageHandler.__new__(MessageHandler)
        assert h._extract_pr_url("see https://github.com/o/r/pull/١٢٣", []) is None


# --- 4. Google 404 -------------------------------------------------------------------


class TestNotFoundMapping:
    @pytest.mark.parametrize("body", [None, {}, {"error": {"code": 404, "message": "x"}}])
    def test_any_404_is_a_configuration_error(self, body):
        # A generic ModelHTTPError (no NOT_FOUND status in the body) still maps
        err = ModelHTTPError(status_code=404, model_name="m", body=body)
        assert isinstance(map_error(err, "google:m"), LLMConfigurationError)

    def test_other_statuses_are_not_configuration_errors(self):
        err = ModelHTTPError(status_code=418, model_name="m", body=None)
        assert not isinstance(map_error(err), LLMConfigurationError)


# --- 5. model per role in the result -------------------------------------------------


class TestModelsByRole:
    @pytest.mark.asyncio
    async def test_result_records_each_role_model(self):
        analyzer_, gh, llm = make_analyzer()
        llm.models_by_role = MagicMock(return_value={
            "security": "anthropic:a", "performance": "google:b",
            "best_practices": "google:b", "summary": "openai:c"})
        result = await run(analyzer_, gh)
        assert result.llm_models_by_role["security"] == "anthropic:a"
        assert result.llm_models_by_role["summary"] == "openai:c"

    def test_service_reports_the_client_model_per_role(self):
        from app.llm import Role
        from app.services.llm_service import LLMService

        client = MagicMock()
        client.model_name.side_effect = lambda role: f"p:{role}"
        assert LLMService(client=client).models_by_role() == {str(r): f"p:{r}" for r in Role}


# --- 6. status in A2A report and RPC result ------------------------------------------


class TestStatusReported:
    @pytest.mark.asyncio
    async def test_a2a_report_shows_status_and_reasons(self):
        analyzer_, gh, llm = make_analyzer()
        llm.analyze_security = AsyncMock(side_effect=RuntimeError("secret model text"))
        result = await run(analyzer_, gh)
        assert result.status == AnalysisStatus.INCOMPLETE
        text = MessageHandler.__new__(MessageHandler)._format_analysis_as_text(result, PR_URL)
        assert "**Status**: INCOMPLETE" in text
        assert "Security analysis failed (RuntimeError)" in text
        assert "secret model text" not in text
        assert result.approval_recommendation != ApprovalRecommendation.APPROVE

    @pytest.mark.asyncio
    async def test_complete_review_shows_status_without_reasons(self):
        analyzer_, gh, _ = make_analyzer()
        result = await run(analyzer_, gh)
        text = MessageHandler.__new__(MessageHandler)._format_analysis_as_text(result, PR_URL)
        assert "**Status**: COMPLETE" in text
        assert "not complete" not in text

    @pytest.mark.asyncio
    async def test_analyze_pr_rpc_result_has_status_and_reasons(self, monkeypatch):
        import app.main as main

        analyzer_, gh, llm = make_analyzer()
        llm.analyze_performance = AsyncMock(side_effect=RuntimeError("x"))
        result = await run(analyzer_, gh)
        monkeypatch.setattr(
            main.app.state, "code_analyzer",
            SimpleNamespace(analyze_pr=AsyncMock(return_value=result)), raising=False)
        out = await main.handle_analyze_pr(PR_URL)
        assert out["analysis_status"] == "incomplete"
        assert out["incomplete_reasons"] == result.incomplete_reasons
        assert "llm_models_by_role" in out
        # "status" would make the RPC layer stamp kind=task on a non-task result
        assert "status" not in out


# --- 7. push URL: embedded IPv4 and ports --------------------------------------------


class TestPushUrlHardening:
    @pytest.fixture(autouse=True)
    def allowed(self, monkeypatch):
        monkeypatch.setattr(push_url.settings, "PUSH_URL_ALLOWED_HOSTS", "hooks.example.com")
        monkeypatch.setattr(push_url.settings, "PUSH_URL_ALLOWED_PORTS", "")

        async def resolve(host, port):
            return ["8.8.8.8"]

        monkeypatch.setattr(push_url, "_resolve", resolve)

    @pytest.mark.parametrize(
        "address",
        ["::7f00:1", "::127.0.0.1", "::a00:1", "::c0a8:1", "::a9fe:a9fe",
         "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe", "::", "::1"],
    )
    def test_embedded_private_ipv4_is_not_public(self, address):
        import ipaddress

        assert push_url._is_public(ipaddress.ip_address(address)) is False

    @pytest.mark.parametrize("address", ["64:ff9b::808:808", "::ffff:8.8.8.8", "2606:4700::1"])
    def test_embedded_public_ipv4_stays_public(self, address):
        import ipaddress

        assert push_url._is_public(ipaddress.ip_address(address)) is True

    @pytest.mark.asyncio
    async def test_resolved_nat64_loopback_is_rejected(self, monkeypatch):
        async def resolve(host, port):
            return ["64:ff9b::7f00:1"]

        monkeypatch.setattr(push_url, "_resolve", resolve)
        with pytest.raises(PushUrlRejected, match="non-public"):
            await validate_push_url("https://hooks.example.com/x")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("port", [80, 8080, 22, 6379, 0])
    async def test_other_ports_are_rejected_by_default(self, port):
        with pytest.raises(PushUrlRejected, match="port"):
            await validate_push_url(f"https://hooks.example.com:{port}/x")

    @pytest.mark.asyncio
    async def test_default_and_explicit_443_are_accepted(self):
        await validate_push_url("https://hooks.example.com/x")
        await validate_push_url("https://hooks.example.com:443/x")

    @pytest.mark.asyncio
    async def test_configured_port_is_accepted(self, monkeypatch):
        monkeypatch.setattr(push_url.settings, "PUSH_URL_ALLOWED_PORTS", "8443")
        await validate_push_url("https://hooks.example.com:8443/x")
        with pytest.raises(PushUrlRejected, match="port"):
            await validate_push_url("https://hooks.example.com:9443/x")

    @pytest.mark.parametrize("value", ["abc", "0", "65536", "-1", "443,x", "٤٤٣"])
    def test_bad_port_setting_is_refused(self, value):
        with pytest.raises(ValidationError, match="PUSH_URL_ALLOWED_PORTS"):
            make_settings(PUSH_URL_ALLOWED_PORTS=value)

    def test_port_setting_parsing(self):
        assert make_settings().push_url_allowed_ports == {443}
        assert make_settings(PUSH_URL_ALLOWED_PORTS="8443, 9443").push_url_allowed_ports == {
            443, 8443, 9443}


# --- 8. webhook secret length --------------------------------------------------------


class TestWebhookSecretLength:
    @pytest.mark.parametrize("n", [1, 5, MIN_WEBHOOK_SECRET_LENGTH - 1])
    def test_short_secret_is_refused(self, n):
        with pytest.raises(ValidationError, match="at least 32 characters"):
            make_settings(GITHUB_WEBHOOK_SECRET="s" * n)

    def test_minimum_length_is_accepted(self):
        assert make_settings(GITHUB_WEBHOOK_SECRET="s" * MIN_WEBHOOK_SECRET_LENGTH)

    def test_ci_and_test_dummies_pass_the_check(self):
        import os
        import re
        from pathlib import Path

        ci = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
        value = re.search(r"GITHUB_WEBHOOK_SECRET:\s*(\S+)", ci.read_text(encoding="utf-8")).group(1)
        assert make_settings(GITHUB_WEBHOOK_SECRET=value)
        assert make_settings(GITHUB_WEBHOOK_SECRET=os.environ["GITHUB_WEBHOOK_SECRET"])


# --- 9. CORS origin case -------------------------------------------------------------


class TestCorsOriginCase:
    def test_mixed_case_origin_is_lowercased(self):
        s = make_settings(CORS_ALLOWED_ORIGINS="HTTPS://App.Example.COM, http://Localhost:3000")
        assert s.cors_allowed_origins == ["https://app.example.com", "http://localhost:3000"]


# --- 10. empty batch -----------------------------------------------------------------


class TestEmptyBatch:
    def test_empty_batch_is_invalid_request(self, client):
        res = client.post("/rpc", json=[])
        assert res.status_code == 200
        body = res.json()
        assert body == {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"},
                        "id": None}

    def test_non_empty_batch_still_works(self, client):
        res = client.post("/rpc", json=[{"jsonrpc": "2.0", "method": "add",
                                         "params": {"a": 1, "b": 2}, "id": 1}])
        assert res.json()[0]["result"] == {"sum": 3}

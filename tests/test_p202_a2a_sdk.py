# tests/test_p202_a2a_sdk.py

"""P2-02: A2A v1.0 protocol layer using the official `a2a-sdk` client and types.

Exercises discovery via `A2ACardResolver`, authentication via `AuthInterceptor` and
`bearerAuth` from the agent card, and end-to-end PR reviews through the real FastAPI
app, `MessageHandler`, `CodeAnalyzerService`, and `LLMService` with a fake LLMClient
and stubbed GitHub service (no real network calls).
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from a2a.client import (
    A2ACardResolver,
    A2AClientError,
    ClientCallContext,
    ClientConfig,
    create_client,
)
from a2a.client.auth import AuthInterceptor, InMemoryContextCredentialStore
from a2a.helpers.proto_helpers import get_artifact_text
from a2a.types import (
    InvalidParamsError,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    TaskPushNotificationConfig,
    TaskState,
    UnsupportedOperationError,
)
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
from a2a.utils.proto_utils import warn_on_missing_required_fields
from fastapi.testclient import TestClient
from google.protobuf.json_format import MessageToDict

from app.core.exceptions import GitHubMCPError
from app.llm import Role as LLMRole
from app.llm.errors import LLMOutputError
from app.main import app
from app.models.analysis import (
    BestPracticesReport,
    PerformanceReport,
    SecurityReport,
)
from app.models.github import PullRequestDiff
from app.services.code_analyzer import CodeAnalyzerService
from app.services.llm_service import LLMService
from tests.conftest import API_KEY, AUTH_HEADERS
from tests.test_code_analyzer import SAFE_DIFF, SAMPLE_PR
from tests.test_p201_structured_output import make_client

BASE_URL = "http://testserver"
PR_URL = "https://github.com/test/repo/pull/123"


def _fake_github() -> MagicMock:
    github = MagicMock()
    github.parse_pr_url = MagicMock(return_value=("test", "repo", 123))
    github.get_pr_with_diff = AsyncMock(
        return_value=(SAMPLE_PR, PullRequestDiff(pr_number=123, raw_diff=SAFE_DIFF, files=[]))
    )
    github.__aenter__ = AsyncMock(return_value=github)
    github.__aexit__ = AsyncMock(return_value=None)
    return github


def _analyzer_with_fake_llm(role_outputs: dict[LLMRole, object]) -> CodeAnalyzerService:
    llm_service = LLMService(client=make_client(role_outputs))
    with patch("app.services.code_analyzer.LLMService", return_value=llm_service):
        return CodeAnalyzerService()


@asynccontextmanager
async def _sdk_client(authenticated: bool = True):
    """Boot the real FastAPI app lifespan and yield `(a2a_client, call_context)`."""
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
            timeout=10.0,
        ) as http_client:
            interceptors = []
            call_context = None
            if authenticated:
                store = InMemoryContextCredentialStore()
                await store.set_credentials("test-session", "bearerAuth", API_KEY)
                interceptors = [AuthInterceptor(store)]
                call_context = ClientCallContext(state={"sessionId": "test-session"})

            a2a_client = await create_client(
                BASE_URL,
                client_config=ClientConfig(httpx_client=http_client, streaming=False),
                interceptors=interceptors,
            )
            try:
                yield a2a_client, call_context
            finally:
                await a2a_client.close()


def _user_request(
    text: str,
    configuration: SendMessageConfiguration | None = None,
) -> SendMessageRequest:
    kwargs: dict[str, object] = {
        "message": Message(
            message_id="msg-sdk-1",
            role=Role.ROLE_USER,
            parts=[Part(text=text)],
        )
    }
    if configuration is not None:
        kwargs["configuration"] = configuration
    return SendMessageRequest(**kwargs)  # type: ignore[arg-type]


async def _send_single(a2a_client, req: SendMessageRequest, context=None):
    responses = [resp async for resp in a2a_client.send_message(req, context=context)]
    assert len(responses) == 1
    return responses[0]


# ---------------------------------------------------------------------------
# Discovery and AgentCard v1.0 contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [None, "/.well-known/agent.json"])
async def test_agent_card_discovery_and_v1_schema(path):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=BASE_URL,
    ) as http_client:
        resolver = A2ACardResolver(http_client, BASE_URL)
        card = await resolver.get_agent_card(relative_card_path=path)

    assert warn_on_missing_required_fields(card, "agent_card") is True
    assert card.name == "PRRover Code Review Agent"
    assert card.version == "1.0.0"
    assert len(card.supported_interfaces) == 1
    iface = card.supported_interfaces[0]
    assert iface.protocol_binding == "JSONRPC"
    assert iface.protocol_version == "1.0"
    assert iface.url == f"{BASE_URL}/a2a/tasks"

    assert len(card.skills) >= 1
    assert card.skills[0].id == "analyze_pr"
    assert list(card.skills[0].examples)
    assert all(isinstance(ex, str) for ex in card.skills[0].examples)

    assert "bearerAuth" in card.security_schemes
    scheme = card.security_schemes["bearerAuth"].http_auth_security_scheme
    assert scheme.scheme == "bearer"
    assert any("bearerAuth" in req.schemes for req in card.security_requirements)


# ---------------------------------------------------------------------------
# Auth enforcement via real a2a-sdk client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_a2a_sdk_client_is_rejected():
    async with _sdk_client(authenticated=False) as (a2a_client, ctx):
        with pytest.raises(A2AClientError, match="401"):
            await _send_single(
                a2a_client,
                _user_request("Hello without key"),
                context=ctx,
            )


# ---------------------------------------------------------------------------
# Acceptance check: real a2a-sdk client end-to-end review
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_to_end_review_via_a2a_sdk_client():
    fake_outputs = {
        LLMRole.SECURITY: SecurityReport(findings=[]),
        LLMRole.PERFORMANCE: PerformanceReport(findings=[]),
        LLMRole.BEST_PRACTICES: BestPracticesReport(findings=[]),
        LLMRole.SUMMARY: "Clean change that safely formats user names.",
    }
    github = _fake_github()

    async with _sdk_client(authenticated=True) as (a2a_client, ctx):
        app.state.message_handler.analyzer = _analyzer_with_fake_llm(fake_outputs)
        with patch("app.services.code_analyzer.GitHubMCPService", return_value=github):
            resp = await _send_single(
                a2a_client,
                _user_request(f"Please review {PR_URL}"),
                context=ctx,
            )

    assert resp.HasField("task")
    task = resp.task
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    assert len(task.artifacts) == 1

    artifact_text = get_artifact_text(task.artifacts[0])
    assert "**Status**: COMPLETE" in artifact_text
    assert "**Recommendation**: APPROVE" in artifact_text
    assert "PR #123" in artifact_text
    assert "Clean change that safely formats user names." in artifact_text

    task_meta = MessageToDict(task.metadata)
    artifact_meta = MessageToDict(task.artifacts[0].metadata)
    assert task_meta["analysis_status"] == "complete"
    assert task_meta["incomplete_reasons"] == []
    assert task_meta["approval_recommendation"] == "approve"
    assert artifact_meta == task_meta


# ---------------------------------------------------------------------------
# Fail-closed preservation through A2A v1.0
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fail_closed_incomplete_review_never_approves(caplog):
    caplog.set_level(logging.DEBUG)
    sentinel = "SENTINEL-P202-RAW-MODEL-TEXT"
    fake_outputs = {
        LLMRole.SECURITY: RuntimeError(f"bad model json {sentinel}"),
        LLMRole.PERFORMANCE: PerformanceReport(findings=[]),
        LLMRole.BEST_PRACTICES: BestPracticesReport(findings=[]),
        LLMRole.SUMMARY: "Partial summary.",
    }
    github = _fake_github()

    async with _sdk_client(authenticated=True) as (a2a_client, ctx):
        app.state.message_handler.analyzer = _analyzer_with_fake_llm(fake_outputs)
        with patch("app.services.code_analyzer.GitHubMCPService", return_value=github):
            resp = await _send_single(
                a2a_client,
                _user_request(f"Analyze {PR_URL}"),
                context=ctx,
            )

    task = resp.task
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    artifact_text = get_artifact_text(task.artifacts[0])
    assert "**Status**: INCOMPLETE" in artifact_text
    assert "**Recommendation**: INCOMPLETE" in artifact_text
    assert "APPROVE" not in artifact_text

    task_meta = MessageToDict(task.metadata)
    assert task_meta["analysis_status"] == "incomplete"
    assert task_meta["approval_recommendation"] == "incomplete"
    assert len(task_meta["incomplete_reasons"]) >= 1
    assert sentinel not in artifact_text
    assert sentinel not in str(task_meta)
    assert sentinel not in caplog.text


@pytest.mark.asyncio
async def test_fail_closed_all_steps_failed_status_is_failed(caplog):
    caplog.set_level(logging.DEBUG)
    sentinel = "SENTINEL-P202-ALL-FAILED"
    boom = RuntimeError(sentinel)
    fake_outputs = {
        LLMRole.SECURITY: boom,
        LLMRole.PERFORMANCE: LLMOutputError("output validation failed"),
        LLMRole.BEST_PRACTICES: boom,
        LLMRole.SUMMARY: "Summary.",
    }
    github = _fake_github()

    async with _sdk_client(authenticated=True) as (a2a_client, ctx):
        app.state.message_handler.analyzer = _analyzer_with_fake_llm(fake_outputs)
        with patch("app.services.code_analyzer.GitHubMCPService", return_value=github):
            resp = await _send_single(
                a2a_client,
                _user_request(f"Review {PR_URL}"),
                context=ctx,
            )

    task = resp.task
    artifact_text = get_artifact_text(task.artifacts[0])
    assert "**Status**: FAILED" in artifact_text
    assert "**Recommendation**: INCOMPLETE" in artifact_text
    assert "APPROVE" not in artifact_text

    task_meta = MessageToDict(task.metadata)
    assert task_meta["analysis_status"] == "failed"
    assert task_meta["approval_recommendation"] == "incomplete"
    assert len(task_meta["incomplete_reasons"]) == 3
    assert sentinel not in artifact_text
    assert sentinel not in caplog.text


@pytest.mark.asyncio
async def test_github_failure_returns_failed_task_without_leaking_body(caplog):
    caplog.set_level(logging.DEBUG)
    sentinel = "SENTINEL-GH-UPSTREAM-BODY"
    github = _fake_github()
    github.get_pr_with_diff = AsyncMock(side_effect=GitHubMCPError(f"upstream {sentinel}"))

    async with _sdk_client(authenticated=True) as (a2a_client, ctx):
        with patch("app.services.code_analyzer.GitHubMCPService", return_value=github):
            resp = await _send_single(
                a2a_client,
                _user_request(f"Review {PR_URL}"),
                context=ctx,
            )

    assert resp.HasField("task")
    task = resp.task
    assert task.status.state == TaskState.TASK_STATE_FAILED
    assert not task.artifacts
    msg_text = "\n".join(p.text for p in task.status.message.parts)
    assert "Unable to Access Pull Request" in msg_text
    assert "Error id:" in msg_text
    assert sentinel not in msg_text
    assert sentinel not in caplog.text


# ---------------------------------------------------------------------------
# Input-required, push guard, timeout, and notification rules for SendMessage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_input_required_without_pr_url_via_a2a_sdk_client():
    async with _sdk_client(authenticated=True) as (a2a_client, ctx):
        resp = await _send_single(
            a2a_client,
            _user_request("Hello, can you help me review a change?"),
            context=ctx,
        )

    assert resp.HasField("task")
    assert resp.task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    assert len(resp.task.artifacts) == 0
    assert "Pull Request URL" in resp.task.status.message.parts[0].text


@pytest.mark.asyncio
async def test_push_url_guard_rejects_private_url_in_v1_send_message(monkeypatch):
    from app.core import push_url

    monkeypatch.setattr(push_url.settings, "PUSH_URL_ALLOWED_HOSTS", "hooks.example.com")

    async def resolve(host, port):
        return ["169.254.169.254"]

    monkeypatch.setattr(push_url, "_resolve", resolve)

    async with _sdk_client(authenticated=True) as (a2a_client, ctx):
        # Private/metadata DNS resolution is rejected with -32602 without echoing path
        req_ssrf = _user_request(
            f"Review {PR_URL}",
            configuration=SendMessageConfiguration(
                return_immediately=True,
                task_push_notification_config=TaskPushNotificationConfig(
                    url="https://hooks.example.com/SENTINEL-SECRET-HOOK",
                ),
            ),
        )
        with pytest.raises(InvalidParamsError) as exc_info:
            await _send_single(a2a_client, req_ssrf, context=ctx)
        assert "non-public" in str(exc_info.value)
        assert "SENTINEL-SECRET-HOOK" not in str(exc_info.value)

        # Non-allowlisted host / loopback is also rejected with -32602
        req_loopback = _user_request(
            f"Review {PR_URL}",
            configuration=SendMessageConfiguration(
                return_immediately=True,
                task_push_notification_config=TaskPushNotificationConfig(
                    url="https://127.0.0.1/hook",
                ),
            ),
        )
        with pytest.raises(InvalidParamsError) as exc_loop:
            await _send_single(a2a_client, req_loopback, context=ctx)
        assert "allowlist" in str(exc_loop.value)


@pytest.mark.asyncio
async def test_blocking_timeout_in_v1_send_message(monkeypatch):
    from app.core import config

    monkeypatch.setattr(config.settings, "A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)
    github = _fake_github()

    async def slow_fetch(*args, **kwargs):
        await asyncio.sleep(1.0)
        return (SAMPLE_PR, PullRequestDiff(pr_number=123, raw_diff=SAFE_DIFF, files=[]))

    github.get_pr_with_diff = AsyncMock(side_effect=slow_fetch)

    async with _sdk_client(authenticated=True) as (a2a_client, ctx):
        with patch("app.services.code_analyzer.GitHubMCPService", return_value=github):
            with pytest.raises(UnsupportedOperationError, match="did not finish within"):
                await _send_single(
                    a2a_client,
                    _user_request(f"Review {PR_URL}"),
                    context=ctx,
                )


def test_send_message_notification_and_discovery_routes():
    with TestClient(app, headers=AUTH_HEADERS) as client:
        # introspect exposes v1.0 SendMessage alongside v0.3 message/send
        intro = client.post(
            "/rpc", json={"jsonrpc": "2.0", "method": "introspect", "id": 1}
        ).json()["result"]
        assert {"SendMessage", "message/send", "analyze_pr", "introspect"} <= set(intro["methods"])

        # root points to the standard v1.0 agent card well-known path
        root = client.get("/").json()
        assert root["endpoints"]["agent_card"] == AGENT_CARD_WELL_KNOWN_PATH
        assert root["protocols"]["a2a"] == "1.0"

        # blocking id-less SendMessage notification is rejected with -32600
        rejected = client.post(
            "/a2a/tasks",
            json={
                "jsonrpc": "2.0",
                "method": "SendMessage",
                "params": {"message": {"parts": [{"text": f"review {PR_URL}"}]}},
            },
        )
        assert rejected.status_code == 200
        err = rejected.json()["error"]
        assert err["code"] == -32600
        assert "returnImmediately" in err["message"]
        assert "taskPushNotificationConfig" in err["message"]

        # non-blocking id-less SendMessage with push config runs as a 204 notification
        with patch.object(
            app.state.message_handler, "_process_and_push_safe", new=AsyncMock()
        ), patch("app.services.message_handler.validate_push_url", new=AsyncMock()):
            ok = client.post(
                "/rpc",
                json={
                    "jsonrpc": "2.0",
                    "method": "SendMessage",
                    "params": {
                        "message": {"parts": [{"text": f"review {PR_URL}"}]},
                        "configuration": {
                            "returnImmediately": True,
                            "taskPushNotificationConfig": {"url": "https://hooks.example.test/x"},
                        },
                    },
                },
            )
            assert ok.status_code == 204

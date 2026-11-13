"""P1-17: no raw exception text in logs, raised errors, tracebacks or responses."""

import logging
import os
import traceback
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from github import GithubException

os.environ.setdefault("GITHUB_TOKEN", "dummy")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-not-a-secret-0123456789")
os.environ.setdefault("SECRET_KEY", "dummy")
os.environ.setdefault("GOOGLE_API_KEY", "dummy")

from app.core.exceptions import GitHubMCPError, LLMError  # noqa: E402
from app.routes import a2a_tasks, jsonrpc  # noqa: E402
from app.services.code_analyzer import CodeAnalyzerService  # noqa: E402
from app.services.github_mcp import GitHubMCPService  # noqa: E402
from app.services.jsonrpc_handler import JSONRPCHandler  # noqa: E402
from app.services.llm_service import LLMService  # noqa: E402
from app.services.message_handler import MessageHandler  # noqa: E402
from tests.conftest import AUTH_HEADERS  # noqa: E402

SENTINEL = "SENTINEL-P117-RAW-TEXT"
PR_URL = "https://github.com/octo/repo/pull/7"


def _full_text(exc: BaseException) -> str:
    """Message plus the whole formatted traceback, including chained causes."""
    return str(exc) + "".join(traceback.format_exception(exc))


def _service(exc: Exception) -> GitHubMCPService:
    service = GitHubMCPService()
    client = MagicMock()
    client.get_repo.side_effect = exc
    service._client = client
    return service


CALLS = {
    "get_pull_request": lambda s: s.get_pull_request("o", "r", 1),
    "get_pr_diff": lambda s: s.get_pr_diff("o", "r", 1),
    "list_pr_files": lambda s: s.list_pr_files("o", "r", 1),
    "get_file_content": lambda s: s.get_file_content("o", "r", "a.py"),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("name", list(CALLS))
@pytest.mark.parametrize("kind", ["github", "generic"])
async def test_github_fetch_errors_carry_no_raw_text(name, kind, caplog):
    caplog.set_level(logging.DEBUG)
    exc = (
        GithubException(502, {"message": SENTINEL}, None)
        if kind == "github"
        else RuntimeError(SENTINEL)
    )
    with pytest.raises(GitHubMCPError) as info:
        await CALLS[name](_service(exc))

    assert info.value.__cause__ is None
    assert info.value.__suppress_context__ is True
    assert SENTINEL not in _full_text(info.value)
    assert SENTINEL not in caplog.text
    for record in caplog.records:
        assert record.exc_info is None
    if kind == "github":
        assert "502" in str(info.value)
    else:
        assert "error id" in str(info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["github", "generic"])
async def test_optional_reviews_failure_logs_no_raw_text(kind, caplog):
    caplog.set_level(logging.DEBUG)
    exc = (
        GithubException(500, {"message": SENTINEL}, None)
        if kind == "github"
        else RuntimeError(SENTINEL)
    )
    assert await _service(exc).get_pr_reviews("o", "r", 1) == []
    assert SENTINEL not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["github", "generic"])
async def test_post_comment_failure_has_no_cause(kind, caplog):
    caplog.set_level(logging.DEBUG)
    exc = (
        GithubException(403, {"message": SENTINEL}, None)
        if kind == "github"
        else RuntimeError(SENTINEL)
    )
    with pytest.raises(GitHubMCPError) as info:
        await _service(exc).post_pr_comment("o", "r", 1, "body")
    assert info.value.__cause__ is None
    assert SENTINEL not in _full_text(info.value)
    assert SENTINEL not in caplog.text


@pytest.mark.asyncio
async def test_close_failure_logs_no_raw_text(caplog):
    caplog.set_level(logging.DEBUG)
    service = GitHubMCPService()
    service._client = MagicMock()
    service._client.close.side_effect = RuntimeError(SENTINEL)
    await service.__aexit__(None, None, None)
    assert SENTINEL not in caplog.text


@pytest.mark.asyncio
async def test_analyzer_fetch_pr_data_logs_type_only(caplog):
    caplog.set_level(logging.DEBUG)
    analyzer = CodeAnalyzerService()
    with patch("app.services.code_analyzer.GitHubMCPService") as svc:
        svc.return_value.__aenter__.side_effect = RuntimeError(SENTINEL)
        with pytest.raises(RuntimeError):
            await analyzer._fetch_pr_data(PR_URL)
    assert SENTINEL not in caplog.text
    assert "RuntimeError" in caplog.text


@pytest.mark.asyncio
async def test_analyzer_github_and_llm_errors_log_no_raw_text(caplog):
    caplog.set_level(logging.DEBUG)
    analyzer = CodeAnalyzerService()
    analyzer._fetch_pr_data = AsyncMock(side_effect=GitHubMCPError("Invalid " + SENTINEL))
    with pytest.raises(GitHubMCPError):
        await analyzer.analyze_pr(PR_URL)
    assert SENTINEL not in caplog.text

    # LLMError text comes from safe_message(), so it is logged as-is
    analyzer._fetch_pr_data = AsyncMock(side_effect=LLMError("RateLimitError, status 429"))
    with pytest.raises(LLMError):
        await analyzer.analyze_pr(PR_URL)
    assert "RateLimitError, status 429" in caplog.text


@pytest.mark.asyncio
async def test_llm_service_wrap_error_has_no_cause(caplog):
    caplog.set_level(logging.DEBUG)
    service = LLMService.__new__(LLMService)
    service._generate = AsyncMock(side_effect=RuntimeError(SENTINEL))
    service.prompts = {}
    with pytest.raises(LLMError) as info:
        await service.analyze_security("diff", [])
    assert info.value.__cause__ is None
    assert SENTINEL not in _full_text(info.value)
    assert SENTINEL not in caplog.text


@pytest.fixture
def client_app():
    app = FastAPI()
    app.include_router(jsonrpc.router)
    app.include_router(a2a_tasks.router)
    handler = JSONRPCHandler()

    async def typed(x: int):
        return x

    async def boom():
        raise RuntimeError(SENTINEL)

    handler.register_method("typed", typed)
    handler.register_method("boom", boom)
    app.state.jsonrpc_handler = handler
    return app


def test_rpc_routes_and_handler_log_no_raw_text(client_app, caplog):
    caplog.set_level(logging.DEBUG)
    bad = ("{bad " + SENTINEL).encode()
    json_header = {"content-type": "application/json"}
    with TestClient(client_app, headers=AUTH_HEADERS) as client:
        responses = [
            client.post("/rpc", content=bad, headers=json_header),
            client.post("/a2a/tasks", content=bad, headers=json_header),
            client.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "boom"}),
            # TypeError path: wrong argument names
            client.post(
                "/rpc",
                json={"jsonrpc": "2.0", "id": 2, "method": "typed", "params": {SENTINEL: 1}},
            ),
        ]
        # endpoint-level catch-all: the handler itself raises
        with patch.object(
            JSONRPCHandler, "handle_request", AsyncMock(side_effect=RuntimeError(SENTINEL))
        ):
            responses.append(
                client.post("/rpc", json={"jsonrpc": "2.0", "id": 3, "method": "boom"})
            )

    for resp in responses:
        assert SENTINEL not in resp.text
    assert SENTINEL not in caplog.text
    for record in caplog.records:
        assert record.exc_info is None


@pytest.mark.asyncio
async def test_jsonrpc_handler_catch_all_logs_no_raw_text(caplog):
    caplog.set_level(logging.DEBUG)
    handler = JSONRPCHandler()
    async def boom():
        raise RuntimeError(SENTINEL)

    handler.register_method("boom", boom)
    with patch.object(handler, "_success_response", side_effect=RuntimeError(SENTINEL)):
        resp = await handler.handle_request({"jsonrpc": "2.0", "id": 4, "method": "boom"})
    assert SENTINEL not in str(resp)
    assert SENTINEL not in caplog.text
    for record in caplog.records:
        assert record.exc_info is None


def test_agent_card_failure_logs_no_raw_text(caplog):
    from app.main import app

    caplog.set_level(logging.DEBUG)
    with patch("app.main.open", side_effect=OSError(SENTINEL), create=True):
        resp = TestClient(app).get("/.well-known/agent.json")
    assert resp.status_code == 500
    assert SENTINEL not in resp.text
    assert SENTINEL not in caplog.text


@pytest.mark.asyncio
async def test_message_handler_failures_log_no_raw_text(push_allowed, caplog):
    caplog.set_level(logging.DEBUG)
    handler = MessageHandler()
    config = {
        "url": "https://hooks.example.test/x",
        "token": "t",
        "authentication": {"schemes": ["Bearer"]},
    }
    msg = {"messageId": "m", "parts": []}

    # background failure, then the error push itself fails
    handler._process_and_push = AsyncMock(side_effect=RuntimeError(SENTINEL))
    handler._push_error = AsyncMock(side_effect=httpx.ConnectError(SENTINEL))
    await handler._process_and_push_safe(PR_URL, "t", "m", msg, config)
    assert SENTINEL not in caplog.text
    for record in caplog.records:
        assert record.exc_info is None

    # analysis failure inside _process_and_push, then the error push fails too
    caplog.clear()
    handler2 = MessageHandler()
    handler2.analyzer.analyze_pr = AsyncMock(side_effect=RuntimeError(SENTINEL))
    handler2._push_error = AsyncMock(side_effect=httpx.ConnectError(SENTINEL))
    await handler2._process_and_push_safe(PR_URL, "t", "m", msg, config)
    assert SENTINEL not in caplog.text
    for record in caplog.records:
        assert record.exc_info is None

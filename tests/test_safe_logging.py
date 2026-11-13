"""F-05: secrets and payloads stay out of logs, and clients get safe error messages."""

import logging
import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("GITHUB_TOKEN", "dummy")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-not-a-secret-0123456789")
os.environ.setdefault("SECRET_KEY", "dummy")
os.environ.setdefault("GOOGLE_API_KEY", "dummy")

from app.core.exceptions import GitHubMCPError  # noqa: E402
from app.llm.errors import LLMRateLimitError  # noqa: E402
from app.routes import a2a_tasks, jsonrpc  # noqa: E402
from app.services.github_mcp import GitHubMCPService  # noqa: E402
from app.services.jsonrpc_handler import JSONRPCHandler  # noqa: E402
from app.services.message_handler import MessageHandler  # noqa: E402
from tests.conftest import AUTH_HEADERS  # noqa: E402

TOKEN = "SENTINEL-TOKEN-123"
INTERNAL = "SENTINEL-INTERNAL-DETAIL /srv/app/secret.py"
PR_URL = "https://github.com/octo/repo/pull/7"


def _rpc_body(config):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "messageId": "m-1",
                "role": "user",
                "kind": "message",
                "parts": [{"kind": "text", "text": f"please review {PR_URL}"}],
            },
            "configuration": config,
        },
    }


def _push_config():
    return {
        "url": "https://hooks.example.test/path/SENTINEL-URL-SECRET?key=SENTINEL-QUERY",
        "token": TOKEN,
        "authentication": {"schemes": ["Bearer"]},
    }


@pytest.fixture
def app_and_handler(push_allowed):
    app = FastAPI()
    app.include_router(jsonrpc.router)
    app.include_router(a2a_tasks.router)
    handler = JSONRPCHandler()
    message_handler = MessageHandler()

    async def message_send(message, configuration=None):
        return await message_handler.handle_message_send(message, configuration)

    handler.register_method("message/send", message_send)

    async def boom():
        raise RuntimeError(INTERNAL)

    handler.register_method("boom", boom)
    app.state.jsonrpc_handler = handler
    app.state.message_handler = message_handler
    return app, message_handler


def test_configuration_token_never_logged_or_returned(app_and_handler, caplog):
    app, message_handler = app_and_handler
    caplog.set_level(logging.DEBUG)
    body = _rpc_body({"blocking": False, "pushNotificationConfig": _push_config()})

    with patch.object(MessageHandler, "_process_and_push_safe", new=AsyncMock()):
        with TestClient(app, headers=AUTH_HEADERS) as client:
            r1 = client.post("/rpc", json=body)
            r2 = client.post("/a2a/tasks", json=body)

    for resp in (r1, r2):
        assert resp.status_code == 200
        assert TOKEN not in resp.text
    assert TOKEN not in caplog.text
    assert "SENTINEL-URL-SECRET" not in caplog.text
    assert "SENTINEL-QUERY" not in caplog.text


@pytest.mark.asyncio
async def test_background_failure_push_has_no_token_url_or_internal_text(app_and_handler, caplog):
    _, message_handler = app_and_handler
    caplog.set_level(logging.DEBUG)
    posted = []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            posted.append(json)
            return httpx.Response(200, request=httpx.Request("POST", url))

    message_handler.analyzer.analyze_pr = AsyncMock(side_effect=RuntimeError(INTERNAL))
    msg = {"messageId": "m-1", "parts": []}

    with patch("app.services.message_handler.httpx.AsyncClient", FakeClient):
        await message_handler._process_and_push_safe(
            PR_URL, "t-1", "m-1", msg, _push_config()
        )

    assert posted, "an error result should have been pushed"
    pushed = str(posted)
    assert INTERNAL not in pushed
    assert "SENTINEL-INTERNAL" not in pushed
    assert TOKEN not in pushed
    assert "error id" in pushed.lower()
    assert TOKEN not in caplog.text
    assert "SENTINEL-URL-SECRET" not in caplog.text


@pytest.mark.asyncio
async def test_push_error_categories_survive_without_raw_text(app_and_handler):
    _, message_handler = app_and_handler
    posted = []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            posted.append(json)
            return httpx.Response(200, request=httpx.Request("POST", url))

    with patch("app.services.message_handler.httpx.AsyncClient", FakeClient):
        await message_handler._push_error("t", "m", {}, _push_config(), LLMRateLimitError(INTERNAL), "abc12345")
        await message_handler._push_error("t", "m", {}, _push_config(), GitHubMCPError(INTERNAL), "abc12345")

    assert "Temporarily Unavailable" in str(posted[0])
    assert "Unable to Access Pull Request" in str(posted[1])
    for p in posted:
        assert "SENTINEL-INTERNAL" not in str(p)
        assert "abc12345" in str(p)


def test_internal_exception_message_not_returned_by_rpc(app_and_handler, caplog):
    app, _ = app_and_handler
    caplog.set_level(logging.DEBUG)
    with TestClient(app, headers=AUTH_HEADERS) as client:
        resp = client.post("/rpc", json={"jsonrpc": "2.0", "id": 9, "method": "boom"})

    body = resp.json()
    assert body["error"]["code"] == -32603
    assert "SENTINEL-INTERNAL" not in resp.text
    assert "RuntimeError" not in resp.text
    error_id = body["error"]["data"]["error_id"]
    # P1-17: the id and exception type are kept server-side, never the text or traceback
    assert error_id in caplog.text
    assert "SENTINEL-INTERNAL" not in caplog.text
    assert "RuntimeError" in caplog.text


def test_invalid_params_and_bad_json_do_not_echo_internals(app_and_handler):
    app, _ = app_and_handler
    with TestClient(app, headers=AUTH_HEADERS) as client:
        bad_params = client.post(
            "/rpc",
            json={"jsonrpc": "2.0", "id": 2, "method": "boom", "params": {"secret_kw": TOKEN}},
        )
        bad_json = client.post("/rpc", content=b"{not json " + TOKEN.encode(),
                               headers={"content-type": "application/json"})
        bad_a2a = client.post("/a2a/tasks", content=b"{not json " + TOKEN.encode(),
                              headers={"content-type": "application/json"})

    for resp in (bad_params, bad_json, bad_a2a):
        assert TOKEN not in resp.text
        assert "secret_kw" not in resp.text
        assert "error_id" in resp.text or "error id" in resp.text
    assert bad_params.json()["error"]["code"] == -32602
    assert bad_json.json()["error"]["code"] == -32700
    assert bad_a2a.status_code == 422


@pytest.mark.asyncio
async def test_github_client_does_not_log_token_or_length(caplog, monkeypatch):
    monkeypatch.setenv("SKIP_GITHUB_CONNECTION_TEST", "true")
    caplog.set_level(logging.DEBUG)
    client = GitHubMCPService()
    client.token = TOKEN
    async with client:
        pass
    assert TOKEN not in caplog.text
    assert f"Length: {len(TOKEN)}" not in caplog.text
    assert "Token present: True" in caplog.text

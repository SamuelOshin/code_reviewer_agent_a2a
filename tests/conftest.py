# tests/conftest.py

"""Shared fixtures.

Settings are read when `app.core.config` is first imported, so the dummy values
must be in the environment before any app module loads. Real environment values
win (setdefault), which lets CI pass them in explicitly. Nothing here talks to
the network.
"""

import os

for _key in ("GITHUB_TOKEN", "GITHUB_WEBHOOK_SECRET", "SECRET_KEY", "GOOGLE_API_KEY"):
    os.environ.setdefault(_key, "dummy")
# The app builds its model client at startup and needs a model setting. A fake ID:
# tests never call a real model.
os.environ.setdefault("LLM_MODEL", "google:test-model")
# /rpc and /a2a/* need a bearer key of at least 32 characters (P1-07). Test value only.
os.environ.setdefault("API_KEY", "test-api-key-not-a-secret-0123456789")
API_KEY = os.environ["API_KEY"]
AUTH_HEADERS = {"Authorization": f"Bearer {API_KEY}"}
# A public address returned by the stubbed resolver; nothing ever connects to it
PUBLIC_IP = "8.8.8.8"

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.routes import a2a_tasks, jsonrpc, webhooks  # noqa: E402
from app.services.jsonrpc_handler import JSONRPCHandler  # noqa: E402

WEBHOOK_SECRET = "test-webhook-secret"


@pytest.fixture
def rpc_handler() -> JSONRPCHandler:
    """A fresh handler with a few trivial methods and no LLM or GitHub access."""
    handler = JSONRPCHandler()

    async def echo(**params):
        return {"echo": params}

    async def add(a: int, b: int):
        return {"sum": a + b}

    async def boom():
        raise RuntimeError("handler exploded")

    async def task_like():
        return {"status": "completed"}

    handler.register_method("echo", echo)
    handler.register_method("add", add)
    handler.register_method("boom", boom)
    handler.register_method("task_like", task_like)
    return handler


@pytest.fixture
def test_app(rpc_handler: JSONRPCHandler) -> FastAPI:
    """Minimal app with the real routers and no lifespan (no analyzer is built)."""
    app = FastAPI()
    app.state.jsonrpc_handler = rpc_handler
    app.include_router(jsonrpc.router)
    app.include_router(webhooks.router)
    app.include_router(a2a_tasks.router)
    return app


@pytest.fixture
def client(test_app: FastAPI) -> TestClient:
    """Authenticated client: sends the API key on every request."""
    return TestClient(test_app, headers=AUTH_HEADERS)


@pytest.fixture
def anon_client(test_app: FastAPI) -> TestClient:
    """Client that sends no Authorization header."""
    return TestClient(test_app)


@pytest.fixture
def push_allowed(monkeypatch) -> None:
    """Allowlist the test push hosts and resolve every name to a public IP offline."""
    from app.core import push_url

    monkeypatch.setattr(
        push_url.settings, "PUSH_URL_ALLOWED_HOSTS", "hooks.example.test,x.test"
    )

    async def resolve(host, port):
        return [PUBLIC_IP]

    monkeypatch.setattr(push_url, "_resolve", resolve)


@pytest.fixture
def webhook_secret(monkeypatch) -> str:
    monkeypatch.setattr(webhooks.settings, "GITHUB_WEBHOOK_SECRET", WEBHOOK_SECRET)
    return WEBHOOK_SECRET

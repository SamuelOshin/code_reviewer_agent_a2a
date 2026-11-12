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
    return TestClient(test_app)


@pytest.fixture
def webhook_secret(monkeypatch) -> str:
    monkeypatch.setattr(webhooks.settings, "GITHUB_WEBHOOK_SECRET", WEBHOOK_SECRET)
    return WEBHOOK_SECRET

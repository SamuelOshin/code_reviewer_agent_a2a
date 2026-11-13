"""P1-07 (F-04): API key auth, mandatory webhook secret, push URL allowlist and
SSRF guard, CORS restriction and JSON-RPC batch limit.

Nothing here touches the network: DNS answers come from a stubbed resolver.
"""

import os
import secrets
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core import auth, push_url
from app.core.config import MIN_API_KEY_LENGTH, PLACEHOLDER_SECRETS, Settings
from app.core.push_url import PushUrlRejected, validate_push_url
from app.models.jsonrpc import JSONRPCErrorCode as Code
from app.services.message_handler import MessageHandler
from tests.conftest import API_KEY, AUTH_HEADERS

ROOT = Path(__file__).resolve().parent.parent
RPC = {"jsonrpc": "2.0", "method": "add", "params": {"a": 1, "b": 2}, "id": 1}
A2A = {"message": "hi"}
GOOD_KEY = "k" * MIN_API_KEY_LENGTH
PR_URL = "https://github.com/octo/repo/pull/1"


def base_env(**overrides):
    env = {"GITHUB_TOKEN": "x", "GITHUB_WEBHOOK_SECRET": "x", "API_KEY": GOOD_KEY}
    env.update(overrides)
    return env


def make_settings(**overrides):
    return Settings(_env_file=None, **base_env(**overrides))


def stub_dns(monkeypatch, answers):
    async def resolve(host, port):
        if host not in answers:
            raise OSError("no such host")
        return answers[host]

    monkeypatch.setattr(push_url, "_resolve", resolve)


def allow(monkeypatch, hosts):
    monkeypatch.setattr(push_url.settings, "PUSH_URL_ALLOWED_HOSTS", hosts)


# ---------------------------------------------------------------------------
# Auth on /rpc and /a2a/*
# ---------------------------------------------------------------------------


class TestApiKeyAuth:
    @pytest.mark.parametrize("path,body", [("/rpc", RPC), ("/a2a/tasks", A2A)])
    def test_unauthenticated_call_is_rejected(self, anon_client, path, body):
        res = anon_client.post(path, json=body)
        assert res.status_code == 401
        assert res.headers["www-authenticate"] == "Bearer"
        assert API_KEY not in res.text

    @pytest.mark.parametrize("path,body", [("/rpc", RPC), ("/a2a/tasks", A2A)])
    def test_wrong_key_is_rejected(self, anon_client, path, body):
        res = anon_client.post(path, json=body, headers={"Authorization": "Bearer " + "x" * 40})
        assert res.status_code == 401

    def test_correct_key_is_accepted(self, client):
        res = client.post("/rpc", json=RPC)
        assert res.status_code == 200
        assert res.json()["result"] == {"sum": 3}

    def test_rejected_call_never_reaches_the_handler(self, anon_client, rpc_handler):
        called = AsyncMock(return_value={})
        rpc_handler.register_method("add", called)
        anon_client.post("/rpc", json=RPC)
        anon_client.post("/rpc", json=[RPC])
        anon_client.post("/a2a/tasks", json=A2A)
        called.assert_not_called()

    @pytest.mark.parametrize(
        "header",
        [
            f"bearer {API_KEY}",  # the scheme is case-insensitive (RFC 7235)
            f"BEARER {API_KEY}",
            f"Bearer   {API_KEY}",  # extra spaces between scheme and token
            f"Bearer {API_KEY}  ",  # trailing whitespace
        ],
    )
    def test_scheme_case_and_whitespace_variants_accepted(self, anon_client, header):
        res = anon_client.post("/rpc", json=RPC, headers={"Authorization": header})
        assert res.status_code == 200

    @pytest.mark.parametrize(
        "header",
        [
            API_KEY,  # no scheme
            f"Bearer{API_KEY}",  # no separator
            f"Bearer\t{API_KEY}",  # tab is not the separator
            f"Basic {API_KEY}",
            f"Token {API_KEY}",
            f"Bearer {API_KEY.upper()}",  # the key itself is case-sensitive
            f"Bearer {API_KEY[:-1]}",  # prefix of the key
            f"Bearer {API_KEY}x",  # key plus a suffix
            f"Bearer {API_KEY} {API_KEY}",
            "Bearer ",
            "Bearer",
            "",
        ],
    )
    def test_malformed_or_near_miss_headers_rejected(self, anon_client, header):
        res = anon_client.post("/rpc", json=RPC, headers={"Authorization": header})
        assert res.status_code == 401

    def test_non_ascii_key_is_rejected_not_an_error(self):
        # compare_digest raises TypeError on non-ASCII str; the check compares bytes
        assert auth.is_valid_api_key("ключ-" + "x" * 40) is False

    def test_key_in_other_header_or_query_is_not_accepted(self, anon_client):
        assert anon_client.post("/rpc", json=RPC, headers={"X-API-Key": API_KEY}).status_code == 401
        assert anon_client.post(f"/rpc?api_key={API_KEY}", json=RPC).status_code == 401

    def test_empty_configured_key_rejects_everything(self, anon_client, monkeypatch):
        # Startup refuses this; the check must still fail closed if it happens
        monkeypatch.setattr(auth.settings, "API_KEY", "")
        for header in ("Bearer ", "Bearer", "", f"Bearer {API_KEY}"):
            res = anon_client.post("/rpc", json=RPC, headers={"Authorization": header})
            assert res.status_code == 401

    def test_comparison_uses_compare_digest(self, monkeypatch):
        calls = []
        real = auth.hmac.compare_digest

        def spy(a, b):
            calls.append((a, b))
            return real(a, b)

        monkeypatch.setattr(auth.hmac, "compare_digest", spy)
        assert auth.is_valid_api_key(API_KEY)
        assert not auth.is_valid_api_key("nope")
        assert len(calls) == 2

    def test_rejected_key_is_not_logged(self, anon_client, caplog):
        anon_client.post("/rpc", json=RPC, headers={"Authorization": "Bearer SENTINEL-WRONG-KEY"})
        assert "SENTINEL-WRONG-KEY" not in caplog.text

    def test_webhooks_use_the_signature_not_the_api_key(self, anon_client):
        res = anon_client.post("/webhooks/github", content=b"{}")
        assert res.status_code == 401
        assert "signature" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------


class TestStartupValidation:
    @pytest.mark.parametrize("value", ["", "   ", "\t\n"])
    def test_missing_or_blank_webhook_secret_is_refused(self, value):
        with pytest.raises(ValidationError, match="GITHUB_WEBHOOK_SECRET"):
            make_settings(GITHUB_WEBHOOK_SECRET=value)

    @pytest.mark.parametrize(
        "value",
        ["", " ", "short", "k" * (MIN_API_KEY_LENGTH - 1), f" {GOOD_KEY}", f"{GOOD_KEY} "],
    )
    def test_empty_short_or_padded_api_key_is_refused(self, value):
        with pytest.raises(ValidationError, match="API_KEY"):
            make_settings(API_KEY=value)

    @pytest.mark.parametrize("name", sorted(PLACEHOLDER_SECRETS))
    def test_env_example_placeholders_are_refused(self, name):
        with pytest.raises(ValidationError, match=f"{name} is still the public placeholder"):
            make_settings(**{name: PLACEHOLDER_SECRETS[name]})

    def test_random_values_are_accepted(self):
        s = make_settings(
            API_KEY=secrets.token_urlsafe(32), GITHUB_WEBHOOK_SECRET=secrets.token_hex(32)
        )
        assert s.API_KEY not in PLACEHOLDER_SECRETS.values()

    def test_placeholder_list_matches_env_example(self):
        # The refused values must be the ones .env.example actually prints
        values = dict(
            line.split("=", 1)
            for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#") and "=" in line
        )
        for name, placeholder in PLACEHOLDER_SECRETS.items():
            assert values[name] == placeholder

    def test_unedited_env_example_does_not_start(self, tmp_path):
        env = {k: v for k, v in os.environ.items() if k not in PLACEHOLDER_SECRETS}
        env.pop("GITHUB_TOKEN", None)
        (tmp_path / ".env").write_text(
            (ROOT / ".env.example").read_text(encoding="utf-8"), encoding="utf-8"
        )
        proc = self.import_app(env, tmp_path)
        assert proc.returncode != 0
        assert "is still the public placeholder" in proc.stderr

    def test_defaults_disable_push_and_cors(self):
        s = make_settings()
        assert s.push_url_allowed_hosts == frozenset()
        assert s.cors_allowed_origins == []
        assert s.JSONRPC_MAX_BATCH_SIZE == 10

    @pytest.mark.parametrize(
        "value",
        ["*", "https://hooks.example.com", "hooks.example.com/path", "*.example.com",
         "hooks.example.com:8443", "bad host", "::1"],
    )
    def test_bad_push_allowlist_entries_are_refused(self, value):
        with pytest.raises(ValidationError, match="PUSH_URL_ALLOWED_HOSTS"):
            make_settings(PUSH_URL_ALLOWED_HOSTS=value)

    def test_push_allowlist_is_parsed_and_lowercased(self):
        s = make_settings(PUSH_URL_ALLOWED_HOSTS=" Hooks.Example.com , a.example.org ,")
        assert s.push_url_allowed_hosts == {"hooks.example.com", "a.example.org"}

    @pytest.mark.parametrize(
        "value", ["*", "https://app.example.com/path", "app.example.com", "ftp://app.example.com"]
    )
    def test_bad_cors_origins_are_refused(self, value):
        with pytest.raises(ValidationError, match="CORS_ALLOWED_ORIGINS"):
            make_settings(CORS_ALLOWED_ORIGINS=value)

    @pytest.mark.parametrize("value", [0, -1, 101])
    def test_batch_size_out_of_range_is_refused(self, value):
        with pytest.raises(ValidationError):
            make_settings(JSONRPC_MAX_BATCH_SIZE=value)

    @staticmethod
    def import_app(env, cwd):
        # A fresh interpreter, so the module-level settings are really rebuilt.
        # cwd is an empty dir, so no .env file can supply a value.
        env = dict(env, PYTHONPATH=str(ROOT))
        return subprocess.run(
            [sys.executable, "-c", "import app.main"],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=120,
        )

    @pytest.mark.parametrize(
        "missing,blank", [("GITHUB_WEBHOOK_SECRET", None), ("GITHUB_WEBHOOK_SECRET", ""),
                          ("API_KEY", None), ("API_KEY", "")],
    )
    def test_app_does_not_start_without_required_secret(self, missing, blank, tmp_path):
        env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_WEBHOOK_SECRET", "API_KEY")}
        env.update(base_env())
        if blank is None:
            del env[missing]
        else:
            env[missing] = blank
        proc = self.import_app(env, tmp_path)
        assert proc.returncode != 0
        assert missing in proc.stderr

    def test_app_starts_with_required_secrets(self, tmp_path):
        proc = self.import_app({**os.environ, **base_env()}, tmp_path)
        assert proc.returncode == 0, proc.stderr[-2000:]


# ---------------------------------------------------------------------------
# Push URL allowlist and SSRF guard
# ---------------------------------------------------------------------------


class TestPushUrlGuard:
    @pytest.mark.asyncio
    async def test_allowlisted_public_https_url_is_accepted(self, monkeypatch):
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {"hooks.example.com": ["8.8.8.8", "2606:4700::1"]})
        url = "https://Hooks.Example.com/a2a/push?x=1"
        assert await validate_push_url(url) == url

    @pytest.mark.asyncio
    async def test_push_disabled_when_allowlist_empty(self, monkeypatch):
        allow(monkeypatch, "")
        with pytest.raises(PushUrlRejected, match="disabled"):
            await validate_push_url("https://hooks.example.com/x")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example.net/x",
            "https://hooks.example.com.evil.net/x",  # suffix trick
            "https://evilhooks.example.com/x",
            "https://hooks.example.com@evil.net/x",  # userinfo trick: the host is evil.net
            "https://sub.hooks.example.com/x",  # no implicit subdomains
        ],
    )
    async def test_host_not_on_allowlist_is_rejected(self, monkeypatch, url):
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {})
        with pytest.raises(PushUrlRejected, match="allowlist"):
            await validate_push_url(url)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "url",
        ["http://hooks.example.com/x", "ftp://hooks.example.com/x", "file:///etc/passwd",
         "gopher://hooks.example.com/", "//hooks.example.com/x", "hooks.example.com/x"],
    )
    async def test_non_https_scheme_is_rejected(self, monkeypatch, url):
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {"hooks.example.com": ["8.8.8.8"]})
        with pytest.raises(PushUrlRejected, match="https"):
            await validate_push_url(url)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", [None, "", 123, {"url": "x"}])
    async def test_missing_or_non_string_url_is_rejected(self, monkeypatch, value):
        allow(monkeypatch, "hooks.example.com")
        with pytest.raises(PushUrlRejected):
            await validate_push_url(value)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "url",
        ["http://127.0.0.1/x", "http://[::1]/x", "http://169.254.169.254/latest/meta-data/",
         "https://127.0.0.1/x", "https://[::1]/x", "https://169.254.169.254/latest/meta-data/"],
    )
    async def test_loopback_and_metadata_ip_literals_are_rejected(self, monkeypatch, url):
        allow(monkeypatch, "hooks.example.com")
        with pytest.raises(PushUrlRejected):
            await validate_push_url(url)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "10.0.0.5"])
    async def test_allowlisted_private_ip_literal_is_still_rejected(self, monkeypatch, ip):
        # Even if an operator allowlists a private IPv4 literal by mistake
        allow(monkeypatch, ip)
        with pytest.raises(PushUrlRejected, match="non-public"):
            await validate_push_url(f"https://{ip}/x")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "address",
        ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
         "100.64.0.1", "0.0.0.0", "::1", "fe80::1%eth0", "fd00::1", "::ffff:127.0.0.1",
         "::ffff:169.254.169.254", "224.0.0.1", "ff02::1"],
    )
    async def test_dns_name_resolving_to_non_public_address_is_rejected(self, monkeypatch, address):
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {"hooks.example.com": [address]})
        with pytest.raises(PushUrlRejected, match="non-public"):
            await validate_push_url("https://hooks.example.com/x")

    @pytest.mark.asyncio
    async def test_any_private_answer_among_public_ones_is_rejected(self, monkeypatch):
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {"hooks.example.com": ["8.8.8.8", "10.0.0.7"]})
        with pytest.raises(PushUrlRejected, match="non-public"):
            await validate_push_url("https://hooks.example.com/x")

    @pytest.mark.asyncio
    async def test_unresolvable_host_is_rejected(self, monkeypatch):
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {})
        with pytest.raises(PushUrlRejected, match="resolve"):
            await validate_push_url("https://hooks.example.com/x")

    @pytest.mark.asyncio
    async def test_invalid_port_is_rejected(self, monkeypatch):
        allow(monkeypatch, "hooks.example.com")
        with pytest.raises(PushUrlRejected, match="valid URL"):
            await validate_push_url("https://hooks.example.com:99999/x")


class FakeHttpClient:
    """Stands in for httpx.AsyncClient; records constructor kwargs and posted URLs."""

    instances: list = []
    posted: list = []

    def __init__(self, *args, **kwargs):
        FakeHttpClient.instances.append(kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, **kwargs):
        FakeHttpClient.posted.append(url)
        return httpx.Response(200, request=httpx.Request("POST", url))


class TestPushUrlInMessageSend:
    @pytest.fixture
    def handler(self):
        h = MessageHandler.__new__(MessageHandler)
        h.analyzer = MagicMock()
        h.analyzer.analyze_pr = AsyncMock()
        h._background_tasks = set()
        return h

    @pytest.fixture
    def fake_http(self):
        FakeHttpClient.instances = []
        FakeHttpClient.posted = []
        with patch("app.services.message_handler.httpx.AsyncClient", FakeHttpClient):
            yield FakeHttpClient

    @staticmethod
    def message():
        return {
            "kind": "message",
            "role": "user",
            "messageId": "m1",
            "parts": [{"kind": "text", "text": f"review {PR_URL}"}],
        }

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "url", ["http://127.0.0.1:8000/x", "https://evil.example.net/x", "http://[::1]/x"]
    )
    async def test_disallowed_url_rejected_before_any_work(self, handler, monkeypatch, url):
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {})
        configuration = {"blocking": False, "pushNotificationConfig": {"url": url}}
        with patch.object(MessageHandler, "_process_and_push_safe", new=AsyncMock()) as push:
            with pytest.raises(PushUrlRejected):
                await handler.handle_message_send(self.message(), configuration)
        push.assert_not_called()
        handler.analyzer.analyze_pr.assert_not_called()
        assert handler._background_tasks == set()

    def test_rejection_is_an_invalid_params_error_over_http(
        self, test_app, rpc_handler, handler, monkeypatch
    ):
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {"hooks.example.com": ["169.254.169.254"]})

        async def message_send(message, configuration=None):
            return await handler.handle_message_send(message, configuration)

        rpc_handler.register_method("message/send", message_send)
        body = {
            "jsonrpc": "2.0", "id": 5, "method": "message/send",
            "params": {
                "message": self.message(),
                "configuration": {
                    "blocking": False,
                    "pushNotificationConfig": {"url": "https://hooks.example.com/SENTINEL-PATH"},
                },
            },
        }
        res = TestClient(test_app, headers=AUTH_HEADERS).post("/a2a/tasks", json=body)
        error = res.json()["error"]
        assert error["code"] == Code.INVALID_PARAMS
        assert "non-public" in error["message"]
        assert "SENTINEL-PATH" not in res.text
        handler.analyzer.analyze_pr.assert_not_called()

    @pytest.mark.asyncio
    async def test_dns_change_before_push_blocks_the_push(self, handler, monkeypatch, fake_http):
        # Accepted at request time, then the name starts resolving to the metadata IP
        allow(monkeypatch, "hooks.example.com")
        stub_dns(monkeypatch, {"hooks.example.com": ["169.254.169.254"]})
        handler._analyze_and_return = AsyncMock(return_value={"kind": "task", "status": {}})
        handler._create_lightweight_result = MagicMock(return_value={"status": {}})
        await handler._process_and_push_safe(
            PR_URL, "t", "m", self.message(), {"url": "https://hooks.example.com/x"}
        )
        assert fake_http.posted == []

    @pytest.mark.asyncio
    async def test_push_client_does_not_follow_redirects(self, handler, push_allowed, fake_http):
        handler._analyze_and_return = AsyncMock(return_value={"kind": "task", "status": {}})
        handler._create_lightweight_result = MagicMock(return_value={"status": {}})
        await handler._process_and_push_safe(
            PR_URL, "t", "m", self.message(), {"url": "https://hooks.example.test/x"}
        )
        assert fake_http.posted == ["https://hooks.example.test/x"]
        assert fake_http.instances
        assert all(k.get("follow_redirects") is False for k in fake_http.instances)


# ---------------------------------------------------------------------------
# JSON-RPC batch limit
# ---------------------------------------------------------------------------


class TestBatchLimit:
    def test_batch_at_limit_is_processed(self, client, monkeypatch):
        monkeypatch.setattr("app.routes.jsonrpc.settings.JSONRPC_MAX_BATCH_SIZE", 3)
        res = client.post("/rpc", json=[dict(RPC, id=i) for i in range(3)])
        assert [r["result"]["sum"] for r in res.json()] == [3, 3, 3]

    def test_oversize_batch_is_rejected_without_running_any_call(
        self, client, rpc_handler, monkeypatch
    ):
        monkeypatch.setattr("app.routes.jsonrpc.settings.JSONRPC_MAX_BATCH_SIZE", 3)
        called = AsyncMock(return_value={})
        rpc_handler.register_method("add", called)
        res = client.post("/rpc", json=[dict(RPC, id=i) for i in range(4)])
        body = res.json()
        assert isinstance(body, dict)
        assert body["error"]["code"] == Code.INVALID_REQUEST
        assert "Batch too large" in body["error"]["message"]
        called.assert_not_called()

    def test_default_limit_rejects_a_large_batch(self, client):
        res = client.post("/rpc", json=[RPC] * 1000)
        assert res.json()["error"]["code"] == Code.INVALID_REQUEST

    def test_oversize_batch_without_key_is_401_first(self, anon_client):
        assert anon_client.post("/rpc", json=[RPC] * 1000).status_code == 401


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


class TestCors:
    @pytest.fixture
    def build_app(self, monkeypatch):
        """Reload app.main with a CORS setting, and restore the module afterwards."""
        import importlib

        import app.core.config as config
        import app.main as main

        def build(origins: str) -> FastAPI:
            monkeypatch.setattr(config.settings, "CORS_ALLOWED_ORIGINS", origins)
            return importlib.reload(main).app

        yield build
        monkeypatch.undo()
        importlib.reload(main)

    @staticmethod
    def preflight(app, origin):
        return TestClient(app).options(
            "/rpc",
            headers={"Origin": origin, "Access-Control-Request-Method": "POST",
                     "Access-Control-Request-Headers": "authorization,content-type"},
        )

    def test_no_cors_headers_by_default(self, build_app):
        app = build_app("")
        res = TestClient(app).get("/", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in res.headers
        assert "access-control-allow-origin" not in self.preflight(app, "https://evil.example").headers

    def test_configured_origin_is_allowed_without_credentials(self, build_app):
        app = build_app("https://app.example.com")
        res = self.preflight(app, "https://app.example.com")
        assert res.headers["access-control-allow-origin"] == "https://app.example.com"
        assert "access-control-allow-credentials" not in res.headers

    def test_other_origin_is_not_allowed(self, build_app):
        app = build_app("https://app.example.com")
        res = self.preflight(app, "https://evil.example")
        assert res.headers.get("access-control-allow-origin") not in ("https://evil.example", "*")
        simple = TestClient(app).get("/", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in simple.headers

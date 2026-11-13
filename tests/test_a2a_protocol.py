# tests/test_a2a_protocol.py

"""/a2a/tasks: JSON-RPC forwarding, the plain-message shortcut, and input-required.

The first group uses a stub message/send handler. The last group runs the real
MessageHandler for the one path that needs no PR analysis (no PR URL in the text).
"""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.models.jsonrpc import JSONRPCErrorCode as Code
from app.services.message_handler import MessageHandler
from tests.conftest import AUTH_HEADERS

PR_URL = "https://github.com/octo/repo/pull/42"


def bare_handler() -> MessageHandler:
    """A MessageHandler without its analyzer, so no LLM service is built."""
    return MessageHandler.__new__(MessageHandler)


@pytest.fixture
def captured(rpc_handler):
    """Register a stub message/send that records what it was given."""
    calls = []

    async def message_send(message, configuration=None):
        calls.append({"message": message, "configuration": configuration})
        return {"id": "t1", "status": {"state": "completed"}, "kind": "task"}

    rpc_handler.register_method("message/send", message_send)
    return calls


def rpc_message_send(text="hello", request_id=9):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "message/send",
        "params": {
            "message": {
                "messageId": "m1",
                "role": "user",
                "kind": "message",
                "parts": [{"kind": "text", "text": text}],
            }
        },
    }


class TestForwarding:
    def test_jsonrpc_message_send_is_forwarded(self, client, captured):
        res = client.post("/a2a/tasks", json=rpc_message_send(PR_URL))
        assert res.status_code == 200
        body = res.json()
        assert body["id"] == 9
        assert body["result"]["status"]["state"] == "completed"
        assert captured[0]["message"]["parts"][0]["text"] == PR_URL

    def test_plain_message_is_converted(self, client, captured):
        res = client.post("/a2a/tasks", json={"message": f"review {PR_URL}", "id": "req-1"})
        assert res.status_code == 200
        assert res.json()["id"] == "req-1"
        sent = captured[0]
        assert sent["message"]["role"] == "user"
        assert sent["message"]["parts"] == [{"kind": "text", "text": f"review {PR_URL}"}]
        assert sent["configuration"]["blocking"] is False
        assert sent["configuration"]["pushNotificationConfig"] is None

    def test_plain_message_without_id_gets_one(self, client, captured):
        res = client.post("/a2a/tasks", json={"message": "hi"})
        assert res.status_code == 200
        assert res.json()["id"]

    @pytest.mark.parametrize(
        "body",
        [
            {"foo": "bar"},
            {"message": 123},
            {"message": {"parts": []}},
            {"jsonrpc": "2.0", "method": "other/method", "id": 1},
            [],
            "just a string",
        ],
    )
    def test_unknown_shape_is_422(self, client, captured, body):
        assert client.post("/a2a/tasks", json=body).status_code == 422
        assert captured == []

    def test_invalid_json_is_422(self, client):
        res = client.post(
            "/a2a/tasks", content=b"{oops", headers={"content-type": "application/json"}
        )
        assert res.status_code == 422

    def test_missing_rpc_handler_is_500(self, test_app):
        del test_app.state.jsonrpc_handler
        res = TestClient(test_app, headers=AUTH_HEADERS).post("/a2a/tasks", json={"message": "hi"})
        assert res.status_code == 500

    def test_handler_failure_is_a_jsonrpc_error(self, client, rpc_handler):
        async def failing(message, configuration=None):
            raise RuntimeError("down")

        rpc_handler.register_method("message/send", failing)
        res = client.post("/a2a/tasks", json=rpc_message_send())
        assert res.status_code == 200
        assert res.json()["error"]["code"] == Code.INTERNAL_ERROR


class TestInputRequired:
    """Real MessageHandler. No PR URL means no analysis, so nothing is mocked."""

    @pytest.fixture
    def real_handler_client(self, test_app, rpc_handler):
        handler = bare_handler()

        async def message_send(message, configuration=None):
            return await handler.handle_message_send(message, configuration)

        rpc_handler.register_method("message/send", message_send)
        return TestClient(test_app, headers=AUTH_HEADERS)

    def test_no_pr_url_asks_for_one(self, real_handler_client):
        res = real_handler_client.post("/a2a/tasks", json=rpc_message_send("please review my code"))
        assert res.status_code == 200
        task = res.json()["result"]
        assert task["kind"] == "task"
        assert task["status"]["state"] == "input-required"
        assert task["artifacts"] == []

    def test_plain_message_without_pr_url_asks_for_one(self, real_handler_client):
        res = real_handler_client.post("/a2a/tasks", json={"message": "hello there"})
        assert res.json()["result"]["status"]["state"] == "input-required"

    @pytest.mark.parametrize(
        "text, expected",
        [
            (f"check {PR_URL} please", PR_URL),
            ("see github.com/octo/repo/pull/7", "https://github.com/octo/repo/pull/7"),
            ("no link here", None),
        ],
    )
    def test_extract_pr_url(self, text, expected):
        assert bare_handler()._extract_pr_url(text, []) == expected

    def test_extract_pr_url_falls_back_to_history(self):
        history = [{"text": "old https://github.com/a/b/pull/1"}, {"text": f"new {PR_URL}"}]
        assert bare_handler()._extract_pr_url("no link", history) == PR_URL


def _analysis():
    from app.models.analysis import ApprovalRecommendation, CodeAnalysisResult, RiskLevel

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
        analyzed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


class TestResultPath:
    """message/send must return a result without Telex-style push config."""

    @pytest.fixture
    def handler(self, push_allowed):
        from app.utils.formatters import SummaryFormatter

        h = MessageHandler.__new__(MessageHandler)
        h.analyzer = MagicMock()
        h.analyzer.analyze_pr = AsyncMock(return_value=_analysis())
        h.formatter = SummaryFormatter()
        h._background_tasks = set()
        return h

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
        "configuration",
        [
            None,
            {},
            {"blocking": True},
            {"blocking": False},
            {"blocking": True, "pushNotificationConfig": {"url": "https://x.test"}},
        ],
    )
    async def test_no_push_or_blocking_returns_completed_task(self, handler, configuration):
        task = await handler.handle_message_send(self.message(), configuration)
        assert task["kind"] == "task"
        assert task["status"]["state"] == "completed"
        assert task["status"]["message"]["parts"][0]["text"]
        assert len(task["artifacts"]) == 1
        assert "Executive Summary" in task["artifacts"][0]["parts"][0]["text"]
        handler.analyzer.analyze_pr.assert_awaited_once_with(PR_URL)

    @pytest.mark.asyncio
    async def test_analysis_failure_returns_failed_task(self, handler):
        handler.analyzer.analyze_pr.side_effect = RuntimeError("secret detail")
        task = await handler.handle_message_send(self.message(), None)
        assert task["status"]["state"] == "failed"
        assert "secret detail" not in str(task)

    @pytest.mark.asyncio
    async def test_push_mode_returns_working_message_and_keeps_task_reference(self, handler):
        release = asyncio.Event()

        async def slow(*args, **kwargs):
            await release.wait()

        configuration = {"blocking": False, "pushNotificationConfig": {"url": "https://x.test"}}
        with patch.object(MessageHandler, "_process_and_push_safe", new=slow):
            result = await handler.handle_message_send(self.message(), configuration)
            assert result["kind"] == "message"
            handler.analyzer.analyze_pr.assert_not_called()
            assert len(handler._background_tasks) == 1  # strong reference held
            release.set()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        assert handler._background_tasks == set()  # released once done

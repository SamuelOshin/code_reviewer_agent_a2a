"""P1-23: notifications, "result": null, webhook 5xx, rate-limit flags. No network."""

import asyncio
import logging
import re
from unittest.mock import AsyncMock

import pytest

from app.llm.errors import LLMRateLimitError
from tests.test_code_analyzer import make_analyzer, run
from tests.test_p121_followups import PUSH_CONFIG, _handler_with_ok_analysis, _install_fake_webhook

# --- 1. a request without an "id" member is a notification: no reply ------------------


def test_single_notification_gets_204_no_body_and_still_runs(client, rpc_handler):
    seen = []

    async def record(**params):
        seen.append(params)
        return {"ok": True}

    rpc_handler.register_method("record", record)
    res = client.post("/rpc", json={"jsonrpc": "2.0", "method": "record", "params": {"a": 1}})
    assert res.status_code == 204
    assert res.content == b""
    assert seen == [{"a": 1}]


def test_notification_errors_are_not_answered_either(client):
    for body in (
        {"jsonrpc": "2.0", "method": "missing"},
        {"jsonrpc": "2.0", "method": "boom"},
        {"jsonrpc": "2.0", "method": "add", "params": {"a": 1}},
    ):
        res = client.post("/rpc", json=body)
        assert res.status_code == 204 and res.content == b""


def test_null_id_is_a_request_and_gets_a_reply(client):
    res = client.post("/rpc", json={"jsonrpc": "2.0", "method": "add", "params": {"a": 1, "b": 2}, "id": None})
    assert res.status_code == 200
    body = res.json()
    assert body["id"] is None and body["result"] == {"sum": 3}


def test_invalid_request_without_id_still_gets_an_error_with_null_id(client):
    res = client.post("/rpc", json={"jsonrpc": "2.0"})  # no method, no id
    assert res.status_code == 200
    body = res.json()
    assert body["error"]["code"] == -32600 and body["id"] is None and "result" not in body


def test_mixed_batch_leaves_notifications_out(client):
    res = client.post(
        "/rpc",
        json=[
            {"jsonrpc": "2.0", "method": "add", "params": {"a": 1, "b": 1}, "id": 1},
            {"jsonrpc": "2.0", "method": "add", "params": {"a": 5, "b": 5}},  # notification
            {"jsonrpc": "2.0", "method": "missing", "id": "x"},
            {"jsonrpc": "2.0", "method": "missing"},  # notification
            {"jsonrpc": "2.0", "method": "add", "params": {"a": 2, "b": 2}, "id": None},
            7,  # not a request object: Invalid Request with id null
        ],
    )
    assert res.status_code == 200
    body = res.json()
    assert [r["id"] for r in body] == [1, "x", None, None]
    assert body[0]["result"] == {"sum": 2}
    assert body[1]["error"]["code"] == -32601
    assert body[2]["result"] == {"sum": 4}
    assert body[3]["error"]["code"] == -32600


def test_all_notification_batch_gets_204(client, rpc_handler):
    seen = []

    async def record(**params):
        seen.append(params)

    rpc_handler.register_method("record", record)
    res = client.post(
        "/rpc",
        json=[{"jsonrpc": "2.0", "method": "record", "params": {"n": n}} for n in range(3)],
    )
    assert res.status_code == 204 and res.content == b""
    assert sorted(s["n"] for s in seen) == [0, 1, 2]


def test_a2a_tasks_route_follows_the_same_rule(client, rpc_handler):
    async def send(**_):
        return {"status": "submitted"}

    rpc_handler.register_method("message/send", send)
    res = client.post("/a2a/tasks", json={"jsonrpc": "2.0", "method": "message/send", "params": {}})
    assert res.status_code == 204 and res.content == b""
    res = client.post("/a2a/tasks", json={"jsonrpc": "2.0", "method": "message/send", "params": {}, "id": 5})
    assert res.status_code == 200 and res.json()["id"] == 5


# --- 2. "result": null on success; error and result never together ---------------------


def test_method_returning_none_carries_result_null_and_no_error(client, rpc_handler):
    async def nothing():
        return None

    rpc_handler.register_method("nothing", nothing)
    body = client.post("/rpc", json={"jsonrpc": "2.0", "method": "nothing", "id": 1}).json()
    assert "result" in body and body["result"] is None
    assert "error" not in body and body["id"] == 1


@pytest.mark.parametrize(
    "request_data",
    [
        {"jsonrpc": "2.0", "method": "missing", "id": 1},
        {"jsonrpc": "2.0", "method": "boom", "id": 1},
        {"jsonrpc": "2.0", "method": "add", "id": 1},
        {"jsonrpc": "2.0", "id": 1},
        {"jsonrpc": "1.0", "method": "add", "id": 1},
    ],
)
def test_error_responses_have_no_result_key(rpc_handler, request_data):
    out = asyncio.run(rpc_handler.handle_request(request_data))
    assert "error" in out and "result" not in out and "id" in out


# --- 3. webhook 5xx before storing: no overwrite, logged with an error id --------------


def test_webhook_5xx_posts_nothing_more_and_logs_status_and_error_id(monkeypatch, caplog):
    sent = _install_fake_webhook(monkeypatch, [503, 200])
    with caplog.at_level(logging.WARNING):
        asyncio.run(_handler_with_ok_analysis()._process_and_push("u", "t1", "m1", {}, PUSH_CONFIG))
    assert len(sent) == 1  # no "failed" post that could overwrite a stored result
    line = next(r.getMessage() for r in caplog.records if "Not pushing an error after" in r.getMessage())
    assert "503" in line and re.search(r"error_id=\w+", line)


# --- 4. the rate-limit lead-in comes from per-step flags --------------------------------


async def _result_with(security, performance, best_practices):
    analyzer, github, llm = make_analyzer()
    llm.analyze_security = AsyncMock(side_effect=security)
    llm.analyze_performance = AsyncMock(side_effect=performance)
    llm.analyze_best_practices = AsyncMock(side_effect=best_practices)
    llm.generate_summary = AsyncMock(return_value="Model prose.")
    return await run(analyzer, github)


@pytest.mark.asyncio
async def test_lead_in_appears_when_every_step_was_rate_limited():
    boom = LLMRateLimitError("x")
    result = await _result_with(boom, boom, boom)
    assert result.executive_summary.startswith("The model was rate-limited")


@pytest.mark.asyncio
async def test_no_lead_in_when_one_step_failed_for_another_reason():
    boom = LLMRateLimitError("x")
    result = await _result_with(boom, boom, RuntimeError("y"))
    assert not result.executive_summary.startswith("The model was rate-limited")


@pytest.mark.asyncio
async def test_no_lead_in_when_one_step_succeeded():
    boom = LLMRateLimitError("x")
    result = await _result_with(boom, boom, lambda *a, **k: [])
    assert not result.executive_summary.startswith("The model was rate-limited")

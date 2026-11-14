"""P1-24: notifications that need a reply, required "jsonrpc", explicit answer flag,
non-object bodies. No network."""

import asyncio

import pytest

from app.main import message_send_needs_reply
from app.services.jsonrpc_handler import JSONRPCHandler

BLOCKING_PARAMS = {"message": {"parts": []}}
PUSH_PARAMS = {
    "message": {"parts": []},
    "configuration": {"blocking": False, "pushNotificationConfig": {"url": "https://hook.example"}},
}


def _register_send(rpc_handler):
    calls = []

    async def send(**params):
        calls.append(params)
        return {"status": "submitted"}

    rpc_handler.register_method("message/send", send, reply_required=message_send_needs_reply)
    return calls


# --- 1. an id-less call that only replies with its result is rejected -------------------


@pytest.mark.parametrize("route", ["/rpc", "/a2a/tasks"])
def test_idless_blocking_message_send_is_rejected_before_running(client, rpc_handler, route):
    calls = _register_send(rpc_handler)
    res = client.post(route, json={"jsonrpc": "2.0", "method": "message/send", "params": BLOCKING_PARAMS})
    assert res.status_code == 200
    body = res.json()
    assert body["error"]["code"] == -32600
    assert body["id"] is None
    assert "id" in body["error"]["message"]
    assert calls == []  # no review ran


@pytest.mark.parametrize(
    "configuration",
    [None, {}, {"blocking": True}, {"blocking": False}, {"blocking": True, "pushNotificationConfig": {"url": "x"}}],
)
def test_message_send_needs_a_reply_unless_it_pushes(configuration):
    params = {"message": {}} if configuration is None else {"message": {}, "configuration": configuration}
    assert message_send_needs_reply(params) is True


def test_idless_non_blocking_push_message_send_stays_a_notification(client, rpc_handler):
    calls = _register_send(rpc_handler)
    res = client.post("/rpc", json={"jsonrpc": "2.0", "method": "message/send", "params": PUSH_PARAMS})
    assert res.status_code == 204 and res.content == b""
    assert len(calls) == 1


def test_message_send_with_an_id_still_replies(client, rpc_handler):
    _register_send(rpc_handler)
    res = client.post("/rpc", json={"jsonrpc": "2.0", "method": "message/send", "params": BLOCKING_PARAMS, "id": 3})
    body = res.json()
    assert body["id"] == 3 and body["result"]["status"] == "submitted" and "error" not in body


def test_idless_blocking_call_in_a_batch_gets_its_error(client, rpc_handler):
    calls = _register_send(rpc_handler)
    res = client.post(
        "/rpc",
        json=[
            {"jsonrpc": "2.0", "method": "message/send", "params": BLOCKING_PARAMS},
            {"jsonrpc": "2.0", "method": "message/send", "params": BLOCKING_PARAMS, "id": 1},
        ],
    )
    out = res.json()
    assert [(r["id"], r.get("error", {}).get("code")) for r in out] == [(None, -32600), (1, None)]
    assert len(calls) == 1


# --- 2. "jsonrpc" is required -----------------------------------------------------------


@pytest.mark.parametrize("body", [{"method": "record"}, {"method": "record", "id": 4}])
def test_body_without_jsonrpc_is_an_invalid_request(client, rpc_handler, body):
    ran = []

    async def record():
        ran.append(1)
        return "ok"

    rpc_handler.register_method("record", record)
    res = client.post("/rpc", json=body)
    assert res.status_code == 200
    assert res.json()["error"]["code"] == -32600
    assert res.json()["id"] == body.get("id")
    assert ran == []


def test_simple_a2a_message_form_still_works(client, rpc_handler):
    calls = _register_send(rpc_handler)
    res = client.post("/a2a/tasks", json={"message": "review https://github.com/o/r/pull/1"})
    assert res.status_code == 200
    assert res.json()["result"]["status"] == "submitted"
    assert len(calls) == 1


# --- 3. the "answer anyway" decision is explicit, not inferred from the error code ------


def test_notification_whose_method_error_uses_32600_gets_no_reply():
    from app.core.errors import ClientInputError

    handler = JSONRPCHandler()

    async def boom():
        raise ClientInputError("bad")

    handler.register_method("boom", boom)
    # Simulate a method error mapped to -32600 by patching the error code used for it
    from app.models import jsonrpc as models

    original = models.JSONRPCErrorCode.INVALID_PARAMS
    models.JSONRPCErrorCode.INVALID_PARAMS = models.JSONRPCErrorCode.INVALID_REQUEST
    try:
        out = asyncio.run(handler.handle_request({"jsonrpc": "2.0", "method": "boom"}))
        replied = asyncio.run(handler.handle_request({"jsonrpc": "2.0", "method": "boom", "id": 1}))
    finally:
        models.JSONRPCErrorCode.INVALID_PARAMS = original
    assert out is None
    assert replied["error"]["code"] == -32600  # the method error really used -32600


# --- 4. a body that is neither an object nor an array -----------------------------------


@pytest.mark.parametrize("body", ["42", '"x"', "true", "null", "1.5"])
def test_non_object_body_is_an_invalid_request(client, body):
    res = client.post("/rpc", content=body, headers={"Content-Type": "application/json"})
    assert res.status_code == 200
    assert res.json()["error"]["code"] == -32600
    assert res.json()["id"] is None


# --- review round 1 ---------------------------------------------------------------------


@pytest.mark.parametrize("blocking", [False, 0, None, ""])
def test_any_falsy_blocking_with_push_is_treated_as_a_push_like_the_handler(blocking):
    # Bobby Review: the handler pushes on `not is_blocking and push_config`
    params = {"message": {}, "configuration": {"blocking": blocking, "pushNotificationConfig": {"url": "x"}}}
    assert message_send_needs_reply(params) is False


def test_rejection_hint_is_per_method(client, rpc_handler):
    async def analyze(**_):
        return {}

    rpc_handler.register_method("analyze_pr", analyze, reply_required=lambda _p: True)
    _register_send(rpc_handler)
    rpc_handler.register_method(
        "message/send",
        rpc_handler._methods["message/send"],
        reply_required=message_send_needs_reply,
        reply_hint="Or send it non-blocking with a pushNotificationConfig.",
    )
    a = client.post("/rpc", json={"jsonrpc": "2.0", "method": "analyze_pr", "params": {}}).json()
    m = client.post("/rpc", json={"jsonrpc": "2.0", "method": "message/send", "params": BLOCKING_PARAMS}).json()
    assert "push" not in a["error"]["message"].lower()
    assert "pushNotificationConfig" in m["error"]["message"]

"""P1-25: rejected calls are answered before a batch slot, escaped method logs,
non-object configuration, the real app's reply hints. No network."""

import asyncio
import logging

import pytest

from app.core.config import settings
from app.main import register_rpc_methods
from app.services.jsonrpc_handler import BATCH_CONCURRENCY, JSONRPCHandler


def _busy_batch(handler, calls):
    """Hold every batch slot, then send `calls` as a second batch."""
    release = asyncio.Event()

    async def hold():
        await release.wait()
        return "ok"

    handler.register_method("hold", hold)

    async def main():
        holders = asyncio.create_task(
            handler.handle_batch(
                [{"jsonrpc": "2.0", "method": "hold", "id": i} for i in range(BATCH_CONCURRENCY)]
            )
        )
        await asyncio.sleep(0.01)
        out = await handler.handle_batch(calls)
        release.set()
        await holders
        return out

    return asyncio.run(main())


# --- 1. a call that would be rejected is answered even in a busy batch ------------------


def test_rejected_idless_calls_are_answered_in_a_busy_batch(monkeypatch):
    monkeypatch.setattr(settings, "A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)
    handler = JSONRPCHandler()
    ran = []

    async def review(**_):
        ran.append(1)
        return {}

    handler.register_method("analyze_pr", review, reply_required=lambda _p: True)
    out = _busy_batch(
        handler,
        [
            {"jsonrpc": "2.0", "method": "analyze_pr"},  # needs a reply
            {"method": "introspect"},  # no "jsonrpc"
            {"jsonrpc": "2.0"},  # no method
            {"jsonrpc": "2.0", "method": "analyze_pr", "id": 3},  # valid, gets no slot
        ],
    )
    assert [(r["id"], r["error"]["code"]) for r in out] == [
        (None, -32600),
        (None, -32600),
        (None, -32600),
        (3, -32004),
    ]
    assert ran == []


def test_a_valid_notification_in_a_busy_batch_is_still_dropped(monkeypatch):
    monkeypatch.setattr(settings, "A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)
    handler = JSONRPCHandler()
    handler.register_method("note", lambda: None)
    assert _busy_batch(handler, [{"jsonrpc": "2.0", "method": "note"}]) == []


# --- 2. client method names are logged escaped and capped -------------------------------


def test_method_name_is_logged_escaped_and_capped(caplog):
    handler = JSONRPCHandler()
    name = "x\nFAKE LOG LINE " + "A" * 500
    with caplog.at_level(logging.INFO):
        asyncio.run(handler.handle_request({"jsonrpc": "2.0", "method": name, "id": 1}))
    lines = [r.getMessage() for r in caplog.records if "JSON-RPC request" in r.getMessage() or "Method not found" in r.getMessage()]
    assert len(lines) == 2
    for line in lines:
        assert "\n" not in line
        assert "A" * 200 not in line


# --- 3. a non-object configuration is Invalid params ------------------------------------


@pytest.mark.parametrize("configuration", ["x", [1], 5])
def test_non_object_configuration_is_invalid_params(configuration):
    from app.services.message_handler import MessageHandler

    handler = JSONRPCHandler()
    message_handler = MessageHandler.__new__(MessageHandler)
    handler.register_method("message/send", message_handler.handle_message_send)
    out = asyncio.run(
        handler.handle_request(
            {
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {"message": {"parts": []}, "configuration": configuration},
                "id": 1,
            }
        )
    )
    assert out["error"]["code"] == -32602
    assert out["error"]["message"] == "configuration must be an object"


# --- 4. the real app's reply hints ------------------------------------------------------


def test_real_app_registers_reply_rules_and_hints():
    handler = JSONRPCHandler()
    asyncio.run(register_rpc_methods(handler))
    assert set(handler._reply_required) == {"analyze_pr", "message/send"}
    assert "analyze_pr" not in handler._reply_hints
    assert "pushNotificationConfig" in handler._reply_hints["message/send"]
    assert handler._reply_required["analyze_pr"]({}) is True
    assert handler._reply_required["message/send"]({"message": {}}) is True


def test_batch_survives_a_failing_precheck_with_a_malformed_id(monkeypatch):
    # Bobby Review: if _precheck itself raises, run_one falls through to the slot wait;
    # the batch must still answer every call, echoing only a valid id (P1-21 guard)
    monkeypatch.setattr(settings, "A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)
    handler = JSONRPCHandler()
    handler.register_method("ok", lambda: "ok")
    original = handler._precheck
    calls = {"n": 0}

    def flaky(request_data):
        calls["n"] += 1
        if isinstance(request_data, dict) and request_data.get("method") == "ok":
            raise RuntimeError("precheck broke")
        return original(request_data)

    monkeypatch.setattr(handler, "_precheck", flaky)
    out = _busy_batch(
        handler,
        [
            {"jsonrpc": "2.0", "method": "ok", "id": {"a": 1}},
            {"jsonrpc": "2.0", "method": "ok", "id": 7},
        ],
    )
    assert [(r.get("id"), r["error"]["code"]) for r in out] == [(None, -32004), (7, -32004)]
    assert calls["n"] >= 2

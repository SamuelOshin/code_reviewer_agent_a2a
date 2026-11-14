"""P1-26: escaped client ids in logs, non-object message, capped method name in the
reply, one pre-check per batch call. No network."""

import asyncio
import logging

import pytest

from app.services.jsonrpc_handler import JSONRPCHandler
from app.services.message_handler import MessageHandler


def _send_handler():
    handler = JSONRPCHandler()
    message_handler = MessageHandler.__new__(MessageHandler)
    handler.register_method("message/send", message_handler.handle_message_send)
    return handler


# --- 1. client message and task ids are logged escaped and capped -----------------------


def test_message_id_with_a_newline_is_logged_escaped(caplog):
    handler = _send_handler()
    forged = "m\nINJECTED-MSGID " + "B" * 500
    with caplog.at_level(logging.INFO):
        asyncio.run(
            handler.handle_request(
                {
                    "jsonrpc": "2.0",
                    "method": "message/send",
                    "params": {"message": {"messageId": forged, "parts": []}},
                    "id": 1,
                }
            )
        )
    lines = [r.getMessage() for r in caplog.records if "Handling message/send" in r.getMessage()]
    assert lines
    for line in lines:
        assert "\n" not in line and "B" * 200 not in line


# --- 2. a non-object message is Invalid params -------------------------------------------


@pytest.mark.parametrize("message", ["x", [1], 5, None, True])
def test_non_object_message_is_invalid_params(message):
    out = asyncio.run(
        _send_handler().handle_request(
            {"jsonrpc": "2.0", "method": "message/send", "params": {"message": message}, "id": 1}
        )
    )
    assert out["error"]["code"] == -32602
    assert out["error"]["message"] == "message must be an object"


# --- 3. an unknown method name is capped in the reply -----------------------------------


def test_unknown_method_name_is_capped_in_the_reply():
    name = "m" * 3000
    out = asyncio.run(JSONRPCHandler().handle_request({"jsonrpc": "2.0", "method": name, "id": 1}))
    assert out["error"]["code"] == -32601
    assert len(out["error"]["message"]) < 150
    assert out["error"]["message"].endswith("...")


def test_short_unknown_method_name_is_echoed_whole():
    out = asyncio.run(JSONRPCHandler().handle_request({"jsonrpc": "2.0", "method": "nope", "id": 1}))
    assert out["error"]["message"] == "Method not found: nope"


# --- 4. a batch call is pre-checked once ------------------------------------------------


def test_reply_required_runs_once_per_batch_call():
    handler = JSONRPCHandler()
    seen = []

    def needs_reply(params):
        seen.append(params)
        return False

    async def note(**_):
        return "ok"

    handler.register_method("note", note, reply_required=needs_reply)
    asyncio.run(
        handler.handle_batch(
            [
                {"jsonrpc": "2.0", "method": "note", "params": {"n": 1}},
                {"jsonrpc": "2.0", "method": "note", "params": {"n": 2}},
            ]
        )
    )
    assert sorted(p["n"] for p in seen) == [1, 2]

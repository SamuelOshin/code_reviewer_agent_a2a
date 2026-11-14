"""P2-10: wrong shapes inside an object message get -32602, not -32603. No network."""

import asyncio

import pytest

from app.services.jsonrpc_handler import JSONRPCHandler
from app.services.message_handler import MessageHandler


def _send(message):
    handler = JSONRPCHandler()
    message_handler = MessageHandler.__new__(MessageHandler)
    handler.register_method("message/send", message_handler.handle_message_send)
    return asyncio.run(
        handler.handle_request(
            {"jsonrpc": "2.0", "method": "message/send", "params": {"message": message}, "id": 1}
        )
    )


@pytest.mark.parametrize(
    ("message", "text"),
    [
        ({"parts": "abc"}, "message.parts must be an array"),
        ({"parts": {"kind": "text"}}, "message.parts must be an array"),
        ({"parts": ["a"]}, "each message part must be an object"),
        ({"parts": [{"kind": "text", "text": "x"}, 5]}, "each message part must be an object"),
        ({"parts": [{"kind": "text", "text": 5}]}, "a text part's text must be a string"),
        ({"parts": [{"kind": "text", "text": "x"}, {"kind": "data", "data": "y"}]}, "a data part's data must be an array"),
        ({"taskId": ["t"], "parts": []}, "messageId and taskId must be strings"),
        ({"messageId": 5, "parts": []}, "messageId and taskId must be strings"),
    ],
)
def test_wrong_shapes_are_invalid_params(message, text):
    out = _send(message)
    assert out["error"]["code"] == -32602
    assert out["error"]["message"] == text


def test_well_formed_message_still_reaches_the_url_check():
    # No PR URL in the text: the handler asks for one instead of failing
    out = _send({"parts": [{"kind": "text", "text": "hello"}, {"kind": "data", "data": []}]})
    assert "error" not in out
    assert out["result"]["status"]["state"] == "input-required"

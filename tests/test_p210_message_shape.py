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
        ({"contextId": 5, "parts": []}, "contextId must be a string"),
        ({"contextId": ["c"], "parts": []}, "contextId must be a string"),
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


@pytest.mark.parametrize(
    "message",
    [
        # A2A allows any JSON value in a data part; a non-array just means no history
        {"parts": [{"kind": "text", "text": "hello"}, {"kind": "data", "data": {"k": "v"}}]},
        {"parts": [{"kind": "text", "text": "hello"}, {"kind": "data", "data": "y"}]},
        # taskId and contextId are optional; a null from a serializer means unset
        {"taskId": None, "contextId": None, "parts": [{"kind": "text", "text": "hello"}]},
    ],
)
def test_spec_valid_shapes_are_accepted(message):
    out = _send(message)
    assert "error" not in out
    assert out["result"]["status"]["state"] == "input-required"


def test_null_context_id_completes_a_blocking_review():
    # It used to pass the shape stage and fail only when the task was built, after
    # the review had run (-32603)
    from app.utils.formatters import SummaryFormatter
    from tests.test_webhooks import make_result

    handler = JSONRPCHandler()
    message_handler = MessageHandler.__new__(MessageHandler)
    message_handler.formatter = SummaryFormatter()
    message_handler._background_tasks = set()

    class Analyzer:
        async def analyze_pr(self, url):
            return make_result()

    message_handler.analyzer = Analyzer()
    handler.register_method("message/send", message_handler.handle_message_send)
    message = {
        "contextId": None,
        "parts": [{"kind": "text", "text": "review https://github.com/o/r/pull/1"}],
    }
    out = asyncio.run(
        handler.handle_request(
            {"jsonrpc": "2.0", "method": "message/send", "params": {"message": message}, "id": 1}
        )
    )
    assert "error" not in out
    assert isinstance(out["result"]["contextId"], str)


def test_bad_context_id_is_rejected_before_any_review():
    calls = []
    handler = JSONRPCHandler()
    message_handler = MessageHandler.__new__(MessageHandler)

    class Analyzer:
        async def analyze_pr(self, url):
            calls.append(url)

    message_handler.analyzer = Analyzer()
    handler.register_method("message/send", message_handler.handle_message_send)
    message = {"contextId": 5, "parts": [{"kind": "text", "text": "https://github.com/o/r/pull/1"}]}
    out = asyncio.run(
        handler.handle_request(
            {"jsonrpc": "2.0", "method": "message/send", "params": {"message": message}, "id": 1}
        )
    )
    assert out["error"]["code"] == -32602
    assert calls == []

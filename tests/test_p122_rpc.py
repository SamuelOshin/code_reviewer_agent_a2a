"""P1-22: "id": null on every response and integral float ids. No network."""

import asyncio

import pytest

from app.services.jsonrpc_handler import JSONRPCHandler

# --- 4 and 5. "id": null on every response, integral float id on slot timeout ------------


def _handler():
    h = JSONRPCHandler()

    async def ok(**_):
        return {"x": 1}

    h.register_method("ok", ok)
    return h


@pytest.mark.parametrize(
    "request_data",
    [
        {"jsonrpc": "2.0", "method": "nope"},  # no id
        {"jsonrpc": "1.0", "method": "ok", "id": 1},
        {"jsonrpc": "2.0", "id": {"a": 1}},  # no method, unreadable id
        {"jsonrpc": "2.0", "method": "ok", "id": [1], "params": {}},
        "not an object",
    ],
)
def test_error_responses_always_carry_id(request_data):
    out = asyncio.run(_handler().handle_request(request_data))
    assert "error" in out and "result" not in out
    assert out["jsonrpc"] == "2.0"
    assert "id" in out


def test_unreadable_id_is_null_and_readable_id_is_echoed():
    h = _handler()
    assert asyncio.run(h.handle_request({"jsonrpc": "2.0", "id": {"a": 1}}))["id"] is None
    assert asyncio.run(h.handle_request({"jsonrpc": "2.0", "method": "nope"}))["id"] is None
    assert asyncio.run(h.handle_request({"jsonrpc": "2.0", "method": "nope", "id": "a"}))["id"] == "a"
    assert asyncio.run(h.handle_request({"jsonrpc": "2.0", "id": 1.0}))["id"] == 1


def test_success_response_without_id_carries_null_and_no_error_key():
    out = asyncio.run(_handler().handle_request({"jsonrpc": "2.0", "method": "ok"}))
    assert out["id"] is None and out["result"] == {"x": 1}
    assert "error" not in out


@pytest.mark.parametrize(
    ("raw", "echoed"),
    [(1.0, 1), (7, 7), ("a", "a"), (1.5, None), (True, None), ({"a": 1}, None), ([1], None), (None, None)],
)
def test_batch_slot_timeout_id(monkeypatch, raw, echoed):
    from app.core.config import settings
    from app.services import jsonrpc_handler as jh

    monkeypatch.setattr(settings, "A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)

    async def go():
        sem = jh._batch_semaphore()
        held = [await sem.acquire() for _ in range(jh.BATCH_CONCURRENCY)]
        try:
            return await _handler().handle_batch([{"jsonrpc": "2.0", "method": "ok", "id": raw}])
        finally:
            for _ in held:
                sem.release()

    (out,) = asyncio.run(go())
    assert out["error"]["code"] == -32004
    assert out["id"] == echoed and "result" not in out
    if isinstance(raw, float) and echoed is not None:
        assert isinstance(out["id"], int)


@pytest.mark.parametrize("bool_id", [True, False])
def test_bool_id_is_invalid_with_null_id_on_the_normal_path(bool_id):
    # Bobby Review: lax mode turned true/false into 1/0 on the normal path, while the
    # slot-timeout path dropped them. A bool is not a JSON-RPC id on either path.
    out = asyncio.run(_handler().handle_request({"jsonrpc": "2.0", "method": "ok", "id": bool_id}))
    assert out["error"]["code"] == -32600
    assert out["id"] is None

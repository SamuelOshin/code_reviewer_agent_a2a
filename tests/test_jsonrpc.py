# tests/test_jsonrpc.py

"""JSON-RPC handler and the /rpc endpoint.

Assertions use status codes, JSON-RPC error codes and response structure, never
error message text, because messages are being reworked (P1-08).
"""

import pytest
from fastapi.testclient import TestClient

from app.models.jsonrpc import JSONRPCErrorCode as Code


def call(client: TestClient, body):
    response = client.post("/rpc", json=body)
    assert response.status_code == 200
    return response.json()


class TestHandler:
    @pytest.mark.asyncio
    async def test_success_with_dict_params(self, rpc_handler):
        res = await rpc_handler.handle_request(
            {"jsonrpc": "2.0", "method": "add", "params": {"a": 2, "b": 3}, "id": 1}
        )
        assert res == {"jsonrpc": "2.0", "result": {"sum": 5}, "id": 1}

    @pytest.mark.asyncio
    async def test_string_id_is_echoed(self, rpc_handler):
        res = await rpc_handler.handle_request(
            {"jsonrpc": "2.0", "method": "echo", "params": {}, "id": "abc"}
        )
        assert res["id"] == "abc"

    @pytest.mark.asyncio
    async def test_method_not_found_lists_available_methods(self, rpc_handler):
        res = await rpc_handler.handle_request({"jsonrpc": "2.0", "method": "nope", "id": 7})
        assert res["error"]["code"] == Code.METHOD_NOT_FOUND
        assert res["id"] == 7
        assert set(res["error"]["data"]["available_methods"]) == set(rpc_handler.list_methods())

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad",
        [
            {"jsonrpc": "1.0", "method": "echo", "id": 1},  # wrong version
            {"jsonrpc": "2.0", "id": 1},  # no method
            {"jsonrpc": "2.0", "method": 5, "id": 1},  # method not a string
            {"jsonrpc": "2.0", "method": "echo", "params": [1, 2], "id": 1},  # list params
        ],
    )
    async def test_invalid_request(self, rpc_handler, bad):
        res = await rpc_handler.handle_request(bad)
        assert res["error"]["code"] == Code.INVALID_REQUEST

    @pytest.mark.asyncio
    async def test_wrong_param_names_is_invalid_params(self, rpc_handler):
        res = await rpc_handler.handle_request(
            {"jsonrpc": "2.0", "method": "add", "params": {"x": 1}, "id": 1}
        )
        assert res["error"]["code"] == Code.INVALID_PARAMS

    @pytest.mark.asyncio
    async def test_handler_exception_is_internal_error(self, rpc_handler):
        res = await rpc_handler.handle_request({"jsonrpc": "2.0", "method": "boom", "id": 1})
        assert res["error"]["code"] == Code.INTERNAL_ERROR
        assert res["id"] == 1
        assert "result" not in res

    @pytest.mark.asyncio
    async def test_task_like_result_gets_kind(self, rpc_handler):
        res = await rpc_handler.handle_request({"jsonrpc": "2.0", "method": "task_like", "id": 1})
        assert res["result"]["kind"] == "task"

    @pytest.mark.asyncio
    async def test_batch_returns_one_response_per_request_in_order(self, rpc_handler):
        res = await rpc_handler.handle_batch(
            [
                {"jsonrpc": "2.0", "method": "add", "params": {"a": 1, "b": 1}, "id": 1},
                {"jsonrpc": "2.0", "method": "nope", "id": 2},
                {"jsonrpc": "2.0", "method": "boom", "id": 3},
            ]
        )
        assert [r["id"] for r in res] == [1, 2, 3]
        assert res[0]["result"] == {"sum": 2}
        assert res[1]["error"]["code"] == Code.METHOD_NOT_FOUND
        assert res[2]["error"]["code"] == Code.INTERNAL_ERROR

    def test_register_unregister_and_introspect(self, rpc_handler):
        async def extra():
            return 1

        rpc_handler.register_method("extra", extra)
        assert "extra" in rpc_handler.list_methods()
        assert rpc_handler.introspect()["count"] == len(rpc_handler.list_methods())
        rpc_handler.unregister_method("extra")
        assert "extra" not in rpc_handler.list_methods()
        rpc_handler.unregister_method("never-registered")  # no-op, no error


class TestRpcEndpoint:
    def test_single_request(self, client):
        res = call(client, {"jsonrpc": "2.0", "method": "add", "params": {"a": 4, "b": 5}, "id": 1})
        assert res["result"] == {"sum": 9}

    def test_parse_error(self, client):
        response = client.post(
            "/rpc", content=b"{not json", headers={"content-type": "application/json"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["error"]["code"] == Code.PARSE_ERROR
        assert body["id"] is None

    def test_invalid_request(self, client):
        res = call(client, {"jsonrpc": "2.0", "id": 1})
        assert res["error"]["code"] == Code.INVALID_REQUEST

    def test_method_not_found(self, client):
        res = call(client, {"jsonrpc": "2.0", "method": "missing", "id": 1})
        assert res["error"]["code"] == Code.METHOD_NOT_FOUND

    def test_batch(self, client):
        res = call(
            client,
            [
                {"jsonrpc": "2.0", "method": "add", "params": {"a": 1, "b": 2}, "id": 1},
                {"jsonrpc": "2.0", "method": "missing", "id": 2},
            ],
        )
        assert isinstance(res, list) and len(res) == 2
        assert res[0]["result"] == {"sum": 3}
        assert res[1]["error"]["code"] == Code.METHOD_NOT_FOUND

    def test_non_object_body_returns_an_error_object(self, client):
        # A bare JSON string is not a valid request. The endpoint must answer
        # with a JSON-RPC error and not crash.
        res = call(client, "hello")
        assert "error" in res and "result" not in res

    def test_missing_handler_in_app_state_is_http_500(self, test_app):
        del test_app.state.jsonrpc_handler
        response = TestClient(test_app).post("/rpc", json={"jsonrpc": "2.0", "method": "x", "id": 1})
        assert response.status_code == 500


class TestRealApp:
    """The production app with its lifespan: registered methods and introspect."""

    @pytest.fixture
    def real_client(self):
        from app.main import app

        with TestClient(app) as c:
            yield c

    def test_introspect_lists_registered_methods(self, real_client):
        res = call(real_client, {"jsonrpc": "2.0", "method": "introspect", "id": 1})
        result = res["result"]
        assert {"analyze_pr", "introspect", "message/send"} <= set(result["methods"])
        assert result["count"] == len(result["methods"])
        assert result["version"] == "2.0"

    def test_agent_card_is_served(self, real_client):
        response = real_client.get("/.well-known/agent.json")
        assert response.status_code == 200
        assert "name" in response.json()

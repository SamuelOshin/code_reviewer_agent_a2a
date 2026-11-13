# tests/test_llm_contract.py

"""Contract tests for the model layer (tracker section 4, P1-05).

The same checks run against every adapter the factory can build. Each adapter is
the real Pydantic AI model and provider SDK, built from settings by
`app.llm.build_client`. Only the network is replaced: an `httpx2.MockTransport`
answers with canned responses in each provider's own wire format, so the SDK's
request building and response parsing really run. Nothing leaves the machine.
"""

import json
from types import SimpleNamespace

import httpx2
import pytest
from pydantic import BaseModel

from app.llm import (
    LLMAuthError,
    LLMConfigurationError,
    LLMContextLengthError,
    LLMOutputError,
    LLMRateLimitError,
    LLMUnavailableError,
    ModelSpec,
    Role,
    build_client,
)
from app.llm.factory import role_chain

PROVIDERS = ["google", "openai", "anthropic", "openai-compatible"]
MODEL_ID = "test-model"  # fake ID: no real model is ever called here


def make_settings(provider: str, **overrides) -> SimpleNamespace:
    values = dict(
        LLM_MODEL=f"{provider}:{MODEL_ID}",
        LLM_MODEL_SECURITY="",
        LLM_MODEL_PERFORMANCE="",
        LLM_MODEL_BEST_PRACTICES="",
        LLM_MODEL_SUMMARY="",
        LLM_FALLBACK_MODELS="",
        LLM_STRUCTURED_OUTPUT_MODE="auto",
        LLM_TEMPERATURE=0.0,
        LLM_MAX_TOKENS=256,
        LLM_MAX_RETRIES=0,
        LLM_TIMEOUT_SECONDS=10.0,
        OPENAI_API_KEY="test-key",
        ANTHROPIC_API_KEY="test-key",
        GOOGLE_API_KEY="test-key",
        OPENAI_COMPATIBLE_BASE_URL="http://llm.test/v1",
        OPENAI_COMPATIBLE_API_KEY="",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


# --- canned provider responses ---------------------------------------------------

USAGE_IN, USAGE_OUT = 11, 7


def text_body(provider: str, text: str) -> dict:
    if provider == "google":
        return {
            "candidates": [{"content": {"role": "model", "parts": [{"text": text}]},
                            "finishReason": "STOP", "index": 0}],
            "usageMetadata": {"promptTokenCount": USAGE_IN, "candidatesTokenCount": USAGE_OUT,
                              "totalTokenCount": USAGE_IN + USAGE_OUT},
            "modelVersion": MODEL_ID, "responseId": "r1",
        }
    if provider == "openai":
        return {
            "id": "resp_1", "object": "response", "created_at": 1, "status": "completed",
            "model": MODEL_ID,
            "output": [{"type": "message", "id": "msg_1", "status": "completed",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": text, "annotations": []}]}],
            "usage": {"input_tokens": USAGE_IN, "output_tokens": USAGE_OUT,
                      "total_tokens": USAGE_IN + USAGE_OUT,
                      "input_tokens_details": {"cached_tokens": 0},
                      "output_tokens_details": {"reasoning_tokens": 0}},
            "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
        }
    if provider == "anthropic":
        return {
            "id": "msg_1", "type": "message", "role": "assistant", "model": MODEL_ID,
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": USAGE_IN, "output_tokens": USAGE_OUT},
        }
    return {  # openai-compatible: Chat Completions
        "id": "c1", "object": "chat.completion", "created": 1, "model": MODEL_ID,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": USAGE_IN, "completion_tokens": USAGE_OUT,
                  "total_tokens": USAGE_IN + USAGE_OUT},
    }


def tool_call_body(provider: str, name: str, args: dict) -> dict:
    if provider == "google":
        body = text_body(provider, "")
        body["candidates"][0]["content"]["parts"] = [{"functionCall": {"name": name, "args": args}}]
        return body
    if provider == "openai":
        body = text_body(provider, "")
        body["output"] = [{"type": "function_call", "id": "fc_1", "call_id": "call_1",
                           "name": name, "arguments": json.dumps(args), "status": "completed"}]
        return body
    if provider == "anthropic":
        body = text_body(provider, "")
        body["content"] = [{"type": "tool_use", "id": "toolu_1", "name": name, "input": args}]
        body["stop_reason"] = "tool_use"
        return body
    body = text_body(provider, "")
    body["choices"][0]["message"] = {
        "role": "assistant", "content": None,
        "tool_calls": [{"id": "call_1", "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)}}],
    }
    body["choices"][0]["finish_reason"] = "tool_calls"
    return body


def error_body(provider: str, status: int, message: str, kind: str) -> dict:
    if provider == "google":
        names = {400: "INVALID_ARGUMENT", 401: "UNAUTHENTICATED", 429: "RESOURCE_EXHAUSTED",
                 503: "UNAVAILABLE"}
        return {"error": {"code": status, "message": message, "status": names[status]}}
    if provider == "anthropic":
        return {"type": "error", "error": {"type": kind, "message": message}}
    return {"error": {"message": message, "type": kind, "code": kind}}


ERRORS = {
    "rate_limit": (429, "rate_limit_error", "Rate limit reached, slow down"),
    "auth": (401, "authentication_error", "Invalid API key"),
    "unavailable": (503, "overloaded_error", "The service is temporarily unavailable"),
}

CONTEXT_ERRORS = {
    "google": "The input token count (2000000) exceeds the maximum number of tokens "
              "allowed (1048576).",
    "openai": "This model's maximum context length is 128000 tokens. However, your "
              "messages resulted in 200000 tokens.",
    "anthropic": "prompt is too long: 250000 tokens > 200000 maximum",
    "openai-compatible": "This model's maximum context length is 8192 tokens. However, "
                         "your messages resulted in 20000 tokens.",
}


class Scripted:
    """A mock HTTP transport that answers requests from a script, in order."""

    def __init__(self, *responses: tuple[int, dict]):
        self.responses = list(responses)
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        assert self.responses, f"unexpected extra request to {request.url}"
        status, body = self.responses.pop(0)
        return httpx2.Response(status, json=body, headers={"retry-after": "0"})

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self), timeout=30)

    def body(self, index: int) -> str:
        return self.requests[index].content.decode()


def client_for(provider: str, script: Scripted, **overrides):
    return build_client(make_settings(provider, **overrides), http_client=script.client())


class Finding(BaseModel):
    title: str
    line: int


class Findings(BaseModel):
    findings: list[Finding]


def structured_reply(provider: str, client, data: dict) -> dict:
    """Answer the way the chosen output mode expects: JSON text, or the output tool."""
    caps = client.capabilities(Role.SECURITY)
    if caps.native_structured_output:
        return text_body(provider, json.dumps(data))
    return tool_call_body(provider, "final_result", data)


# --- the contract ---------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("provider", PROVIDERS)
class TestAdapterContract:

    async def test_text_output_and_usage(self, provider):
        script = Scripted((200, text_body(provider, "LGTM")))
        client = client_for(provider, script)

        result = await client.generate(Role.SUMMARY, "Summarize", instructions="Be brief")

        assert result.output == "LGTM"
        assert result.model == f"{provider}:{MODEL_ID}"
        assert result.usage.input_tokens == USAGE_IN
        assert result.usage.output_tokens == USAGE_OUT
        assert result.usage.total_tokens == USAGE_IN + USAGE_OUT
        assert result.usage.requests == 1
        assert result.usage.latency_ms >= 0
        assert result.usage.cost_usd is None or result.usage.cost_usd >= 0
        assert "Be brief" in script.body(0)
        assert "Summarize" in script.body(0)

    async def test_structured_output_is_validated(self, provider):
        script = Scripted()
        client = client_for(provider, script)
        data = {"findings": [{"title": "SQL injection", "line": 3}]}
        script.responses.append((200, structured_reply(provider, client, data)))

        result = await client.generate(Role.SECURITY, "Review", output_type=Findings)

        assert result.output == Findings(findings=[Finding(title="SQL injection", line=3)])

    async def test_invalid_structured_output_is_retried_once(self, provider):
        script = Scripted()
        client = client_for(provider, script)
        bad = structured_reply(provider, client, {"findings": [{"title": "x"}]})  # no line
        good = structured_reply(provider, client, {"findings": []})
        script.responses += [(200, bad), (200, good)]

        result = await client.generate(Role.SECURITY, "Review", output_type=Findings)

        assert result.output == Findings(findings=[])
        assert result.usage.requests == 2

    async def test_invalid_structured_output_twice_fails_closed(self, provider):
        script = Scripted()
        client = client_for(provider, script)
        bad = structured_reply(provider, client, {"findings": "not a list"})
        script.responses += [(200, bad), (200, bad)]

        with pytest.raises(LLMOutputError):
            await client.generate(Role.SECURITY, "Review", output_type=Findings)
        assert len(script.requests) == 2

    async def test_tool_calling(self, provider):
        calls = []

        def read_file(path: str) -> str:
            """Read a file from the repository."""
            calls.append(path)
            return "SECRET_SENTINEL_CONTENT"

        script = Scripted(
            (200, tool_call_body(provider, "read_file", {"path": "app/main.py"})),
            (200, text_body(provider, "done")),
        )
        client = client_for(provider, script)

        result = await client.generate(Role.SECURITY, "Check main", tools=[read_file])

        assert result.output == "done"
        assert calls == ["app/main.py"]
        assert "read_file" in script.body(0)  # tool schema was sent
        assert "SECRET_SENTINEL_CONTENT" in script.body(1)  # tool result went back
        assert result.usage.requests == 2

    @pytest.mark.parametrize(
        ("kind", "error_type"),
        [("rate_limit", LLMRateLimitError), ("auth", LLMAuthError),
         ("unavailable", LLMUnavailableError)],
    )
    async def test_errors_map_to_shared_types(self, provider, kind, error_type):
        status, error_kind, message = ERRORS[kind]
        script = Scripted((status, error_body(provider, status, message, error_kind)))
        client = client_for(provider, script)

        with pytest.raises(error_type):
            await client.generate(Role.SUMMARY, "hi")
        assert len(script.requests) == 1  # LLM_MAX_RETRIES=0: no retry

    async def test_context_length_error(self, provider):
        body = error_body(provider, 400, CONTEXT_ERRORS[provider], "invalid_request_error")
        if provider in ("openai", "openai-compatible"):
            body["error"]["code"] = "context_length_exceeded"
        script = Scripted((400, body))
        client = client_for(provider, script)

        with pytest.raises(LLMContextLengthError):
            await client.generate(Role.SUMMARY, "a very long prompt")
        assert len(script.requests) == 1

    async def test_transient_error_is_retried_by_config(self, provider):
        status, error_kind, message = ERRORS["unavailable"]
        script = Scripted(
            (status, error_body(provider, status, message, error_kind)),
            (200, text_body(provider, "ok")),
        )
        client = client_for(provider, script, LLM_MAX_RETRIES=1)

        result = await client.generate(Role.SUMMARY, "hi")

        assert result.output == "ok"
        assert len(script.requests) == 2

    async def test_capabilities_are_declared(self, provider):
        client = client_for(provider, Scripted())
        caps = client.capabilities(Role.SECURITY)

        assert caps.tools is True
        assert caps.text_output is True
        client.require(Role.SECURITY, tools=True)  # does not raise

    async def test_missing_key_fails_at_build(self, provider):
        key = {"google": "GOOGLE_API_KEY", "openai": "OPENAI_API_KEY",
               "anthropic": "ANTHROPIC_API_KEY",
               "openai-compatible": "OPENAI_COMPATIBLE_BASE_URL"}[provider]
        with pytest.raises(LLMConfigurationError, match=key):
            build_client(make_settings(provider, **{key: ""}))


# --- configuration and composition ----------------------------------------------

@pytest.mark.asyncio
async def test_fallback_model_used_when_primary_unavailable():
    status, error_kind, message = ERRORS["unavailable"]
    script = Scripted(
        (status, error_body("openai", status, message, error_kind)),
        (200, text_body("anthropic", "from fallback")),
    )
    client = client_for("openai", script, LLM_FALLBACK_MODELS=f"anthropic:{MODEL_ID}")

    result = await client.generate(Role.SUMMARY, "hi")

    assert result.output == "from fallback"
    assert result.model == f"anthropic:{MODEL_ID}"
    assert client.model_name(Role.SUMMARY) == f"openai:{MODEL_ID}, anthropic:{MODEL_ID}"


@pytest.mark.asyncio
async def test_every_model_in_fallback_chain_failing_maps_to_shared_error():
    status, error_kind, message = ERRORS["rate_limit"]
    script = Scripted(
        (status, error_body("openai", status, message, error_kind)),
        (status, error_body("google", status, message, error_kind)),
    )
    client = client_for("openai", script, LLM_FALLBACK_MODELS=f"google:{MODEL_ID}")

    with pytest.raises(LLMRateLimitError):
        await client.generate(Role.SUMMARY, "hi")


@pytest.mark.asyncio
async def test_role_models_route_to_their_own_provider():
    script = Scripted((200, text_body("anthropic", "summary")))
    client = client_for("google", script, LLM_MODEL_SUMMARY=f"anthropic:{MODEL_ID}")

    result = await client.generate(Role.SUMMARY, "hi")

    assert result.model == f"anthropic:{MODEL_ID}"
    assert script.requests[0].url.host == "api.anthropic.com"
    assert client.model_name(Role.SECURITY) == f"google:{MODEL_ID}"


def test_openai_compatible_uses_configured_base_url():
    script = Scripted()
    client_for("openai-compatible", script)  # builds without an API key
    chain = role_chain(Role.SECURITY, make_settings("openai-compatible"))
    assert chain == [ModelSpec("openai-compatible", MODEL_ID)]


@pytest.mark.asyncio
async def test_openai_compatible_request_goes_to_base_url():
    script = Scripted((200, text_body("openai-compatible", "hi")))
    client = client_for("openai-compatible", script)

    await client.generate(Role.SUMMARY, "hi")

    assert str(script.requests[0].url) == "http://llm.test/v1/chat/completions"


@pytest.mark.parametrize("value", ["", "gemini-1.5-flash", "nope:model", "openai:"])
def test_bad_model_setting_fails_clearly(value):
    with pytest.raises(LLMConfigurationError):
        build_client(make_settings("openai", LLM_MODEL=value))


def test_bad_output_mode_fails_clearly():
    with pytest.raises(LLMConfigurationError):
        build_client(make_settings("openai", LLM_STRUCTURED_OUTPUT_MODE="xml"))


def test_model_spec_parsing():
    assert ModelSpec.parse(" OpenAI : some-model ") == ModelSpec("openai", "some-model")
    assert ModelSpec.parse("openai-compatible:org/model:tag") == ModelSpec(
        "openai-compatible", "org/model:tag")


def test_settings_derive_provider_from_model():
    from app.core.config import Settings

    s = Settings(GITHUB_TOKEN="x", GITHUB_WEBHOOK_SECRET="x", LLM_MODEL="anthropic:m")
    assert s.LLM_PROVIDER == "anthropic"
    assert Settings(GITHUB_TOKEN="x", GITHUB_WEBHOOK_SECRET="x", LLM_MODEL="bad").LLM_PROVIDER == ""


# --- review fixes: safe errors, clear config errors, validated settings ----------

SENTINEL = "UPSTREAM_BODY_SENTINEL_7f3a"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("status", [400, 401, 429, 503])
async def test_provider_error_body_never_reaches_message_or_logs(provider, status, caplog):
    import logging
    import traceback

    from app.core.exceptions import LLMError
    from app.services.llm_service import LLMService

    kind = {400: "invalid_request_error", 401: "authentication_error",
            429: "rate_limit_error", 503: "overloaded_error"}[status]
    script = Scripted((status, error_body(provider, status, f"echo: {SENTINEL}", kind)))
    service = LLMService(client=client_for(provider, script))

    with caplog.at_level(logging.DEBUG), pytest.raises(LLMError) as info:
        await service.analyze_security("diff", [{"filename": "a.py"}])

    err = info.value
    assert SENTINEL not in str(err)
    assert SENTINEL not in caplog.text
    # A traceback logged with exc_info=True must not carry the body either
    assert SENTINEL not in "".join(traceback.format_exception(err))
    # The message keeps the safe fields
    assert f"status {status}" in str(err)
    assert f"{provider}:{MODEL_ID}" in str(err)
    # The original stays available for debugging, outside the message
    assert SENTINEL in str(getattr(err, "provider_error", ""))


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", PROVIDERS)
async def test_unknown_model_is_a_configuration_error(provider):
    body = error_body(provider, 401, "model not found", "not_found_error")
    if provider == "google":
        body = {"error": {"code": 404, "message": "models/test-model is not found",
                          "status": "NOT_FOUND"}}
    script = Scripted((404, body))
    client = client_for(provider, script)

    with pytest.raises(LLMConfigurationError):
        await client.generate(Role.SUMMARY, "hi")


def test_old_style_model_setting_explains_the_new_format():
    with pytest.raises(LLMConfigurationError) as info:
        build_client(make_settings("google", LLM_MODEL="gemini-1.5-flash"))
    message = str(info.value)
    assert "LLM_MODEL='gemini-1.5-flash'" in message
    assert "<provider>:<model-id>" in message
    assert "google:<model-id>" in message
    assert "LLM_PROVIDER is no longer read" in message


def test_role_setting_is_named_in_the_error():
    with pytest.raises(LLMConfigurationError, match="LLM_MODEL_SUMMARY"):
        build_client(make_settings("google", LLM_MODEL_SUMMARY="no-prefix"))


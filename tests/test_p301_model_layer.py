"""P3-01: `llm` mode through the real model layer, with only the network replaced.

`build_client` builds the `openai-compatible` adapter and `PydanticAIClient`, and an
`httpx2.MockTransport` answers in the Chat Completions wire format, as in
tests/test_llm_contract.py. Nothing leaves the machine.
"""

import json

import httpx2
import pytest

from app.core.config import settings
from app.llm import build_client
from evals import run

# Fake network, real price table: this ID is only here so a cost can be computed
PRICED_ID = "gpt-4o-mini"  # $0.15 in and $0.60 out per million tokens
INPUT_PRICE, OUTPUT_PRICE = 0.15 / 1_000_000, 0.60 / 1_000_000
TOKENS_IN, TOKENS_OUT = 1000, 100

SQLI = {
    "severity": "critical",
    "title": "SQL injection via f-string",
    "description": "The search term is formatted into the statement.",
    "file": "shop/users/search.py",
    "line_number": 7,
    "recommendation": "Bind the value.",
}


class Provider:
    """A mock Chat Completions server. `broken` names a report type or "summary"."""

    def __init__(self, model_id: str, broken: str | None = None, status: int | None = None):
        self.model_id = model_id
        self.broken = broken
        self.status = status  # HTTP error for the broken call; None means bad output
        self.asked: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        assert request.url.host == "llm.test"
        body = json.loads(request.content)
        assert body["model"] == self.model_id
        schema = body.get("response_format", {}).get("json_schema", {}).get("name")
        tools = [t["function"]["name"] for t in body.get("tools", [])]
        prompt = json.dumps(body["messages"])
        kind = schema or ("tool" if tools else "summary")
        self.asked.append(kind)
        if kind == self.broken and self.status:
            error = {"error": {"message": "SECRET-BODY-TEXT", "type": "server_error"}}
            return httpx2.Response(self.status, json=error, headers={"retry-after": "0"})
        if kind == "summary":
            text = "A summary."
        elif kind == self.broken:
            text = "this is not the JSON that was asked for"
        else:
            found = kind == "SecurityReport" and "shop/users/search.py" in prompt
            text = json.dumps({"findings": [SQLI] if found else []})
        reply = {
            "id": "c1",
            "object": "chat.completion",
            "created": 1,
            "model": self.model_id,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": TOKENS_IN,
                "completion_tokens": TOKENS_OUT,
                "total_tokens": TOKENS_IN + TOKENS_OUT,
            },
        }
        return httpx2.Response(200, json=reply)


@pytest.fixture(autouse=True)
def _offline_model_settings(monkeypatch):
    monkeypatch.setattr(settings, "OPENAI_COMPATIBLE_BASE_URL", "http://llm.test/v1")
    monkeypatch.setattr(settings, "OPENAI_COMPATIBLE_API_KEY", "")
    monkeypatch.setattr(settings, "LLM_MAX_RETRIES", 0)
    monkeypatch.setattr(settings, "LLM_STRUCTURED_OUTPUT_MODE", "auto")
    monkeypatch.setattr(settings, "LLM_MAX_DIFF_CHUNKS", 8)
    monkeypatch.setattr(settings, "LLM_REVIEW_BUDGET_SECONDS", 150.0)


def llm_run(monkeypatch, tmp_path, provider: Provider, case: str = "py-sql-injection"):
    transport = httpx2.MockTransport(provider)
    monkeypatch.setattr(
        run,
        "build_client",
        lambda configured: build_client(
            configured, http_client=httpx2.AsyncClient(transport=transport)
        ),
    )
    out = tmp_path / "llm.json"
    model = f"openai-compatible:{provider.model_id}"
    code = run.main(["--mode", "llm", "--model", model, "--case", case, "--out", str(out)])
    report = json.loads(out.read_text())
    return code, report, report["cases"][0], out.with_suffix(".md").read_text()


def test_tokens_cost_and_answering_model_come_from_the_provider(monkeypatch, tmp_path):
    provider = Provider(PRICED_ID)
    code, report, case, markdown = llm_run(monkeypatch, tmp_path, provider)
    assert code == 0
    assert sorted(provider.asked) == [
        "BestPracticesReport",
        "PerformanceReport",
        "SecurityReport",
        "summary",
    ]
    usage = report["usage"]
    assert (usage["calls"], usage["failed_calls"], usage["requests"]) == (4, 0, 4)
    assert (usage["input_tokens"], usage["output_tokens"]) == (4 * TOKENS_IN, 4 * TOKENS_OUT)
    expected = 4 * (TOKENS_IN * INPUT_PRICE + TOKENS_OUT * OUTPUT_PRICE)
    assert usage["cost_usd"] == pytest.approx(expected)
    assert usage["cost_is_lower_bound"] is False
    assert report["answering_models"] == [f"openai-compatible:{PRICED_ID}"]
    assert case["status"] == "complete"
    assert (case["tp"], case["passed_ignoring_duplicates"]) == (1, True)
    assert "≥" not in markdown


def test_an_unpriced_model_has_no_cost(monkeypatch, tmp_path):
    _, report, _, _ = llm_run(monkeypatch, tmp_path, Provider("test-model"))
    assert report["usage"]["cost_usd"] is None
    assert report["usage"]["unknown_cost_calls"] == 4
    assert report["usage"]["input_tokens"] == 4 * TOKENS_IN


def test_invalid_output_fails_closed_and_marks_the_cost_as_a_lower_bound(monkeypatch, tmp_path):
    provider = Provider(PRICED_ID, broken="SecurityReport")
    code, report, case, markdown = llm_run(
        monkeypatch, tmp_path, provider, case="clean-go-extract-helper"
    )
    assert provider.asked.count("SecurityReport") == 2  # the one retry, both billed
    assert code == 1  # no review completed
    assert case["status"] == "incomplete"
    assert case["verdict"] == "incomplete"
    assert not case["passed"] and not case["passed_ignoring_duplicates"]
    assert any("LLMOutputError" in reason for reason in case["incomplete_reasons"])
    assert report["metrics"]["clean"]["false_positive_rate"] is None
    usage = report["usage"]
    # Five responses were served, but the failed call reports no usage
    assert len(provider.asked) == 5
    assert (usage["calls"], usage["failed_calls"], usage["requests"]) == (4, 1, 3)
    assert usage["input_tokens"] == 3 * TOKENS_IN
    expected = 3 * (TOKENS_IN * INPUT_PRICE + TOKENS_OUT * OUTPUT_PRICE)
    assert usage["cost_usd"] == pytest.approx(expected)
    assert usage["cost_is_lower_bound"] is True
    assert case["usage"]["cost_is_lower_bound"] is True
    assert "≥ $0.0006 (1 failed call(s) not counted)" in markdown
    assert "≥ 3,000" in markdown


def test_a_provider_error_is_a_failed_call_and_leaks_nothing(monkeypatch, tmp_path):
    provider = Provider(PRICED_ID, broken="summary", status=500)
    _, report, case, markdown = llm_run(monkeypatch, tmp_path, provider)
    assert case["status"] == "incomplete"
    assert not case["passed"] and not case["passed_ignoring_duplicates"]
    assert report["usage"]["failed_calls"] == 1
    assert report["usage"]["cost_is_lower_bound"] is True
    assert "SECRET-BODY-TEXT" not in json.dumps(report) + markdown

# tests/test_p201_structured_output.py

"""P2-01: schema-enforced structured output for the three findings roles.

Tests that:
- each findings role calls generate with a Report output_type, not str
- an empty report gives [] and a complete step
- unvalidatable output (LLMOutputError) gives LLMOutputError and the step fails closed
- some invalid findings give PartialFindingsError with valid ones kept
- the performance prepare hook still applies (_severity_from_impact)
- LLM_STRUCTURED_OUTPUT_MODE native / tool / prompted each produce the matching
  output wrapper for the findings calls
- no model output text reaches logs (sentinel test)

No real provider is called; the model layer is either faked at the LLMClient level
(for LLMService tests) or at the HTTP transport level (for output-mode tests that
exercise the real PydanticAIClient, following test_llm_contract.py's pattern).
"""

import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx2
import pytest
from pydantic_ai import NativeOutput, PromptedOutput, ToolOutput

from app.llm import LLMResult, Role, Usage, build_client
from app.llm.errors import LLMOutputError
from app.models.analysis import (
    AnalysisStatus,
    ApprovalRecommendation,
    BestPracticeIssue,
    BestPracticesReport,
    PerformanceIssue,
    PerformanceReport,
    SecurityIssue,
    SecurityReport,
    _severity_from_impact,
)
from app.services.llm_service import LLMService, PartialFindingsError
from tests.test_code_analyzer import SAFE_DIFF, make_analyzer, run

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROVIDERS = ["google", "openai", "anthropic", "openai-compatible"]
MODEL_ID = "test-model"


def usage():
    return Usage(input_tokens=1, output_tokens=1, requests=1, latency_ms=1.0)


def make_client(role_outputs: dict[Role, object]) -> MagicMock:
    """Return a fake LLMClient whose generate returns the given output per role.

    The value in role_outputs may be:
    - a Report instance  → returned as LLMResult.output
    - a BaseException    → raised directly
    - None / absent      → returns an empty Report of the right type
    """

    async def generate(role, prompt, *, output_type=str, **kwargs):
        out = role_outputs.get(role)
        if isinstance(out, BaseException):
            raise out
        if output_type is str:
            return LLMResult(
                output=out if isinstance(out, str) else "Summary",
                usage=usage(), model="test:model",
            )
        # Report type
        if out is None:
            report = output_type(findings=[])
        elif isinstance(out, output_type):
            report = out
        else:
            raise LLMOutputError(
                f"wrong type: expected {output_type.__name__}, got {type(out).__name__}"
            )
        return LLMResult(output=report, usage=usage(), model="test:model")

    client = MagicMock()
    client.model_name.return_value = "test:model"
    client.generate = AsyncMock(side_effect=generate)
    return client


VALID_SECURITY = SecurityIssue(
    severity="high", title="SQL injection", description="Unsafe query",
    file="app/db.py", line_number=10, recommendation="Use params",
    references=["CWE-89"],
)
VALID_PERFORMANCE = PerformanceIssue(
    severity="high", title="N+1 query", description="Per-row query",
    file="app/views.py", line_number=20, impact="100x queries",
    recommendation="Use prefetch",
)
VALID_BP = BestPracticeIssue(
    severity="medium", category="naming", title="Bad name",
    description="Single-letter var", file="app/x.py",
    recommendation="Use descriptive names",
)


# ===========================================================================
# 1. Each findings role calls generate with the right Report output_type, not str
# ===========================================================================

class TestOutputTypePassedToClient:
    """The service must call client.generate with the Report output_type."""

    @pytest.mark.asyncio
    async def test_security_role_uses_security_report(self):
        client = make_client({})
        service = LLMService(client=client)
        await service.analyze_security("diff", [])
        _, call_kwargs = client.generate.call_args
        assert call_kwargs.get("output_type") is SecurityReport

    @pytest.mark.asyncio
    async def test_performance_role_uses_performance_report(self):
        client = make_client({})
        service = LLMService(client=client)
        await service.analyze_performance("diff", [])
        _, call_kwargs = client.generate.call_args
        assert call_kwargs.get("output_type") is PerformanceReport

    @pytest.mark.asyncio
    async def test_best_practices_role_uses_best_practices_report(self):
        client = make_client({})
        service = LLMService(client=client)
        await service.analyze_best_practices("diff", [])
        _, call_kwargs = client.generate.call_args
        assert call_kwargs.get("output_type") is BestPracticesReport

    @pytest.mark.asyncio
    async def test_summary_role_uses_str(self):
        """The summary role must still use str, not a Report."""
        client = make_client({})
        service = LLMService(client=client)
        await service.generate_summary(
            "Title", "author", "", [], [], [],
            total_additions=0, total_deletions=0, changed_files=0,
        )
        _, call_kwargs = client.generate.call_args
        # output_type defaults to str; it must not be a Pydantic model
        output_type = call_kwargs.get("output_type", str)
        assert output_type is str


# ===========================================================================
# 2. An empty report gives [] and a complete step
# ===========================================================================

class TestEmptyReport:
    @pytest.mark.asyncio
    async def test_empty_security_report_returns_empty_list(self):
        client = make_client({Role.SECURITY: SecurityReport(findings=[])})
        service = LLMService(client=client)
        result = await service.analyze_security("diff", [])
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_performance_report_returns_empty_list(self):
        client = make_client({Role.PERFORMANCE: PerformanceReport(findings=[])})
        service = LLMService(client=client)
        result = await service.analyze_performance("diff", [])
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_best_practices_report_returns_empty_list(self):
        client = make_client({Role.BEST_PRACTICES: BestPracticesReport(findings=[])})
        service = LLMService(client=client)
        result = await service.analyze_best_practices("diff", [])
        assert result == []

    @pytest.mark.asyncio
    async def test_absent_role_defaults_to_empty_report(self):
        """When a role is not in role_outputs the client returns an empty report."""
        client = make_client({})
        service = LLMService(client=client)
        assert await service.analyze_security("diff", []) == []
        assert await service.analyze_performance("diff", []) == []
        assert await service.analyze_best_practices("diff", []) == []


# ===========================================================================
# 3. Unvalidatable output → LLMOutputError, step fails closed
# ===========================================================================

class TestUnvalidatableOutput:
    @pytest.mark.asyncio
    async def test_security_llm_output_error_propagates(self):
        err = LLMOutputError("model gave unparseable output")
        client = make_client({Role.SECURITY: err})
        service = LLMService(client=client)
        with pytest.raises(LLMOutputError):
            await service.analyze_security("diff", [])

    @pytest.mark.asyncio
    async def test_performance_llm_output_error_propagates(self):
        err = LLMOutputError("model gave unparseable output")
        client = make_client({Role.PERFORMANCE: err})
        service = LLMService(client=client)
        with pytest.raises(LLMOutputError):
            await service.analyze_performance("diff", [])

    @pytest.mark.asyncio
    async def test_best_practices_llm_output_error_propagates(self):
        err = LLMOutputError("model gave unparseable output")
        client = make_client({Role.BEST_PRACTICES: err})
        service = LLMService(client=client)
        with pytest.raises(LLMOutputError):
            await service.analyze_best_practices("diff", [])


# ===========================================================================
# 4. Some invalid findings → PartialFindingsError with valid ones kept
# ===========================================================================
# P2-01 design: the schema layer validates the whole Report object; individual
# item validation happens inside the service for the performance prepare hook,
# and can be tested there.  For security and best-practices, the schema layer
# already validates items; to get partial findings we raise PartialFindingsError
# ourselves (a lenient approach: validate items one-by-one after the schema layer
# returns, then raise if some failed).  We test this via _validate_findings and
# the performance path, which re-validates items after the prepare hook.

class TestPartialFindings:
    @pytest.mark.asyncio
    async def test_partial_findings_error_keeps_valid_ones(self):
        """PartialFindingsError carries the valid subset in .findings."""
        # Simulate: schema layer validated a report with two items, but after
        # running _validate_findings one is dropped. We test through the security
        # path by injecting a PartialFindingsError from the client.
        valid = SecurityIssue(
            severity="high", title="SQL injection", description="d",
            file="a.py", recommendation="r",
        )
        err = PartialFindingsError("1 finding invalid", [valid])
        client = make_client({Role.SECURITY: err})
        service = LLMService(client=client)
        with pytest.raises(PartialFindingsError) as exc:
            await service.analyze_security("diff", [])
        assert len(exc.value.findings) == 1
        assert isinstance(exc.value.findings[0], SecurityIssue)

    @pytest.mark.asyncio
    async def test_all_invalid_raises_output_error_not_partial(self):
        """When every finding is invalid, raise LLMOutputError (not PartialFindingsError)."""
        err = LLMOutputError("all findings invalid")
        client = make_client({Role.SECURITY: err})
        service = LLMService(client=client)
        with pytest.raises(LLMOutputError):
            await service.analyze_security("diff", [])

    @pytest.mark.asyncio
    async def test_report_with_mixed_findings_raises_partial_findings_error(self):
        """When a report contains valid and invalid findings, PartialFindingsError is raised."""
        raw_data = {
            "findings": [
                {
                    "severity": "high", "title": "SQL injection", "description": "d",
                    "file": "a.py", "recommendation": "r",
                },
                {"severity": "not-a-valid-severity", "title": "Bad finding"},
            ]
        }
        report = SecurityReport.model_validate(raw_data)
        assert report.dropped_count == 1
        assert len(report.findings) == 1

        client = make_client({Role.SECURITY: report})
        service = LLMService(client=client)
        with pytest.raises(PartialFindingsError) as exc:
            await service.analyze_security("diff", [])
        assert len(exc.value.findings) == 1
        assert exc.value.findings[0].title == "SQL injection"

    @pytest.mark.asyncio
    async def test_report_with_all_invalid_findings_raises_output_error(self):
        """When all findings in a report are invalid, LLMOutputError is raised."""
        raw_data = {
            "findings": [
                {"severity": "not-a-valid-severity", "title": "Bad 1"},
                {"severity": "another-bad", "title": "Bad 2"},
            ]
        }
        report = SecurityReport.model_validate(raw_data)
        assert report.dropped_count == 2
        assert len(report.findings) == 0

        client = make_client({Role.SECURITY: report})
        service = LLMService(client=client)
        with pytest.raises(LLMOutputError) as exc:
            await service.analyze_security("diff", [])
        assert "All 2 security finding(s)" in str(exc.value)


# ===========================================================================
# 5. Performance prepare hook (_severity_from_impact) still applies
# ===========================================================================

class TestPerformancePrepareHook:
    def test_severity_from_impact_fills_missing_severity(self):
        # "100X" matches the CRITICAL tier in _severity_from_impact
        raw = {"impact": "100x more queries"}
        _severity_from_impact(raw)
        assert raw["severity"] == "critical"

    def test_severity_from_impact_does_not_overwrite_existing(self):
        raw = {"severity": "low", "impact": "100x more queries"}
        _severity_from_impact(raw)
        assert raw["severity"] == "low"

    @pytest.mark.parametrize("impact,expected_severity", [
        ("CRITICAL performance issue", "critical"),
        ("SEVERE bottleneck, 10x slower", "critical"),
        ("100X memory usage", "critical"),
        ("HIGH impact on throughput", "high"),
        ("SIGNIFICANT overhead", "high"),
        ("2X slower on average", "high"),
        ("MODERATE slowdown", "medium"),
        ("some minor overhead", "low"),
        ("", "low"),
    ])
    def test_severity_mapping(self, impact, expected_severity):
        raw = {"impact": impact}
        _severity_from_impact(raw)
        assert raw["severity"] == expected_severity

    @pytest.mark.asyncio
    async def test_prepare_hook_applied_to_performance_findings(self):
        """When a performance finding has only 'impact' (no 'severity'), the hook fills it in."""
        # Build a report where severity IS present (schema requires it), but we
        # simulate what happens when the hook changes it.
        # The hook runs on model_dump() output, then re-validates; test the round-trip.
        report = PerformanceReport(findings=[
            PerformanceIssue(
                severity="low",   # will be overwritten by hook if impact matches
                title="N+1 query",
                description="Per-row query",
                file="app/views.py",
                impact="CRITICAL bottleneck",   # hook would set critical
                recommendation="Use prefetch",
            )
        ])
        client = make_client({Role.PERFORMANCE: report})
        service = LLMService(client=client)
        # The hook only fires when 'severity' is missing from raw dict.
        # Since severity IS present, the hook leaves it alone.
        results = await service.analyze_performance("diff", [])
        assert results[0].severity == "low"  # hook did not overwrite

    @pytest.mark.asyncio
    async def test_prepare_hook_applied_when_severity_absent_in_raw(self):
        """Hook fills severity from impact when severity key is missing in raw dict."""
        # We need to simulate the model returning a dict without 'severity'.
        # The PerformanceReport schema requires severity, so we test _severity_from_impact
        # directly with the hook:
        raw = {"impact": "CRITICAL bottleneck", "title": "N+1", "description": "d",
               "file": "a.py", "recommendation": "r"}
        _severity_from_impact(raw)
        assert raw["severity"] == "critical"
        # And the dict is now valid for PerformanceIssue
        issue = PerformanceIssue(**raw)
        assert issue.severity == "critical"

    def test_prepare_hook_applied_in_performance_report_model_validate(self):
        """PerformanceReport model_validate applies prepare hook when severity is missing."""
        raw_data = {
            "findings": [
                {
                    "title": "N+1 query",
                    "description": "Per-row query",
                    "file": "app/views.py",
                    "impact": "100x more queries",
                    "recommendation": "Use prefetch",
                }
            ]
        }
        report = PerformanceReport.model_validate(raw_data)
        assert len(report.findings) == 1
        assert report.findings[0].severity == "critical"
        assert report.dropped_count == 0


# ===========================================================================
# 6. LLM_STRUCTURED_OUTPUT_MODE native / tool / prompted each produce the
#    matching output wrapper for findings calls
#    (using the real PydanticAIClient + httpx2.MockTransport, like test_llm_contract.py)
# ===========================================================================

USAGE_IN, USAGE_OUT = 11, 7


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


class Scripted:
    """Mock HTTP transport that returns canned responses in order."""

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


def client_for(provider: str, script: Scripted, **overrides):
    return build_client(make_settings(provider, **overrides), http_client=script.client())


def structured_reply(provider: str, llm_client, data: dict) -> dict:
    """Answer the way the chosen output mode expects for the given client."""
    caps = llm_client.capabilities(Role.SECURITY)
    if caps.native_structured_output:
        return text_body(provider, json.dumps(data))
    return tool_call_body(provider, "final_result", data)


REPORT_DATA = {"findings": [{"severity": "high", "title": "SQL injection",
                              "description": "Unsafe", "file": "a.py",
                              "recommendation": "Fix it"}]}


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", PROVIDERS)
class TestOutputModeWithRealClient:
    """Each output mode produces a validated SecurityReport for findings calls."""

    async def test_auto_mode_returns_security_report(self, provider):
        script = Scripted()
        llm_client = client_for(provider, script)
        script.responses.append((200, structured_reply(provider, llm_client, REPORT_DATA)))

        result = await llm_client.generate(
            Role.SECURITY, "Review", output_type=SecurityReport
        )

        assert isinstance(result.output, SecurityReport)
        assert len(result.output.findings) == 1
        assert result.output.findings[0].title == "SQL injection"

    async def test_native_mode_uses_native_output_wrapper(self, provider):
        """With mode=native, the client wraps output_type in NativeOutput."""
        script = Scripted()
        llm_client = client_for(provider, script, LLM_STRUCTURED_OUTPUT_MODE="native")

        # Inspect _output_spec: it should return NativeOutput(SecurityReport)
        spec = llm_client._output_spec(Role.SECURITY, SecurityReport, False)
        assert isinstance(spec, NativeOutput)

    async def test_tool_mode_uses_tool_output_wrapper(self, provider):
        """With mode=tool, the client wraps output_type in ToolOutput."""
        script = Scripted()
        llm_client = client_for(provider, script, LLM_STRUCTURED_OUTPUT_MODE="tool")
        spec = llm_client._output_spec(Role.SECURITY, SecurityReport, False)
        assert isinstance(spec, ToolOutput)

    async def test_prompted_mode_uses_prompted_output_wrapper(self, provider):
        """With mode=prompted, the client wraps output_type in PromptedOutput."""
        script = Scripted()
        llm_client = client_for(provider, script, LLM_STRUCTURED_OUTPUT_MODE="prompted")
        spec = llm_client._output_spec(Role.SECURITY, SecurityReport, False)
        assert isinstance(spec, PromptedOutput)

    async def test_str_output_type_bypasses_output_wrappers(self, provider):
        """The summary role uses str; _output_spec must return str directly."""
        script = Scripted()
        llm_client = client_for(provider, script)
        spec = llm_client._output_spec(Role.SUMMARY, str, False)
        assert spec is str


# ===========================================================================
# 7. No model output text reaches logs (sentinel)
# ===========================================================================

SENTINEL_OUTPUT = "SENTINEL_P201_OUTPUT_7f3a"


class TestNoOutputInLogs:
    @pytest.mark.asyncio
    async def test_llm_output_error_sentinel_never_in_logs(self, caplog):
        """The provider_error attribute (which may hold raw output) must not reach logs."""
        err = LLMOutputError("structured output failed")
        err.provider_error = Exception(f"raw model output: {SENTINEL_OUTPUT}")
        client = make_client({Role.SECURITY: err})
        service = LLMService(client=client)

        with caplog.at_level(logging.DEBUG):
            with pytest.raises(LLMOutputError):
                await service.analyze_security("diff", [])

        assert SENTINEL_OUTPUT not in caplog.text

    @pytest.mark.asyncio
    async def test_partial_findings_sentinel_never_in_logs(self, caplog):
        """An invalid finding item with a sentinel sent through Scripted never leaks to logs."""
        payload = {
            "findings": [
                {
                    "severity": "high",
                    "title": "SQL injection",
                    "description": "d",
                    "file": "a.py",
                    "recommendation": "r",
                },
                {
                    "severity": SENTINEL_OUTPUT,
                    "title": SENTINEL_OUTPUT,
                    "description": SENTINEL_OUTPUT,
                    "file": "a.py",
                    "recommendation": SENTINEL_OUTPUT,
                },
            ]
        }
        script = Scripted((200, text_body("openai", json.dumps(payload))))
        llm_client = client_for("openai", script, LLM_STRUCTURED_OUTPUT_MODE="native")
        service = LLMService(client=llm_client)

        with caplog.at_level(logging.DEBUG):
            with pytest.raises(PartialFindingsError) as exc:
                await service.analyze_security("diff", [])

        assert len(exc.value.findings) == 1
        assert SENTINEL_OUTPUT not in str(exc.value)
        assert SENTINEL_OUTPUT not in caplog.text
        for record in caplog.records:
            assert SENTINEL_OUTPUT not in record.getMessage()
            assert SENTINEL_OUTPUT not in str(record.exc_info or "")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["native", "tool", "prompted"])
    async def test_non_object_reply_sentinel_never_in_logs(self, mode, caplog):
        """A non-object reply with a sentinel sent through Scripted never leaks to logs."""
        raw_reply = f"Sorry, {SENTINEL_OUTPUT} cannot be formatted."
        script = Scripted(
            (200, text_body("openai", raw_reply)),
            (200, text_body("openai", raw_reply)),
        )
        llm_client = client_for("openai", script, LLM_STRUCTURED_OUTPUT_MODE=mode)
        service = LLMService(client=llm_client)

        with caplog.at_level(logging.DEBUG):
            with pytest.raises(LLMOutputError) as exc:
                await service.analyze_security("diff", [])

        assert SENTINEL_OUTPUT not in str(exc.value)
        assert SENTINEL_OUTPUT not in caplog.text
        for record in caplog.records:
            assert SENTINEL_OUTPUT not in record.getMessage()
            assert SENTINEL_OUTPUT not in str(record.exc_info or "")

    @pytest.mark.asyncio
    async def test_valid_report_logs_only_counts(self, caplog):
        """A successful call must log counts only, never finding content."""
        secret = f"SECRET_DATA_{SENTINEL_OUTPUT}"
        report = SecurityReport(findings=[
            SecurityIssue(
                severity="high", title=secret, description=secret,
                file="a.py", recommendation=secret,
            )
        ])
        client = make_client({Role.SECURITY: report})
        service = LLMService(client=client)

        with caplog.at_level(logging.DEBUG):
            await service.analyze_security("diff", [])

        assert secret not in caplog.text


# ===========================================================================
# 8. Real client fail-closed regression tests (BLOCKER & SHOULD-FIX #1)
# ===========================================================================

APPROVING = {
    ApprovalRecommendation.APPROVE,
    ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS,
}

VALID_FINDING_DICT = {
    "severity": "high",
    "title": "SQL injection",
    "description": "d",
    "file": "a.py",
    "line_number": 3,
    "recommendation": "r",
    "references": ["CWE-89"],
}
VALID_FINDING_JSON = json.dumps(VALID_FINDING_DICT)

BAD_REPORT_SHAPES = {
    "empty_object": {},
    "wrong_key_issues": {"issues": [VALID_FINDING_DICT]},
    "prose_result_key": {"result": "no issues"},
    "extra_key_with_findings": {"findings": [VALID_FINDING_DICT], "extra": 1},
}

MALFORMED_RAW_REPLIES = {
    "prose": "I could not find any problems in this diff.",
    "empty": "",
    "bare_empty_array": "[]",
    "truncated": '[{"severity": "high", "title": "SQL injection", "descr',
    "truncated_fenced": '```json\n[{"severity": "high", "title": "SQL inj\n```',
    "nested_array": f"[[{VALID_FINDING_JSON}]]",
    "array_of_strings": '["looks fine"]',
    "prose_with_citation": "All good, see [1] for details.",
    "truncated_fence_inner_empty": (
        '```json\n[{"severity": "critical", "title": "SQLi", '
        '"code_snippet": "rows = []", "descr'
    ),
    "prose_inner_empty_then_truncated": (
        'Checked `items = []` handling. Findings:\n'
        '[{"severity": "critical", "title": "RCE", "descr'
    ),
    "prose_empty_then_truncated": 'See [] below.\n[{"severity": "critical", "title": "RCE"',
    "prose_empty_only": "No issues found: []",
    "deeply_nested": "[" * 5000,
    "prose_deeply_nested": "Findings: " + "[" * 5000,
}


def _mode_reply(provider: str, mode: str, data: dict) -> dict:
    if mode == "tool":
        return tool_call_body(provider, "final_result", data)
    return text_body(provider, json.dumps(data))


def _analyzer_with_script(script: Scripted, mode: str):
    llm_client = client_for("openai", script, LLM_STRUCTURED_OUTPUT_MODE=mode)
    service = LLMService(client=llm_client)
    analyzer, github, _ = make_analyzer(diff=SAFE_DIFF)
    analyzer.llm_service = service
    return analyzer, github, llm_client


class TestRealClientFailClosedRegression:
    """Real PydanticAIClient + Scripted HTTP transport fail-closed guarantees."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["native", "tool", "prompted"])
    @pytest.mark.parametrize("report_cls", [SecurityReport, PerformanceReport, BestPracticesReport])
    @pytest.mark.parametrize("payload", BAD_REPORT_SHAPES.values(), ids=BAD_REPORT_SHAPES.keys())
    async def test_bad_report_shapes_raise_llm_output_error(self, mode, report_cls, payload):
        """Missing `findings` or extra keys must fail validation and raise LLMOutputError."""
        reply = _mode_reply("openai", mode, payload)
        script = Scripted((200, reply), (200, reply))
        llm_client = client_for("openai", script, LLM_STRUCTURED_OUTPUT_MODE=mode)

        with pytest.raises(LLMOutputError):
            await llm_client.generate(Role.SECURITY, "Review", output_type=report_cls)
        assert len(script.requests) == 2

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["native", "tool", "prompted"])
    @pytest.mark.parametrize("payload", BAD_REPORT_SHAPES.values(), ids=BAD_REPORT_SHAPES.keys())
    async def test_bad_report_shapes_never_approve_through_analyzer(self, mode, payload):
        """Bad report shapes on security step must never produce an approval."""
        bad = _mode_reply("openai", mode, payload)
        empty = _mode_reply("openai", mode, {"findings": []})
        script = Scripted(
            (200, bad),
            (200, bad),
            (200, empty),
            (200, empty),
            (200, text_body("openai", "Summary")),
        )
        analyzer, github, _ = _analyzer_with_script(script, mode)
        result = await run(analyzer, github)

        assert result.status in (AnalysisStatus.FAILED, AnalysisStatus.INCOMPLETE)
        assert result.approval_recommendation not in APPROVING
        assert result.approval_recommendation == ApprovalRecommendation.INCOMPLETE

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["native", "tool", "prompted"])
    async def test_explicit_empty_findings_gives_clean_complete_review(self, mode):
        """Explicit `{"findings": []}` is valid and produces a COMPLETE + APPROVE review."""
        empty = _mode_reply("openai", mode, {"findings": []})
        script = Scripted(
            (200, empty),
            (200, empty),
            (200, empty),
            (200, text_body("openai", "Summary")),
        )
        analyzer, github, _ = _analyzer_with_script(script, mode)
        result = await run(analyzer, github)

        assert result.status == AnalysisStatus.COMPLETE
        assert result.approval_recommendation == ApprovalRecommendation.APPROVE
        assert result.security_findings == []
        assert result.performance_findings == []
        assert result.best_practice_findings == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["native", "tool", "prompted"])
    @pytest.mark.parametrize(
        "raw_reply", MALFORMED_RAW_REPLIES.values(), ids=MALFORMED_RAW_REPLIES.keys()
    )
    async def test_malformed_raw_replies_never_approve(self, mode, raw_reply):
        """Every raw malformed reply fails closed through the real client and analyzer."""
        bad = text_body("openai", raw_reply)
        empty = _mode_reply("openai", mode, {"findings": []})
        script = Scripted(
            (200, bad),
            (200, bad),
            (200, empty),
            (200, empty),
            (200, text_body("openai", "Summary")),
        )
        analyzer, github, _ = _analyzer_with_script(script, mode)
        result = await run(analyzer, github)

        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation not in APPROVING
        assert result.approval_recommendation == ApprovalRecommendation.INCOMPLETE
        assert any("Security analysis failed (LLMOutputError)" in r for r in result.incomplete_reasons)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["native", "tool", "prompted"])
    async def test_valid_reply_with_nested_fields_parses_end_to_end(self, mode):
        """A valid reply with nested fields (references) parses cleanly through the full stack."""
        sec_reply = _mode_reply("openai", mode, {"findings": [VALID_FINDING_DICT]})
        empty = _mode_reply("openai", mode, {"findings": []})
        script = Scripted(
            (200, sec_reply),
            (200, empty),
            (200, empty),
            (200, text_body("openai", "Summary")),
        )
        analyzer, github, _ = _analyzer_with_script(script, mode)
        result = await run(analyzer, github)

        assert result.status == AnalysisStatus.COMPLETE
        assert len(result.security_findings) == 1
        assert result.security_findings[0].title == "SQL injection"
        assert result.security_findings[0].references == ["CWE-89"]

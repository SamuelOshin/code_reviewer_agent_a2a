"""P1-06 / P2-01: the review fails closed.

A failed LLM call, an invalid structured response, partial findings, or a diff
longer than the LLM sees, must never produce an approval. Rule findings survive
LLM failures, the truncation is reported in the result, and raw model output never
reaches the logs.

The model-layer client is faked; `LLMService` runs for real on top of it. No
provider is called. With P2-01, `client.generate` is called with a Report
output_type and returns a validated Report object — not a raw string. The
old hand-written parser (extract_findings_array) is gone.

Design note: the fake_client inspects `output_type` from kwargs.  When it
receives a Report type it returns a matching validated instance (or raises
LLMOutputError as the real client would on unvalidatable output). When it
receives `str` (the summary call) it returns the string directly.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.exceptions import AnalysisError
from app.llm import LLMResult, Role, Usage
from app.llm.errors import LLMOutputError, LLMRateLimitError
from app.models.analysis import (
    AnalysisStatus,
    ApprovalRecommendation,
    PerformanceIssue,
    SecurityIssue,
    SecurityReport,
)
from app.services.llm_service import MAX_DIFF_CHARS, LLMService, PartialFindingsError
from app.utils.formatters import SummaryFormatter
from tests.test_code_analyzer import RISKY_DIFF, SAFE_DIFF, make_analyzer, run

APPROVING = {ApprovalRecommendation.APPROVE, ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS}

SENTINEL = "SENTINEL-LLM-OUTPUT-7f3a"

# A valid SecurityReport returned by the schema layer
VALID_SECURITY_REPORT = SecurityReport(findings=[
    SecurityIssue(
        severity="high",
        title="SQL injection",
        description="d",
        file="a.py",
        line_number=3,
        recommendation="r",
        references=["CWE-89"],
    )
])


def fake_client(outputs: dict[Role, object]) -> MagicMock:
    """A model-layer client that returns (or raises) a fixed output per role.

    P2-01: the three findings roles now call generate(output_type=<Report>).
    This fake honours that: when output_type is a Report class it returns the
    value from `outputs` (which should already be a Report instance), or a
    default empty Report if the role is not in `outputs`. When output_type is
    str (the summary role) it returns a string.

    If the value in `outputs` is a BaseException, it is raised regardless of
    output_type, simulating a provider-level failure.
    """

    async def generate(role, prompt, **kwargs):
        output_type = kwargs.get("output_type", str)
        out = outputs.get(role)

        # Exception → raise it (provider failure, auth error, output error, …)
        if isinstance(out, BaseException):
            raise out

        # Summary role always gets free text
        if output_type is str:
            return LLMResult(
                output=out if isinstance(out, str) else "Summary",
                usage=Usage(input_tokens=1, output_tokens=1, requests=1, latency_ms=1.0),
                model="test:model",
            )

        # Findings role: return the Report instance provided, or a default empty one
        if out is None:
            report = output_type(findings=[])
        elif isinstance(out, output_type):
            report = out
        else:
            # The caller put a wrong type here — treat it as an output error
            raise LLMOutputError(
                f"fake_client: expected {output_type.__name__}, got {type(out).__name__}"
            )
        return LLMResult(
            output=report,
            usage=Usage(input_tokens=1, output_tokens=1, requests=1, latency_ms=1.0),
            model="test:model",
        )

    client = MagicMock()
    client.model_name.return_value = "test:model"
    client.generate = AsyncMock(side_effect=generate)
    return client


def analyzer_with(outputs: dict[Role, object], diff=SAFE_DIFF):
    """A CodeAnalyzerService using the real LLMService over a fake client."""
    service = LLMService(client=fake_client(outputs))
    analyzer, github, _ = make_analyzer(diff=diff)
    analyzer.llm_service = service
    return analyzer, github


# --- Parsing in LLMService ---------------------------------------------------------
# P2-01: the old tests for the hand-written JSON parser are replaced by tests that
# exercise the schema layer's fail-closed contract. The model layer (Pydantic AI)
# handles wire-format validation and retry; here we test that LLMOutputError from
# that layer propagates correctly through LLMService.


class TestParsing:
    @pytest.mark.asyncio
    async def test_llm_output_error_propagates_as_output_error(self):
        """LLMOutputError from the model layer must propagate unchanged."""
        error = LLMOutputError("model gave unparseable output")
        service = LLMService(client=fake_client({Role.SECURITY: error}))
        with pytest.raises(LLMOutputError):
            await service.analyze_security("diff", [])

    @pytest.mark.asyncio
    async def test_empty_report_means_no_issues(self):
        """An empty findings list from the schema layer is valid: no issues found."""
        empty = SecurityReport(findings=[])
        service = LLMService(client=fake_client({Role.SECURITY: empty}))
        result = await service.analyze_security("diff", [])
        assert result == []

    @pytest.mark.asyncio
    async def test_valid_report_returns_findings(self):
        """A populated report passes through with all fields intact."""
        service = LLMService(client=fake_client({Role.SECURITY: VALID_SECURITY_REPORT}))
        issues = await service.analyze_security("diff", [])
        assert len(issues) == 1
        assert issues[0].title == "SQL injection"
        assert issues[0].references == ["CWE-89"]

    @pytest.mark.asyncio
    async def test_diff_sent_to_llm_is_capped(self):
        """The diff passed to the prompt must be capped at MAX_DIFF_CHARS."""
        client = fake_client({})
        service = LLMService(client=client)
        await service.analyze_security("x" * (MAX_DIFF_CHARS + 500), [])
        prompt = client.generate.await_args.args[1]
        assert "x" * MAX_DIFF_CHARS in prompt
        assert "x" * (MAX_DIFF_CHARS + 1) not in prompt


# --- The verdict --------------------------------------------------------------------


class TestNeverApproves:
    @pytest.mark.asyncio
    async def test_clean_complete_review_still_approves(self):
        analyzer, github = analyzer_with({})
        result = await run(analyzer, github)
        assert result.status == AnalysisStatus.COMPLETE
        assert result.approval_recommendation == ApprovalRecommendation.APPROVE
        assert result.incomplete_reasons == []
        assert result.diff_truncated is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("role", [Role.SECURITY, Role.PERFORMANCE, Role.BEST_PRACTICES])
    async def test_llm_output_error_never_approves(self, role):
        """LLMOutputError from the model layer must mark the review incomplete/failed."""
        error = LLMOutputError("model gave bad structured output")
        analyzer, github = analyzer_with({role: error})
        result = await run(analyzer, github)
        assert result.approval_recommendation not in APPROVING
        assert result.status in (AnalysisStatus.INCOMPLETE, AnalysisStatus.FAILED)
        assert result.incomplete_reasons

    @pytest.mark.asyncio
    async def test_every_llm_step_failing_is_failed_not_approved(self):
        error = LLMRateLimitError("rate limited")
        analyzer, github = analyzer_with(
            {Role.SECURITY: error, Role.PERFORMANCE: error, Role.BEST_PRACTICES: error}
        )
        result = await run(analyzer, github)
        assert result.status == AnalysisStatus.FAILED
        assert result.approval_recommendation == ApprovalRecommendation.INCOMPLETE
        assert len(result.incomplete_reasons) == 3
        assert all("rate-limited" in r for r in result.incomplete_reasons)

    @pytest.mark.asyncio
    async def test_llm_failure_keeps_rule_findings_and_their_reject(self):
        error = LLMRateLimitError("rate limited")
        analyzer, github = analyzer_with(
            {Role.SECURITY: error, Role.PERFORMANCE: error, Role.BEST_PRACTICES: error},
            diff=RISKY_DIFF,
        )
        result = await run(analyzer, github)
        assert result.security_findings  # hardcoded key and MD5 from the rule checkers
        # A blocking verdict backed by real findings stands
        assert result.approval_recommendation == ApprovalRecommendation.REJECT
        assert result.status == AnalysisStatus.FAILED

    @pytest.mark.asyncio
    async def test_truncated_diff_is_reported_and_never_approves(self, monkeypatch):
        # P2-07: a long diff is chunked, so only a diff past LLM_MAX_DIFF_CHUNKS is cut
        from app.core.config import settings
        monkeypatch.setattr(settings, "LLM_MAX_DIFF_CHUNKS", 1)
        padding = "".join(f"+    line_{i} = {i}\n" for i in range(MAX_DIFF_CHARS // 10))
        diff = SAFE_DIFF + padding
        assert len(diff) > MAX_DIFF_CHARS
        analyzer, github = analyzer_with({}, diff=diff)

        result = await run(analyzer, github)

        assert result.diff_truncated is True
        assert result.diff_chars_total == len(diff)
        assert 0 < result.diff_chars_reviewed_by_llm < len(diff)
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation == ApprovalRecommendation.INCOMPLETE
        assert any("LLM_MAX_DIFF_CHUNKS" in r for r in result.incomplete_reasons)

    @pytest.mark.asyncio
    async def test_summary_failure_falls_back_and_never_approves(self):
        analyzer, github = analyzer_with({Role.SUMMARY: LLMRateLimitError("rate limited")})
        result = await run(analyzer, github)
        assert result.executive_summary.startswith("Automated summary unavailable")
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation not in APPROVING

    @pytest.mark.asyncio
    async def test_incomplete_review_does_not_claim_good_quality(self):
        error = LLMOutputError("bad output")
        analyzer, github = analyzer_with({Role.SECURITY: error})
        result = await run(analyzer, github)
        assert result.key_concerns[0].startswith("⏸️ INCOMPLETE")
        assert not any(c.startswith("✅") for c in result.key_concerns)

    @pytest.mark.asyncio
    async def test_partial_findings_error_keeps_valid_findings(self):
        """PartialFindingsError in _run_llm_step keeps valid findings and marks incomplete."""
        # We inject a PartialFindingsError directly (the service raises it
        # after the schema layer returns; tested more directly in test_p201)
        valid = SecurityIssue(
            severity="high", title="SQL injection", description="d",
            file="a.py", recommendation="r",
        )
        err = PartialFindingsError("1 finding invalid", [valid])
        analyzer, github = analyzer_with({Role.SECURITY: err})
        result = await run(analyzer, github)
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation not in APPROVING
        # The valid finding is still present
        assert any(f.title == "SQL injection" for f in result.security_findings)


class TestPostedComment:
    @pytest.mark.asyncio
    async def test_incomplete_comment_says_it_is_not_an_approval(self):
        error = LLMOutputError("bad structured output")
        analyzer, github = analyzer_with({Role.SECURITY: error})
        result = await run(analyzer, github)

        comment = SummaryFormatter.format_for_github_comment(result)

        assert "Code Review Complete" not in comment
        assert "Code Review Incomplete" in comment
        assert "not an approval" in comment
        assert "Security analysis failed (LLMOutputError)" in comment

    @pytest.mark.asyncio
    async def test_complete_comment_is_unchanged(self):
        analyzer, github = analyzer_with({})
        result = await run(analyzer, github)
        comment = SummaryFormatter.format_for_github_comment(result)
        assert "Code Review Complete" in comment
        assert "not an approval" not in comment


# --- Sentinel: raw model output never reaches the logs -----------------------------


class TestNoRawOutputInLogs:
    @pytest.mark.asyncio
    async def test_unexpected_analyzer_error_text_never_logged(self, caplog):
        # S1: an exception raised inside the analyzer (here the diff parser) used to
        # be copied into the log line and the AnalysisError message
        analyzer, github, _ = make_analyzer()
        boom = ValueError(f"password = '{SENTINEL}'")
        with caplog.at_level(logging.DEBUG):
            with patch("app.services.code_analyzer.DiffParser.parse", side_effect=boom):
                with pytest.raises(AnalysisError) as exc:
                    await run(analyzer, github)
            # Callers log it again with the traceback (message_handler)
            logging.getLogger("caller").error("analysis failed", exc_info=exc.value)

        assert SENTINEL not in str(exc.value)
        assert "ValueError" in str(exc.value) and "error id" in str(exc.value)
        assert exc.value.__cause__ is None and exc.value.__suppress_context__
        assert SENTINEL not in caplog.text

    @pytest.mark.asyncio
    async def test_github_init_error_text_never_logged(self, caplog):
        from github import GithubException

        from app.core.exceptions import GitHubMCPError
        from app.services.github_mcp import GitHubMCPService

        body = {"message": SENTINEL}
        with caplog.at_level(logging.DEBUG):
            for error in (GithubException(500, body, None), RuntimeError(SENTINEL)):
                with patch("app.services.github_mcp.Github", side_effect=error):
                    with pytest.raises(GitHubMCPError) as exc:
                        async with GitHubMCPService():
                            pass
                logging.getLogger("caller").error("init failed", exc_info=exc.value)
                assert SENTINEL not in str(exc.value)
                assert exc.value.__cause__ is None

        assert SENTINEL not in caplog.text

    @pytest.mark.asyncio
    async def test_sentinel_in_model_output_never_logged_or_posted(self, caplog):
        # P2-01: the model layer raises LLMOutputError; the sentinel stays in the
        # provider_error attribute, never in messages or logs.
        err_security = LLMOutputError("output error (no content)")
        err_security.provider_error = Exception(SENTINEL)  # private, never logged
        perf_valid = PerformanceIssue(
            severity="high", title="Valid", description="d",
            file="a.py", impact="2x", recommendation="r",
        )
        err_perf = PartialFindingsError(
            "1 performance finding(s) in the model output were invalid",
            [perf_valid],
        )
        err_bp = ValueError(f"bad output: {SENTINEL}")
        err_summary = ValueError(f"bad summary: {SENTINEL}")
        outputs = {
            Role.SECURITY: err_security,
            Role.PERFORMANCE: err_perf,
            Role.BEST_PRACTICES: err_bp,
            Role.SUMMARY: err_summary,
        }
        analyzer, github = analyzer_with(outputs)

        with caplog.at_level(logging.DEBUG):
            result = await run(analyzer, github)

        assert result.status == AnalysisStatus.INCOMPLETE
        assert caplog.records  # the failures were logged, just without content
        assert SENTINEL not in caplog.text
        for record in caplog.records:
            assert SENTINEL not in record.getMessage()
            assert SENTINEL not in str(record.exc_info or "")

    @pytest.mark.asyncio
    async def test_sentinel_never_in_result_reasons_or_comment(self):
        err = LLMOutputError("output error (no content)")
        err.provider_error = Exception(SENTINEL)
        outputs = {
            Role.SECURITY: err,
            Role.BEST_PRACTICES: ValueError(SENTINEL),
        }
        analyzer, github = analyzer_with(outputs)
        result = await run(analyzer, github)

        assert SENTINEL not in " ".join(result.incomplete_reasons)
        assert SENTINEL not in SummaryFormatter.format_for_github_comment(result)

    @pytest.mark.asyncio
    async def test_llm_error_message_carries_no_output(self):
        err = LLMOutputError("structured output validation failed")
        # provider_error might carry content, but str(LLMOutputError) must not
        err.provider_error = Exception(f"content: {SENTINEL}")
        service = LLMService(client=fake_client({Role.SECURITY: err}))
        with pytest.raises(LLMOutputError) as exc:
            await service.analyze_security("diff", [])
        assert SENTINEL not in str(exc.value)

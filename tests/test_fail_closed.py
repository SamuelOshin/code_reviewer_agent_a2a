"""P1-06: the review fails closed.

Unreadable, truncated or partial LLM output, a failed LLM call, or a diff longer than
the LLM sees, must never produce an approval. Rule findings survive LLM failures, the
truncation is reported in the result, and raw model output never reaches the logs.

The model-layer client is faked, so the real parsing in `LLMService` runs. No
provider is called.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.exceptions import AnalysisError
from app.llm import LLMResult, Role, Usage
from app.llm.errors import LLMOutputError, LLMRateLimitError
from app.models.analysis import AnalysisStatus, ApprovalRecommendation, SecurityIssue
from app.services.llm_service import MAX_DIFF_CHARS, LLMService, PartialFindingsError
from app.utils.formatters import SummaryFormatter
from tests.test_code_analyzer import RISKY_DIFF, SAFE_DIFF, make_analyzer, run

APPROVING = {ApprovalRecommendation.APPROVE, ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS}

SENTINEL = "SENTINEL-LLM-OUTPUT-7f3a"

VALID_FINDING = (
    '{"severity": "high", "title": "SQL injection", "description": "d", '
    '"file": "a.py", "line_number": 3, "recommendation": "r", "references": ["CWE-89"]}'
)

# Output that must never be read as "no issues"
MALFORMED_OUTPUTS = {
    "prose": "I could not find any problems in this diff.",
    "empty": "",
    "object": '{"findings": []}',
    "truncated": '[{"severity": "high", "title": "SQL injection", "descr',
    "truncated_fenced": '```json\n[{"severity": "high", "title": "SQL inj\n```',
    "nested_array": f"[[{VALID_FINDING}]]",
    "array_of_strings": '["looks fine"]',
    "prose_with_citation": "All good, see [1] for details.",
    # B1: a truncated array with an inner `[]` used to parse as "no issues"
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


def fake_client(outputs: dict[Role, object]) -> MagicMock:
    """A model-layer client that returns (or raises) a fixed output per role."""

    async def generate(role, prompt, **kwargs):
        out = outputs.get(role, "[]" if role != Role.SUMMARY else "Summary")
        if isinstance(out, BaseException):
            raise out
        return LLMResult(
            output=out,
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


class TestParsing:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("output", MALFORMED_OUTPUTS.values(), ids=MALFORMED_OUTPUTS.keys())
    async def test_unreadable_output_raises_instead_of_empty_list(self, output):
        service = LLMService(client=fake_client({Role.SECURITY: output}))
        with pytest.raises(LLMOutputError):
            await service.analyze_security("diff", [])

    @pytest.mark.asyncio
    @pytest.mark.parametrize("output", [
        f"[{VALID_FINDING}]",
        f"```json\n[{VALID_FINDING}]\n```",
        f"Here is what I found:\n[{VALID_FINDING}]\nHope that helps.",
    ], ids=["bare", "fenced", "prose"])
    async def test_valid_array_is_parsed_including_nested_fields(self, output):
        # The old non-greedy regex cut the array at the first ']' (inside
        # "references") and returned [] for the prose case
        service = LLMService(client=fake_client({Role.SECURITY: output}))
        issues = await service.analyze_security("diff", [])
        assert len(issues) == 1
        assert issues[0].references == ["CWE-89"]

    @pytest.mark.asyncio
    async def test_empty_array_means_no_issues(self):
        service = LLMService(client=fake_client({Role.SECURITY: "[]"}))
        assert await service.analyze_security("diff", []) == []

    @pytest.mark.asyncio
    async def test_invalid_findings_are_dropped_but_reported(self):
        output = f'[{VALID_FINDING}, {{"severity": "nope", "title": "x"}}]'
        service = LLMService(client=fake_client({Role.SECURITY: output}))
        with pytest.raises(PartialFindingsError) as exc:
            await service.analyze_security("diff", [])
        assert len(exc.value.findings) == 1
        assert isinstance(exc.value.findings[0], SecurityIssue)

    @pytest.mark.asyncio
    async def test_diff_sent_to_llm_is_capped(self):
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
    @pytest.mark.parametrize("output", MALFORMED_OUTPUTS.values(), ids=MALFORMED_OUTPUTS.keys())
    async def test_malformed_output_never_approves(self, role, output):
        analyzer, github = analyzer_with({role: output})
        result = await run(analyzer, github)
        assert result.approval_recommendation not in APPROVING
        assert result.approval_recommendation == ApprovalRecommendation.INCOMPLETE
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.incomplete_reasons

    @pytest.mark.asyncio
    async def test_partly_invalid_output_never_approves_and_keeps_valid_findings(self):
        output = f'[{VALID_FINDING}, {{"title": "missing fields"}}]'
        analyzer, github = analyzer_with({Role.SECURITY: output})
        result = await run(analyzer, github)
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation not in APPROVING
        assert [i.title for i in result.security_findings] == ["SQL injection"]

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
    async def test_truncated_diff_is_reported_and_never_approves(self):
        padding = "".join(f"+    line_{i} = {i}\n" for i in range(MAX_DIFF_CHARS // 10))
        diff = SAFE_DIFF + padding
        assert len(diff) > MAX_DIFF_CHARS
        analyzer, github = analyzer_with({}, diff=diff)

        result = await run(analyzer, github)

        assert result.diff_truncated is True
        assert result.diff_chars_total == len(diff)
        assert result.diff_chars_reviewed_by_llm == MAX_DIFF_CHARS
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation == ApprovalRecommendation.INCOMPLETE
        assert any("first 8,000" in r for r in result.incomplete_reasons)

    @pytest.mark.asyncio
    async def test_summary_failure_falls_back_and_never_approves(self):
        analyzer, github = analyzer_with({Role.SUMMARY: LLMRateLimitError("rate limited")})
        result = await run(analyzer, github)
        assert result.executive_summary.startswith("Automated summary unavailable")
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation not in APPROVING

    @pytest.mark.asyncio
    async def test_incomplete_review_does_not_claim_good_quality(self):
        analyzer, github = analyzer_with({Role.SECURITY: "not json"})
        result = await run(analyzer, github)
        assert result.key_concerns[0].startswith("⏸️ INCOMPLETE")
        assert not any(c.startswith("✅") for c in result.key_concerns)


class TestPostedComment:
    @pytest.mark.asyncio
    async def test_incomplete_comment_says_it_is_not_an_approval(self):
        analyzer, github = analyzer_with({Role.SECURITY: "not json"})
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
        outputs = {
            # Unparseable text (the old code logged its first 200 characters)
            Role.SECURITY: f"Sorry, {SENTINEL} is not something I can review.",
            # Invalid findings: validation errors echo their input
            Role.PERFORMANCE: (
                f'[{{"severity": "{SENTINEL}", "title": "{SENTINEL}", '
                f'"impact": "{SENTINEL}", "file": "a.py"}}]'
            ),
            # A non-LLMError whose message carries output (str(e) used to be logged
            # and copied into the LLMError message)
            Role.BEST_PRACTICES: ValueError(f"bad output: {SENTINEL}"),
            Role.SUMMARY: ValueError(f"bad summary: {SENTINEL}"),
        }
        analyzer, github = analyzer_with(outputs)

        with caplog.at_level(logging.DEBUG):
            # LLMService wraps the summary ValueError in an LLMError, so the analyzer
            # falls back to a plain summary instead of raising
            result = await run(analyzer, github)

        assert result.status == AnalysisStatus.INCOMPLETE
        assert caplog.records  # the failures were logged, just without content
        assert SENTINEL not in caplog.text
        for record in caplog.records:
            assert SENTINEL not in record.getMessage()
            assert SENTINEL not in str(record.exc_info or "")

    @pytest.mark.asyncio
    async def test_sentinel_never_in_result_reasons_or_comment(self):
        outputs = {
            Role.SECURITY: f"{SENTINEL} [{{\"title\": \"{SENTINEL}\"}}]",
            Role.BEST_PRACTICES: ValueError(SENTINEL),
        }
        analyzer, github = analyzer_with(outputs)
        result = await run(analyzer, github)

        assert SENTINEL not in " ".join(result.incomplete_reasons)
        assert SENTINEL not in SummaryFormatter.format_for_github_comment(result)

    @pytest.mark.asyncio
    async def test_llm_error_message_carries_no_output(self):
        service = LLMService(client=fake_client({Role.SECURITY: f"text {SENTINEL}"}))
        with pytest.raises(LLMOutputError) as exc:
            await service.analyze_security("diff", [])
        assert SENTINEL not in str(exc.value)

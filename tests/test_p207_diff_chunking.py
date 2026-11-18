"""P2-07: the LLM reviews whole PRs by chunking large diffs.

Before P2-07 the findings prompts held only the first 8,000 characters of the diff.
Now the diff is split into chunks (per file, then per hunk, then per line) and each
chunk is reviewed. A diff needing more than LLM_MAX_DIFF_CHUNKS chunks is reviewed up
to the cap and marked incomplete, with the uncovered part stated in the result.
"""

import random
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import settings
from app.llm import LLMResult, Role, Usage
from app.llm.errors import LLMOutputError, LLMRateLimitError
from app.models.analysis import (
    AnalysisStatus,
    ApprovalRecommendation,
    SecurityIssue,
    SecurityReport,
)
from app.services.code_analyzer import RATE_LIMITED_TEXT
from app.services.llm_service import MAX_DIFF_CHARS, LLMService
from app.utils.diff_chunker import chunk_diff
from tests.test_code_analyzer import make_analyzer, run

APPROVING = {ApprovalRecommendation.APPROVE, ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS}
BUG_MARKER = "eval(request_body)  # BUG-MARKER-P207"


def file_diff(name: str, lines: int, hunks: int = 1, extra: str = "") -> str:
    """A new-file diff with `hunks` hunks of `lines` added lines each."""
    out = [
        f"diff --git a/{name} b/{name}\n",
        "new file mode 100644\n",
        "index 0000000..1111111\n",
        "--- /dev/null\n",
        f"+++ b/{name}\n",
    ]
    for h in range(hunks):
        out.append(f"@@ -0,0 +{h * lines + 1},{lines} @@\n")
        out.extend(f"+value_{h}_{i} = {i}  # padding to make the diff long\n" for i in range(lines))
    if extra:
        out.append(f"+{extra}\n")
    return "".join(out)


def header_of(diff: str) -> str:
    return diff[: diff.index("@@")]


# --- The chunker ------------------------------------------------------------------


class TestChunker:
    def test_a_diff_that_fits_is_one_unchanged_chunk(self):
        diff = file_diff("a.py", 5)
        result = chunk_diff(diff, 8000, 8)
        assert result.chunks == [diff]
        assert result.chars_reviewed == result.chars_total == len(diff)
        assert not result.capped

    def test_an_empty_diff_is_still_one_chunk(self):
        result = chunk_diff("", 8000, 8)
        assert result.chunks == [""]
        assert not result.capped

    def test_whole_files_are_packed_in_order_without_loss(self):
        files = [file_diff(f"f{i}.py", 40) for i in range(12)]
        diff = "".join(files)
        result = chunk_diff(diff, 8000, 50)
        assert len(result.chunks) > 1
        assert all(len(c) <= 8000 for c in result.chunks)
        # No file was split, so the chunks are the diff cut at file boundaries
        assert "".join(result.chunks) == diff
        assert result.chars_reviewed == len(diff)
        assert result.files_total == 12
        assert result.files_not_fully_reviewed == 0
        assert not result.capped

    def test_a_big_file_is_split_at_hunks_with_its_header_repeated(self):
        diff = file_diff("big.py", 60, hunks=10)
        result = chunk_diff(diff, 8000, 50)
        header = header_of(diff)
        assert len(result.chunks) > 1
        for chunk in result.chunks:
            assert len(chunk) <= 8000
            assert chunk.startswith(header)
        # Every hunk appears once, in order
        bodies = "".join(c[len(header):] for c in result.chunks)
        assert bodies == diff[len(header):]
        assert result.chars_reviewed == len(diff)
        assert not result.capped

    def test_a_huge_hunk_is_split_by_lines(self):
        diff = file_diff("huge.py", 600)
        result = chunk_diff(diff, 8000, 50)
        header = header_of(diff)
        assert len(result.chunks) > 1
        assert all(len(c) <= 8000 and c.startswith(header) for c in result.chunks)
        bodies = "".join(c[len(header):] for c in result.chunks)
        assert bodies == diff[len(header):]
        # Splits fall on line breaks
        assert all(c.endswith("\n") for c in result.chunks)

    def test_a_single_line_longer_than_a_chunk_is_split_by_characters(self):
        minified = "x" * 20000
        diff = file_diff("app.min.js", 1, extra=minified)
        result = chunk_diff(diff, 8000, 50)
        header = header_of(diff)
        assert all(len(c) <= 8000 for c in result.chunks)
        bodies = "".join(c[len(header):] for c in result.chunks)
        assert bodies == diff[len(header):]
        assert result.chars_reviewed == len(diff)

    def test_text_that_is_not_a_git_diff_is_still_covered(self):
        text = "line of text\n" * 2000
        result = chunk_diff(text, 8000, 50)
        assert all(len(c) <= 8000 for c in result.chunks)
        assert "".join(result.chunks) == text
        assert not result.capped

    def test_the_chunk_cap_is_reported(self):
        diff = "".join(file_diff(f"f{i}.py", 150) for i in range(6))
        result = chunk_diff(diff, 8000, 2)
        assert len(result.chunks) == 2
        assert result.chunks_needed > 2
        assert result.capped
        assert 0 < result.chars_reviewed < result.chars_total
        assert result.files_not_fully_reviewed > 0
        # What was reviewed is the start of the diff
        assert diff.startswith(result.chunks[0])

    def test_a_partly_reviewed_file_counts_as_not_fully_reviewed(self):
        diff = file_diff("big.py", 60, hunks=10)
        result = chunk_diff(diff, 8000, 1)
        assert result.capped
        assert result.files_total == 1
        assert result.files_not_fully_reviewed == 1

    @pytest.mark.parametrize("max_chars,max_chunks", [(0, 1), (8000, 0), (-1, 5)])
    def test_bad_limits_are_refused(self, max_chars, max_chunks):
        with pytest.raises(ValueError):
            chunk_diff("diff", max_chars, max_chunks)

    def test_random_diffs_are_always_fully_covered_within_the_size_limit(self):
        rng = random.Random(207)
        for _ in range(60):
            files = []
            for i in range(rng.randint(1, 8)):
                files.append(file_diff(f"dir/f{i}.py", rng.randint(1, 200), hunks=rng.randint(1, 6),
                                       extra="y" * rng.choice([0, 0, 50, 9000])))
            diff = "".join(files)
            size = rng.choice([500, 2000, 8000])
            result = chunk_diff(diff, size, 10_000)
            assert all(0 < len(c) <= size for c in result.chunks)
            assert result.chars_reviewed == result.chars_total == len(diff)
            assert result.files_not_fully_reviewed == 0
            assert not result.capped


# --- The analyzer over a fake model ----------------------------------------------


def recording_client(fail_on: dict[Role, object] | None = None):
    """A fake model client that records prompts and reports BUG_MARKER when it sees it.

    `fail_on` maps a role to an exception raised for every call of that role, or to a
    (call_number, exception) pair raised only on that call (1-based).
    """
    fail_on = fail_on or {}
    prompts: dict[Role, list[str]] = {r: [] for r in Role}

    async def generate(role, prompt, **kwargs):
        prompts[role].append(prompt)
        output_type = kwargs.get("output_type", str)
        rule = fail_on.get(role)
        if isinstance(rule, BaseException):
            raise rule
        if isinstance(rule, tuple) and rule[0] == len(prompts[role]):
            raise rule[1]
        usage = Usage(input_tokens=1, output_tokens=1, requests=1, latency_ms=1.0)
        if output_type is str:
            return LLMResult(output="Summary", usage=usage, model="test:model")
        findings = []
        if output_type is SecurityReport and BUG_MARKER in prompt:
            findings = [SecurityIssue(severity="critical", title="eval of request body",
                                      description="d", file="late.py", line_number=1,
                                      recommendation="r")]
        return LLMResult(output=output_type(findings=findings), usage=usage, model="test:model")

    client = MagicMock()
    client.model_name.return_value = "test:model"
    client.generate = AsyncMock(side_effect=generate)
    return client, prompts


def analyzer_over(diff: str, fail_on=None):
    client, prompts = recording_client(fail_on)
    analyzer, github, _ = make_analyzer(diff=diff)
    analyzer.llm_service = LLMService(client=client)
    return analyzer, github, prompts


LONG_DIFF = file_diff("early.py", 300) + file_diff("late.py", 2, extra=BUG_MARKER)


class TestWholePrReview:
    @pytest.mark.asyncio
    async def test_a_bug_past_the_old_8000_character_limit_is_reviewed(self):
        """Acceptance check for P2-07."""
        assert LONG_DIFF.index(BUG_MARKER) > MAX_DIFF_CHARS
        analyzer, github, prompts = analyzer_over(LONG_DIFF)

        result = await run(analyzer, github)

        assert any(BUG_MARKER in p for p in prompts[Role.SECURITY])
        assert any(i.title == "eval of request body" for i in result.security_findings)
        assert result.diff_truncated is False
        assert result.diff_chars_reviewed_by_llm == result.diff_chars_total == len(LONG_DIFF)
        assert result.status == AnalysisStatus.COMPLETE
        # The critical finding from the late chunk drives the verdict
        assert result.approval_recommendation not in APPROVING

    @pytest.mark.asyncio
    async def test_every_role_reviews_every_chunk_and_the_summary_runs_once(self):
        analyzer, github, prompts = analyzer_over(LONG_DIFF)
        await run(analyzer, github)
        n = len(chunk_diff(LONG_DIFF, MAX_DIFF_CHARS, settings.LLM_MAX_DIFF_CHUNKS).chunks)
        assert n > 1
        assert len(prompts[Role.SECURITY]) == n
        assert len(prompts[Role.PERFORMANCE]) == n
        assert len(prompts[Role.BEST_PRACTICES]) == n
        assert len(prompts[Role.SUMMARY]) == 1

    @pytest.mark.asyncio
    async def test_a_diff_past_the_chunk_cap_is_incomplete_and_says_how_much(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_MAX_DIFF_CHUNKS", 1)
        analyzer, github, prompts = analyzer_over(LONG_DIFF)

        result = await run(analyzer, github)

        assert len(prompts[Role.SECURITY]) == 1
        assert not any(BUG_MARKER in p for p in prompts[Role.SECURITY])
        assert result.diff_truncated is True
        assert result.diff_chars_reviewed_by_llm < result.diff_chars_total
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation == ApprovalRecommendation.INCOMPLETE
        reason = next(r for r in result.incomplete_reasons if "LLM_MAX_DIFF_CHUNKS" in r)
        assert f"{len(LONG_DIFF):,} characters" in reason
        assert "2 file(s)" in reason
        assert "Rule-based checks covered the whole diff" in reason

    @pytest.mark.asyncio
    async def test_one_failed_chunk_keeps_the_others_and_marks_incomplete(self):
        analyzer, github, _ = analyzer_over(
            LONG_DIFF, fail_on={Role.SECURITY: (1, LLMOutputError("bad output"))}
        )

        result = await run(analyzer, github)

        # The bug was in the second chunk, which still ran
        assert any(i.title == "eval of request body" for i in result.security_findings)
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation not in APPROVING
        assert any("Security analysis failed on 1 of" in r and "LLMOutputError" in r
                   for r in result.incomplete_reasons)

    @pytest.mark.asyncio
    async def test_a_rate_limit_stops_the_rest_of_that_step(self):
        analyzer, github, prompts = analyzer_over(
            LONG_DIFF, fail_on={Role.SECURITY: LLMRateLimitError("rate limited")}
        )

        result = await run(analyzer, github)

        assert len(prompts[Role.SECURITY]) == 1  # no calls wasted on a throttled model
        assert f"Security analysis failed: {RATE_LIMITED_TEXT}" in result.incomplete_reasons
        assert result.status == AnalysisStatus.INCOMPLETE

    @pytest.mark.asyncio
    async def test_a_rate_limit_after_a_good_chunk_keeps_the_good_findings(self):
        diff = file_diff("late.py", 2, extra=BUG_MARKER) + file_diff("other.py", 300)
        analyzer, github, _ = analyzer_over(
            diff, fail_on={Role.SECURITY: (2, LLMRateLimitError("rate limited"))}
        )

        result = await run(analyzer, github)

        assert any(i.title == "eval of request body" for i in result.security_findings)
        assert any("failed on" in r and RATE_LIMITED_TEXT in r for r in result.incomplete_reasons)
        assert result.status == AnalysisStatus.INCOMPLETE

    @pytest.mark.asyncio
    async def test_all_chunks_rate_limited_on_every_step_is_failed(self):
        error = LLMRateLimitError("rate limited")
        analyzer, github, _ = analyzer_over(
            LONG_DIFF,
            fail_on={Role.SECURITY: error, Role.PERFORMANCE: error, Role.BEST_PRACTICES: error},
        )

        result = await run(analyzer, github)

        assert result.status == AnalysisStatus.FAILED
        assert result.executive_summary.startswith("The model was rate-limited")

    @pytest.mark.asyncio
    async def test_every_chunk_failing_with_mixed_errors_is_a_failed_step(self):
        analyzer, github, _ = analyzer_over(
            LONG_DIFF, fail_on={Role.SECURITY: LLMOutputError("bad output")}
        )

        result = await run(analyzer, github)

        assert "Security analysis failed (LLMOutputError)." in result.incomplete_reasons
        assert result.status == AnalysisStatus.INCOMPLETE

    @pytest.mark.asyncio
    async def test_no_prompt_holds_more_than_one_chunk_of_diff(self):
        analyzer, github, prompts = analyzer_over(file_diff("huge.py", 900))
        await run(analyzer, github)
        for prompt in prompts[Role.SECURITY]:
            diff_part = prompt.split("```diff\n", 1)[1].rsplit("\n```", 1)[0]
            assert len(diff_part) <= MAX_DIFF_CHARS


class TestConfig:
    def test_default_cap(self):
        assert settings.LLM_MAX_DIFF_CHUNKS >= 1

    @pytest.mark.parametrize("value", [0, -1, 51])
    def test_out_of_range_caps_are_refused(self, value):
        from pydantic import ValidationError

        from app.core.config import Settings
        with pytest.raises(ValidationError):
            Settings(
                GITHUB_TOKEN="t", GITHUB_WEBHOOK_SECRET="s" * 40, API_KEY="k" * 40,
                LLM_MAX_DIFF_CHUNKS=value, _env_file=None,
            )

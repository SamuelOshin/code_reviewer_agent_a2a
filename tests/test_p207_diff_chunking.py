"""P2-07: the LLM reviews whole PRs by chunking large diffs.

Before P2-07 the findings prompts held only the first 8,000 characters of the diff.
Now the diff is split into chunks (per file, then per hunk, then per line) and each
chunk is reviewed. A diff needing more than LLM_MAX_DIFF_CHUNKS chunks is reviewed up
to the cap and marked incomplete, with the uncovered part stated in the result.
"""

import random
import re
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


CONTINUED = re.compile(r"^@@ -([0-9]+),[0-9]+ \+([0-9]+),[0-9]+ @@ \(continued\)\n")


def body_of(chunk: str, header: str) -> str:
    """A chunk's original text: without the repeated file header or continuation line."""
    body = chunk[len(header) :]
    return CONTINUED.sub("", body, count=1)


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
        bodies = "".join(c[len(header) :] for c in result.chunks)
        assert bodies == diff[len(header) :]
        assert result.chars_reviewed == len(diff)
        assert not result.capped

    def test_a_huge_hunk_is_split_by_lines(self):
        diff = file_diff("huge.py", 600)
        result = chunk_diff(diff, 8000, 50)
        header = header_of(diff)
        assert len(result.chunks) > 1
        assert all(len(c) <= 8000 and c.startswith(header) for c in result.chunks)
        bodies = "".join(body_of(c, header) for c in result.chunks)
        assert bodies == diff[len(header) :]
        # Splits fall on line breaks
        assert all(c.endswith("\n") for c in result.chunks)

    def test_a_single_line_longer_than_a_chunk_is_split_by_characters(self):
        minified = "x" * 20000
        diff = file_diff("app.min.js", 1, extra=minified)
        result = chunk_diff(diff, 8000, 50)
        header = header_of(diff)
        assert all(len(c) <= 8000 for c in result.chunks)
        bodies = "".join(body_of(c, header) for c in result.chunks)
        assert bodies == diff[len(header) :]
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

    # --- S2 from the review: pieces of a split hunk keep real line numbers ---------

    def test_every_piece_of_a_split_hunk_says_where_it_starts(self):
        lines = "".join(f"+line {i} of the new file, padded to be long\n" for i in range(1, 1001))
        diff = (
            "diff --git a/n.py b/n.py\nnew file mode 100644\n--- /dev/null\n+++ b/n.py\n"
            "@@ -0,0 +1,1000 @@\n" + lines
        )
        result = chunk_diff(diff, 8000, 50)
        header = header_of(diff)
        assert len(result.chunks) > 2
        for chunk in result.chunks[1:]:
            match = CONTINUED.match(chunk[len(header) :])
            assert match, "a later piece has no hunk header"
            first_line = chunk[len(header) + match.end() :].split("\n", 1)[0]
            assert first_line.startswith(f"+line {match[2]} ")
            assert len(chunk) <= 8000
        assert result.chars_reviewed == len(diff)
        assert sum(result.chunk_chars) == len(diff)

    def test_line_numbers_follow_context_and_deleted_lines(self):
        # Context moves both numbers, + only the new one, - only the old one
        old_no, new_no = 10, 20
        body = []
        for i in range(900):
            kind = " +-"[i % 3]
            body.append(f"{kind}old={old_no} new={new_no} padding to make it long enough\n")
            old_no += kind != "+"
            new_no += kind != "-"
        diff = (
            "diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n"
            "@@ -10,600 +20,600 @@ def handler():\n" + "".join(body)
        )
        result = chunk_diff(diff, 8000, 50)
        header = header_of(diff)
        assert len(result.chunks) > 2
        for chunk in result.chunks[1:]:
            match = CONTINUED.match(chunk[len(header) :])
            first = chunk[len(header) + match.end() :].split("\n", 1)[0]
            if first[0] != "+":
                assert f"old={match[1]} " in first
            if first[0] != "-":
                assert f"new={match[2]} " in first

    def test_no_newline_marker_is_not_counted_as_a_line(self):
        body = "".join(f"+row {i} with padding padding padding\n" for i in range(1, 400))
        diff = (
            "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1,1 +1,400 @@\n"
            "-old\n\\ No newline at end of file\n" + body
        )
        result = chunk_diff(diff, 4000, 50)
        header = header_of(diff)
        match = CONTINUED.match(result.chunks[1][len(header) :])
        first = result.chunks[1][len(header) + match.end() :].split("\n", 1)[0]
        assert first.startswith(f"+row {match[2]} ")

    @pytest.mark.parametrize("sep", ["\u2028", "\u2029", "\x0c", "\x85", "\x1c", "\r"])
    def test_only_newline_ends_a_line_for_continuation_numbers(self, sep):
        # Round 2 review: str.splitlines broke "+s = 'a<sep>b'" into two lines, so the
        # old-side number of every later piece was one too high
        body = [f"+s = 'a{sep}b'\n"]
        old_no, new_no = 1, 2
        for _ in range(60):
            body.append(f" ctx old={old_no} new={new_no} padding padding\n")
            old_no += 1
            new_no += 1
        diff = "diff --git a/s.js b/s.js\n--- a/s.js\n+++ b/s.js\n@@ -1,60 +1,61 @@\n" + "".join(
            body
        )
        result = chunk_diff(diff, 600, 50)
        header = header_of(diff)
        assert len(result.chunks) > 2
        for chunk in result.chunks[1:]:
            match = CONTINUED.match(chunk[len(header) :])
            first = chunk[len(header) + match.end() :].split("\n", 1)[0]
            assert f"old={match[1]} new={match[2]} " in first
        assert result.chars_reviewed == len(diff)

    def test_a_line_separator_in_content_is_not_a_new_file(self):
        diff = file_diff("a.js", 3, extra="x = 'a\u2028diff --git b'") + file_diff("b.js", 3)
        assert chunk_diff(diff, 8000, 8).files_total == 2

    def test_files_complete_after_counts_each_file_once(self):
        diff = "".join(file_diff(f"f{i}.py", 150) for i in range(6))
        result = chunk_diff(diff, 8000, 50)
        assert result.files_complete_after[-1] == 6
        assert result.files_complete_after == sorted(result.files_complete_after)

    def test_absurd_hunk_line_numbers_still_fit_the_chunk_size(self):
        huge = "9" * 80
        body = "".join(f"+x{i} padding padding padding padding\n" for i in range(800))
        diff = (
            f"diff --git a/z.py b/z.py\n--- a/z.py\n+++ b/z.py\n@@ -{huge},1 +{huge},800 @@\n"
            + body
        )
        result = chunk_diff(diff, 8000, 50)
        assert all(len(c) <= 8000 for c in result.chunks)
        assert result.chars_reviewed == len(diff)

    def test_a_very_long_line_is_split_in_linear_time(self):
        # F1 from the review: the old split copied the rest of the line on every pass
        import time

        diff = file_diff("big.min.js", 1, extra="z" * 8_000_000)
        started = time.perf_counter()
        result = chunk_diff(diff, 8000, 10_000)
        assert time.perf_counter() - started < 5
        assert result.chars_reviewed == len(diff)

    @pytest.mark.parametrize("max_chars,max_chunks", [(0, 1), (8000, 0), (-1, 5)])
    def test_bad_limits_are_refused(self, max_chars, max_chunks):
        with pytest.raises(ValueError):
            chunk_diff("diff", max_chars, max_chunks)

    def test_random_diffs_are_always_fully_covered_within_the_size_limit(self):
        rng = random.Random(207)
        for _ in range(60):
            files = []
            for i in range(rng.randint(1, 8)):
                files.append(
                    file_diff(
                        f"dir/f{i}.py",
                        rng.randint(1, 200),
                        hunks=rng.randint(1, 6),
                        extra="y" * rng.choice([0, 0, 50, 9000]),
                    )
                )
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
            findings = [
                SecurityIssue(
                    severity="critical",
                    title="eval of request body",
                    description="d",
                    file="late.py",
                    line_number=1,
                    recommendation="r",
                )
            ]
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
        assert any(
            "Security analysis failed on 1 of" in r and "LLMOutputError" in r
            for r in result.incomplete_reasons
        )

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

    # --- S1 from the review: a time budget so a big PR still returns a result -------

    @pytest.mark.asyncio
    async def test_the_time_budget_stops_new_parts_and_reports_coverage(self, monkeypatch):
        import itertools

        import app.services.code_analyzer as code_analyzer

        monkeypatch.setattr(settings, "LLM_REVIEW_BUDGET_SECONDS", 10.0)
        ticks = itertools.count(0, 100)  # each reading is 100 s later than the last
        monkeypatch.setattr(code_analyzer, "_clock", lambda: next(ticks))
        analyzer, github, prompts = analyzer_over(LONG_DIFF)

        result = await run(analyzer, github)

        chunked = chunk_diff(LONG_DIFF, MAX_DIFF_CHARS, settings.LLM_MAX_DIFF_CHUNKS)
        assert len(chunked.chunks) > 1
        # The first part always runs, through every step; nothing after it
        for role in (Role.SECURITY, Role.PERFORMANCE, Role.BEST_PRACTICES):
            assert len(prompts[role]) == 1
        assert len(prompts[Role.SUMMARY]) == 1
        assert result.diff_truncated is True
        assert result.diff_chars_reviewed_by_llm == chunked.chunk_chars[0]
        assert result.status == AnalysisStatus.INCOMPLETE
        assert result.approval_recommendation == ApprovalRecommendation.INCOMPLETE
        reason = next(r for r in result.incomplete_reasons if "LLM_REVIEW_BUDGET_SECONDS" in r)
        assert f"(1 of {chunked.chunks_needed} diff parts" in reason
        # A budget stop is not reported as a failed step
        assert not any("failed on" in r for r in result.incomplete_reasons)

    @pytest.mark.asyncio
    async def test_cap_and_budget_together_give_one_true_coverage_reason(self, monkeypatch):
        import itertools

        import app.services.code_analyzer as code_analyzer

        diff = "".join(file_diff(f"f{i}.py", 150) for i in range(10))
        monkeypatch.setattr(settings, "LLM_MAX_DIFF_CHUNKS", 3)
        monkeypatch.setattr(settings, "LLM_REVIEW_BUDGET_SECONDS", 10.0)
        ticks = itertools.count(0, 100)
        monkeypatch.setattr(code_analyzer, "_clock", lambda: next(ticks))
        analyzer, github, _ = analyzer_over(diff)

        result = await run(analyzer, github)

        chunked = chunk_diff(diff, MAX_DIFF_CHARS, 3)
        reasons = [r for r in result.incomplete_reasons if "diff parts" in r]
        assert len(reasons) == 1
        reason = reasons[0]
        assert f"reviewed {chunked.chunk_chars[0]:,} of them" in reason
        assert f"(1 of {chunked.chunks_needed} diff parts" in reason
        assert "LLM_MAX_DIFF_CHUNKS" in reason and "LLM_REVIEW_BUDGET_SECONDS" in reason
        not_fully = chunked.files_total - chunked.files_complete_after[0]
        assert f"and {not_fully} file(s) were not fully reviewed" in reason
        assert result.diff_chars_reviewed_by_llm == chunked.chunk_chars[0]

    @pytest.mark.asyncio
    async def test_all_steps_rate_limited_stops_the_loop(self):
        error = LLMRateLimitError("rate limited")
        analyzer, github, prompts = analyzer_over(
            LONG_DIFF,
            fail_on={Role.SECURITY: error, Role.PERFORMANCE: error, Role.BEST_PRACTICES: error},
        )

        result = await run(analyzer, github)

        chunked = chunk_diff(LONG_DIFF, MAX_DIFF_CHARS, settings.LLM_MAX_DIFF_CHUNKS)
        assert len(chunked.chunks) > 1
        assert [
            len(prompts[r]) for r in (Role.SECURITY, Role.PERFORMANCE, Role.BEST_PRACTICES)
        ] == [1, 1, 1]
        # Only the part that was sent counts towards coverage
        assert result.diff_chars_reviewed_by_llm == chunked.chunk_chars[0]
        assert result.status == AnalysisStatus.FAILED

    @pytest.mark.asyncio
    async def test_parts_run_chunk_by_chunk_through_every_step(self):
        analyzer, github, _ = analyzer_over(LONG_DIFF)
        client = analyzer.llm_service.client
        await run(analyzer, github)
        roles = [call.args[0] for call in client.generate.call_args_list]
        findings_roles = [r for r in roles if r != Role.SUMMARY]
        n = len(findings_roles) // 3
        assert n > 1
        assert findings_roles == [Role.SECURITY, Role.PERFORMANCE, Role.BEST_PRACTICES] * n

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

    def test_default_budget_leaves_room_inside_the_blocking_timeout(self):
        from app.core.config import Settings

        fields = Settings.model_fields
        assert (
            fields["LLM_REVIEW_BUDGET_SECONDS"].default
            < fields["A2A_BLOCKING_TIMEOUT_SECONDS"].default
        )

    @pytest.mark.parametrize("budget,blocking", [(300, 300), (400, 300), (150, 120)])
    def test_a_budget_not_below_the_blocking_timeout_is_refused(self, budget, blocking):
        from pydantic import ValidationError

        from app.core.config import Settings

        with pytest.raises(ValidationError, match="LLM_REVIEW_BUDGET_SECONDS must be less"):
            Settings(
                GITHUB_TOKEN="t",
                GITHUB_WEBHOOK_SECRET="s" * 40,
                API_KEY="k" * 40,
                LLM_REVIEW_BUDGET_SECONDS=budget,
                A2A_BLOCKING_TIMEOUT_SECONDS=blocking,
                _env_file=None,
            )

    def test_a_budget_below_the_blocking_timeout_is_accepted(self):
        from app.core.config import Settings

        s = Settings(
            GITHUB_TOKEN="t",
            GITHUB_WEBHOOK_SECRET="s" * 40,
            API_KEY="k" * 40,
            LLM_REVIEW_BUDGET_SECONDS=60,
            A2A_BLOCKING_TIMEOUT_SECONDS=120,
            _env_file=None,
        )
        assert s.LLM_REVIEW_BUDGET_SECONDS == 60

    @pytest.mark.parametrize("value", [0, -1, 3601])
    def test_out_of_range_budgets_are_refused(self, value):
        from pydantic import ValidationError

        from app.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(
                GITHUB_TOKEN="t",
                GITHUB_WEBHOOK_SECRET="s" * 40,
                API_KEY="k" * 40,
                LLM_REVIEW_BUDGET_SECONDS=value,
                _env_file=None,
            )

    @pytest.mark.parametrize("value", [0, -1, 51])
    def test_out_of_range_caps_are_refused(self, value):
        from pydantic import ValidationError

        from app.core.config import Settings

        with pytest.raises(ValidationError):
            Settings(
                GITHUB_TOKEN="t",
                GITHUB_WEBHOOK_SECRET="s" * 40,
                API_KEY="k" * 40,
                LLM_MAX_DIFF_CHUNKS=value,
                _env_file=None,
            )

# tests/test_code_analyzer.py

"""Tests for CodeAnalyzerService

The GitHub and LLM services are mocked. The rule checkers (SecurityChecker,
PerformanceChecker) and DiffParser run for real, so these tests reflect current
behaviour of the orchestration layer.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.exceptions import AnalysisError, GitHubMCPError
from app.models.analysis import (
    ApprovalRecommendation,
    BestPracticeIssue,
    PerformanceIssue,
    RiskLevel,
    SecurityIssue,
    Severity,
)
from app.models.github import GitHubUser, PullRequest, PullRequestDiff
from app.services.code_analyzer import CodeAnalyzerService

PR_URL = "https://github.com/test/repo/pull/123"

SAMPLE_PR = PullRequest(
    id=1001,
    number=123,
    state="open",
    title="Add user authentication",
    body="Implements JWT-based authentication",
    user=GitHubUser(login="testuser", id=1),
    created_at=datetime(2026, 1, 1, tzinfo=UTC),
    updated_at=datetime(2026, 1, 2, tzinfo=UTC),
    html_url=PR_URL,
    head={"sha": "abc123", "ref": "feature"},
    base={"sha": "def456", "ref": "main"},
    additions=15,
    deletions=0,
    changed_files=1,
)

# Rule checkers flag the hardcoded key and the MD5 usage in this diff
RISKY_DIFF = """diff --git a/app/auth.py b/app/auth.py
new file mode 100644
index 0000000..111111
--- /dev/null
+++ b/app/auth.py
@@ -0,0 +1,6 @@
+import hashlib
+
+API_KEY = "sk_live_secret123456789"
+
+def authenticate(username, password):
+    return hashlib.md5(password.encode()).hexdigest()
"""

SAFE_DIFF = """diff --git a/app/utils.py b/app/utils.py
new file mode 100644
index 0000000..111111
--- /dev/null
+++ b/app/utils.py
@@ -0,0 +1,2 @@
+def format_name(name: str) -> str:
+    return name.strip().title()
"""


def sec(severity, title="Issue", line=1, file="other.py"):
    return SecurityIssue(
        severity=severity, title=title, description="d", file=file,
        line_number=line, recommendation="r",
    )


def perf(severity, impact="100x more queries", title="Perf", line=1, file="other.py"):
    return PerformanceIssue(
        severity=severity, title=title, description="d", file=file,
        line_number=line, impact=impact, recommendation="r",
    )


def make_analyzer(diff=RISKY_DIFF, llm_security=None, llm_performance=None,
                  llm_best_practice=None, summary="Summary"):
    """Build a CodeAnalyzerService with mocked GitHub and LLM services."""
    github = MagicMock()
    github.parse_pr_url = MagicMock(return_value=("test", "repo", 123))
    github.get_pr_with_diff = AsyncMock(
        return_value=(SAMPLE_PR, PullRequestDiff(pr_number=123, raw_diff=diff, files=[]))
    )
    github.__aenter__ = AsyncMock(return_value=github)
    github.__aexit__ = AsyncMock(return_value=None)

    llm = MagicMock()
    llm.analyze_security = AsyncMock(return_value=llm_security or [])
    llm.analyze_performance = AsyncMock(return_value=llm_performance or [])
    llm.analyze_best_practices = AsyncMock(return_value=llm_best_practice or [])
    llm.generate_summary = AsyncMock(return_value=summary)

    with patch("app.services.code_analyzer.LLMService", return_value=llm):
        analyzer = CodeAnalyzerService()
    return analyzer, github, llm


async def run(analyzer, github):
    with patch("app.services.code_analyzer.GitHubMCPService", return_value=github):
        return await analyzer.analyze_pr(PR_URL)


class TestAnalyzePr:
    @pytest.mark.asyncio
    async def test_populates_pr_metadata(self):
        analyzer, github, llm = make_analyzer()
        result = await run(analyzer, github)

        assert result.pr_number == 123
        assert result.pr_title == "Add user authentication"
        assert result.author == "testuser"
        assert result.repository == "test/repo"
        assert result.executive_summary == "Summary"
        assert result.files_changed == 1
        assert result.lines_added == 15
        assert result.analysis_duration_seconds >= 0
        github.get_pr_with_diff.assert_awaited_once_with("test", "repo", 123)
        llm.generate_summary.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rule_checkers_find_hardcoded_secret_in_diff(self):
        analyzer, github, _ = make_analyzer()
        result = await run(analyzer, github)

        assert result.security_findings
        assert any(i.severity == Severity.CRITICAL for i in result.security_findings)

    @pytest.mark.asyncio
    async def test_critical_rule_finding_means_critical_risk_and_reject(self):
        analyzer, github, _ = make_analyzer()
        result = await run(analyzer, github)

        assert result.risk_level == RiskLevel.CRITICAL
        assert result.approval_recommendation == ApprovalRecommendation.REJECT
        assert any("CRITICAL" in c for c in result.key_concerns)

    @pytest.mark.asyncio
    async def test_clean_diff_is_approved(self):
        analyzer, github, _ = make_analyzer(diff=SAFE_DIFF)
        result = await run(analyzer, github)

        assert result.security_findings == []
        assert result.risk_level == RiskLevel.MINIMAL
        assert result.approval_recommendation == ApprovalRecommendation.APPROVE

    @pytest.mark.asyncio
    async def test_github_error_propagates(self):
        analyzer, github, _ = make_analyzer()
        github.get_pr_with_diff = AsyncMock(side_effect=GitHubMCPError("boom"))

        with pytest.raises(GitHubMCPError):
            await run(analyzer, github)

    @pytest.mark.asyncio
    async def test_unexpected_error_is_wrapped_in_analysis_error(self):
        analyzer, github, llm = make_analyzer()
        llm.generate_summary = AsyncMock(side_effect=RuntimeError("bad"))

        with pytest.raises(AnalysisError):
            await run(analyzer, github)

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        strict=True,
        reason="F-03: LLM failures are not handled, so an LLM error aborts the whole "
               "analysis instead of falling back to rule-based results",
    )
    async def test_llm_error_falls_back_to_rule_results(self):
        analyzer, github, llm = make_analyzer()
        llm.analyze_security = AsyncMock(side_effect=Exception("LLM error"))

        result = await run(analyzer, github)

        assert result.security_findings  # rule-based findings still reported


class TestRiskLevel:
    def setup_method(self):
        self.analyzer, _, _ = make_analyzer()

    def test_high_severity_performance_with_free_text_impact_raises_risk(self):
        # F-06: LLM impact text like "100x more queries" never equalled "HIGH"
        risk = self.analyzer._calculate_risk_level(
            [], [perf(Severity.HIGH, impact="100x more queries")]
        )
        assert risk == RiskLevel.MEDIUM

    def test_high_impact_text_with_low_severity_does_not_raise_risk(self):
        risk = self.analyzer._calculate_risk_level(
            [], [perf(Severity.LOW, impact="HIGH")]
        )
        assert risk == RiskLevel.LOW

    def test_high_security_and_two_high_performance_is_high(self):
        risk = self.analyzer._calculate_risk_level(
            [sec(Severity.HIGH)],
            [perf(Severity.HIGH), perf(Severity.HIGH, title="Other")],
        )
        assert risk == RiskLevel.HIGH

    def test_three_high_security_is_high(self):
        risk = self.analyzer._calculate_risk_level([sec(Severity.HIGH)] * 3, [])
        assert risk == RiskLevel.HIGH

    def test_critical_security_is_critical(self):
        assert self.analyzer._calculate_risk_level([sec(Severity.CRITICAL)], []) == RiskLevel.CRITICAL

    def test_no_findings_is_minimal(self):
        assert self.analyzer._calculate_risk_level([], []) == RiskLevel.MINIMAL

    def test_only_low_findings_is_low(self):
        assert self.analyzer._calculate_risk_level([sec(Severity.LOW)], []) == RiskLevel.LOW


class TestApproval:
    def setup_method(self):
        self.analyzer, _, _ = make_analyzer()

    def test_critical_security_rejects(self):
        got = self.analyzer._determine_approval(RiskLevel.CRITICAL, [sec(Severity.CRITICAL)], [])
        assert got == ApprovalRecommendation.REJECT

    def test_two_high_security_requests_changes(self):
        got = self.analyzer._determine_approval(
            RiskLevel.MEDIUM, [sec(Severity.HIGH), sec(Severity.HIGH, title="B")], []
        )
        assert got == ApprovalRecommendation.REQUEST_CHANGES

    def test_medium_risk_approves_with_suggestions(self):
        got = self.analyzer._determine_approval(RiskLevel.MEDIUM, [], [perf(Severity.HIGH)])
        assert got == ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS


class TestMerge:
    def setup_method(self):
        self.analyzer, _, _ = make_analyzer()

    def test_duplicate_security_issue_is_merged_and_higher_severity_kept(self):
        rule = [sec(Severity.HIGH, title="SQL Injection", file="a.py", line=10)]
        llm = [sec(Severity.CRITICAL, title="SQL Injection vulnerability", file="a.py", line=10)]

        merged = self.analyzer._merge_security_issues(rule, llm)

        assert len(merged) == 1
        assert merged[0].severity == Severity.CRITICAL

    def test_distinct_security_issues_are_kept_and_sorted_by_severity(self):
        merged = self.analyzer._merge_security_issues(
            [sec(Severity.LOW, title="Alpha", line=1)],
            [sec(Severity.CRITICAL, title="Bravo", line=2)],
        )
        assert [i.severity for i in merged] == [Severity.CRITICAL, Severity.LOW]

    def test_performance_issues_sorted_by_severity_not_impact_text(self):
        merged = self.analyzer._merge_performance_issues(
            [perf(Severity.LOW, impact="HIGH", title="Alpha", line=1)],
            [perf(Severity.HIGH, impact="slow", title="Bravo", line=2)],
        )
        assert [i.severity for i in merged] == [Severity.HIGH, Severity.LOW]

    def test_duplicate_performance_issue_is_merged(self):
        merged = self.analyzer._merge_performance_issues(
            [perf(Severity.HIGH, title="N+1 query", file="a.py", line=5)],
            [perf(Severity.HIGH, title="N+1 query pattern", file="a.py", line=5)],
        )
        assert len(merged) == 1


class TestRecommendations:
    def setup_method(self):
        self.analyzer, _, _ = make_analyzer()

    def test_high_severity_performance_is_recommended_regardless_of_impact_text(self):
        recs = self.analyzer._generate_recommendations(
            [], [perf(Severity.HIGH, impact="100x more queries")], []
        )
        assert any("PERFORMANCE" in r for r in recs)

    def test_low_severity_performance_is_not_flagged_even_if_impact_says_high(self):
        recs = self.analyzer._generate_recommendations(
            [], [perf(Severity.LOW, impact="HIGH")], []
        )
        assert not any("PERFORMANCE" in r for r in recs)

    def test_critical_and_high_security_recommendations(self):
        recs = self.analyzer._generate_recommendations(
            [sec(Severity.CRITICAL), sec(Severity.HIGH, title="B")], [], []
        )
        assert any("CRITICAL" in r for r in recs)
        assert any("HIGH" in r for r in recs)

    def test_best_practice_category_recommendation(self):
        bp = BestPracticeIssue(
            category="testing", severity=Severity.LOW, title="t", description="d",
            file="a.py", recommendation="r",
        )
        recs = self.analyzer._generate_recommendations([], [], [bp])
        assert any("BEST PRACTICES" in r and "testing" in r for r in recs)

    def test_at_most_five_recommendations(self):
        recs = self.analyzer._generate_recommendations(
            [sec(Severity.CRITICAL), sec(Severity.HIGH, title="B")],
            [perf(Severity.HIGH)], [],
        )
        assert len(recs) <= 5

    @pytest.mark.asyncio
    async def test_llm_high_severity_performance_raises_end_to_end_risk(self):
        analyzer, github, _ = make_analyzer(
            diff=SAFE_DIFF,
            llm_performance=[perf(Severity.HIGH, impact="100x more queries", file="app/utils.py")],
        )
        result = await run(analyzer, github)

        assert result.risk_level == RiskLevel.MEDIUM
        assert result.approval_recommendation == ApprovalRecommendation.APPROVE_WITH_SUGGESTIONS

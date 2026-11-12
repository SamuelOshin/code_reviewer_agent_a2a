# tests/test_llm_summary.py

"""Tests for LLMService.generate_summary (F-06)

The summary prompt must count findings by Severity member. Before the fix it compared
against uppercase strings, so every summary reported 0 critical.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.analysis import PerformanceIssue, SecurityIssue, Severity
from app.services.llm_service import LLMService


def sec(severity, title):
    return SecurityIssue(
        severity=severity, title=title, description="d", file="a.py",
        line_number=1, recommendation="r",
    )


def perf(severity, title, impact="100x more queries"):
    return PerformanceIssue(
        severity=severity, title=title, description="d", file="a.py",
        line_number=1, impact=impact, recommendation="r",
    )


def make_service():
    # Skip __init__ so no real provider SDK is created
    service = LLMService.__new__(LLMService)
    service.llm = MagicMock()
    service.llm.generate = AsyncMock(return_value="summary text")
    service.prompts = {}
    return service


async def summarize(service, security, performance):
    result = await service.generate_summary(
        pr_title="t", pr_author="a", pr_description="d",
        security_issues=security, performance_issues=performance,
        best_practice_issues=[], total_additions=1, total_deletions=0, changed_files=1,
    )
    assert result == "summary text"
    return service.llm.generate.await_args.kwargs["prompt"]


@pytest.mark.asyncio
async def test_summary_prompt_counts_critical_and_high_security():
    service = make_service()
    prompt = await summarize(
        service,
        [sec(Severity.CRITICAL, "SQL injection"), sec(Severity.CRITICAL, "Hardcoded key"),
         sec(Severity.HIGH, "Weak hash"), sec(Severity.LOW, "Minor")],
        [],
    )

    assert "Security Issues: 4 total (2 critical, 1 high)" in prompt
    assert "- SQL injection" in prompt
    assert "- Hardcoded key" in prompt
    assert "- Weak hash" in prompt
    assert "- Minor" not in prompt


@pytest.mark.asyncio
async def test_summary_prompt_counts_performance_by_severity_not_impact_text():
    service = make_service()
    prompt = await summarize(
        service,
        [],
        [perf(Severity.HIGH, "N+1 query", impact="100x more queries"),
         perf(Severity.LOW, "Minor loop", impact="HIGH")],
    )

    assert "Performance Issues: 2 total (1 high severity)" in prompt
    assert "- N+1 query" in prompt
    assert "- Minor loop" not in prompt

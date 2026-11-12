# tests/test_llm_summary.py

"""Tests for LLMService.generate_summary (F-06)

The summary prompt must count findings by Severity member. Before the fix it compared
against uppercase strings, so every summary reported 0 critical.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.llm import LLMResult, Role, Usage
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
    # A mocked model-layer client, so no provider is built
    client = MagicMock()
    client.model_name.return_value = "test:model"
    client.generate = AsyncMock(return_value=LLMResult(
        output="summary text",
        usage=Usage(input_tokens=1, output_tokens=1, requests=1, latency_ms=1.0),
        model="test:model",
    ))
    return LLMService(client=client)


async def summarize(service, security, performance):
    result = await service.generate_summary(
        pr_title="t", pr_author="a", pr_description="d",
        security_issues=security, performance_issues=performance,
        best_practice_issues=[], total_additions=1, total_deletions=0, changed_files=1,
    )
    assert result == "summary text"
    call = service.client.generate.await_args
    assert call.args[0] == Role.SUMMARY
    return call.args[1]


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


@pytest.mark.asyncio
async def test_shared_error_type_reaches_the_caller():
    from app.llm import LLMRateLimitError

    service = make_service()
    service.client.generate = AsyncMock(side_effect=LLMRateLimitError("429"))

    with pytest.raises(LLMRateLimitError):
        await service.analyze_security("diff", [{"filename": "a.py"}])


@pytest.mark.asyncio
async def test_each_analysis_uses_its_own_role():
    service = make_service()
    service.client.generate = AsyncMock(return_value=LLMResult(
        output="[]",
        usage=Usage(input_tokens=1, output_tokens=1, requests=1, latency_ms=1.0),
        model="test:model",
    ))

    await service.analyze_security("diff", [])
    await service.analyze_performance("diff", [])
    await service.analyze_best_practices("diff", [])

    roles = [call.args[0] for call in service.client.generate.await_args_list]
    assert roles == [Role.SECURITY, Role.PERFORMANCE, Role.BEST_PRACTICES]

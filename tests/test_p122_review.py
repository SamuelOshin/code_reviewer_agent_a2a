"""P1-22: a rate-limited model is named in the review. No network."""

from unittest.mock import AsyncMock

import pytest

from app.llm.errors import LLMRateLimitError
from tests.test_code_analyzer import make_analyzer, run

# --- 3. a rate-limited model is said so, in fixed text ----------------------------------


@pytest.mark.asyncio
async def test_rate_limited_steps_get_a_clear_reason():
    analyzer, github, llm = make_analyzer()
    boom = LLMRateLimitError("SECRET-DETAIL")
    llm.analyze_security = AsyncMock(side_effect=boom)
    llm.analyze_performance = AsyncMock(side_effect=boom)
    llm.analyze_best_practices = AsyncMock(side_effect=boom)
    llm.generate_summary = AsyncMock(side_effect=boom)

    result = await run(analyzer, github)

    assert result.status.value == "failed"
    assert len(result.incomplete_reasons) == 4
    assert all("rate-limited" in r and "run the review again" in r for r in result.incomplete_reasons)
    assert "rate-limited" in result.executive_summary
    blob = " ".join(result.incomplete_reasons) + result.executive_summary
    assert "SECRET-DETAIL" not in blob and "LLMRateLimitError" not in blob


@pytest.mark.asyncio
async def test_other_step_failure_keeps_type_only_reason():
    analyzer, github, llm = make_analyzer()
    llm.analyze_security = AsyncMock(side_effect=RuntimeError("x"))
    result = await run(analyzer, github)
    assert "Security analysis failed (RuntimeError)." in result.incomplete_reasons

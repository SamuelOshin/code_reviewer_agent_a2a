# app/services/llm_service.py

"""Review-specific LLM calls: prompts in, typed findings and a summary out.

Every model call goes through the provider-agnostic layer in `app.llm`, so this file
never touches a provider SDK. Provider and model per role are configuration.

P2-01: the three findings roles now call `client.generate(output_type=<Report>)`.
The model layer validates the structured response and retries once; two failures raise
`LLMOutputError`, which the analyzer records as a failed step (fail-closed).
`generate_summary` stays free-text; do not change it.
"""

import logging
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from app.core.config import settings
from app.core.exceptions import LLMError
from app.llm import LLMClient, LLMResult, Role, build_client
from app.llm.errors import LLMOutputError
from app.models.analysis import (
    BestPracticeIssue,
    BestPracticesReport,
    PerformanceIssue,
    PerformanceReport,
    SecurityIssue,
    SecurityReport,
    Severity,
    _severity_from_impact,
)

__all__ = ["LLMService", "PartialFindingsError", "MAX_DIFF_CHARS", "_severity_from_impact"]

logger = logging.getLogger(__name__)

# How much of the diff each findings prompt includes. A longer diff is cut here, so
# the LLM reviews only part of the PR. The analyzer reports that in the result and
# never approves it (P1-06).
MAX_DIFF_CHARS = 8000

IssueT = TypeVar("IssueT", bound=BaseModel)


class PartialFindingsError(LLMOutputError):
    """Some findings in the model output were invalid and had to be dropped.

    `findings` holds the ones that validated, so the caller can still report them
    while marking the review incomplete. The message never contains model output.
    """

    def __init__(self, message: str, findings: list[Any]):
        super().__init__(message)
        self.findings = findings


class LLMService:
    """Security, performance, best-practice and summary calls for a PR review"""

    def __init__(self, client: LLMClient | None = None):
        # Builds every configured model now, so bad config fails at startup
        self.client = client if client is not None else build_client(settings)
        self.prompts = self._load_prompts()
        logger.info(
            "LLMService initialized with models: "
            + ", ".join(f"{role}={self.client.model_name(role)}" for role in Role)
        )

    def models_by_role(self) -> dict[str, str]:
        """Configured model (with any fallbacks) for each role, for the result record."""
        return {str(role): self.client.model_name(role) for role in Role}

    async def _generate_typed(
        self,
        role: Role,
        prompt: str,
        system_prompt: str | None,
        output_type: type[IssueT],
    ) -> LLMResult[IssueT]:
        """One structured call through the model layer, with usage logged (never output)."""
        result: LLMResult[IssueT] = await self.client.generate(
            role, prompt, instructions=system_prompt or None, output_type=output_type
        )
        usage = result.usage
        logger.info(
            f"LLM {role} call on {result.model}: {usage.input_tokens} in, "
            f"{usage.output_tokens} out, {usage.latency_ms:.0f} ms, cost "
            f"{'unknown' if usage.cost_usd is None else f'${usage.cost_usd:.6f}'}"
        )
        return result

    async def _generate(self, role: Role, prompt: str, system_prompt: str | None) -> str:
        """One text call through the model layer, with usage logged (never the output)."""
        result: LLMResult[str] = await self.client.generate(
            role, prompt, instructions=system_prompt or None
        )
        usage = result.usage
        logger.info(
            f"LLM {role} call on {result.model}: {usage.input_tokens} in, "
            f"{usage.output_tokens} out, {usage.latency_ms:.0f} ms, cost "
            f"{'unknown' if usage.cost_usd is None else f'${usage.cost_usd:.6f}'}"
        )
        return result.output

    def _load_prompts(self) -> dict[str, str]:
        """Load prompt templates from config/prompts/"""
        prompts = {}
        prompt_dir = Path("config/prompts")
        prompt_files = {
            'security_analysis': 'security_analysis.txt',
            'performance_analysis': 'performance_analysis.txt',
            'summary_generation': 'summary_generation.txt'
        }

        for key, filename in prompt_files.items():
            filepath = prompt_dir / filename
            try:
                prompts[key] = filepath.read_text(encoding='utf-8')
                logger.debug(f"Loaded prompt template: {filename}")
            except FileNotFoundError:
                logger.warning(f"Prompt template not found: {filepath}")
                prompts[key] = ""

        return prompts

    @staticmethod
    def _wrap_error(task: str, error: Exception) -> LLMError:
        """Log and return an error for the caller, without upstream or PR content.

        Shared `LLMError` types already carry safe messages. Anything else is
        reported by type only, since its text can echo the prompt or the output.
        """
        if isinstance(error, LLMError):
            logger.error(f"{task} error: {error}")
            return error
        logger.error(f"{task} error: {type(error).__name__}")
        return LLMError(f"{task} failed: {type(error).__name__}")

    @staticmethod
    def _extract_report_findings(role: Role, report: Any) -> list[Any]:
        """Extract validated findings from a Report, failing closed on bad data.

        If every item in the report was invalid, raises `LLMOutputError` (step failure).
        If some were invalid, keeps the valid ones and raises `PartialFindingsError`
        so the review is marked incomplete. Logs counts only, never model output.
        """
        if not hasattr(report, "findings") or not isinstance(report.findings, list):
            raise LLMOutputError(
                f"{role} output is not a valid report object (got {type(report).__name__})"
            )
        dropped = getattr(report, "dropped_count", 0)
        if dropped:
            logger.warning(
                f"Dropped {dropped} invalid {role} finding(s) from model output"
            )
            if not report.findings:
                raise LLMOutputError(
                    f"All {dropped} {role} finding(s) in the model output were invalid"
                )
            raise PartialFindingsError(
                f"{dropped} {role} finding(s) in the model output were invalid",
                list(report.findings),
            )
        findings = list(report.findings)
        logger.info(f"Found {len(findings)} {role} issues")
        return findings

    async def analyze_security(
        self,
        diff_content: str,
        files: list[dict[str, Any]]
    ) -> list[SecurityIssue]:
        """LLM-powered security analysis (P2-01: schema-enforced structured output)."""
        try:
            file_list = "\n".join([
                f"- {f.filename if hasattr(f, 'filename') else f.get('filename', 'unknown')}"
                for f in files[:10]
            ])

            prompt = f"""Analyze the following code changes for security vulnerabilities.

Changed Files ({len(files)}):
{file_list}

Code Diff:
```diff
{diff_content[:MAX_DIFF_CHARS]}
```

Return your findings in the `findings` field. Use an empty list if there are no issues."""

            result = await self._generate_typed(
                Role.SECURITY, prompt,
                self.prompts.get('security_analysis', ''),
                SecurityReport,
            )
            return self._extract_report_findings(Role.SECURITY, result.output)

        except (LLMOutputError, PartialFindingsError):
            raise
        except Exception as e:
            raise self._wrap_error("Security analysis", e) from None

    async def analyze_performance(
        self,
        diff_content: str,
        files: list[dict[str, Any]]
    ) -> list[PerformanceIssue]:
        """LLM-powered performance analysis (P2-01: schema-enforced structured output)."""
        try:
            file_list = "\n".join([
                f"- {f.filename if hasattr(f, 'filename') else f.get('filename', 'unknown')}"
                for f in files[:10]
            ])

            prompt = f"""Analyze the following code changes for performance issues.

Changed Files ({len(files)}):
{file_list}

Code Diff:
```diff
{diff_content[:MAX_DIFF_CHARS]}
```

Return your findings in the `findings` field. Use an empty list if there are no issues."""

            result = await self._generate_typed(
                Role.PERFORMANCE, prompt,
                self.prompts.get('performance_analysis', ''),
                PerformanceReport,
            )
            return self._extract_report_findings(Role.PERFORMANCE, result.output)

        except (LLMOutputError, PartialFindingsError):
            raise
        except Exception as e:
            raise self._wrap_error("Performance analysis", e) from None

    async def analyze_best_practices(
        self,
        diff_content: str,
        files: list[dict[str, Any]]
    ) -> list[BestPracticeIssue]:
        """LLM-powered best practices analysis (P2-01: schema-enforced structured output)."""
        try:
            file_list = "\n".join([
                f"- {f.filename if hasattr(f, 'filename') else f.get('filename', 'unknown')}"
                for f in files[:10]
            ])

            prompt = f"""Analyze the following code changes for coding best practice violations.

Changed Files ({len(files)}):
{file_list}

Code Diff:
```diff
{diff_content[:MAX_DIFF_CHARS]}
```

Focus on: code organization, naming conventions, documentation, error handling, testing, maintainability.

Return your findings in the `findings` field, each with:
- severity (high/medium/low)
- category (e.g., "naming", "documentation", "error-handling")
- title, description, file, recommendation
- line_number and code_snippet are optional

Use an empty list if there are no issues."""

            result = await self._generate_typed(
                Role.BEST_PRACTICES, prompt,
                "You are a code review expert focused on software engineering best practices.",
                BestPracticesReport,
            )
            return self._extract_report_findings(Role.BEST_PRACTICES, result.output)

        except (LLMOutputError, PartialFindingsError):
            raise
        except Exception as e:
            raise self._wrap_error("Best practices analysis", e) from None

    async def generate_summary(
        self,
        pr_title: str,
        pr_author: str,
        pr_description: str,
        security_issues: list[SecurityIssue],
        performance_issues: list[PerformanceIssue],
        best_practice_issues: list[BestPracticeIssue],
        total_additions: int,
        total_deletions: int,
        changed_files: int
    ) -> str:
        """Generate executive summary for PR review (stays free-text; not changed by P2-01)."""
        try:
            # Format findings for context
            critical_security = [s for s in security_issues if s.severity == Severity.CRITICAL]
            high_security = [s for s in security_issues if s.severity == Severity.HIGH]
            high_perf = [p for p in performance_issues if p.severity in (Severity.CRITICAL, Severity.HIGH)]

            prompt = f"""Generate an executive summary for this Pull Request review.

PR Details:
- Title: {pr_title}
- Author: {pr_author}
- Description: {pr_description[:500] if pr_description else 'No description provided'}

Code Changes:
- Files Changed: {changed_files}
- Lines Added: {total_additions}
- Lines Deleted: {total_deletions}

Findings Summary:
- Security Issues: {len(security_issues)} total ({len(critical_security)} critical, {len(high_security)} high)
- Performance Issues: {len(performance_issues)} total ({len(high_perf)} high severity)
- Best Practice Violations: {len(best_practice_issues)}

Top Security Concerns:
{chr(10).join([f"- {s.title}" for s in (critical_security + high_security)[:3]]) if (critical_security or high_security) else "None"}

Top Performance Concerns:
{chr(10).join([f"- {p.title}" for p in high_perf[:3]]) if high_perf else "None"}

Generate the executive summary following the specified format."""

            response = await self._generate(
                Role.SUMMARY, prompt, self.prompts.get('summary_generation', '')
            )

            logger.info("Generated executive summary")
            return response.strip()

        except Exception as e:
            raise self._wrap_error("Summary generation", e) from None

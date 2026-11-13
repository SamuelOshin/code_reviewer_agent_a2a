# app/services/llm_service.py

"""Review-specific LLM calls: prompts in, typed findings and a summary out.

Every model call goes through the provider-agnostic layer in `app.llm`, so this file
never touches a provider SDK. Provider and model per role are configuration.
"""

import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from app.core.config import settings
from app.core.exceptions import LLMError
from app.llm import LLMClient, LLMResult, Role, build_client
from app.llm.errors import LLMOutputError
from app.models.analysis import BestPracticeIssue, PerformanceIssue, SecurityIssue, Severity

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


def _is_findings_array(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def extract_findings_array(response: str, role: Role) -> list[dict[str, Any]]:
    """Parse a JSON array of finding objects out of a model response.

    Accepts a bare array, an array in a markdown code fence, or an array inside
    prose. Anything else (no array, a truncated array, an array of arrays, an
    object) raises `LLMOutputError`. It never returns `[]` for output it could not
    read, because an empty list means "no issues" and could approve the PR (F-03).
    Error messages describe the output's shape only, never its content.
    """
    text = (response or "").strip()
    candidates = [text]
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        candidates.append(fence.group(1).strip())

    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if _is_findings_array(data):
            return data
        raise LLMOutputError(
            f"{role} output is JSON but not an array of finding objects "
            f"(got {type(data).__name__})"
        )

    # Prose around the array: take the first '[' that decodes to an array of objects
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\[", text):
        try:
            data, _ = decoder.raw_decode(text, match.start())
        except json.JSONDecodeError:
            continue
        if _is_findings_array(data):
            return data

    raise LLMOutputError(
        f"{role} output could not be parsed as a JSON array of findings "
        f"({len(text)} characters)"
    )


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
    
    def _parse_findings(
        self,
        role: Role,
        response: str,
        model: type[IssueT],
        prepare: Callable[[dict[str, Any]], None] | None = None,
    ) -> list[IssueT]:
        """Validate model output into findings, failing closed.

        Unparseable output raises `LLMOutputError`. If only some findings are
        invalid, the valid ones are kept and `PartialFindingsError` is raised so the
        review is marked incomplete. Nothing from the output itself is logged:
        validation errors echo their input, which is PR code.
        """
        findings: list[IssueT] = []
        dropped = 0
        for raw in extract_findings_array(response, role):
            try:
                if prepare is not None:
                    prepare(raw)
                findings.append(model(**raw))
            except Exception:
                dropped += 1
        if dropped:
            logger.warning(f"Dropped {dropped} invalid {role} finding(s) from model output")
            raise PartialFindingsError(
                f"{dropped} {role} finding(s) in the model output were invalid", findings
            )
        logger.info(f"Found {len(findings)} {role} issues")
        return findings

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
    
    async def analyze_security(
        self, 
        diff_content: str, 
        files: list[dict[str, Any]]
    ) -> list[SecurityIssue]:
        """LLM-powered security analysis"""
        try:
            # Format file context - handle both dict and PullRequestFile objects
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

Return your findings as a JSON array following the specified format."""
            
            response = await self._generate(
                Role.SECURITY, prompt, self.prompts.get('security_analysis', '')
            )
            
            return self._parse_findings(Role.SECURITY, response, SecurityIssue)

        except Exception as e:
            # Shared error types (rate limit, auth, timeout, output) reach the caller
            raise self._wrap_error("Security analysis", e) from e
    
    async def analyze_performance(
        self, 
        diff_content: str, 
        files: list[dict[str, Any]]
    ) -> list[PerformanceIssue]:
        """LLM-powered performance analysis"""
        try:
            # Format file context - handle both dict and PullRequestFile objects
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

Return your findings as a JSON array following the specified format."""
            
            response = await self._generate(
                Role.PERFORMANCE, prompt, self.prompts.get('performance_analysis', '')
            )
            
            return self._parse_findings(
                Role.PERFORMANCE, response, PerformanceIssue, _severity_from_impact
            )

        except Exception as e:
            # Shared error types (rate limit, auth, timeout, output) reach the caller
            raise self._wrap_error("Performance analysis", e) from e
    
    async def analyze_best_practices(
        self, 
        diff_content: str, 
        files: list[dict[str, Any]]
    ) -> list[BestPracticeIssue]:
        """LLM-powered best practices analysis"""
        try:
            # Format file context - handle both dict and PullRequestFile objects
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

Return your findings as a JSON array with:
- severity (high/medium/low)
- category (e.g., "naming", "documentation", "error-handling")
- title
- description
- file
- line_number (optional)
- code_snippet (optional)
- recommendation"""
            
            response = await self._generate(
                Role.BEST_PRACTICES,
                prompt,
                "You are a code review expert focused on software engineering best practices.",
            )
            
            return self._parse_findings(Role.BEST_PRACTICES, response, BestPracticeIssue)

        except Exception as e:
            # Shared error types (rate limit, auth, timeout, output) reach the caller
            raise self._wrap_error("Best practices analysis", e) from e
    
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
        """Generate executive summary for PR review"""
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
            # Shared error types (rate limit, auth, timeout, output) reach the caller
            raise self._wrap_error("Summary generation", e) from e


def _severity_from_impact(finding: dict[str, Any]) -> None:
    """Fill in `severity` from free-text `impact` when the model left it out."""
    if 'severity' in finding or 'impact' not in finding:
        return
    impact_upper = str(finding.get('impact', '')).upper()
    if any(word in impact_upper for word in ['CRITICAL', 'SEVERE', '10X', '100X']):
        finding['severity'] = 'critical'
    elif any(word in impact_upper for word in ['HIGH', 'SIGNIFICANT', '2X', '3X']):
        finding['severity'] = 'high'
    elif any(word in impact_upper for word in ['MEDIUM', 'MODERATE']):
        finding['severity'] = 'medium'
    else:
        finding['severity'] = 'low'

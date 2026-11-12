# app/services/llm_service.py

"""Review-specific LLM calls: prompts in, typed findings and a summary out.

Every model call goes through the provider-agnostic layer in `app.llm`, so this file
never touches a provider SDK. Provider and model per role are configuration.
"""

import json
import logging
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.exceptions import LLMError
from app.llm import LLMClient, LLMResult, Role, build_client
from app.models.analysis import BestPracticeIssue, PerformanceIssue, SecurityIssue, Severity

logger = logging.getLogger(__name__)


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
    
    def _extract_json_from_response(self, response: str) -> list[dict[str, Any]]:
        """Extract JSON array from LLM response (handles markdown code blocks)"""
        try:
            # Try direct JSON parse first
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            import re
            json_match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Try to find array in response
            array_match = re.search(r'\[.*?\]', response, re.DOTALL)
            if array_match:
                try:
                    return json.loads(array_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            logger.warning(f"Could not extract JSON from LLM response: {response[:200]}")
            return []
    
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
{diff_content[:8000]}
```

Return your findings as a JSON array following the specified format."""
            
            response = await self._generate(
                Role.SECURITY, prompt, self.prompts.get('security_analysis', '')
            )
            
            # Parse JSON response
            findings_data = self._extract_json_from_response(response)
            
            # Convert to SecurityIssue objects
            security_issues = []
            for finding in findings_data:
                try:
                    security_issues.append(SecurityIssue(**finding))
                except Exception as e:
                    logger.warning(f"Failed to parse security finding: {e}")
            
            logger.info(f"Found {len(security_issues)} security issues")
            return security_issues
            
        except LLMError as e:
            # Keep the shared error type (rate limit, auth, timeout...) for the caller
            logger.error(f"Security analysis error: {e}")
            raise
        except Exception as e:
            logger.error(f"Security analysis error: {e}")
            raise LLMError(f"Security analysis failed: {str(e)}") from e
    
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
{diff_content[:8000]}
```

Return your findings as a JSON array following the specified format."""
            
            response = await self._generate(
                Role.PERFORMANCE, prompt, self.prompts.get('performance_analysis', '')
            )
            
            findings_data = self._extract_json_from_response(response)
            
            performance_issues = []
            for finding in findings_data:
                try:
                    # Ensure severity is present (convert impact to severity if needed)
                    if 'severity' not in finding and 'impact' in finding:
                        # Map impact levels to severity
                        impact_upper = str(finding.get('impact', '')).upper()
                        if any(word in impact_upper for word in ['CRITICAL', 'SEVERE', '10X', '100X']):
                            finding['severity'] = 'critical'
                        elif any(word in impact_upper for word in ['HIGH', 'SIGNIFICANT', '2X', '3X']):
                            finding['severity'] = 'high'
                        elif any(word in impact_upper for word in ['MEDIUM', 'MODERATE']):
                            finding['severity'] = 'medium'
                        else:
                            finding['severity'] = 'low'
                    
                    performance_issues.append(PerformanceIssue(**finding))
                except Exception as e:
                    logger.warning(f"Failed to parse performance finding: {e}, data: {finding}")
            
            logger.info(f"Found {len(performance_issues)} performance issues")
            return performance_issues
            
        except LLMError as e:
            # Keep the shared error type (rate limit, auth, timeout...) for the caller
            logger.error(f"Performance analysis error: {e}")
            raise
        except Exception as e:
            logger.error(f"Performance analysis error: {e}")
            raise LLMError(f"Performance analysis failed: {str(e)}") from e
    
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
{diff_content[:8000]}
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
            
            findings_data = self._extract_json_from_response(response)
            
            best_practice_issues = []
            for finding in findings_data:
                try:
                    best_practice_issues.append(BestPracticeIssue(**finding))
                except Exception as e:
                    logger.warning(f"Failed to parse best practice finding: {e}")
            
            logger.info(f"Found {len(best_practice_issues)} best practice issues")
            return best_practice_issues
            
        except LLMError as e:
            # Keep the shared error type (rate limit, auth, timeout...) for the caller
            logger.error(f"Best practices analysis error: {e}")
            raise
        except Exception as e:
            logger.error(f"Best practices analysis error: {e}")
            raise LLMError(f"Best practices analysis failed: {str(e)}") from e
    
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
            
        except LLMError as e:
            # Keep the shared error type (rate limit, auth, timeout...) for the caller
            logger.error(f"Summary generation error: {e}")
            raise
        except Exception as e:
            logger.error(f"Summary generation error: {e}")
            raise LLMError(f"Summary generation failed: {str(e)}") from e



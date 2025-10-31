# app/services/llm_service.py

"""LLM Service with Multi-Provider Support

Supports Google Gemini (default), OpenAI GPT, and Anthropic Claude.
Handles code analysis, security scanning, performance review, and summary generation.
"""

from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
from pathlib import Path
import json
import logging
import asyncio

from app.core.config import settings
from app.core.exceptions import LLMError
from app.models.analysis import SecurityIssue, PerformanceIssue, BestPracticeIssue

logger = logging.getLogger(__name__)


class BaseLLM(ABC):
    """Base LLM interface"""
    
    @abstractmethod
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from LLM"""
        pass


class GoogleLLM(BaseLLM):
    """Google Gemini implementation (DEFAULT)"""
    
    def __init__(self):
        try:
            import google.generativeai as genai
            genai.configure(api_key=settings.GOOGLE_API_KEY)
            self.model = genai.GenerativeModel(settings.LLM_MODEL)
            logger.info(f"Initialized Google Gemini: {settings.LLM_MODEL}")
        except Exception as e:
            raise LLMError(f"Failed to initialize Google Gemini: {str(e)}")
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from Gemini"""
        try:
            # Combine system prompt and user prompt for Gemini
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"
            
            response = await self.model.generate_content_async(
                full_prompt,
                generation_config={
                    "temperature": settings.LLM_TEMPERATURE,
                    "max_output_tokens": settings.LLM_MAX_TOKENS,
                }
            )
            return response.text
        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            raise LLMError(f"Gemini generation failed: {str(e)}")


class OpenAILLM(BaseLLM):
    """OpenAI GPT implementation"""
    
    def __init__(self):
        try:
            import openai
            self.client = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self.model = settings.LLM_MODEL
            logger.info(f"Initialized OpenAI: {settings.LLM_MODEL}")
        except Exception as e:
            raise LLMError(f"Failed to initialize OpenAI: {str(e)}")
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from OpenAI"""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=settings.LLM_TEMPERATURE,
                max_tokens=settings.LLM_MAX_TOKENS
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI generation error: {e}")
            raise LLMError(f"OpenAI generation failed: {str(e)}")


class AnthropicLLM(BaseLLM):
    """Anthropic Claude implementation"""
    
    def __init__(self):
        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
            self.model = settings.LLM_MODEL
            logger.info(f"Initialized Anthropic: {settings.LLM_MODEL}")
        except Exception as e:
            raise LLMError(f"Failed to initialize Anthropic: {str(e)}")
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from Claude"""
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=settings.LLM_MAX_TOKENS,
                temperature=settings.LLM_TEMPERATURE,
                system=system_prompt or "",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic generation error: {e}")
            raise LLMError(f"Anthropic generation failed: {str(e)}")

class LLMService:
    """LLM Service Wrapper with Multi-Provider Support"""
    
    def __init__(self):
        provider = settings.LLM_PROVIDER.lower()
        
        if provider == "google":
            self.llm = GoogleLLM()
        elif provider == "openai":
            self.llm = OpenAILLM()
        elif provider == "anthropic":
            self.llm = AnthropicLLM()
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
        
        # Load prompts
        self.prompts = self._load_prompts()
        logger.info(f"LLMService initialized with provider: {provider}")
    
    def _load_prompts(self) -> Dict[str, str]:
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
    
    def _extract_json_from_response(self, response: str) -> List[Dict[str, Any]]:
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
        files: List[Dict[str, Any]]
    ) -> List[SecurityIssue]:
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
            
            response = await self.llm.generate(
                prompt=prompt,
                system_prompt=self.prompts.get('security_analysis', '')
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
            
        except Exception as e:
            logger.error(f"Security analysis error: {e}")
            raise LLMError(f"Security analysis failed: {str(e)}")
    
    async def analyze_performance(
        self, 
        diff_content: str, 
        files: List[Dict[str, Any]]
    ) -> List[PerformanceIssue]:
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
            
            response = await self.llm.generate(
                prompt=prompt,
                system_prompt=self.prompts.get('performance_analysis', '')
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
            
        except Exception as e:
            logger.error(f"Performance analysis error: {e}")
            raise LLMError(f"Performance analysis failed: {str(e)}")
    
    async def analyze_best_practices(
        self, 
        diff_content: str, 
        files: List[Dict[str, Any]]
    ) -> List[BestPracticeIssue]:
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
            
            response = await self.llm.generate(
                prompt=prompt,
                system_prompt="You are a code review expert focused on software engineering best practices."
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
            
        except Exception as e:
            logger.error(f"Best practices analysis error: {e}")
            raise LLMError(f"Best practices analysis failed: {str(e)}")
    
    async def generate_summary(
        self,
        pr_title: str,
        pr_author: str,
        pr_description: str,
        security_issues: List[SecurityIssue],
        performance_issues: List[PerformanceIssue],
        best_practice_issues: List[BestPracticeIssue],
        total_additions: int,
        total_deletions: int,
        changed_files: int
    ) -> str:
        """Generate executive summary for PR review"""
        try:
            # Format findings for context
            critical_security = [s for s in security_issues if s.severity == "CRITICAL"]
            high_security = [s for s in security_issues if s.severity == "HIGH"]
            high_perf = [p for p in performance_issues if p.impact == "HIGH"]
            
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
- Performance Issues: {len(performance_issues)} total ({len(high_perf)} high impact)
- Best Practice Violations: {len(best_practice_issues)}

Top Security Concerns:
{chr(10).join([f"- {s.title}" for s in (critical_security + high_security)[:3]]) if (critical_security or high_security) else "None"}

Top Performance Concerns:
{chr(10).join([f"- {p.title}" for p in high_perf[:3]]) if high_perf else "None"}

Generate the executive summary following the specified format."""
            
            response = await self.llm.generate(
                prompt=prompt,
                system_prompt=self.prompts.get('summary_generation', '')
            )
            
            logger.info("Generated executive summary")
            return response.strip()
            
        except Exception as e:
            logger.error(f"Summary generation error: {e}")
            raise LLMError(f"Summary generation failed: {str(e)}")



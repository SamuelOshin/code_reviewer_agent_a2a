# app/services/telex_client.py

"""Telex Communication Client

Handles sending code review summaries to Telex using the A2A protocol.
Uses python-a2a library for proper artifact construction and message formatting.
"""

from typing import Optional, Dict, Any
import logging
import httpx
from datetime import datetime, timezone

from app.core.config import settings
from app.core.exceptions import TelexError
from app.models.analysis import CodeAnalysisResult
from app.models.a2a import A2AMessage, A2AArtifact, TaskState
from app.utils.formatters import SummaryFormatter

logger = logging.getLogger(__name__)


class TelexClient:
    """Client for sending code review summaries to Telex via A2A protocol"""
    
    def __init__(self, webhook_url: Optional[str] = None):
        """
        Initialize Telex client
        
        Args:
            webhook_url: Optional override for Telex webhook URL (defaults to settings)
        """
        # Build webhook URL from settings
        if webhook_url:
            self.webhook_url = webhook_url
        elif settings.TELEX_WEBHOOK_URL:
            self.webhook_url = settings.TELEX_WEBHOOK_URL
        elif settings.TELEX_WEBHOOK_HOOK_ID:
            # Build URL from hook ID
            base_url = "https://ping.staging.telex.im"
            self.webhook_url = f"{base_url}/a2a/webhooks/{settings.TELEX_WEBHOOK_HOOK_ID}"
        else:
            # Fallback to old TELEX_URL
            self.webhook_url = settings.TELEX_URL
            
        self.timeout = 30.0  # 30 second timeout
        self.max_retries = 3
        logger.info(f"TelexClient initialized with webhook URL: {self.webhook_url}")
    
    async def send_review_summary(
        self,
        analysis_result: CodeAnalysisResult,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send code review summary to Telex
        
        Args:
            analysis_result: Complete analysis result to send
            task_id: Optional task ID for tracking (generated if not provided)
            
        Returns:
            Response from Telex server
            
        Raises:
            TelexError: If sending fails after retries
        """
        try:
            logger.info(f"Sending review summary for PR #{analysis_result.pr_number}")
            
            # Generate task ID if not provided
            if not task_id:
                task_id = f"pr-{analysis_result.pr_number}-{int(datetime.now(timezone.utc).timestamp())}"
            
            # Format summary for Telex
            formatter = SummaryFormatter()
            formatted_summary = formatter.format_for_telex(analysis_result)
            
            # Build A2A artifact following python-a2a structure
            artifact = self._build_artifact(
                summary_text=formatted_summary,
                analysis_result=analysis_result
            )
            
            # Build A2A message
            message = self._build_message(
                task_id=task_id,
                artifact=artifact,
                analysis_result=analysis_result
            )
            
            # Send with retry logic
            response = await self._send_with_retry(message)
            
            logger.info(f"Successfully sent review summary for PR #{analysis_result.pr_number}")
            return response
            
        except Exception as e:
            logger.error(f"Failed to send review summary: {e}")
            raise TelexError(f"Failed to send review to Telex: {str(e)}")
    
    def _build_artifact(
        self,
        summary_text: str,
        analysis_result: CodeAnalysisResult
    ) -> A2AArtifact:
        """
        Build A2A artifact with proper 'parts' array structure
        
        Args:
            summary_text: Formatted markdown summary
            analysis_result: Analysis result for metadata
            
        Returns:
            A2AArtifact following python-a2a spec
        """
        # Build parts array - python-a2a expects this structure
        parts = [
            {
                "type": "text",
                "content": summary_text
            }
        ]
        
        # Add metadata part with analysis details
        metadata = {
            "pr_number": analysis_result.pr_number,
            "pr_url": analysis_result.pr_url,
            "pr_title": analysis_result.pr_title,
            "pr_author": analysis_result.pr_author,
            "risk_level": analysis_result.risk_level.value,
            "approval_recommendation": analysis_result.approval_recommendation.value,
            "metrics": analysis_result.metrics,
            "analyzed_at": analysis_result.analyzed_at.isoformat(),
            "llm_provider": analysis_result.llm_provider,
            "llm_model": analysis_result.llm_model
        }
        
        parts.append({
            "type": "metadata",
            "content": metadata
        })
        
        return A2AArtifact(
            id=f"review-{analysis_result.pr_number}",
            type="code_review",
            title=f"Code Review: {analysis_result.pr_title}",
            parts=parts,
            metadata={
                "risk_level": analysis_result.risk_level.value,
                "approval": analysis_result.approval_recommendation.value,
                "total_issues": analysis_result.metrics.get("total_issues", 0)
            }
        )
    
    def _build_message(
        self,
        task_id: str,
        artifact: A2AArtifact,
        analysis_result: CodeAnalysisResult
    ) -> A2AMessage:
        """
        Build A2A message envelope
        
        Args:
            task_id: Unique task identifier
            artifact: Artifact to send
            analysis_result: Analysis result for state determination
            
        Returns:
            A2AMessage ready to send
        """
        # Determine task state based on approval
        state = TaskState.COMPLETED
        
        return A2AMessage(
            task_id=task_id,
            state=state,
            artifacts=[artifact],
            metadata={
                "source": "code_review_agent",
                "pr_number": analysis_result.pr_number,
                "pr_url": analysis_result.pr_url,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    async def _send_with_retry(self, message: A2AMessage) -> Dict[str, Any]:
        """
        Send message to Telex with retry logic
        
        Args:
            message: A2A message to send
            
        Returns:
            Response from Telex
            
        Raises:
            TelexError: If all retries fail
        """
        last_error = None
        
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"Sending to Telex (attempt {attempt}/{self.max_retries})")
                
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        self.webhook_url,
                        json=message.model_dump(mode="json"),
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "CodeReviewAgent/1.0"
                        }
                    )
                    
                    # Check for HTTP errors
                    response.raise_for_status()
                    
                    # Parse response
                    result = response.json()
                    logger.debug(f"Telex response: {result}")
                    
                    return result
                    
            except httpx.HTTPStatusError as e:
                last_error = e
                logger.warning(f"HTTP error on attempt {attempt}: {e.response.status_code} - {e.response.text}")
                
                # Don't retry on client errors (4xx)
                if 400 <= e.response.status_code < 500:
                    raise TelexError(f"Client error from Telex: {e.response.status_code} - {e.response.text}")
                
                # Retry on server errors (5xx)
                if attempt < self.max_retries:
                    await self._exponential_backoff(attempt)
                    
            except httpx.RequestError as e:
                last_error = e
                logger.warning(f"Request error on attempt {attempt}: {e}")
                
                if attempt < self.max_retries:
                    await self._exponential_backoff(attempt)
                    
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error on attempt {attempt}: {e}")
                
                if attempt < self.max_retries:
                    await self._exponential_backoff(attempt)
        
        # All retries failed
        raise TelexError(f"Failed to send to Telex after {self.max_retries} attempts: {last_error}")
    
    async def _exponential_backoff(self, attempt: int) -> None:
        """
        Wait with exponential backoff
        
        Args:
            attempt: Current attempt number (1-indexed)
        """
        import asyncio
        
        wait_time = min(2 ** attempt, 30)  # Max 30 seconds
        logger.debug(f"Waiting {wait_time}s before retry...")
        await asyncio.sleep(wait_time)
    
    async def health_check(self) -> bool:
        """
        Check if Telex is reachable
        
        Returns:
            True if Telex is healthy, False otherwise
        """
        try:
            # Try pinging Telex base URL
            base_url = "https://ping.staging.telex.im"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{base_url}/health")
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Telex health check failed: {e}")
            return False

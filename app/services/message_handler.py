# app/services/message_handler.py

"""Message Handler for A2A message/send

Handles message/send JSON-RPC requests from A2A clients, extracting the interpreted
parameters and conversation history from the parts array.
"""

import asyncio
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.config import settings
from app.core.errors import RequestTimeoutError, new_error_id, safe_webhook_target
from app.core.push_url import validate_push_url
from app.models.a2a import A2AArtifact, A2AMessage, A2ATask, ArtifactPart, MessagePart, TaskStatus
from app.services.code_analyzer import CodeAnalyzerService
from app.utils.formatters import SummaryFormatter

logger = logging.getLogger(__name__)


class MessageHandler:
    """Handles incoming A2A messages via message/send"""
    
    def __init__(self):
        self.analyzer = CodeAnalyzerService()
        self.formatter = SummaryFormatter()
        self._background_tasks: set[asyncio.Task] = set()
    
    async def handle_message_send(self, message: dict[str, Any], configuration: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Handle message/send JSON-RPC method
        
        Expected message structure:
        {
            "kind": "message",
            "role": "user",
            "parts": [
                {
                    "kind": "text",
                    "text": "Lagos, Nigeria"  # interpreted request text / extracted params
                },
                {
                    "kind": "data",
                    "data": [...]  # Last 20 messages for context
                }
            ],
            "messageId": "...",
            "taskId": "..."  # Optional
        }
        
        Args:
            message: A2A message object
            configuration: Optional message/send configuration (blocking, pushNotificationConfig)
            
        Returns:
            A2A Task response
        """
        logger.info(f"Handling message/send: {message.get('messageId')}")
        if configuration:
            # Never log the configuration itself: pushNotificationConfig carries a bearer token
            logger.info(
                "Configuration received: keys=%s, has_push_config=%s",
                sorted(str(k) for k in configuration.keys()),
                bool(configuration.get("pushNotificationConfig")),
            )
        
        # Parse message
        message_id = message.get("messageId", str(uuid.uuid4()))
        task_id = message.get("taskId", str(uuid.uuid4()))
        parts = message.get("parts", [])
        
        # Extract interpreted text from parts[0]
        interpreted_text = None
        if len(parts) > 0 and parts[0].get("kind") == "text":
            interpreted_text = parts[0].get("text", "").strip()
        
        # Extract conversation history from parts[1]
        conversation_history = []
        if len(parts) > 1 and parts[1].get("kind") == "data":
            conversation_history = parts[1].get("data", [])
        
        logger.info(f"Interpreted text length: {len(interpreted_text or '')} chars")
        logger.info(f"Conversation history length: {len(conversation_history)}")
        
        # Determine intent and extract PR URL
        pr_url = self._extract_pr_url(interpreted_text, conversation_history)
        
        if not pr_url:
            # No PR URL found - ask user for it
            return await self._create_input_required_response(
                task_id=task_id,
                message_id=message_id,
                prompt="Please provide a GitHub Pull Request URL to analyze (e.g., https://github.com/owner/repo/pull/123)"
            )
        
        # Honor the client's blocking setting
        is_blocking = configuration.get("blocking", True) if configuration else True
        push_config = configuration.get("pushNotificationConfig") if configuration else None
        
        logger.info(f"Request mode: blocking={is_blocking}, has_webhook={push_config is not None}")
        
        # WEBHOOK MODE: Non-blocking mode with real PR analysis
        if not is_blocking and push_config:
            # Reject before any work starts (P1-07): only allowlisted, public https
            # URLs may receive review results. Raises PushUrlRejected, which the
            # JSON-RPC layer returns as Invalid params.
            await validate_push_url(push_config.get("url") if isinstance(push_config, dict) else None)
            logger.info(f"Non-blocking mode: analyzing {pr_url} in background, result will be pushed to webhook")
            
            # Create task ID upfront
            message_id = message.get("messageId", str(uuid.uuid4()))
            
            # Start background task for real analysis
            # Keep a strong reference: the event loop holds tasks weakly, so an
            # unreferenced task can be garbage-collected before it finishes.
            bg_task = asyncio.create_task(
                self._process_and_push_safe(
                    pr_url=pr_url,
                    task_id=task_id,
                    message_id=message_id,
                    message=message,
                    push_config=push_config
                )
            )
            self._background_tasks.add(bg_task)
            bg_task.add_done_callback(self._background_tasks.discard)
            
            # Return MESSAGE (not Task) for immediate response
            accepting_msg = A2AMessage(
                messageId=str(uuid.uuid4()),
                role="agent",
                parts=[
                    MessagePart(
                        kind="text",
                        text=f"🔄 Analyzing PR now! I'll send you the complete security and performance review shortly...\n\n📎 {pr_url}"
                    )
                ],
                kind="message",
                taskId=task_id,
                timestamp=datetime.now(UTC).isoformat()
            )
            
            # Return message as result (NOT Task object)
            result = accepting_msg.model_dump(mode="json", exclude_none=True)
            if "kind" not in result:
                result["kind"] = "message"
            
            logger.info("✅ Returned 'working' message - real analysis will happen in background")
            return result
        
        # BLOCKING MODE: no push config, or blocking requested. Return the finished task.
        logger.info(f"Blocking mode: analyzing {pr_url} and returning the completed task")
        # Bounded (P1-15): a hung model or GitHub call must not hold the request open
        # forever. Cancelling stops the review; the caller can retry or use non-blocking.
        limit = settings.A2A_BLOCKING_TIMEOUT_SECONDS
        try:
            return await asyncio.wait_for(
                self._analyze_and_return(pr_url, task_id, message_id, message), timeout=limit
            )
        except TimeoutError:
            logger.warning(f"Blocking review timed out after {limit:g}s")
            raise RequestTimeoutError(
                f"The review did not finish within {limit:g} seconds. Retry, or send the "
                "request with blocking=false and a pushNotificationConfig to get the "
                "result when it is ready."
            ) from None

    async def _process_and_push_safe(
        self,
        pr_url: str,
        task_id: str,
        message_id: str,
        message: dict[str, Any],
        push_config: dict[str, Any]
    ):
        """Wrapper for _process_and_push with comprehensive error handling"""
        logger.info(f"🚀 _process_and_push_safe STARTED for PR: {pr_url}")
        try:
            logger.info(f"Background task started for PR: {pr_url}")
            logger.info(f"Task details - ID: {task_id}, Message: {message_id}")
            logger.info(f"Push config available: {bool(push_config)}")
            
            await self._process_and_push(pr_url, task_id, message_id, message, push_config)
            logger.info(f"Background task completed successfully for PR: {pr_url}")
        except Exception as e:
            error_id = new_error_id()
            logger.error(
                f"Fatal error in background task [error_id={error_id}] for PR {pr_url}: "
                f"{type(e).__name__}: {e}",
                exc_info=True,
            )
            # Try to push the error to the client's webhook
            try:
                await self._push_error(task_id, message_id, message, push_config, str(e), error_id)
            except Exception as push_error:
                logger.error(f"Failed to push error to webhook: {push_error}", exc_info=True)
    
    async def _push_error(
        self,
        task_id: str,
        message_id: str,
        message: dict[str, Any],
        push_config: dict[str, Any],
        error_message: str,
        error_id: str | None = None
    ):
        """Push error result to the client's push notification webhook

        error_message is used only to pick a user-friendly category. It is never
        sent to the client; the client gets error_id, and the detail is in the logs.
        """
        error_id = error_id or new_error_id()
        logger.info(f"Pushing error for task {task_id} [error_id={error_id}]")

        # Determine error type and create user-friendly message
        if "429" in error_message or "Resource exhausted" in error_message:
            user_message = (
                "⚠️ **Analysis Temporarily Unavailable**\n\n"
                "I've hit my API rate limit while analyzing this PR. This is a temporary issue.\n\n"
                "**What happened:**\n"
                "- The AI service (Gemini) has throttled requests due to high usage\n"
                "- This typically resets within a few minutes\n\n"
                "**What you can do:**\n"
                "1. ⏰ Wait 5-10 minutes and try again\n"
                "2. 🔄 Ask me to analyze the PR again later\n\n"
                f"_Error id: {error_id}_"
            )
        elif "GitHub" in error_message or "404" in error_message:
            user_message = (
                "❌ **Unable to Access Pull Request**\n\n"
                "I couldn't fetch the PR data from GitHub.\n\n"
                "**Possible reasons:**\n"
                "- The PR URL might be incorrect\n"
                "- The repository might be private (I need access)\n"
                "- GitHub API might be temporarily unavailable\n\n"
                "**What you can do:**\n"
                "1. ✅ Verify the PR URL is correct\n"
                "2. 🔑 Ensure I have access to private repositories (if applicable)\n"
                "3. 🔄 Try again in a few moments\n\n"
                f"_Error id: {error_id}_"
            )
        else:
            user_message = (
                "❌ **Analysis Failed**\n\n"
                "I encountered an unexpected error while analyzing this PR.\n\n"
                "**What you can do:**\n"
                "1. 🔄 Try again - it might be a temporary issue\n"
                "2. 📝 If the problem persists, please report this error id\n\n"
                f"_Error id: {error_id}_"
            )
        
        error_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text=user_message
                )
            ],
            kind="message",
            taskId=task_id,
            timestamp=datetime.now(UTC)
        )
        
        # Create error artifact (some A2A clients don't display the message if artifacts=[])
        error_artifact = A2AArtifact(
            artifactId=str(uuid.uuid4()),
            name="Error Report",
            parts=[
                ArtifactPart(
                    kind="text",
                    text=f"# ❌ PR Analysis Error\n\n{user_message}\n\n---\n*Error occurred at {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}*"
                )
            ]
        )
        
        task_obj = A2ATask(
            id=task_id,
            contextId=message.get("contextId", str(uuid.uuid4())),
            status=TaskStatus(
                state="failed",
                timestamp=datetime.now(UTC),
                message=error_msg
            ),
            artifacts=[error_artifact],  
            history=[error_msg],
            kind="task"
        )
        
        # Push to webhook
        webhook_url = push_config.get("url")
        token = push_config.get("token")
        
        headers = {"Content-Type": "application/json"}
        auth_schemes = push_config.get("authentication", {}).get("schemes", [])
        if "Bearer" in auth_schemes and token:
            headers["Authorization"] = f"Bearer {token}"
        
        # Build JSON-RPC RESPONSE (not request!) for the push webhook
        # Expected shape: {"jsonrpc": "2.0", "result": {...task...}, "id": "..."}
        task_result = task_obj.model_dump(mode="json", exclude_none=True)
        
        webhook_payload = {
            "jsonrpc": "2.0",
            "result": task_result,
            "id": str(uuid.uuid4())
        }
        
        # Check again right before sending: DNS may have changed since the request
        await validate_push_url(webhook_url)
        logger.info(f"Pushing error result to webhook: {safe_webhook_target(webhook_url)}")
        logger.info(f"Error task state: {task_result.get('status', {}).get('state')}")
        
        # Never follow redirects: a 3xx could point the push at an internal address
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            response = await client.post(webhook_url, json=webhook_payload, headers=headers)
            response.raise_for_status()
            logger.info(f"Error pushed successfully (status: {response.status_code})")
    
    def _format_analysis_as_text(self, analysis_result, pr_url: str) -> str:
        """Format analysis result as readable text for artifact"""
        lines = []
        
        # Header
        lines.append("# Pull Request Analysis Report")
        lines.append("")
        lines.append(f"**PR #{analysis_result.pr_number}**: {analysis_result.pr_title}")
        lines.append(f"**Author**: {analysis_result.author}")
        lines.append(f"**Repository**: {analysis_result.repository}")
        lines.append(f"**URL**: {pr_url}")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(analysis_result.executive_summary)
        lines.append("")
        
        # Risk Assessment
        lines.append("## Risk Assessment")
        lines.append("")
        lines.append(f"**Risk Level**: {analysis_result.risk_level.value.upper()}")
        lines.append(f"**Recommendation**: {analysis_result.approval_recommendation.value.upper()}")
        lines.append(f"**Status**: {analysis_result.status.value.upper()}")
        if analysis_result.incomplete_reasons:
            lines.append("")
            lines.append("**Why the review is not complete**:")
            for reason in analysis_result.incomplete_reasons:
                lines.append(f"- {reason}")
        lines.append("")
        
        # Key Concerns
        if analysis_result.key_concerns:
            lines.append("## Key Concerns")
            lines.append("")
            for concern in analysis_result.key_concerns:
                lines.append(f"- {concern}")
            lines.append("")
        
        # Statistics
        lines.append("## Statistics")
        lines.append("")
        lines.append(f"- Files changed: {analysis_result.files_changed}")
        lines.append(f"- Lines added: +{analysis_result.lines_added}")
        lines.append(f"- Lines deleted: -{analysis_result.lines_deleted}")
        lines.append("")
        
        # Security Findings
        if analysis_result.security_findings:
            lines.append(f"## 🔒 Security Findings ({len(analysis_result.security_findings)})")
            lines.append("")
            for i, finding in enumerate(analysis_result.security_findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append(f"**Severity**: {finding.severity.upper()}")
                lines.append(f"**File**: `{finding.file}` (Line {finding.line_number})")
                lines.append("")
                lines.append(f"**Description**: {finding.description}")
                lines.append("")
                lines.append(f"**Recommendation**: {finding.recommendation}")
                if finding.cwe_id:
                    lines.append(f"**CWE ID**: {finding.cwe_id}")
                lines.append("")
        
        # Performance Findings
        if analysis_result.performance_findings:
            lines.append(f"## ⚡ Performance Findings ({len(analysis_result.performance_findings)})")
            lines.append("")
            for i, finding in enumerate(analysis_result.performance_findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append(f"**Severity**: {finding.severity.upper()}")
                lines.append(f"**File**: `{finding.file}`")
                lines.append("")
                lines.append(f"**Description**: {finding.description}")
                lines.append("")
                lines.append(f"**Impact**: {finding.impact}")
                lines.append("")
                lines.append(f"**Recommendation**: {finding.recommendation}")
                lines.append("")
        
        # Best Practice Findings
        if analysis_result.best_practice_findings:
            lines.append(f"## 📚 Best Practice Findings ({len(analysis_result.best_practice_findings)})")
            lines.append("")
            for i, finding in enumerate(analysis_result.best_practice_findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append(f"**Category**: {finding.category}")
                lines.append(f"**Severity**: {finding.severity.upper()}")
                if finding.file:
                    lines.append(f"**File**: `{finding.file}`")
                lines.append("")
                lines.append(f"**Description**: {finding.description}")
                lines.append("")
                lines.append(f"**Recommendation**: {finding.recommendation}")
                lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Analysis completed at {analysis_result.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        lines.append(f"*Powered by {analysis_result.llm_provider} ({analysis_result.llm_model})*")
        if analysis_result.llm_models_by_role:
            by_role = ", ".join(f"{r}={m}" for r, m in analysis_result.llm_models_by_role.items())
            lines.append(f"*Models by role: {by_role}*")
        
        return "\n".join(lines)
    
    async def _analyze_and_return(
        self,
        pr_url: str,
        task_id: str,
        message_id: str,
        message: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze PR and return result dict"""
        try:
            logger.info(f"Analyzing PR: {pr_url}")
            logger.info("About to call analyzer.analyze_pr...")
            
            analysis_result = await self.analyzer.analyze_pr(pr_url)
            logger.info(f"Analysis completed successfully, PR#{analysis_result.pr_number}")
            
            # Format summary
            logger.info("Formatting summary...")
            summary_text = self.formatter.format_short(analysis_result)
            logger.info(f"Summary formatted, length: {len(summary_text)} chars")
            
            # Create response message
            response_msg = A2AMessage(
                messageId=str(uuid.uuid4()),
                role="agent",
                parts=[
                    MessagePart(
                        kind="text",
                        text=summary_text
                    )
                ],
                kind="message",
                taskId=task_id,
                timestamp=datetime.now(UTC).isoformat()
            )
            
            # Create artifact with full analysis data as TEXT (not JSON)
            # Format analysis as readable text
            artifact_text = self._format_analysis_as_text(analysis_result, pr_url)
            
            # Truncate artifact text to avoid HTTP 413 (Payload Too Large)
            MAX_ARTIFACT_LENGTH = 50000  # ~50KB for artifact text
            if len(artifact_text) > MAX_ARTIFACT_LENGTH:
                logger.warning(f"Artifact text too long ({len(artifact_text)} chars), truncating to {MAX_ARTIFACT_LENGTH}")
                artifact_text = artifact_text[:MAX_ARTIFACT_LENGTH] + "\n\n...[Analysis truncated due to size limits]"
            
            artifact = A2AArtifact(
                artifactId=str(uuid.uuid4()),
                name=f"PR #{analysis_result.pr_number} Analysis",
                parts=[
                    ArtifactPart(
                        kind="text",
                        text=artifact_text
                    )
                ]
            )
            
            # Create completed task
            task = A2ATask(
                id=task_id,
                contextId=message.get("contextId", str(uuid.uuid4())),
                status=TaskStatus(
                    state="completed",
                    timestamp=datetime.now(UTC).isoformat(),
                    message=response_msg,
                    progress=1.0
                ),
                artifacts=[artifact],
                history=[response_msg],
                kind="task"
            )
            
            # Serialize properly with Pydantic v2 (handles datetime -> ISO string)
            # exclude_none=True removes null fields for cleaner JSON
            result = task.model_dump(mode="json", exclude_none=True)
            
            # Double-check kind field is present
            if "kind" not in result:
                result["kind"] = "task"
            
            logger.info(f"Returning task result: {result.get('id')}, state: {result['status']['state']}, kind: {result.get('kind')}")
            
            return result
            
        except Exception as e:
            error_id = new_error_id()
            logger.error(f"Error analyzing PR {pr_url} [error_id={error_id}]: {e}", exc_info=True)

            # Create error response (generic text; the detail stays in the logs)
            error_msg = A2AMessage(
                messageId=str(uuid.uuid4()),
                role="agent",
                parts=[
                    MessagePart(
                        kind="text",
                        text=f"Failed to analyze PR. Please try again later. (error id: {error_id})"
                    )
                ],
                kind="message",
                taskId=task_id,
                timestamp=datetime.now(UTC).isoformat()
            )
            
            task = A2ATask(
                id=task_id,
                contextId=message.get("contextId", str(uuid.uuid4())),
                status=TaskStatus(
                    state="failed",
                    timestamp=datetime.now(UTC).isoformat(),
                    message=error_msg
                ),
                artifacts=[],
                history=[error_msg],
                kind="task"
            )
            
            return task.model_dump(mode="json", exclude_none=True)
    
    async def _process_and_push(
        self,
        pr_url: str,
        task_id: str,
        message_id: str,
        message: dict[str, Any],
        push_config: dict[str, Any]
    ):
        """Process PR analysis and push result to the push notification webhook (non-blocking mode)"""
        try:
            # Analyze PR
            result_dict = await self._analyze_and_return(pr_url, task_id, message_id, message)
            
            # Serialize properly using Pydantic's model serialization
            # This ensures datetime objects are converted to ISO strings
            
            # Convert any remaining datetime objects to ISO strings
            def serialize_datetime(obj):
                if isinstance(obj, dict):
                    return {k: serialize_datetime(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [serialize_datetime(item) for item in obj]
                elif isinstance(obj, datetime):
                    return obj.isoformat()
                else:
                    return obj
            
            result_serialized = serialize_datetime(result_dict)
            
            # Create a lightweight version for webhook (to avoid 413 payload too large)
            # Only include summary stats, not all findings
            result_lightweight = self._create_lightweight_result(result_serialized)
            
            # Push to webhook
            webhook_url = push_config.get("url")
            token = push_config.get("token")
            
            if not webhook_url:
                logger.error("No webhook URL in pushNotificationConfig")
                return
            
            headers = {
                "Content-Type": "application/json"
            }
            
            # Add authentication if provided
            auth_schemes = push_config.get("authentication", {}).get("schemes", [])
            if "Bearer" in auth_schemes and token:
                headers["Authorization"] = f"Bearer {token}"
            
            # Webhook expects JSON-RPC 2.0 RESPONSE (not request!)
            # Format: {"jsonrpc": "2.0", "result": {...task...}, "id": "..."}
            # Use lightweight version to avoid HTTP 413 (payload too large)
            
            # Build JSON-RPC response with task as result
            webhook_payload = {
                "jsonrpc": "2.0",
                "result": result_lightweight,
                "id": str(uuid.uuid4())
            }
            
            # Check again right before sending: DNS may have changed since the request
            await validate_push_url(webhook_url)
            logger.info(f"Pushing full task result to webhook: {safe_webhook_target(webhook_url)}")
            logger.info(f"Task state: {result_lightweight.get('status', {}).get('state')}")
            logger.info("Sending JSON-RPC response with complete task result")
            
            # Use a longer read timeout for push webhooks (they can be slow)
            # Connect: 10s, Read: 60s
            timeout = httpx.Timeout(10.0, read=60.0)
            
            # Never follow redirects: a 3xx could point the push at an internal address
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                try:
                    response = await client.post(
                        webhook_url,
                        json=webhook_payload,
                        headers=headers
                    )
                    response.raise_for_status()
                    logger.info(f"Successfully pushed result to webhook (status: {response.status_code})")
                except httpx.TimeoutException as timeout_err:
                    logger.warning(f"Webhook push timed out after 60s: {timeout_err}")
                    logger.info("Result was prepared successfully but webhook didn't respond in time")
                    # Don't raise - analysis was successful, webhook timeout is not critical
                except httpx.HTTPStatusError as http_err:
                    # Status only: the response body is third-party content and may echo secrets
                    logger.error(f"Webhook returned error status: {http_err.response.status_code}")
                    raise
                
        except Exception as e:
            error_id = new_error_id()
            logger.error(f"Error processing and pushing result [error_id={error_id}]: {e}", exc_info=True)
            # Try to push the error to the client's webhook
            try:
                await self._push_error(task_id, message_id, message, push_config, str(e), error_id)
            except Exception as push_error:
                logger.error(f"Failed to push error to webhook: {push_error}", exc_info=True)
    
    def _extract_pr_url(self, interpreted_text: str | None, conversation_history: list[dict[str, Any]]) -> str | None:
        """
        Extract GitHub PR URL from interpreted text or conversation history
        
        Args:
            interpreted_text: Interpreted request text (from parts[0])
            conversation_history: Last 20 messages (from parts[1])
            
        Returns:
            PR URL if found, None otherwise
        """
        # GitHub PR URL patterns. The number must not run into more word characters
        # ("pull/12abc" is not PR 12), matching parse_pr_url (P1-18)
        url_patterns = [
            r'https?://github\.com/[^/]+/[^/]+/pull/[0-9]+(?![0-9A-Za-z_])',
            r'github\.com/[^/]+/[^/]+/pull/[0-9]+(?![0-9A-Za-z_])',
        ]
        
        # First check interpreted text
        if interpreted_text:
            for pattern in url_patterns:
                match = re.search(pattern, interpreted_text, re.IGNORECASE)
                if match:
                    url = match.group(0)
                    if not url.startswith('http'):
                        url = 'https://' + url
                    logger.info(f"Found PR URL in interpreted text: {url}")
                    return url
        
        # Then check conversation history (most recent first)
        for msg in reversed(conversation_history):
            if isinstance(msg, dict):
                text = msg.get("text", "")
                for pattern in url_patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        url = match.group(0)
                        if not url.startswith('http'):
                            url = 'https://' + url
                        logger.info(f"Found PR URL in conversation history: {url}")
                        return url
        
        return None
    
    def _create_lightweight_result(self, full_result: dict[str, Any]) -> dict[str, Any]:
        """
        Create a lightweight version of the result for webhook push
        to avoid HTTP 413 (payload too large) errors.
        
        Only includes:
        - Message text (summary)
        - High-level stats (counts, not full findings)
        - Critical/high severity issues only
        
        Args:
            full_result: Complete analysis result with all findings
            
        Returns:
            Lightweight result suitable for webhook push
        """
        lightweight = {
            "id": full_result["id"],
            "contextId": full_result["contextId"],
            "status": full_result["status"],
            "kind": full_result["kind"],
            "history": full_result["history"],
        }
        
        # For text artifacts, just include them as-is (they're already optimized)
        if full_result.get("artifacts"):
            lightweight["artifacts"] = full_result["artifacts"]
        
        return lightweight
    
    async def _create_input_required_response(
        self,
        task_id: str,
        message_id: str,
        prompt: str
    ) -> dict[str, Any]:
        """
        Create an input-required response to ask user for more info
        
        Args:
            task_id: Task ID
            message_id: Original message ID
            prompt: Question to ask the user
            
        Returns:
            A2A Task with input-required status
        """
        response_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text=prompt
                )
            ],
            kind="message",
            taskId=task_id,
            timestamp=datetime.now(UTC).isoformat()
        )
        
        task = A2ATask(
            id=task_id,
            contextId=str(uuid.uuid4()),
            status=TaskStatus(
                state="input-required",
                timestamp=datetime.now(UTC).isoformat(),
                message=response_msg
            ),
            artifacts=[],
            history=[response_msg],
            kind="task"
        )
        
        return task.model_dump(mode="json", exclude_none=True)

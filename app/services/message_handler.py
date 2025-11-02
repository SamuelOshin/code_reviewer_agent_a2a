# app/services/message_handler.py

"""Message Handler for Telex A2A Integration

Handles message/send JSON-RPC requests from Telex, extracting the interpreted
parameters and conversation history from the parts array.
"""

import logging
import uuid
import re
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.models.a2a import A2AMessage, MessagePart, A2ATask, TaskStatus, A2AArtifact, ArtifactPart
from app.services.code_analyzer import CodeAnalyzerService
from app.utils.formatters import SummaryFormatter

logger = logging.getLogger(__name__)


class MessageHandler:
    """Handles incoming messages from Telex via message/send"""
    
    def __init__(self):
        self.analyzer = CodeAnalyzerService()
        self.formatter = SummaryFormatter()
    
    async def handle_message_send(self, message: Dict[str, Any], configuration: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Handle message/send JSON-RPC method from Telex
        
        Expected message structure:
        {
            "kind": "message",
            "role": "user",
            "parts": [
                {
                    "kind": "text",
                    "text": "Lagos, Nigeria"  # Telex's interpretation/extracted params
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
            message: Message object from Telex
            configuration: Optional configuration from Telex (workflow settings, etc.)
            
        Returns:
            A2A Task response
        """
        logger.info(f"Handling message/send: {message.get('messageId')}")
        if configuration:
            logger.info(f"Configuration: {configuration}")
        
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
        
        logger.info(f"Interpreted text: {interpreted_text}")
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
        
        # Check if Telex wants blocking or non-blocking mode
        is_blocking = configuration.get("blocking", True) if configuration else True
        push_config = configuration.get("pushNotificationConfig") if configuration else None
        
        if not is_blocking and push_config:
            # Non-blocking mode - return accepted status and push result via webhook
            logger.info(f"Using NON-BLOCKING mode - will push result to webhook: {push_config.get('url')}")
            return await self._analyze_and_push(pr_url, task_id, message_id, message, push_config)
        else:
            # Blocking mode - return complete analysis immediately
            logger.info(f"Using BLOCKING mode - will return complete analysis immediately")
            return await self._analyze_and_return(pr_url, task_id, message_id, message)
    
    async def _process_and_push_safe(
        self,
        pr_url: str,
        task_id: str,
        message_id: str,
        message: Dict[str, Any],
        push_config: Dict[str, Any]
    ):
        """Wrapper for _process_and_push with comprehensive error handling"""
        try:
            logger.info(f"Background task started for PR: {pr_url}")
            logger.info(f"Task details - ID: {task_id}, Message: {message_id}")
            logger.info(f"Push config available: {bool(push_config)}")
            
            await self._process_and_push(pr_url, task_id, message_id, message, push_config)
            logger.info(f"Background task completed successfully for PR: {pr_url}")
        except Exception as e:
            logger.error(f"Fatal error in background task: {e}", exc_info=True)
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error occurred at PR: {pr_url}")
            # Try to send error to Telex webhook
            try:
                await self._push_error_to_telex(task_id, message_id, message, push_config, str(e))
            except Exception as push_error:
                logger.error(f"Failed to push error to Telex: {push_error}", exc_info=True)
    
    async def _push_error_to_telex(
        self,
        task_id: str,
        message_id: str,
        message: Dict[str, Any],
        push_config: Dict[str, Any],
        error_message: str
    ):
        """Push error result to Telex webhook"""
        error_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text=f"❌ Analysis failed: {error_message}"
                )
            ],
            kind="message",
            taskId=task_id,
            timestamp=datetime.now(timezone.utc)
        )
        
        task_obj = A2ATask(
            id=task_id,
            contextId=message.get("contextId", str(uuid.uuid4())),
            status=TaskStatus(
                state="failed",
                timestamp=datetime.now(timezone.utc),
                message=error_msg
            ),
            artifacts=[],
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
        elif "TelexApiKey" in auth_schemes and token:
            headers["Authorization"] = f"Bearer {token}"
        
        # Build JSON-RPC message/send request (per Telex webhook spec)
        webhook_payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "message/send",
            "params": {
                "message": {
                    "kind": "message",
                    "role": "agent",
                    "parts": [{"kind": "text", "text": f"❌ Analysis failed: {error_message}"}],
                    "messageId": error_msg.messageId,
                    "contextId": task_obj.contextId,
                    "taskId": task_id
                },
                "metadata": {
                    "task": task_obj.model_dump(mode="json", exclude_none=True)
                }
            }
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            await client.post(webhook_url, json=webhook_payload, headers=headers)
    
    async def _analyze_and_push(
        self,
        pr_url: str,
        task_id: str,
        message_id: str,
        message: Dict[str, Any],
        push_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Return 'accepted' status immediately and analyze in background,
        pushing result to webhook when complete (non-blocking mode)
        """
        import asyncio
        
        # Start background task to analyze and push
        asyncio.create_task(
            self._process_and_push_safe(pr_url, task_id, message_id, message, push_config)
        )
        
        # Return "accepted" status immediately
        accepting_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text="🔄 PR analysis started! I'll send you the results shortly via notification."
                )
            ],
            kind="message",
            taskId=task_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        task = A2ATask(
            id=task_id,
            contextId=message.get("contextId", str(uuid.uuid4())),
            status=TaskStatus(
                state="accepted",
                timestamp=datetime.now(timezone.utc).isoformat(),
                message=accepting_msg,
                progress=0.1
            ),
            artifacts=[],
            history=[accepting_msg],
            kind="task"
        )
        
        # Serialize and return
        result = task.model_dump(mode="json", exclude_none=True)
        if "kind" not in result:
            result["kind"] = "task"
        
        logger.info(f"Returned 'accepted' status for task {task_id}, analysis running in background")
        return result
    
    def _format_analysis_as_text(self, analysis_result, pr_url: str) -> str:
        """Format analysis result as readable text for artifact"""
        lines = []
        
        # Header
        lines.append(f"# Pull Request Analysis Report")
        lines.append(f"")
        lines.append(f"**PR #{analysis_result.pr_number}**: {analysis_result.pr_title}")
        lines.append(f"**Author**: {analysis_result.author}")
        lines.append(f"**Repository**: {analysis_result.repository}")
        lines.append(f"**URL**: {pr_url}")
        lines.append(f"")
        
        # Executive Summary
        lines.append(f"## Executive Summary")
        lines.append(f"")
        lines.append(analysis_result.executive_summary)
        lines.append(f"")
        
        # Risk Assessment
        lines.append(f"## Risk Assessment")
        lines.append(f"")
        lines.append(f"**Risk Level**: {analysis_result.risk_level.value.upper()}")
        lines.append(f"**Recommendation**: {analysis_result.approval_recommendation.value.upper()}")
        lines.append(f"")
        
        # Key Concerns
        if analysis_result.key_concerns:
            lines.append(f"## Key Concerns")
            lines.append(f"")
            for concern in analysis_result.key_concerns:
                lines.append(f"- {concern}")
            lines.append(f"")
        
        # Statistics
        lines.append(f"## Statistics")
        lines.append(f"")
        lines.append(f"- Files changed: {analysis_result.files_changed}")
        lines.append(f"- Lines added: +{analysis_result.lines_added}")
        lines.append(f"- Lines deleted: -{analysis_result.lines_deleted}")
        lines.append(f"")
        
        # Security Findings
        if analysis_result.security_findings:
            lines.append(f"## 🔒 Security Findings ({len(analysis_result.security_findings)})")
            lines.append(f"")
            for i, finding in enumerate(analysis_result.security_findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append(f"**Severity**: {finding.severity.upper()}")
                lines.append(f"**File**: `{finding.file}` (Line {finding.line_number})")
                lines.append(f"")
                lines.append(f"**Description**: {finding.description}")
                lines.append(f"")
                lines.append(f"**Recommendation**: {finding.recommendation}")
                if finding.cwe_id:
                    lines.append(f"**CWE ID**: {finding.cwe_id}")
                lines.append(f"")
        
        # Performance Findings
        if analysis_result.performance_findings:
            lines.append(f"## ⚡ Performance Findings ({len(analysis_result.performance_findings)})")
            lines.append(f"")
            for i, finding in enumerate(analysis_result.performance_findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append(f"**Severity**: {finding.severity.upper()}")
                lines.append(f"**File**: `{finding.file}`")
                lines.append(f"")
                lines.append(f"**Description**: {finding.description}")
                lines.append(f"")
                lines.append(f"**Impact**: {finding.impact}")
                lines.append(f"")
                lines.append(f"**Recommendation**: {finding.recommendation}")
                lines.append(f"")
        
        # Best Practice Findings
        if analysis_result.best_practice_findings:
            lines.append(f"## 📚 Best Practice Findings ({len(analysis_result.best_practice_findings)})")
            lines.append(f"")
            for i, finding in enumerate(analysis_result.best_practice_findings, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append(f"**Category**: {finding.category}")
                lines.append(f"**Severity**: {finding.severity.upper()}")
                if finding.file:
                    lines.append(f"**File**: `{finding.file}`")
                lines.append(f"")
                lines.append(f"**Description**: {finding.description}")
                lines.append(f"")
                lines.append(f"**Recommendation**: {finding.recommendation}")
                lines.append(f"")
        
        # Footer
        lines.append(f"---")
        lines.append(f"*Analysis completed at {analysis_result.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        lines.append(f"*Powered by {analysis_result.llm_provider} ({analysis_result.llm_model})*")
        
        return "\n".join(lines)
    
    async def _analyze_and_return(
        self,
        pr_url: str,
        task_id: str,
        message_id: str,
        message: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze PR and return result (blocking mode)"""
        try:
            logger.info(f"Analyzing PR: {pr_url}")
            logger.info("About to call analyzer.analyze_pr...")
            
            analysis_result = await self.analyzer.analyze_pr(pr_url)
            logger.info(f"Analysis completed successfully, PR#{analysis_result.pr_number}")
            
            # Format summary
            logger.info("Formatting summary for Telex...")
            summary_text = self.formatter.format_for_telex(analysis_result)
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
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
            # Create artifact with full analysis data as TEXT (not JSON)
            # Format analysis as readable text
            artifact_text = self._format_analysis_as_text(analysis_result, pr_url)
            
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
                    timestamp=datetime.now(timezone.utc).isoformat(),
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
            
            # Log the complete response for debugging
            import json
            logger.info(f"Returning task result: {result.get('id')}, state: {result['status']['state']}, kind: {result.get('kind')}")
            logger.info("=" * 80)
            logger.info("FULL RESPONSE BODY:")
            logger.info(json.dumps(result, indent=2))
            logger.info("=" * 80)
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing PR {pr_url}: {e}", exc_info=True)
            
            # Create error response
            error_msg = A2AMessage(
                messageId=str(uuid.uuid4()),
                role="agent",
                parts=[
                    MessagePart(
                        kind="text",
                        text=f"Failed to analyze PR: {str(e)}"
                    )
                ],
                kind="message",
                taskId=task_id,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
            task = A2ATask(
                id=task_id,
                contextId=message.get("contextId", str(uuid.uuid4())),
                status=TaskStatus(
                    state="failed",
                    timestamp=datetime.now(timezone.utc).isoformat(),
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
        message: Dict[str, Any],
        push_config: Dict[str, Any]
    ):
        """Process PR analysis and push result to Telex webhook (non-blocking mode)"""
        try:
            # Analyze PR
            result_dict = await self._analyze_and_return(pr_url, task_id, message_id, message)
            
            # Serialize properly using Pydantic's model serialization
            # This ensures datetime objects are converted to ISO strings
            from pydantic import BaseModel
            
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
            
            # Push to Telex webhook
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
            elif "TelexApiKey" in auth_schemes and token:
                headers["Authorization"] = f"Bearer {token}"
            
            # Telex webhook expects JSON-RPC 2.0 message/send request
            # Per https://ping.staging.telex.im/docs/#/default/handleA2AWebhookRequest
            # Use lightweight version to avoid HTTP 413 (payload too large)
            
            # Extract the response message from the task status
            response_message = result_lightweight.get("status", {}).get("message", {})
            
            # Build JSON-RPC message/send request (as shown in Telex docs)
            webhook_payload = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "message/send",
                "params": {
                    "message": {
                        "kind": "message",
                        "role": "agent",
                        "parts": response_message.get("parts", []),
                        "messageId": response_message.get("messageId"),
                        "contextId": result_lightweight.get("contextId"),
                        "taskId": result_lightweight.get("id")
                    },
                    "metadata": {
                        "task": result_lightweight  # Include full task in metadata
                    }
                }
            }
            
            logger.info(f"Pushing lightweight result to webhook: {webhook_url}")
            logger.info(f"Artifact size reduced - including only critical/high severity issues")
            logger.info(f"Sending JSON-RPC message/send request (per Telex webhook spec)")
            
            # Use longer timeout for Telex webhook (they can be slow)
            # Connect: 10s, Read: 60s (Telex processing time)
            timeout = httpx.Timeout(10.0, read=60.0)
            
            async with httpx.AsyncClient(timeout=timeout) as client:
                try:
                    response = await client.post(
                        webhook_url,
                        json=webhook_payload,
                        headers=headers
                    )
                    response.raise_for_status()
                    logger.info(f"Successfully pushed result to Telex (status: {response.status_code})")
                except httpx.TimeoutException as timeout_err:
                    logger.warning(f"Webhook push timed out after 60s: {timeout_err}")
                    logger.info("Result was prepared successfully but Telex webhook didn't respond in time")
                    # Don't raise - analysis was successful, webhook timeout is not critical
                except httpx.HTTPStatusError as http_err:
                    logger.error(f"Webhook returned error status: {http_err.response.status_code}")
                    logger.error(f"Response body: {http_err.response.text}")
                    raise
                
        except Exception as e:
            logger.error(f"Error processing and pushing result: {e}", exc_info=True)
    
    def _extract_pr_url(self, interpreted_text: Optional[str], conversation_history: List[Dict[str, Any]]) -> Optional[str]:
        """
        Extract GitHub PR URL from interpreted text or conversation history
        
        Args:
            interpreted_text: Telex's interpretation (from parts[0])
            conversation_history: Last 20 messages (from parts[1])
            
        Returns:
            PR URL if found, None otherwise
        """
        # GitHub PR URL patterns
        url_patterns = [
            r'https?://github\.com/[^/]+/[^/]+/pull/\d+',
            r'github\.com/[^/]+/[^/]+/pull/\d+',
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
    
    def _create_lightweight_result(self, full_result: Dict[str, Any]) -> Dict[str, Any]:
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
        
        # Create a summary artifact with just counts and critical issues
        if full_result.get("artifacts"):
            artifact_data = full_result["artifacts"][0]["parts"][0]["data"]
            
            # Filter to only high/critical severity issues
            security_critical = [
                f for f in artifact_data.get("security_findings", [])
                if f.get("severity") in ["high", "critical"]
            ][:10]  # Max 10
            
            performance_critical = [
                f for f in artifact_data.get("performance_findings", [])
                if f.get("severity") in ["high", "critical"] and f.get("impact") == "HIGH"
            ][:10]  # Max 10
            
            best_practice_critical = [
                f for f in artifact_data.get("best_practice_findings", [])
                if f.get("severity") in ["high", "medium"]
            ][:10]  # Max 10
            
            lightweight_artifact = {
                "artifactId": full_result["artifacts"][0]["artifactId"],
                "name": full_result["artifacts"][0]["name"],
                "parts": [{
                    "kind": "json",
                    "data": {
                        "pr_number": artifact_data.get("pr_number"),
                        "pr_title": artifact_data.get("pr_title"),
                        "author": artifact_data.get("author"),
                        "repository": artifact_data.get("repository"),
                        "executive_summary": artifact_data.get("executive_summary"),
                        "risk_level": artifact_data.get("risk_level"),
                        "approval_recommendation": artifact_data.get("approval_recommendation"),
                        "key_concerns": artifact_data.get("key_concerns", []),
                        # Summary counts
                        "stats": {
                            "security_total": len(artifact_data.get("security_findings", [])),
                            "performance_total": len(artifact_data.get("performance_findings", [])),
                            "best_practice_total": len(artifact_data.get("best_practice_findings", [])),
                            "files_changed": artifact_data.get("files_changed"),
                            "lines_added": artifact_data.get("lines_added"),
                            "lines_deleted": artifact_data.get("lines_deleted"),
                        },
                        # Only critical/high severity issues (max 10 each)
                        "security_findings": security_critical,
                        "performance_findings": performance_critical,
                        "best_practice_findings": best_practice_critical,
                    }
                }],
                "metadata": full_result["artifacts"][0].get("metadata", {})
            }
            
            lightweight["artifacts"] = [lightweight_artifact]
        else:
            lightweight["artifacts"] = []
        
        return lightweight
    
    async def _create_input_required_response(
        self,
        task_id: str,
        message_id: str,
        prompt: str
    ) -> Dict[str, Any]:
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
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        task = A2ATask(
            id=task_id,
            contextId=str(uuid.uuid4()),
            status=TaskStatus(
                state="input-required",
                timestamp=datetime.now(timezone.utc).isoformat(),
                message=response_msg
            ),
            artifacts=[],
            history=[response_msg],
            kind="task"
        )
        
        return task.model_dump(mode="json", exclude_none=True)

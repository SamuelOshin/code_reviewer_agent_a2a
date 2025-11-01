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
        
        # Check if blocking or non-blocking
        is_blocking = configuration.get("blocking", True) if configuration else True
        push_config = configuration.get("pushNotificationConfig") if configuration else None
        
        if not is_blocking and push_config:
            # Non-blocking mode - return quick acknowledgment and process in background
            logger.info(f"Non-blocking mode detected, will push results to webhook")
            
            # Start background task with error handling
            import asyncio
            task = asyncio.create_task(
                self._process_and_push_safe(pr_url, task_id, message_id, message, push_config)
            )
            # Add done callback to log any exceptions
            task.add_done_callback(self._log_task_exception)
            
            # Return immediate acknowledgment
            ack_msg = A2AMessage(
                messageId=str(uuid.uuid4()),
                role="agent",
                parts=[
                    MessagePart(
                        kind="text",
                        text=f"🔍 Analyzing PR... I'll send you the results shortly!"
                    )
                ],
                kind="message",
                taskId=task_id,
                timestamp=datetime.now(timezone.utc)
            )
            
            task = A2ATask(
                id=task_id,
                contextId=message.get("contextId", str(uuid.uuid4())),
                status=TaskStatus(
                    state="in_progress",
                    timestamp=datetime.now(timezone.utc),
                    message=ack_msg,
                    progress=0.1
                ),
                artifacts=[],
                history=[ack_msg],
                kind="task"
            )
            
            return task.dict()
        
        # Blocking mode - analyze and return result immediately
        return await self._analyze_and_return(pr_url, task_id, message_id, message)
    
    def _log_task_exception(self, task):
        """Log any exceptions from background tasks"""
        try:
            task.result()
        except Exception as e:
            logger.error(f"Background task failed: {e}", exc_info=True)
    
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
        
        rpc_response = {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": task_obj.dict()
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            await client.post(webhook_url, json=rpc_response, headers=headers)
    
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
                timestamp=datetime.now(timezone.utc)
            )
            
            # Create artifact with full analysis data
            artifact = A2AArtifact(
                artifactId=str(uuid.uuid4()),
                name=f"PR #{analysis_result.pr_number} Analysis",
                parts=[
                    ArtifactPart(
                        kind="json",
                        data={
                            "pr_number": analysis_result.pr_number,
                            "pr_title": analysis_result.pr_title,
                            "author": analysis_result.author,
                            "repository": analysis_result.repository,
                            "executive_summary": analysis_result.executive_summary,
                            "risk_level": analysis_result.risk_level.value,
                            "approval_recommendation": analysis_result.approval_recommendation.value,
                            "key_concerns": analysis_result.key_concerns,
                            "security_findings": [f.dict() for f in analysis_result.security_findings],
                            "performance_findings": [f.dict() for f in analysis_result.performance_findings],
                            "best_practice_findings": [f.dict() for f in analysis_result.best_practice_findings],
                            "files_changed": analysis_result.files_changed,
                            "lines_added": analysis_result.lines_added,
                            "lines_deleted": analysis_result.lines_deleted,
                        }
                    )
                ],
                metadata={
                    "pr_url": pr_url,
                    "analyzed_at": analysis_result.analyzed_at.isoformat(),
                    "llm_provider": analysis_result.llm_provider,
                    "llm_model": analysis_result.llm_model,
                }
            )
            
            # Create completed task
            task = A2ATask(
                id=task_id,
                contextId=message.get("contextId", str(uuid.uuid4())),
                status=TaskStatus(
                    state="completed",
                    timestamp=datetime.now(timezone.utc),
                    message=response_msg,
                    progress=1.0
                ),
                artifacts=[artifact],
                history=[response_msg],
                kind="task"
            )
            
            # Return the task as a dict (JSON-RPC handler will wrap it)
            result = task.dict()
            logger.info(f"Returning task result: {result.get('id')}, state: {result['status']['state']}")
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
                timestamp=datetime.now(timezone.utc)
            )
            
            task = A2ATask(
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
            
            return task.dict()
    
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
            
            # Telex webhook expects a message/send JSON-RPC request with full task
            # Include artifacts in the response so Telex can display them
            rpc_request = {
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": result_serialized["status"]["message"]["messageId"],
                        "role": "agent",
                        "parts": result_serialized["status"]["message"]["parts"],
                        "kind": "message",
                        "taskId": result_serialized["id"],
                        "timestamp": result_serialized["status"]["timestamp"]
                    },
                    # Include the full task with artifacts
                    "task": result_serialized
                },
                "id": message_id
            }
            
            logger.info(f"Pushing result to webhook: {webhook_url}")
            
            # Use longer timeout for Telex webhook (they can be slow)
            # Connect: 10s, Read: 60s (Telex processing time)
            timeout = httpx.Timeout(10.0, read=60.0)
            
            async with httpx.AsyncClient(timeout=timeout) as client:
                try:
                    response = await client.post(
                        webhook_url,
                        json=rpc_request,
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
            timestamp=datetime.now(timezone.utc)
        )
        
        task = A2ATask(
            id=task_id,
            contextId=str(uuid.uuid4()),
            status=TaskStatus(
                state="input-required",
                timestamp=datetime.now(timezone.utc),
                message=response_msg
            ),
            artifacts=[],
            history=[response_msg],
            kind="task"
        )
        
        return task.dict()

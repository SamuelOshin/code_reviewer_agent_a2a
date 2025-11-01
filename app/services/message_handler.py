# app/services/message_handler.py

"""Message Handler for Telex A2A Integration

Handles message/send JSON-RPC requests from Telex, extracting the interpreted
parameters and conversation history from the parts array.
"""

import logging
import uuid
import re
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
        
        # Analyze the PR
        try:
            logger.info(f"Analyzing PR: {pr_url}")
            analysis_result = await self.analyzer.analyze_pr(pr_url)
            
            # Format summary
            summary_text = self.formatter.format_for_telex(analysis_result)
            
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
            
            return task.dict()
            
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

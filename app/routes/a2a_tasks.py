# app/routes/a2a_tasks.py

"""A2A Task Handler for Telex Integration

Receives A2A task requests from Telex and other A2A clients,
executes them, and returns A2A-formatted responses matching the Telex spec.
"""

import logging
import uuid
import asyncio
import httpx
from typing import Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse

from app.models.a2a import (
    A2ATaskRequest, A2ATaskResponse, A2ATask, TaskStatus, TaskAcceptedResponse,
    A2AMessage, MessagePart, A2AArtifact, ArtifactPart
)
from app.services.code_analyzer import CodeAnalyzerService
from app.services.github_mcp import GitHubMCPService
from app.services.llm_service import LLMService
from app.utils.formatters import SummaryFormatter
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/a2a", tags=["a2a"])


@router.post("/tasks")
async def handle_a2a_task(request: Request):
    """
    A2A Task Endpoint - Receives task requests from Telex
    
    This endpoint accepts:
    1. JSON-RPC 2.0 format (with message/send method) - Primary format
    2. Simple test requests (for validation bots)
    3. Direct A2ATaskRequest format (legacy)
    
    Args:
        request: FastAPI request object
        
    Returns:
        A2A task response in JSON-RPC 2.0 format with task result
    """
    try:
        body = await request.json()
        
        # Check if it's a JSON-RPC request (primary format)
        if body.get("jsonrpc") == "2.0" and body.get("method") == "message/send":
            logger.info(f"✓ Detected JSON-RPC message/send request - forwarding to RPC handler")
            
            # Get handler from app state and forward to message/send handler
            if hasattr(request.app.state, "jsonrpc_handler"):
                rpc_handler = request.app.state.jsonrpc_handler
                result = await rpc_handler.handle_request(body)
                return JSONResponse(content=result)
            else:
                raise HTTPException(status_code=500, detail="RPC handler not configured")
        
        # Check if it's a simple message request (convert to JSON-RPC format)
        if "message" in body and isinstance(body.get("message"), str):
            logger.info(f"✓ Detected simple message request - converting to JSON-RPC format")
            
            # Convert simple message to proper JSON-RPC message/send format
            jsonrpc_request = {
                "jsonrpc": "2.0",
                "id": body.get("id", str(uuid.uuid4())),
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": str(uuid.uuid4()),
                        "role": "user",
                        "parts": [
                            {
                                "kind": "text",
                                "text": body.get("message")
                            }
                        ],
                        "kind": "message",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    },
                    "configuration": {
                        "blocking": False,
                        "pushNotificationConfig": None  # No webhook for simple requests
                    }
                }
            }
            
            # Forward to RPC handler
            if hasattr(request.app.state, "jsonrpc_handler"):
                rpc_handler = request.app.state.jsonrpc_handler
                result = await rpc_handler.handle_request(jsonrpc_request)
                return JSONResponse(content=result)
            else:
                raise HTTPException(status_code=500, detail="RPC handler not configured")
        
        # Otherwise treat as direct A2ATaskRequest (legacy format)
        task_request = A2ATaskRequest.model_validate(body)
        logger.info(f"Received A2A task: {task_request.task_id} for skill: {task_request.skill}")
        
    except Exception as e:
        logger.error(f"Failed to parse A2A task request: {e}")
        raise HTTPException(status_code=422, detail=f"Invalid request format: {str(e)}")
    
    # Generate context ID for this conversation
    context_id = str(uuid.uuid4())
    
    try:
        # Route based on skill name
        if task_request.skill == "analyze_pr":
            return await _handle_analyze_pr_task(task_request, context_id)
        elif task_request.skill == "get_analysis_status":
            return await _handle_status_task(task_request, context_id)
        else:
            logger.warning(f"Unknown skill requested: {task_request.skill}")
            
            # Create error message
            error_msg = A2AMessage(
                messageId=str(uuid.uuid4()),
                role="agent",
                parts=[
                    MessagePart(
                        kind="text",
                        text=f"Unknown skill: {task_request.skill}. Available skills: analyze_pr, get_analysis_status"
                    )
                ],
                kind="message",
                taskId=task_request.task_id,
                timestamp=datetime.now(timezone.utc)
            )
            
            # Create failed task
            task = A2ATask(
                id=task_request.task_id,
                contextId=context_id,
                status=TaskStatus(
                    state="failed",
                    timestamp=datetime.now(timezone.utc),
                    message=error_msg
                ),
                artifacts=[],
                history=[error_msg],
                kind="task"
            )
            
            return A2ATaskResponse(
                jsonrpc="2.0",
                id=task_request.task_id,
                result=task,
                error={"code": -32601, "message": f"Skill '{task_request.skill}' not supported"}
            )
    
    except Exception as e:
        logger.error(f"Error processing A2A task {task_request.task_id}: {e}")
        
        # Create error message
        error_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text=f"Task execution failed: {str(e)}"
                )
            ],
            kind="message",
            taskId=task_request.task_id,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Create failed task
        task = A2ATask(
            id=task_request.task_id,
            contextId=context_id,
            status=TaskStatus(
                state="failed",
                timestamp=datetime.now(timezone.utc),
                message=error_msg
            ),
            artifacts=[],
            history=[error_msg],
            kind="task"
        )
        
        return A2ATaskResponse(
            jsonrpc="2.0",
            id=task_request.task_id,
            result=task,
            error={"code": -32603, "message": str(e)}
        )


async def _handle_analyze_pr_task(task_request: A2ATaskRequest, context_id: str) -> A2ATaskResponse:
    """
    Handle analyze_pr skill from Telex
    
    Args:
        task_request: A2A task request
        context_id: Generated context/session ID
        
    Returns:
        A2A response with code review analysis in Telex format
    """
    # Extract parameters
    pr_url = task_request.parameters.get("pr_url")
    focus_areas = task_request.parameters.get("focus_areas", ["security", "performance", "best_practices"])
    
    if not pr_url:
        error_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text="Missing required parameter: pr_url"
                )
            ],
            kind="message",
            taskId=task_request.task_id,
            timestamp=datetime.now(timezone.utc)
        )
        
        task = A2ATask(
            id=task_request.task_id,
            contextId=context_id,
            status=TaskStatus(
                state="failed",
                timestamp=datetime.now(timezone.utc),
                message=error_msg
            ),
            artifacts=[],
            history=[error_msg],
            kind="task"
        )
        
        return A2ATaskResponse(
            jsonrpc="2.0",
            id=task_request.task_id,
            result=task,
            error={"code": -32602, "message": "pr_url parameter is required"}
        )
    
    try:
        # Initialize analyzer
        analyzer = CodeAnalyzerService()
        
        # Perform analysis
        logger.info(f"A2A task {task_request.task_id}: Analyzing PR {pr_url}")
        analysis_result = await analyzer.analyze_pr(pr_url)
        
        # Format summary
        formatter = SummaryFormatter()
        summary_text = formatter.format_for_telex(analysis_result)
        
        # Create summary message
        summary_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text=f"✅ Analysis complete for PR #{analysis_result.pr_number}!\n\n"
                         f"**Risk Level:** {analysis_result.risk_level.value}\n"
                         f"**Recommendation:** {analysis_result.approval_recommendation.value}\n\n"
                         f"Found {len(analysis_result.security_findings)} security issues, "
                         f"{len(analysis_result.performance_findings)} performance issues, "
                         f"and {len(analysis_result.best_practice_findings)} best practice violations."
                )
            ],
            kind="message",
            taskId=task_request.task_id,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Build artifacts
        artifacts = [
            # Markdown summary artifact
            A2AArtifact(
                artifactId=str(uuid.uuid4()),
                name="code_review_summary",
                parts=[
                    ArtifactPart(
                        kind="markdown",
                        text=summary_text
                    )
                ],
                metadata={
                    "pr_url": pr_url,
                    "risk_level": analysis_result.risk_level.value,
                    "approval": analysis_result.approval_recommendation.value
                }
            ),
            # JSON data artifact
            A2AArtifact(
                artifactId=str(uuid.uuid4()),
                name="analysis_data",
                parts=[
                    ArtifactPart(
                        kind="json",
                        data={
                            "pr_number": analysis_result.pr_number,
                            "repository": analysis_result.repository,
                            "author": analysis_result.author,
                            "pr_title": analysis_result.pr_title,
                            "risk_level": analysis_result.risk_level.value,
                            "approval_recommendation": analysis_result.approval_recommendation.value,
                            "security_issues": len(analysis_result.security_findings),
                            "performance_issues": len(analysis_result.performance_findings),
                            "best_practice_issues": len(analysis_result.best_practice_findings),
                            "files_changed": analysis_result.files_changed,
                            "lines_added": analysis_result.lines_added,
                            "lines_deleted": analysis_result.lines_deleted,
                            "analyzed_at": analysis_result.analyzed_at.isoformat(),
                            "llm_model": analysis_result.llm_model
                        }
                    )
                ]
            )
        ]
        
        # Build task result
        task = A2ATask(
            id=task_request.task_id,
            contextId=context_id,
            status=TaskStatus(
                state="completed",
                timestamp=datetime.now(timezone.utc),
                message=summary_msg
            ),
            artifacts=artifacts,
            history=[summary_msg],
            kind="task"
        )
        
        # Build JSON-RPC response
        response = A2ATaskResponse(
            jsonrpc="2.0",
            id=task_request.task_id,
            result=task
        )
        
        logger.info(f"A2A task {task_request.task_id}: Analysis completed successfully")
        return response
        
    except Exception as e:
        logger.error(f"A2A task {task_request.task_id}: Analysis failed - {e}")
        
        error_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text=f"❌ Analysis failed: {str(e)}"
                )
            ],
            kind="message",
            taskId=task_request.task_id,
            timestamp=datetime.now(timezone.utc)
        )
        
        task = A2ATask(
            id=task_request.task_id,
            contextId=context_id,
            status=TaskStatus(
                state="failed",
                timestamp=datetime.now(timezone.utc),
                message=error_msg
            ),
            artifacts=[],
            history=[error_msg],
            kind="task"
        )
        
        return A2ATaskResponse(
            jsonrpc="2.0",
            id=task_request.task_id,
            result=task,
            error={"code": -32603, "message": str(e)}
        )


async def _handle_status_task(task_request: A2ATaskRequest, context_id: str) -> A2ATaskResponse:
    """
    Handle get_analysis_status skill
    
    Args:
        task_request: A2A task request
        context_id: Generated context/session ID
        
    Returns:
        A2A response with status (placeholder)
    """
    analysis_id = task_request.parameters.get("analysis_id")
    
    if not analysis_id:
        error_msg = A2AMessage(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[
                MessagePart(
                    kind="text",
                    text="Missing required parameter: analysis_id"
                )
            ],
            kind="message",
            taskId=task_request.task_id,
            timestamp=datetime.now(timezone.utc)
        )
        
        task = A2ATask(
            id=task_request.task_id,
            contextId=context_id,
            status=TaskStatus(
                state="failed",
                timestamp=datetime.now(timezone.utc),
                message=error_msg
            ),
            artifacts=[],
            history=[error_msg],
            kind="task"
        )
        
        return A2ATaskResponse(
            jsonrpc="2.0",
            id=task_request.task_id,
            result=task,
            error={"code": -32602, "message": "analysis_id parameter is required"}
        )
    
    # TODO: Implement actual status tracking
    status_msg = A2AMessage(
        messageId=str(uuid.uuid4()),
        role="agent",
        parts=[
            MessagePart(
                kind="text",
                text="Analysis tracking not yet implemented. This is a placeholder response."
            )
        ],
        kind="message",
        taskId=task_request.task_id,
        timestamp=datetime.now(timezone.utc)
    )
    
    artifact = A2AArtifact(
        artifactId=str(uuid.uuid4()),
        name="status_data",
        parts=[
            ArtifactPart(
                kind="json",
                data={
                    "analysis_id": analysis_id,
                    "status": "unknown",
                    "message": "Analysis tracking feature coming soon"
                }
            )
        ]
    )
    
    task = A2ATask(
        id=task_request.task_id,
        contextId=context_id,
        status=TaskStatus(
            state="completed",
            timestamp=datetime.now(timezone.utc),
            message=status_msg
        ),
        artifacts=[artifact],
        history=[status_msg],
        kind="task"
    )
    
    return A2ATaskResponse(
        jsonrpc="2.0",
        id=task_request.task_id,
        result=task
    )


@router.post("/webhooks/{hook_id}")
async def handle_telex_webhook(
    hook_id: str,
    task_request: A2ATaskRequest,
    background_tasks: BackgroundTasks
):
    """
    Telex Webhook Endpoint - Receives async task requests from Telex
    
    This endpoint matches Telex's webhook pattern:
    POST /a2a/webhooks/{hookId}
    
    Flow:
    1. Telex sends task to this webhook
    2. We return "task accepted" immediately (< 5 seconds)
    3. We process task in background
    4. We send results to Telex callback URL when done
    
    Args:
        hook_id: Webhook ID from Telex
        task_request: A2A task request with callback_url
        background_tasks: FastAPI background tasks
        
    Returns:
        TaskAcceptedResponse - immediate acknowledgment
    """
    logger.info(f"Received Telex webhook task: {task_request.task_id} (hook: {hook_id})")
    
    # Validate we have a callback URL
    callback_url = task_request.callback_url
    if not callback_url:
        logger.warning(f"No callback_url provided for task {task_request.task_id}")
        raise HTTPException(
            status_code=400,
            detail="callback_url is required for webhook requests"
        )
    
    # Add background task to process asynchronously
    background_tasks.add_task(
        _process_task_and_callback,
        task_request,
        callback_url,
        hook_id
    )
    
    # Return immediate acceptance
    logger.info(f"Task {task_request.task_id} accepted, processing in background")
    return TaskAcceptedResponse(
        task_id=task_request.task_id,
        status="accepted",
        message=f"Task accepted and will be processed. Results will be sent to callback URL."
    )


async def _process_task_and_callback(
    task_request: A2ATaskRequest,
    callback_url: str,
    hook_id: str
):
    """
    Process task in background and send results to Telex callback URL
    
    Args:
        task_request: A2A task request
        callback_url: Telex callback URL
        hook_id: Webhook ID
    """
    logger.info(f"Background processing task {task_request.task_id}")
    
    try:
        # Generate context ID
        context_id = str(uuid.uuid4())
        
        # Process the task (reuse existing handlers)
        if task_request.skill == "analyze_pr":
            result = await _handle_analyze_pr_task(task_request, context_id)
        elif task_request.skill == "get_analysis_status":
            result = await _handle_status_task(task_request, context_id)
        else:
            # Unknown skill error
            error_msg = A2AMessage(
                messageId=str(uuid.uuid4()),
                role="agent",
                parts=[
                    MessagePart(
                        kind="text",
                        text=f"Unknown skill: {task_request.skill}"
                    )
                ],
                kind="message",
                taskId=task_request.task_id,
                timestamp=datetime.now(timezone.utc)
            )
            
            task = A2ATask(
                id=task_request.task_id,
                contextId=context_id,
                status=TaskStatus(
                    state="failed",
                    timestamp=datetime.now(timezone.utc),
                    message=error_msg
                ),
                artifacts=[],
                history=[error_msg],
                kind="task"
            )
            
            result = A2ATaskResponse(
                jsonrpc="2.0",
                id=task_request.task_id,
                result=task,
                error={"code": -32601, "message": f"Skill '{task_request.skill}' not supported"}
            )
        
        # Send result to Telex callback URL
        async with httpx.AsyncClient(timeout=30.0) as client:
            logger.info(f"Sending task {task_request.task_id} result to {callback_url}")
            response = await client.post(
                callback_url,
                json=result.model_dump(mode="json"),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully sent task {task_request.task_id} result to Telex")
            else:
                logger.error(
                    f"Failed to send task {task_request.task_id} result. "
                    f"Status: {response.status_code}, Response: {response.text}"
                )
    
    except Exception as e:
        logger.error(f"Error processing background task {task_request.task_id}: {e}", exc_info=True)
        
        # Try to send error to callback
        try:
            error_msg = A2AMessage(
                messageId=str(uuid.uuid4()),
                role="agent",
                parts=[
                    MessagePart(
                        kind="text",
                        text=f"Task processing failed: {str(e)}"
                    )
                ],
                kind="message",
                taskId=task_request.task_id,
                timestamp=datetime.now(timezone.utc)
            )
            
            task = A2ATask(
                id=task_request.task_id,
                contextId=str(uuid.uuid4()),
                status=TaskStatus(
                    state="failed",
                    timestamp=datetime.now(timezone.utc),
                    message=error_msg
                ),
                artifacts=[],
                history=[error_msg],
                kind="task"
            )
            
            error_result = A2ATaskResponse(
                jsonrpc="2.0",
                id=task_request.task_id,
                result=task,
                error={"code": -32603, "message": str(e)}
            )
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                await client.post(
                    callback_url,
                    json=error_result.model_dump(mode="json"),
                    headers={"Content-Type": "application/json"}
                )
        except Exception as callback_error:
            logger.error(f"Failed to send error to callback: {callback_error}")

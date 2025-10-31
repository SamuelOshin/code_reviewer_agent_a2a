# app/routes/a2a_tasks.py

"""A2A Task Handler for Telex Integration

Receives A2A task requests from Telex and other A2A clients,
executes them, and returns A2A-formatted responses.
"""

import logging
from typing import Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.models.a2a import A2ATaskRequest, A2ATaskResponse, A2AMessage, A2AArtifact, ArtifactPart
from app.services.code_analyzer import CodeAnalyzerService
from app.services.github_mcp import GitHubMCPService
from app.services.llm_service import LLMService
from app.utils.formatters import SummaryFormatter
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/a2a", tags=["a2a"])


@router.post("/tasks")
async def handle_a2a_task(task_request: A2ATaskRequest):
    """
    A2A Task Endpoint - Receives task requests from Telex
    
    This endpoint allows Telex (or other A2A clients) to send task requests
    to this agent. The agent processes the task and returns an A2A response.
    
    Args:
        task_request: A2A task request with skill name and parameters
        
    Returns:
        A2A task response with artifacts
    """
    logger.info(f"Received A2A task: {task_request.task_id} for skill: {task_request.skill}")
    
    try:
        # Route based on skill name
        if task_request.skill == "analyze_pr":
            return await _handle_analyze_pr_task(task_request)
        elif task_request.skill == "get_analysis_status":
            return await _handle_status_task(task_request)
        else:
            logger.warning(f"Unknown skill requested: {task_request.skill}")
            return A2ATaskResponse(
                task_id=task_request.task_id,
                status="failed",
                messages=[
                    A2AMessage(
                        role="agent",
                        content=f"Unknown skill: {task_request.skill}. Available skills: analyze_pr, get_analysis_status"
                    )
                ],
                error=f"Skill '{task_request.skill}' not supported"
            )
    
    except Exception as e:
        logger.error(f"Error processing A2A task {task_request.task_id}: {e}")
        return A2ATaskResponse(
            task_id=task_request.task_id,
            status="failed",
            messages=[
                A2AMessage(
                    role="agent",
                    content=f"Task execution failed: {str(e)}"
                )
            ],
            error=str(e)
        )


async def _handle_analyze_pr_task(task_request: A2ATaskRequest) -> A2ATaskResponse:
    """
    Handle analyze_pr skill from Telex
    
    Args:
        task_request: A2A task request
        
    Returns:
        A2A response with code review analysis
    """
    # Extract parameters
    pr_url = task_request.parameters.get("pr_url")
    focus_areas = task_request.parameters.get("focus_areas", ["security", "performance", "best_practices"])
    
    if not pr_url:
        return A2ATaskResponse(
            task_id=task_request.task_id,
            status="failed",
            messages=[
                A2AMessage(
                    role="agent",
                    content="Missing required parameter: pr_url"
                )
            ],
            error="pr_url parameter is required"
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
        
        # Build A2A artifact
        artifact = A2AArtifact(
            parts=[
                ArtifactPart(
                    type="markdown",
                    text=summary_text
                ),
                ArtifactPart(
                    type="json",
                    data={
                        "pr_number": analysis_result.pr_number,
                        "repository": analysis_result.repository,
                        "author": analysis_result.author,
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
            ],
            title=f"Code Review: {analysis_result.pr_title}",
            metadata={
                "pr_url": pr_url,
                "risk_level": analysis_result.risk_level.value,
                "approval": analysis_result.approval_recommendation.value
            }
        )
        
        # Build success response
        response = A2ATaskResponse(
            task_id=task_request.task_id,
            status="completed",
            messages=[
                A2AMessage(
                    role="agent",
                    content=f"Successfully analyzed PR #{analysis_result.pr_number}. Risk level: {analysis_result.risk_level.value}. Recommendation: {analysis_result.approval_recommendation.value}"
                )
            ],
            artifacts=[artifact]
        )
        
        logger.info(f"A2A task {task_request.task_id}: Analysis completed successfully")
        return response
        
    except Exception as e:
        logger.error(f"A2A task {task_request.task_id}: Analysis failed - {e}")
        return A2ATaskResponse(
            task_id=task_request.task_id,
            status="failed",
            messages=[
                A2AMessage(
                    role="agent",
                    content=f"Analysis failed: {str(e)}"
                )
            ],
            error=str(e)
        )


async def _handle_status_task(task_request: A2ATaskRequest) -> A2ATaskResponse:
    """
    Handle get_analysis_status skill
    
    Args:
        task_request: A2A task request
        
    Returns:
        A2A response with status (placeholder)
    """
    analysis_id = task_request.parameters.get("analysis_id")
    
    if not analysis_id:
        return A2ATaskResponse(
            task_id=task_request.task_id,
            status="failed",
            messages=[
                A2AMessage(
                    role="agent",
                    content="Missing required parameter: analysis_id"
                )
            ],
            error="analysis_id parameter is required"
        )
    
    # TODO: Implement actual status tracking
    return A2ATaskResponse(
        task_id=task_request.task_id,
        status="completed",
        messages=[
            A2AMessage(
                role="agent",
                content="Analysis tracking not yet implemented. This is a placeholder response."
            )
        ],
        artifacts=[
            A2AArtifact(
                parts=[
                    ArtifactPart(
                        type="json",
                        data={
                            "analysis_id": analysis_id,
                            "status": "unknown",
                            "message": "Analysis tracking feature coming soon"
                        }
                    )
                ]
            )
        ]
    )

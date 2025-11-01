# app/routes/health.py

"""Health Check Endpoint

Provides health status for the API and its dependencies.
"""

from typing import Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter
from fastapi.responses import JSONResponse
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint
    
    Returns:
        Health status information
    """
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "code_review_agent",
        "version": "1.0.0",
        "checks": {
            "api": "ok"
        }
    }
    
    # Check if critical config is present
    if not settings.GITHUB_TOKEN:
        health_status["checks"]["github"] = "warning - no token configured"
    else:
        health_status["checks"]["github"] = "ok"
    
    if not settings.LLM_PROVIDER or not settings.LLM_MODEL:
        health_status["checks"]["llm"] = "error - not configured"
        health_status["status"] = "degraded"
    else:
        health_status["checks"]["llm"] = f"ok - {settings.LLM_PROVIDER}"
    
    if not settings.TELEX_WEBHOOK_URL:
        health_status["checks"]["telex"] = "warning - not configured"
    else:
        health_status["checks"]["telex"] = "ok"
    
    # Determine overall status
    if any("error" in str(v) for v in health_status["checks"].values()):
        health_status["status"] = "unhealthy"
        status_code = 503
    elif any("warning" in str(v) for v in health_status["checks"].values()):
        health_status["status"] = "degraded"
        status_code = 200
    else:
        status_code = 200
    
    return JSONResponse(content=health_status, status_code=status_code)


@router.get("/ready")
async def readiness_check() -> Dict[str, Any]:
    """
    Readiness check endpoint (Kubernetes-style)
    
    Returns:
        Readiness status
    """
    # Check if service is ready to accept requests
    ready = bool(settings.GITHUB_TOKEN and settings.LLM_PROVIDER and settings.LLM_MODEL)
    
    return JSONResponse(
        content={
            "ready": ready,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        status_code=200 if ready else 503
    )


@router.get("/live")
async def liveness_check() -> Dict[str, Any]:
    """
    Liveness check endpoint (Kubernetes-style)
    
    Returns:
        Liveness status
    """
    return JSONResponse(
        content={
            "alive": True,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        status_code=200
    )
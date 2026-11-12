# app/main.py

"""FastAPI Application Entry Point

Main FastAPI application with:
- Router registration
- JSON-RPC method registration
- CORS configuration
- Startup/shutdown events
- Agent card serving
"""

import json
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import setup_logging
from app.services.jsonrpc_handler import JSONRPCHandler
from app.services.code_analyzer import CodeAnalyzerService
from app.services.message_handler import MessageHandler

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Load agent card
AGENT_CARD_PATH = Path(__file__).parent.parent / "config" / "agent_card.json"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager
    
    Handles startup and shutdown events
    """
    # Startup
    logger.info("=" * 60)
    logger.info("Starting Code Review Agent")
    logger.info("=" * 60)
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"LLM Provider: {settings.LLM_PROVIDER} ({settings.LLM_MODEL})")
    logger.info(f"GitHub Token: {'✓ Configured' if settings.GITHUB_TOKEN else '✗ Not configured'}")
    
    # Initialize JSON-RPC handler
    jsonrpc_handler = JSONRPCHandler()
    
    # Register JSON-RPC methods
    await register_rpc_methods(jsonrpc_handler)
    
    # Store in app state
    app.state.jsonrpc_handler = jsonrpc_handler
    app.state.code_analyzer = CodeAnalyzerService()
    app.state.message_handler = MessageHandler()
    
    logger.info(f"Registered {len(jsonrpc_handler.list_methods())} JSON-RPC methods")
    logger.info("Application startup complete")
    logger.info("=" * 60)
    
    yield
    
    # Shutdown
    logger.info("Shutting down Code Review Agent...")
    logger.info("Cleanup complete")


# Create FastAPI app
app = FastAPI(
    title="Code Review Agent",
    description="AI-powered code review agent for GitHub Pull Requests",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on your needs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# JSON-RPC Method Handlers
# ============================================================================

async def handle_analyze_pr(pr_url: str, focus_areas: list = None) -> Dict[str, Any]:
    """
    JSON-RPC method: analyze_pr
    
    Analyzes a GitHub Pull Request
    """
    logger.info(f"RPC: analyze_pr called for {pr_url}")
    
    # Get services from app state
    analyzer: CodeAnalyzerService = app.state.code_analyzer
    
    # Run analysis
    result = await analyzer.analyze_pr(pr_url)
    
    # Build response
    return {
        "analysis_id": f"analysis-{result.pr_number}-{int(result.analyzed_at.timestamp())}",
        "pr_number": result.pr_number,
        "pr_url": pr_url,  # Use the input pr_url
        "pr_title": result.pr_title,
        "author": result.author,
        "repository": result.repository,
        "executive_summary": result.executive_summary,
        "risk_level": result.risk_level.value,
        "approval_recommendation": result.approval_recommendation.value,
        "security_issues_count": len(result.security_findings),
        "performance_issues_count": len(result.performance_findings),
        "best_practice_issues_count": len(result.best_practice_findings),
        "files_changed": result.files_changed,
        "lines_added": result.lines_added,
        "lines_deleted": result.lines_deleted,
        "key_concerns": result.key_concerns,
        "analyzed_at": result.analyzed_at.isoformat(),
        "analysis_duration_seconds": result.analysis_duration_seconds,
        "llm_provider": result.llm_provider,
        "llm_model": result.llm_model
    }


async def handle_introspect() -> Dict[str, Any]:
    """
    JSON-RPC method: introspect
    
    Returns information about available methods
    """
    handler: JSONRPCHandler = app.state.jsonrpc_handler
    
    return {
        "methods": handler.list_methods(),
        "count": len(handler.list_methods()),
        "version": "2.0",
        "agent_name": "Code Review Agent",
        "agent_version": "1.0.0"
    }


async def handle_message_send(message: Dict[str, Any], configuration: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    JSON-RPC method: message/send
    
    Handles incoming A2A messages with this format:
    - parts[0]: Text part with system's interpretation/extracted parameters
    - parts[1]: Data part with last 20 messages from conversation history
    
    Args:
        message: A2A message object
        configuration: Optional A2A message/send configuration (blocking, pushNotificationConfig)
        
    Returns:
        A2A Task response
    """
    logger.info(f"RPC: message/send called")
    
    message_handler: MessageHandler = app.state.message_handler
    result = await message_handler.handle_message_send(message, configuration)
    
    return result


async def register_rpc_methods(handler: JSONRPCHandler):
    """
    Register all JSON-RPC methods
    
    Args:
        handler: JSONRPCHandler instance
    """
    handler.register_method("analyze_pr", handle_analyze_pr)
    handler.register_method("introspect", handle_introspect)
    handler.register_method("message/send", handle_message_send)


# ============================================================================
# Agent Card Endpoint
# ============================================================================

@app.get("/.well-known/agent.json")
async def get_agent_card():
    """
    Serve the A2A agent card
    
    Returns:
        Agent card JSON
    """
    try:
        with open(AGENT_CARD_PATH, "r") as f:
            agent_card = json.load(f)
        
        return JSONResponse(content=agent_card)
    except Exception as e:
        logger.error(f"Failed to load agent card: {e}")
        return JSONResponse(
            content={"error": "Failed to load agent card"},
            status_code=500
        )


# ============================================================================
# Root Endpoint
# ============================================================================

@app.get("/")
async def root():
    """
    Root endpoint with basic info
    
    Returns:
        API information
    """
    return {
        "name": "Code Review Agent",
        "version": "1.0.0",
        "description": "AI-powered code review agent for GitHub Pull Requests",
        "endpoints": {
            "rpc": "/rpc",
            "a2a_tasks": "/a2a/tasks",
            "webhooks": "/webhooks/github",
            "health": "/health",
            "agent_card": "/.well-known/agent.json",
            "docs": "/docs" if settings.ENVIRONMENT == "development" else None
        },
        "protocols": {
            "jsonrpc": "2.0",
            "a2a": "supported"
        },
        "status": "running"
    }


# ============================================================================
# Include Routers
# ============================================================================

from app.routes import health, webhooks, jsonrpc, a2a_tasks

app.include_router(health.router)
app.include_router(webhooks.router)
app.include_router(jsonrpc.router)
app.include_router(a2a_tasks.router)


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.ENVIRONMENT == "development",
        log_level=settings.LOG_LEVEL.lower()
    )
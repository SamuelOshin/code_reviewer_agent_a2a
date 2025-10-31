# app/routes/webhooks.py

"""GitHub Webhook Handlers

Handles incoming GitHub webhook events, specifically pull_request events.
Includes HMAC signature verification for security.
"""

from typing import Dict, Any
import hashlib
import hmac
import logging
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks, Header
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.services.code_analyzer import CodeAnalyzerService
from app.services.telex_client import TelexClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    """
    Verify GitHub webhook signature using HMAC
    
    Args:
        payload_body: Raw request body
        signature_header: X-Hub-Signature-256 header value
        
    Returns:
        True if signature is valid
    """
    if not settings.GITHUB_WEBHOOK_SECRET:
        logger.warning("GITHUB_WEBHOOK_SECRET not set - skipping signature verification")
        return True
    
    if not signature_header:
        return False
    
    # GitHub sends signature as "sha256=<hex_digest>"
    try:
        hash_algorithm, signature = signature_header.split("=", 1)
    except ValueError:
        return False
    
    if hash_algorithm != "sha256":
        return False
    
    # Calculate expected signature
    mac = hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = mac.hexdigest()
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(signature, expected_signature)


@router.post("/github")
async def handle_github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None)
):
    """
    Handle GitHub webhook events
    
    Args:
        request: FastAPI request object
        background_tasks: FastAPI background tasks
        x_hub_signature_256: GitHub signature header
        x_github_event: GitHub event type header
        
    Returns:
        JSON response with status
    """
    try:
        # Read raw body for signature verification
        body = await request.body()
        
        # Verify signature
        if not verify_github_signature(body, x_hub_signature_256):
            logger.warning("Invalid GitHub webhook signature")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse JSON payload
        try:
            payload = await request.json()
        except Exception as e:
            logger.error(f"Failed to parse webhook payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Handle different event types
        if x_github_event == "pull_request":
            return await handle_pull_request_event(payload, background_tasks)
        
        elif x_github_event == "ping":
            logger.info("Received ping event from GitHub")
            return JSONResponse({
                "status": "ok",
                "message": "Webhook is working!"
            })
        
        else:
            logger.info(f"Ignoring event type: {x_github_event}")
            return JSONResponse({
                "status": "ignored",
                "message": f"Event type '{x_github_event}' not handled"
            })
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in webhook handler: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def handle_pull_request_event(
    payload: Dict[str, Any],
    background_tasks: BackgroundTasks
) -> JSONResponse:
    """
    Handle pull_request events
    
    Args:
        payload: Webhook payload
        background_tasks: FastAPI background tasks
        
    Returns:
        JSON response
    """
    action = payload.get("action")
    pull_request = payload.get("pull_request", {})
    
    logger.info(f"Received pull_request event: action={action}, pr_number={pull_request.get('number')}")
    
    # Only analyze on specific actions
    trigger_actions = ["opened", "synchronize", "reopened"]
    
    if action not in trigger_actions:
        return JSONResponse({
            "status": "ignored",
            "message": f"Action '{action}' does not trigger analysis"
        })
    
    # Extract PR URL
    pr_url = pull_request.get("html_url")
    pr_number = pull_request.get("number")
    
    if not pr_url:
        logger.error("No PR URL in webhook payload")
        raise HTTPException(status_code=400, detail="Missing PR URL in payload")
    
    # Queue analysis as background task
    background_tasks.add_task(
        analyze_pr_background,
        pr_url=pr_url,
        pr_number=pr_number
    )
    
    return JSONResponse({
        "status": "queued",
        "message": f"Analysis queued for PR #{pr_number}",
        "pr_url": pr_url
    })


async def analyze_pr_background(pr_url: str, pr_number: int):
    """
    Background task to analyze PR and send to Telex
    
    Args:
        pr_url: PR URL
        pr_number: PR number
    """
    try:
        logger.info(f"Starting background analysis for PR #{pr_number}")
        
        # Initialize services
        analyzer = CodeAnalyzerService()
        telex_client = TelexClient()
        
        # Run analysis
        analysis_result = await analyzer.analyze_pr(pr_url)
        
        # Send to Telex
        try:
            await telex_client.send_review_summary(analysis_result)
            logger.info(f"Successfully sent analysis for PR #{pr_number} to Telex")
        except Exception as e:
            logger.error(f"Failed to send to Telex for PR #{pr_number}: {e}")
            # Continue even if Telex fails
        
        logger.info(f"Background analysis completed for PR #{pr_number}")
        
    except Exception as e:
        logger.error(f"Background analysis failed for PR #{pr_number}: {e}")
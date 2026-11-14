# app/routes/a2a_tasks.py

"""A2A Task Endpoint

Receives A2A requests from any A2A client and forwards them to the JSON-RPC
handler (message/send). Plain `{"message": "<text>"}` bodies are converted to a
message/send request for simple clients.
"""

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from app.core.auth import require_api_key
from app.core.errors import new_error_id

logger = logging.getLogger(__name__)

# Every /a2a/* route needs the API key (P1-07): tasks run reviews with GITHUB_TOKEN
router = APIRouter(prefix="/a2a", tags=["a2a"], dependencies=[Depends(require_api_key)])


@router.post("/tasks")
async def handle_a2a_task(request: Request):
    """
    A2A task endpoint

    Accepts:
    1. JSON-RPC 2.0 requests with method message/send
    2. Simple requests of the form {"message": "<text>"}, converted to message/send

    Args:
        request: FastAPI request object

    Returns:
        JSON-RPC 2.0 response with the A2A task result
    """
    try:
        body = await request.json()
    except Exception as e:
        error_id = new_error_id()
        logger.error(f"Failed to parse A2A task request [error_id={error_id}]: {type(e).__name__}")
        raise HTTPException(status_code=422, detail=f"Invalid request format (error id: {error_id})") from None

    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Invalid request format: expected a JSON object")

    if body.get("jsonrpc") == "2.0" and body.get("method") == "message/send":
        logger.info("Detected JSON-RPC message/send request, forwarding to RPC handler")
        jsonrpc_request = body
    elif isinstance(body.get("message"), str):
        logger.info("Detected simple message request, converting to JSON-RPC message/send")
        jsonrpc_request = {
            "jsonrpc": "2.0",
            "id": body.get("id", str(uuid.uuid4())),
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": str(uuid.uuid4()),
                    "role": "user",
                    "parts": [{"kind": "text", "text": body["message"]}],
                    "kind": "message",
                    "timestamp": datetime.now(UTC).isoformat()
                },
                "configuration": {
                    "blocking": False,
                    "pushNotificationConfig": None  # No push webhook for simple requests
                }
            }
        }
    else:
        raise HTTPException(
            status_code=422,
            detail="Invalid request format: expected JSON-RPC message/send or {\"message\": \"<text>\"}"
        )

    rpc_handler = getattr(request.app.state, "jsonrpc_handler", None)
    if rpc_handler is None:
        raise HTTPException(status_code=500, detail="RPC handler not configured")

    result = await rpc_handler.handle_request(jsonrpc_request)
    if result is None:
        # A JSON-RPC message/send with no "id" is a notification: no reply (P1-23)
        return Response(status_code=204)
    return JSONResponse(content=result)

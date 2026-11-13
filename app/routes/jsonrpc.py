# app/routes/jsonrpc.py

"""JSON-RPC 2.0 Endpoint

Handles JSON-RPC requests for code analysis operations.
Methods are registered in app/main.py during startup.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.core.auth import require_api_key
from app.core.config import settings
from app.core.errors import new_error_id

logger = logging.getLogger(__name__)

# Every call needs the API key (P1-07): methods run reviews with GITHUB_TOKEN
router = APIRouter(prefix="/rpc", tags=["jsonrpc"], dependencies=[Depends(require_api_key)])


@router.post("")
async def jsonrpc_endpoint(request: Request):
    """
    JSON-RPC 2.0 Endpoint
    
    Accepts JSON-RPC 2.0 requests and routes to registered handlers.
    Supports both single requests and batch requests.
    
    Args:
        request: FastAPI request object
        
    Returns:
        JSON-RPC response
    """
    try:
        # Get JSON-RPC handler from app state
        if not hasattr(request.app.state, "jsonrpc_handler"):
            logger.error("JSONRPCHandler not initialized in app state")
            raise HTTPException(status_code=500, detail="RPC handler not configured")
        
        rpc_handler = request.app.state.jsonrpc_handler
        
        # Parse request body
        try:
            body = await request.json()
        except Exception as e:
            error_id = new_error_id()
            logger.error(f"Failed to parse JSON-RPC request body [error_id={error_id}]: {e}")
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error",
                        "data": {"error_id": error_id}
                    },
                    "id": None
                },
                status_code=200  # JSON-RPC errors still return 200
            )
        
        # Handle batch requests
        if isinstance(body, list):
            # JSON-RPC 2.0: an empty array is an Invalid Request, not an empty batch
            if not body:
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {"code": -32600, "message": "Invalid Request"},
                        "id": None
                    },
                    status_code=200
                )
            # Each call can start a full review, so cap the batch (P1-07)
            if len(body) > settings.JSONRPC_MAX_BATCH_SIZE:
                logger.warning(f"Rejected JSON-RPC batch of {len(body)} calls")
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": (
                                f"Batch too large: at most {settings.JSONRPC_MAX_BATCH_SIZE} calls"
                            ),
                        },
                        "id": None
                    },
                    status_code=200
                )
            logger.info(f"Processing JSON-RPC batch request with {len(body)} calls")
            responses = await rpc_handler.handle_batch(body)
            return JSONResponse(content=responses)
        
        # Handle single request
        logger.info(f"Processing JSON-RPC request: {body.get('method')}")
        response = await rpc_handler.handle_request(body)
        return JSONResponse(content=response)
    
    except HTTPException:
        raise
    except Exception as e:
        error_id = new_error_id()
        logger.error(f"Unexpected error in JSON-RPC endpoint [error_id={error_id}]: {e}", exc_info=True)
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": {"error_id": error_id}
                },
                "id": None
            },
            status_code=200
        )
# app/routes/jsonrpc.py

"""JSON-RPC 2.0 Endpoint

Handles JSON-RPC requests for code analysis operations.
Methods are registered in app/main.py during startup.
"""

from typing import Dict, Any
import logging
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rpc", tags=["jsonrpc"])


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
            logger.error(f"Failed to parse JSON-RPC request body: {e}")
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error",
                        "data": str(e)
                    },
                    "id": None
                },
                status_code=200  # JSON-RPC errors still return 200
            )
        
        # Handle batch requests
        if isinstance(body, list):
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
        logger.error(f"Unexpected error in JSON-RPC endpoint: {e}")
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                },
                "id": None
            },
            status_code=200
        )
# app/services/jsonrpc_handler.py

"""JSON-RPC 2.0 Request Handler

Handles JSON-RPC method registration and request processing.
Supports async handlers and proper error handling per JSON-RPC 2.0 spec.
"""

import asyncio
import logging
import weakref
from collections.abc import Awaitable, Callable
from typing import Any

from app.core.errors import ClientInputError, RequestTimeoutError, new_error_id
from app.models.jsonrpc import JSONRPCError, JSONRPCErrorCode, JSONRPCRequest, JSONRPCResponse

logger = logging.getLogger(__name__)

# How many batch calls run at the same time, across all batches (P1-18, P1-20). A batch
# used to run its calls one after another, so 100 blocking message/send calls could hold the request
# for 100 x A2A_BLOCKING_TIMEOUT_SECONDS. Running them concurrently, a few at a time,
# bounds that to ceil(n / limit) x the timeout without letting one batch start 100
# model calls at once. Kept here, not in config, because it is a protection constant.
BATCH_CONCURRENCY = 5

# P1-20: the limit is shared by every batch in the process. A semaphore per batch let
# 4 concurrent batches run 20 calls at once. An asyncio semaphore belongs to one event
# loop, so it is created lazily on the running loop and kept per loop (a weak key, so
# a closed loop, e.g. one per test, takes its semaphore with it). A server has one loop.
_batch_semaphores: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = (
    weakref.WeakKeyDictionary()
)


def _batch_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    semaphore = _batch_semaphores.get(loop)
    if semaphore is None:
        semaphore = _batch_semaphores[loop] = asyncio.Semaphore(BATCH_CONCURRENCY)
    return semaphore


class JSONRPCHandler:
    """JSON-RPC 2.0 request handler with method registration"""
    
    def __init__(self):
        """Initialize handler with empty method registry"""
        self._methods: dict[str, Callable[..., Awaitable[Any]]] = {}
        logger.info("JSONRPCHandler initialized")
    
    def register_method(
        self,
        name: str,
        handler: Callable[..., Awaitable[Any]]
    ) -> None:
        """
        Register a JSON-RPC method
        
        Args:
            name: Method name (e.g., "analyze_pr")
            handler: Async function to handle the method
            
        Example:
            async def analyze_pr(pr_url: str) -> dict:
                # Implementation
                return {"status": "completed"}
            
            rpc_handler.register_method("analyze_pr", analyze_pr)
        """
        if name in self._methods:
            logger.warning(f"Overwriting existing method: {name}")
        
        self._methods[name] = handler
        logger.info(f"Registered JSON-RPC method: {name}")
    
    def unregister_method(self, name: str) -> None:
        """
        Unregister a JSON-RPC method
        
        Args:
            name: Method name to remove
        """
        if name in self._methods:
            del self._methods[name]
            logger.info(f"Unregistered JSON-RPC method: {name}")
    
    def list_methods(self) -> list[str]:
        """
        List all registered method names
        
        Returns:
            List of method names
        """
        return list(self._methods.keys())
    
    async def handle_request(self, request_data: dict[str, Any]) -> dict[str, Any]:
        """
        Handle a JSON-RPC request
        
        Args:
            request_data: Raw request dictionary
            
        Returns:
            JSON-RPC response dictionary
        """
        try:
            # Parse request
            try:
                request = JSONRPCRequest.model_validate(request_data)
            except Exception as e:
                # Pydantic errors echo the offending input, so keep them server-side
                error_id = new_error_id()
                logger.error(f"Invalid JSON-RPC request [error_id={error_id}]: {type(e).__name__}")
                return self._error_response(
                    request_id=request_data.get("id") if isinstance(request_data, dict) else None,
                    code=JSONRPCErrorCode.INVALID_REQUEST,
                    message="Invalid Request",
                    data={"error_id": error_id}
                )
            
            logger.info(f"Handling JSON-RPC request: {request.method} (id={request.id})")
            
            # Check if method exists
            if request.method not in self._methods:
                logger.warning(f"Method not found: {request.method}")
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.METHOD_NOT_FOUND,
                    message=f"Method not found: {request.method}",
                    data={"available_methods": self.list_methods()}
                )
            
            # Get handler
            handler = self._methods[request.method]
            
            # Call handler with params
            try:
                params = request.params or {}
                
                # Support both dict and list params
                if isinstance(params, dict):
                    result = await handler(**params)
                elif isinstance(params, list):
                    result = await handler(*params)
                else:
                    result = await handler()
                
                logger.info(f"Method {request.method} completed successfully")
                
                # Build success response
                return self._success_response(
                    request_id=request.id,
                    result=result
                )
                
            except ClientInputError as e:
                # The message was written for the caller (e.g. a rejected push URL)
                # ClientInputError messages are written for the caller and safe to log
                logger.warning(f"Rejected params for {request.method}: {e}")
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.INVALID_PARAMS,
                    message=str(e),
                )

            except RequestTimeoutError as e:
                logger.warning(f"Timed out: {request.method}")
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.TIMEOUT,
                    message=str(e),
                )

            except TypeError as e:
                # Invalid params (wrong arguments)
                error_id = new_error_id()
                logger.error(
                    f"Invalid params for {request.method} [error_id={error_id}]: "
                    f"{type(e).__name__}",
                )
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.INVALID_PARAMS,
                    message="Invalid method parameters",
                    data={"error_id": error_id}
                )
            
            except Exception as e:
                # Internal error during method execution
                error_id = new_error_id()
                logger.error(
                    f"Error executing {request.method} [error_id={error_id}]: "
                    f"{type(e).__name__}",
                )
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.INTERNAL_ERROR,
                    message="Internal error",
                    data={"error_id": error_id}
                )
        
        except Exception as e:
            # Unexpected error in handler itself
            error_id = new_error_id()
            logger.error(
                f"Unexpected error in JSON-RPC handler [error_id={error_id}]: "
                f"{type(e).__name__}",
            )
            return self._error_response(
                request_id=None,
                code=JSONRPCErrorCode.INTERNAL_ERROR,
                message="Internal server error",
                data={"error_id": error_id}
            )
    
    async def handle_batch(self, batch_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Handle a batch of JSON-RPC requests
        
        Args:
            batch_data: List of request dictionaries
            
        Returns:
            List of response dictionaries
        """
        logger.info(f"Handling batch of {len(batch_data)} JSON-RPC requests")
        
        semaphore = _batch_semaphore()

        async def run_one(request_data: dict[str, Any]) -> dict[str, Any]:
            async with semaphore:
                return await self.handle_request(request_data)

        # gather returns results in input order, so responses match request order.
        # handle_request never raises, so one failing call cannot cancel the others.
        return list(await asyncio.gather(*(run_one(r) for r in batch_data)))
    
    def _success_response(
        self,
        request_id: Any | None,
        result: Any
    ) -> dict[str, Any]:
        """
        Build a success response
        
        Args:
            request_id: Request ID
            result: Result to return
            
        Returns:
            Response dictionary
        """
        # Ensure result has 'kind' field if it's a task
        if isinstance(result, dict) and "status" in result and "kind" not in result:
            result["kind"] = "task"
        
        response = JSONRPCResponse(
            id=request_id,
            result=result
        )
        
        # Serialize the complete JSON-RPC response
        response_dict = response.model_dump(mode="json", exclude_none=True)
        
        return response_dict
    
    def _error_response(
        self,
        request_id: Any | None,
        code: int,
        message: str,
        data: Any | None = None
    ) -> dict[str, Any]:
        """
        Build an error response
        
        Args:
            request_id: Request ID (can be None for parse errors)
            code: Error code
            message: Error message
            data: Optional additional error data
            
        Returns:
            Error response dictionary
        """
        error = JSONRPCError(
            code=code,
            message=message,
            data=data
        )
        
        response = JSONRPCResponse(
            id=request_id,
            error=error
        )
        
        return response.model_dump(mode="json", exclude_none=True)
    
    def introspect(self) -> dict[str, Any]:
        """
        Get introspection data about registered methods
        
        Returns:
            Dictionary with method information
        """
        return {
            "methods": self.list_methods(),
            "count": len(self._methods),
            "version": "2.0"
        }
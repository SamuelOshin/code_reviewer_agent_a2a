# app/services/jsonrpc_handler.py

"""JSON-RPC 2.0 Request Handler

Handles JSON-RPC method registration and request processing.
Supports async handlers and proper error handling per JSON-RPC 2.0 spec.
"""

from typing import Dict, Any, Callable, Awaitable, Optional
import logging
import traceback

from app.models.jsonrpc import (
    JSONRPCRequest,
    JSONRPCResponse,
    JSONRPCError,
    JSONRPCErrorCode
)

logger = logging.getLogger(__name__)


class JSONRPCHandler:
    """JSON-RPC 2.0 request handler with method registration"""
    
    def __init__(self):
        """Initialize handler with empty method registry"""
        self._methods: Dict[str, Callable[..., Awaitable[Any]]] = {}
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
    
    async def handle_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
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
                logger.error(f"Invalid JSON-RPC request: {e}")
                return self._error_response(
                    request_id=request_data.get("id"),
                    code=JSONRPCErrorCode.INVALID_REQUEST,
                    message="Invalid Request",
                    data=str(e)
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
                
            except TypeError as e:
                # Invalid params (wrong arguments)
                logger.error(f"Invalid params for {request.method}: {e}")
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.INVALID_PARAMS,
                    message="Invalid method parameters",
                    data=str(e)
                )
            
            except Exception as e:
                # Internal error during method execution
                logger.error(f"Error executing {request.method}: {e}")
                logger.debug(traceback.format_exc())
                
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.INTERNAL_ERROR,
                    message=f"Internal error: {str(e)}",
                    data={
                        "error_type": type(e).__name__,
                        "error_message": str(e)
                    }
                )
        
        except Exception as e:
            # Unexpected error in handler itself
            logger.error(f"Unexpected error in JSON-RPC handler: {e}")
            logger.debug(traceback.format_exc())
            
            return self._error_response(
                request_id=None,
                code=JSONRPCErrorCode.INTERNAL_ERROR,
                message="Internal server error",
                data=str(e)
            )
    
    async def handle_batch(self, batch_data: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        """
        Handle a batch of JSON-RPC requests
        
        Args:
            batch_data: List of request dictionaries
            
        Returns:
            List of response dictionaries
        """
        logger.info(f"Handling batch of {len(batch_data)} JSON-RPC requests")
        
        responses = []
        for request_data in batch_data:
            response = await self.handle_request(request_data)
            responses.append(response)
        
        return responses
    
    def _success_response(
        self,
        request_id: Optional[Any],
        result: Any
    ) -> Dict[str, Any]:
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
        
        # Log the complete JSON-RPC envelope
        import json
        logger.info("=" * 80)
        logger.info("COMPLETE JSON-RPC RESPONSE:")
        logger.info(json.dumps(response_dict, indent=2))
        logger.info("=" * 80)
        
        return response_dict
    
    def _error_response(
        self,
        request_id: Optional[Any],
        code: int,
        message: str,
        data: Optional[Any] = None
    ) -> Dict[str, Any]:
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
    
    def introspect(self) -> Dict[str, Any]:
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
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

from app.core.config import settings
from app.core.errors import ClientInputError, RequestTimeoutError, new_error_id
from app.models.jsonrpc import JSONRPCError, JSONRPCErrorCode, JSONRPCRequest, JSONRPCResponse

logger = logging.getLogger(__name__)

# How many batch calls run at the same time, across all batches (P1-18, P1-20). A batch
# used to run its calls one after another, so 100 blocking message/send calls could
# hold the request for 100 x A2A_BLOCKING_TIMEOUT_SECONDS. Now each call waits at most
# that timeout for a slot (else -32004, P1-21) and then runs under the same timeout,
# so a batch finishes within about twice the timeout, and one batch cannot start 100
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


def _echo_id(raw_id: Any) -> str | int | None:
    """The id to echo in a response, or None when there is no valid one (P1-22).

    A string or integer is echoed as is, an integral float (1.0) as the integer, as the
    request model does. bool, other floats, objects and lists are not valid ids.
    """
    if isinstance(raw_id, bool):
        return None
    if isinstance(raw_id, (str, int)):
        return raw_id
    if isinstance(raw_id, float) and raw_id.is_integer():
        return int(raw_id)
    return None


def _cap(text: str, limit: int = 100) -> str:
    """Client text echoed in a reply, cut to `limit` characters (P1-26)."""
    return text if len(text) <= limit else text[:limit] + "..."


def _is_notification(request_data: Any) -> bool:
    """A request object with no "id" member is a notification (P1-23). "id": null is a
    request that wants a reply (with id null); only a missing key means no reply."""
    return isinstance(request_data, dict) and "id" not in request_data


class JSONRPCHandler:
    """JSON-RPC 2.0 request handler with method registration"""
    
    def __init__(self):
        """Initialize handler with empty method registry"""
        self._methods: dict[str, Callable[..., Awaitable[Any]]] = {}
        # Methods that must not be called as notifications, decided from the params
        self._reply_required: dict[str, Callable[[dict[str, Any]], bool]] = {}
        # Extra advice for the -32600 a rejected notification gets, per method
        self._reply_hints: dict[str, str] = {}
        logger.info("JSONRPCHandler initialized")
    
    def register_method(
        self,
        name: str,
        handler: Callable[..., Awaitable[Any]],
        reply_required: Callable[[dict[str, Any]], bool] | None = None,
        reply_hint: str | None = None,
    ) -> None:
        """
        Register a JSON-RPC method
        
        Args:
            name: Method name (e.g., "analyze_pr")
            handler: Async function to handle the method
            reply_required: Given the params, whether the call only makes sense with a
                reply. If true, a notification (no "id") is rejected with -32600 before
                the method runs (P1-24). It should be a pure function of the params:
                it runs once per call, before any batch slot wait (P1-26).
            reply_hint: Optional advice appended to that error, e.g. how to get the
                result without a reply. Only give advice that applies to this method.
            
        Example:
            async def analyze_pr(pr_url: str) -> dict:
                # Implementation
                return {"status": "completed"}
            
            rpc_handler.register_method("analyze_pr", analyze_pr)
        """
        if name in self._methods:
            logger.warning(f"Overwriting existing method: {name}")
        
        self._methods[name] = handler
        if reply_required is None:
            self._reply_required.pop(name, None)
        else:
            self._reply_required[name] = reply_required
        if reply_hint is None:
            self._reply_hints.pop(name, None)
        else:
            self._reply_hints[name] = reply_hint
        logger.info(f"Registered JSON-RPC method: {name}")
    
    def unregister_method(self, name: str) -> None:
        """
        Unregister a JSON-RPC method
        
        Args:
            name: Method name to remove
        """
        if name in self._methods:
            del self._methods[name]
            self._reply_required.pop(name, None)
            self._reply_hints.pop(name, None)
            logger.info(f"Unregistered JSON-RPC method: {name}")
    
    def list_methods(self) -> list[str]:
        """
        List all registered method names
        
        Returns:
            List of method names
        """
        return list(self._methods.keys())
    
    async def handle_request(
        self,
        request_data: Any,
        _prechecked: tuple[JSONRPCRequest | None, dict[str, Any] | None] | None = None,
    ) -> dict[str, Any] | None:
        """
        Handle a JSON-RPC request

        Args:
            request_data: The decoded JSON value (normally an object)

        Returns:
            JSON-RPC response dictionary, or None for a notification (a valid request
            with no "id" member): the method still runs but the server must not reply,
            not even with an error (P1-23). An invalid request is always answered.
        """
        response, always_answer = await self._handle_request(request_data, _prechecked)
        if _is_notification(request_data) and not always_answer:
            return None
        return response

    def _precheck(self, request_data: Any) -> tuple[JSONRPCRequest | None, dict[str, Any] | None]:
        """Reject a request before it runs or waits for a batch slot (P1-24, P1-25).

        Returns the parsed request, or a rejection that must be answered even for a
        notification: the body is not a valid request, or it is a notification for a
        method whose result only comes back in the reply (a blocking review).
        """
        try:
            request = JSONRPCRequest.model_validate(request_data)
        except Exception as e:
            # Pydantic errors echo the offending input, so keep them server-side
            error_id = new_error_id()
            logger.error(f"Invalid JSON-RPC request [error_id={error_id}]: {type(e).__name__}")
            return None, self._error_response(
                request_id=(
                    _echo_id(request_data.get("id")) if isinstance(request_data, dict) else None
                ),
                code=JSONRPCErrorCode.INVALID_REQUEST,
                message="Invalid Request",
                data={"error_id": error_id}
            )

        # P1-24: a call whose only output is its reply (a blocking review) must not
        # be sent as a notification: it would run a full review and return nothing
        reply_required = self._reply_required.get(request.method)
        if (
            _is_notification(request_data)
            and reply_required is not None
            and reply_required(request.params or {})
        ):
            logger.warning(f"Rejected {request.method!r:.100} sent as a notification")
            return None, self._error_response(
                request_id=None,
                code=JSONRPCErrorCode.INVALID_REQUEST,
                message=" ".join(
                    part
                    for part in (
                        f"{request.method} returns its result in the reply, so it "
                        "needs an \"id\".",
                        self._reply_hints.get(request.method),
                    )
                    if part
                ),
            )
        return request, None

    async def _handle_request(
        self,
        request_data: Any,
        prechecked: tuple[JSONRPCRequest | None, dict[str, Any] | None] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """The response, and whether it must be sent even for a notification.

        P1-24: an explicit flag, set only where the request itself was rejected (not
        readable, or a notification that needs a reply), instead of inferring it from
        the error code, which a method error could also use.
        """
        try:
            # A batch call was already pre-checked before its slot wait; reuse that
            # result so validation and reply_required run once per call (P1-26)
            request, rejection = (
                prechecked if prechecked is not None else self._precheck(request_data)
            )
            if rejection is not None:
                return rejection, True

            # !r and a cap: the method name is client text and may hold newlines (P1-25)
            logger.info(f"Handling JSON-RPC request: {request.method!r:.100} (id={request.id!r:.100})")

            # Check if method exists
            if request.method not in self._methods:
                logger.warning(f"Method not found: {request.method!r:.100}")
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.METHOD_NOT_FOUND,
                    # Capped: the name is client text and the reply should not grow with it (P1-26)
                    message=f"Method not found: {_cap(request.method)}",
                    data={"available_methods": self.list_methods()}
                ), False

            
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
                ), False
                
            except ClientInputError as e:
                # The message was written for the caller (e.g. a rejected push URL)
                # ClientInputError messages are written for the caller and safe to log
                logger.warning(f"Rejected params for {request.method}: {e}")
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.INVALID_PARAMS,
                    message=str(e),
                ), False

            except RequestTimeoutError as e:
                logger.warning(f"Timed out: {request.method}")
                return self._error_response(
                    request_id=request.id,
                    code=JSONRPCErrorCode.TIMEOUT,
                    message=str(e),
                ), False

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
                ), False
            
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
                ), False
        
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
            ), False
    
    async def handle_batch(self, batch_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Handle a batch of JSON-RPC requests

        Args:
            batch_data: List of request dictionaries

        Returns:
            List of response dictionaries, in request order, without the entries for
            notifications (P1-23). Empty when every call was a notification.
        """
        logger.info(f"Handling batch of {len(batch_data)} JSON-RPC requests")
        
        semaphore = _batch_semaphore()

        # P1-21: waiting for a slot is bounded by A2A_BLOCKING_TIMEOUT_SECONDS, so a
        # busy process answers -32004 instead of holding the request open. The wait
        # does not count against the call's own run time, which has its own limit.
        # Single (non-batch) requests are deliberately not routed through this limit:
        # a blocking message/send already has the same timeout, a non-blocking one
        # returns at once, and queuing ordinary requests behind batches would add
        # latency for clients that never batch. A process-wide cap on model calls
        # would be a separate feature.
        async def run_one(request_data: Any) -> dict[str, Any] | None:
            # P1-25: a call that would be rejected is answered before it waits for a
            # slot, so a busy batch can't drop it silently; it costs no slot either
            try:
                prechecked = self._precheck(request_data)
            except Exception:
                prechecked = None  # let handle_request's safety net deal with it
            if prechecked is not None and prechecked[1] is not None:
                return prechecked[1]
            limit = settings.A2A_BLOCKING_TIMEOUT_SECONDS
            try:
                await asyncio.wait_for(semaphore.acquire(), timeout=limit)
            except TimeoutError:
                logger.warning(f"Batch call waited {limit:g}s for a slot")
                # This response is built outside handle_request's safety net, so only
                # a valid JSON-RPC id is echoed; a malformed one (object, list, bool,
                # non-integral float) must not fail the whole batch (P1-21 review).
                # An integral float (1.0) is echoed as 1, like the normal path (P1-22).
                if _is_notification(request_data):
                    return None  # a notification gets no reply, not even this one (P1-23)
                raw_id = request_data.get("id") if isinstance(request_data, dict) else None
                return self._error_response(
                    request_id=_echo_id(raw_id),
                    code=JSONRPCErrorCode.TIMEOUT,
                    message=(
                        f"The server is busy: no batch slot was free within {limit:g} seconds. "
                        "Retry later or send fewer calls at once."
                    ),
                )
            try:
                return await self.handle_request(request_data, prechecked)
            finally:
                semaphore.release()

        # gather returns results in input order, so responses match request order.
        # handle_request never raises, and the slot-timeout response above only echoes a
        # valid id, so one failing call cannot fail or cancel the others.
        results = await asyncio.gather(*(run_one(r) for r in batch_data))
        return [r for r in results if r is not None]
    
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
        out = self._with_id(response.model_dump(mode="json", exclude_none=True), request_id)
        # exclude_none drops a None result, but a success response must carry "result"
        # (null allowed) and never "error" (P1-23)
        out.setdefault("result", None)
        out.pop("error", None)
        return out
    
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
        
        out = self._with_id(response.model_dump(mode="json", exclude_none=True), request_id)
        out.pop("result", None)  # an error response never carries "result" (P1-23)
        return out

    @staticmethod
    def _with_id(response: dict[str, Any], request_id: Any) -> dict[str, Any]:
        """exclude_none drops a null id, but JSON-RPC 2.0 wants "id": null when the
        request id could not be read (P1-22)."""
        response["id"] = request_id
        return response

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
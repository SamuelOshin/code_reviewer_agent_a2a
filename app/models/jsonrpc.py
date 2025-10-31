# app/models/jsonrpc.py

from typing import Any, Optional, Union, Literal
from pydantic import BaseModel, Field

class JSONRPCRequest(BaseModel):
    """JSON-RPC 2.0 Request"""
    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: Optional[dict[str, Any]] = None
    id: Optional[Union[str, int]] = None

class JSONRPCError(BaseModel):
    """JSON-RPC 2.0 Error Object"""
    code: int
    message: str
    data: Optional[Any] = None

class JSONRPCResponse(BaseModel):
    """JSON-RPC 2.0 Response"""
    jsonrpc: Literal["2.0"] = "2.0"
    result: Optional[Any] = None
    error: Optional[JSONRPCError] = None
    id: Optional[Union[str, int]] = None

# Standard JSON-RPC Error Codes
class JSONRPCErrorCode:
    """JSON-RPC 2.0 Standard Error Codes"""
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    
    # Server errors -32000 to -32099
    SERVER_ERROR = -32000
    
    # Custom application errors
    GITHUB_ERROR = -32001
    ANALYSIS_ERROR = -32002
    LLM_ERROR = -32003
    TELEX_ERROR = -32004

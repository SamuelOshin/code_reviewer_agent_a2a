# app/core/exceptions.py

"""Custom exceptions for the Code Review Summarizer Agent"""


class CodeReviewAgentException(Exception):
    """Base exception for all agent errors"""
    
    def __init__(self, message: str, details: dict = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class GitHubMCPError(CodeReviewAgentException):
    """Exception raised when GitHub MCP operations fail"""
    pass


class AnalysisError(CodeReviewAgentException):
    """Exception raised when code analysis fails"""
    pass


class LLMError(CodeReviewAgentException):
    """Exception raised when LLM operations fail"""
    pass


class TelexError(CodeReviewAgentException):
    """Exception raised when Telex integration fails"""
    pass


class A2AError(CodeReviewAgentException):
    """Exception raised when A2A protocol operations fail"""
    pass


class JSONRPCError(CodeReviewAgentException):
    """Exception raised when JSON-RPC operations fail"""
    
    def __init__(self, code: int, message: str, data: dict = None):
        self.code = code
        self.data = data or {}
        super().__init__(message, details={"code": code, "data": data})


class ConfigurationError(CodeReviewAgentException):
    """Exception raised when configuration is invalid or missing"""
    pass


class ValidationError(CodeReviewAgentException):
    """Exception raised when data validation fails"""
    pass


class WebhookVerificationError(CodeReviewAgentException):
    """Exception raised when webhook signature verification fails"""
    pass

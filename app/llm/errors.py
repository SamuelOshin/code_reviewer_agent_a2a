"""Shared error types for every LLM provider.

Callers catch these, never a provider SDK's exceptions. All of them subclass the
app's existing `LLMError`, so code that already catches `LLMError` keeps working.
"""

from app.core.exceptions import LLMError


class LLMConfigurationError(LLMError):
    """The model settings are invalid, a key is missing, or a capability is absent."""


class LLMRateLimitError(LLMError):
    """The provider throttled the request or the account is out of quota."""


class LLMTimeoutError(LLMError):
    """The request or the whole run took too long."""


class LLMAuthError(LLMError):
    """The provider rejected the credentials."""


class LLMContextLengthError(LLMError):
    """The prompt does not fit in the model's context window."""


class LLMUnavailableError(LLMError):
    """The provider is overloaded, erroring, or unreachable."""


class LLMOutputError(LLMError):
    """The model's output could not be validated, even after the retry."""

"""Provider-agnostic model layer (tracker section 4, decision D-06).

Application code imports from here only. Provider SDKs and Pydantic AI are imported
only inside this package.
"""

from app.llm.errors import (
    LLMAuthError,
    LLMConfigurationError,
    LLMContextLengthError,
    LLMOutputError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMUnavailableError,
)
from app.llm.interface import LLMClient
from app.llm.types import LLMResult, ModelCapabilities, ModelSpec, Role, Usage


def build_client(settings, http_client=None) -> LLMClient:
    """Build the configured client. Imported lazily so `app.llm` stays light."""
    from app.llm.factory import build_client as _build

    return _build(settings, http_client=http_client)


__all__ = [
    "LLMAuthError",
    "LLMClient",
    "LLMConfigurationError",
    "LLMContextLengthError",
    "LLMOutputError",
    "LLMRateLimitError",
    "LLMResult",
    "LLMTimeoutError",
    "LLMUnavailableError",
    "ModelCapabilities",
    "ModelSpec",
    "Role",
    "Usage",
    "build_client",
]

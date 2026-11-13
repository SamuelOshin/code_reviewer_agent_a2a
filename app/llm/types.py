"""Provider-neutral types for the model layer.

Nothing here imports a provider SDK. The rest of the app depends on these types and
on the `LLMClient` interface, never on a provider's request or response format.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, TypeVar

from app.llm.errors import LLMConfigurationError

T = TypeVar("T")

# Providers the factory can build. "openai-compatible" is any server that speaks the
# OpenAI Chat Completions API at a configured base URL (local models, gateways).
SUPPORTED_PROVIDERS = ("google", "openai", "anthropic", "openai-compatible")


class Role(StrEnum):
    """What a call is for. Each role can be configured with its own model."""

    SECURITY = "security"
    PERFORMANCE = "performance"
    BEST_PRACTICES = "best_practices"
    SUMMARY = "summary"


@dataclass(frozen=True)
class ModelSpec:
    """A configured model, written as `<provider>:<model-id>`."""

    provider: str
    model_id: str

    @classmethod
    def parse(cls, value: str, setting: str = "LLM_MODEL") -> "ModelSpec":
        text = (value or "").strip()
        provider, sep, model_id = text.partition(":")
        provider, model_id = provider.strip().lower(), model_id.strip()
        providers = ", ".join(SUPPORTED_PROVIDERS)
        if not sep or not provider or not model_id:
            raise LLMConfigurationError(
                f"Invalid {setting}={text!r}. The format is <provider>:<model-id>, for "
                f"example 'google:<model-id>' or 'anthropic:<model-id>', with provider one "
                f"of {providers}. LLM_PROVIDER is no longer read: put the provider in "
                f"front of the model ID. See .env.example for current model IDs."
            )
        if provider not in SUPPORTED_PROVIDERS:
            raise LLMConfigurationError(
                f"Unsupported provider {provider!r} in {setting}={text!r}. "
                f"Use one of {providers}, as <provider>:<model-id>."
            )
        return cls(provider=provider, model_id=model_id)

    def __str__(self) -> str:
        return f"{self.provider}:{self.model_id}"


@dataclass(frozen=True)
class ModelCapabilities:
    """What a configured model (or every model in its fallback chain) supports."""

    tools: bool
    native_structured_output: bool
    json_mode: bool
    text_output: bool = True


@dataclass(frozen=True)
class Usage:
    """Usage for one `generate` call, in the same shape for every provider.

    `cost_usd` is None when the price of the model is unknown, which is not the
    same as zero.
    """

    input_tokens: int
    output_tokens: int
    requests: int
    latency_ms: float
    cost_usd: float | None = None

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True)
class LLMResult(Generic[T]):
    """A typed result plus the usage it took to produce it."""

    output: T
    usage: Usage
    model: str

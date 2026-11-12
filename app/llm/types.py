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
    def parse(cls, value: str) -> "ModelSpec":
        text = (value or "").strip()
        provider, sep, model_id = text.partition(":")
        provider, model_id = provider.strip().lower(), model_id.strip()
        if not sep or not provider or not model_id:
            raise LLMConfigurationError(
                f"Invalid model setting {text!r}: expected '<provider>:<model-id>', "
                f"with provider one of {', '.join(SUPPORTED_PROVIDERS)}"
            )
        if provider not in SUPPORTED_PROVIDERS:
            raise LLMConfigurationError(
                f"Unsupported LLM provider {provider!r} in {text!r}: "
                f"use one of {', '.join(SUPPORTED_PROVIDERS)}"
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

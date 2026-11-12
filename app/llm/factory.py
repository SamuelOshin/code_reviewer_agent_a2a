"""Build the configured `LLMClient` from settings.

Provider and model come only from configuration (D-06). This is the one place that
imports provider-specific Pydantic AI classes.
"""

from typing import Any

from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.fallback import FallbackModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.settings import ModelSettings

from app.llm.errors import LLMConfigurationError
from app.llm.pydantic_ai_client import PydanticAIClient
from app.llm.types import ModelSpec, Role

# Placeholder key for OpenAI-compatible servers that need none (the SDK requires one)
NO_KEY_NEEDED = "not-needed"


def _key(value: str, name: str, spec: ModelSpec) -> str:
    if not value:
        raise LLMConfigurationError(f"{name} is required for model {spec}")
    return value


def build_model(spec: ModelSpec, settings: Any, http_client: Any = None) -> Model:
    """Build one Pydantic AI model. `http_client` lets tests mock the network."""
    if spec.provider == "google":
        provider = GoogleProvider(
            api_key=_key(settings.GOOGLE_API_KEY, "GOOGLE_API_KEY", spec), http_client=http_client
        )
        return GoogleModel(spec.model_id, provider=provider)
    if spec.provider == "openai":
        provider = OpenAIProvider(
            api_key=_key(settings.OPENAI_API_KEY, "OPENAI_API_KEY", spec), http_client=http_client
        )
        return OpenAIResponsesModel(spec.model_id, provider=provider)
    if spec.provider == "openai-compatible":
        base_url = _key(settings.OPENAI_COMPATIBLE_BASE_URL, "OPENAI_COMPATIBLE_BASE_URL", spec)
        provider = OpenAIProvider(
            base_url=base_url,
            api_key=settings.OPENAI_COMPATIBLE_API_KEY or NO_KEY_NEEDED,
            http_client=http_client,
        )
        return OpenAIChatModel(spec.model_id, provider=provider)
    if spec.provider == "anthropic":
        provider = AnthropicProvider(
            api_key=_key(settings.ANTHROPIC_API_KEY, "ANTHROPIC_API_KEY", spec),
            http_client=http_client,
        )
        return AnthropicModel(spec.model_id, provider=provider)
    raise LLMConfigurationError(f"Unsupported LLM provider: {spec.provider}")


def role_chain(role: Role, settings: Any) -> list[ModelSpec]:
    """The configured model for a role, followed by any fallback models."""
    primary = getattr(settings, f"LLM_MODEL_{role.name}", "") or settings.LLM_MODEL
    if not primary:
        raise LLMConfigurationError(
            "LLM_MODEL is not set. Use '<provider>:<model-id>', for example in .env.example"
        )
    chain = [ModelSpec.parse(primary)]
    for item in (settings.LLM_FALLBACK_MODELS or "").split(","):
        if item.strip():
            spec = ModelSpec.parse(item)
            if spec not in chain:
                chain.append(spec)
    return chain


def build_client(settings: Any, http_client: Any = None) -> PydanticAIClient:
    """Build the client for every role. Fails at startup on bad config or missing keys."""
    cache: dict[ModelSpec, Model] = {}

    def model_for(spec: ModelSpec) -> Model:
        if spec not in cache:
            cache[spec] = build_model(spec, settings, http_client)
        return cache[spec]

    models: dict[Role, Model] = {}
    chains: dict[Role, list[ModelSpec]] = {}
    for role in Role:
        chain = role_chain(role, settings)
        built = [model_for(spec) for spec in chain]
        models[role] = built[0] if len(built) == 1 else FallbackModel(*built)
        chains[role] = chain

    model_settings = ModelSettings(
        temperature=settings.LLM_TEMPERATURE,
        max_tokens=settings.LLM_MAX_TOKENS,
        max_retries=settings.LLM_MAX_RETRIES,
        timeout=settings.LLM_TIMEOUT_SECONDS,
    )
    return PydanticAIClient(
        models,
        chains,
        model_settings=model_settings,
        output_mode=settings.LLM_STRUCTURED_OUTPUT_MODE,
    )

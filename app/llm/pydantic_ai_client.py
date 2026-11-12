"""`LLMClient` implemented with Pydantic AI (decision D-12).

This module and `app/llm/factory.py` are the only places that import Pydantic AI or
a provider SDK. Swapping the library means rewriting these two files, not the app.

What this adds on top of Pydantic AI:
- one place that maps every library or provider exception to `app.llm.errors`
- latency measurement (Pydantic AI reports tokens and cost, not latency)
- the structured-output mode choice: native schema when the model has it, else a
  validated tool or prompted fallback, retried once
- capability checks per role, across a fallback chain
"""

import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, TypeVar

from pydantic_ai import Agent, NativeOutput, PromptedOutput, ToolOutput
from pydantic_ai import exceptions as pai_errors
from pydantic_ai.models import Model
from pydantic_ai.models.fallback import FallbackModel
from pydantic_ai.settings import ModelSettings

from app.core.exceptions import LLMError
from app.llm.errors import (
    LLMAuthError,
    LLMConfigurationError,
    LLMContextLengthError,
    LLMOutputError,
    LLMRateLimitError,
    LLMTimeoutError,
    LLMUnavailableError,
)
from app.llm.types import LLMResult, ModelCapabilities, ModelSpec, Role, Usage

T = TypeVar("T")

OUTPUT_MODES = ("auto", "native", "tool", "prompted")

# Section 4: validate structured output and retry once, then fail.
OUTPUT_RETRIES = 1


def map_error(exc: BaseException) -> LLMError:
    """Map a Pydantic AI or provider exception to a shared error type."""
    if isinstance(exc, LLMError):
        return exc
    if isinstance(exc, pai_errors.FallbackExceptionGroup) and exc.exceptions:
        # Every model in the chain failed; report the last failure.
        return map_error(exc.exceptions[-1])

    message = f"{type(exc).__name__}: {exc}"
    checks: tuple[tuple[tuple[type[BaseException], ...], type[LLMError]], ...] = (
        ((pai_errors.ModelContextWindowExceededError,), LLMContextLengthError),
        ((pai_errors.ModelAuthenticationError,), LLMAuthError),
        ((pai_errors.ModelRateLimitError, pai_errors.ModelQuotaExceededError), LLMRateLimitError),
        (
            (
                pai_errors.ModelTimeoutError,
                pai_errors.ModelRequestTimeout,
                pai_errors.RunTimedOut,
                TimeoutError,
            ),
            LLMTimeoutError,
        ),
        (
            (
                pai_errors.ModelUnavailableError,
                pai_errors.ModelServerError,
                pai_errors.ModelConnectionError,
            ),
            LLMUnavailableError,
        ),
        ((pai_errors.UnexpectedModelBehavior,), LLMOutputError),
        ((pai_errors.UserError, pai_errors.ModelNotFoundError), LLMConfigurationError),
    )
    for types, error_type in checks:
        if isinstance(exc, types):
            return error_type(message)
    return LLMError(message)


def capabilities_of(model: Model) -> ModelCapabilities:
    """Read what a Pydantic AI model declares it supports."""
    if isinstance(model, FallbackModel):
        parts = [capabilities_of(m) for m in model.models]
        return ModelCapabilities(
            tools=all(p.tools for p in parts),
            native_structured_output=all(p.native_structured_output for p in parts),
            json_mode=all(p.json_mode for p in parts),
            text_output=all(p.text_output for p in parts),
        )
    profile = model.profile
    return ModelCapabilities(
        tools=bool(profile.get("supports_tools", True)),
        native_structured_output=bool(profile.get("supports_json_schema_output", False)),
        json_mode=bool(profile.get("supports_json_object_output", False)),
        text_output=bool(profile.get("supports_text_output", True)),
    )


class PydanticAIClient:
    """`LLMClient` backed by Pydantic AI agents, one model (or fallback chain) per role."""

    def __init__(
        self,
        models: Mapping[Role, Model],
        chains: Mapping[Role, Sequence[ModelSpec]],
        *,
        model_settings: ModelSettings | None = None,
        output_mode: str = "auto",
    ):
        missing = [role for role in Role if role not in models]
        if missing:
            raise LLMConfigurationError(f"No model configured for roles: {missing}")
        if output_mode not in OUTPUT_MODES:
            raise LLMConfigurationError(
                f"Invalid structured output mode {output_mode!r}: use one of {OUTPUT_MODES}"
            )
        self._models = dict(models)
        self._chains = {role: list(chain) for role, chain in chains.items()}
        self._model_settings = model_settings or ModelSettings()
        self._output_mode = output_mode

    def model_name(self, role: Role) -> str:
        return ", ".join(str(spec) for spec in self._chains[role])

    def capabilities(self, role: Role) -> ModelCapabilities:
        return capabilities_of(self._models[role])

    def require(
        self, role: Role, *, tools: bool = False, native_structured_output: bool = False
    ) -> None:
        caps = self.capabilities(role)
        missing = []
        if tools and not caps.tools:
            missing.append("tool calling")
        if native_structured_output and not caps.native_structured_output:
            missing.append("native structured output")
        if not caps.text_output:
            missing.append("text output")
        if missing:
            raise LLMConfigurationError(
                f"Model {self.model_name(role)} for role '{role}' does not support: "
                f"{', '.join(missing)}"
            )

    def _output_spec(self, role: Role, output_type: Any, has_tools: bool) -> Any:
        if output_type is str:
            return str
        caps = self.capabilities(role)
        mode = self._output_mode
        if mode == "auto":
            if caps.native_structured_output and not has_tools:
                mode = "native"
            elif caps.tools:
                mode = "tool"
            else:
                mode = "prompted"
        wrappers = {"native": NativeOutput, "tool": ToolOutput, "prompted": PromptedOutput}
        return wrappers[mode](output_type)

    def _answering_model(self, role: Role, response: Any) -> str:
        """The configured spec of the model that answered (matters with fallbacks)."""
        chain = self._chains[role]
        model_name = getattr(response, "model_name", None)
        provider_name = getattr(response, "provider_name", None)
        matches = [spec for spec in chain if spec.model_id == model_name] or chain
        for spec in matches:
            family = "openai" if spec.provider == "openai-compatible" else spec.provider
            if family == provider_name:
                return str(spec)
        return str(matches[0])

    async def generate(
        self,
        role: Role,
        prompt: str,
        *,
        instructions: str | None = None,
        output_type: type[T] = str,  # type: ignore[assignment]
        tools: Sequence[Callable[..., Any]] = (),
    ) -> LLMResult[T]:
        if tools:
            self.require(role, tools=True)
        agent: Agent[None, Any] = Agent(
            self._models[role],
            output_type=self._output_spec(role, output_type, bool(tools)),
            instructions=instructions,
            tools=list(tools),
            model_settings=self._model_settings,
            retries={"output": OUTPUT_RETRIES},
        )
        started = time.perf_counter()
        try:
            result = await agent.run(prompt)
        except Exception as exc:
            raise map_error(exc) from exc
        latency_ms = (time.perf_counter() - started) * 1000

        run_usage = result.usage
        cost = getattr(run_usage, "cost", None)
        usage = Usage(
            input_tokens=run_usage.input_tokens or 0,
            output_tokens=run_usage.output_tokens or 0,
            requests=run_usage.requests or 0,
            latency_ms=latency_ms,
            cost_usd=float(cost) if cost is not None else None,
        )
        model = self._answering_model(role, result.response)
        return LLMResult(output=result.output, usage=usage, model=model)

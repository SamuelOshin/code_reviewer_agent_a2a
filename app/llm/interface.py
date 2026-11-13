"""The one interface the application uses for LLM calls."""

from collections.abc import Callable, Sequence
from typing import Any, Protocol, TypeVar

from app.llm.types import LLMResult, ModelCapabilities, Role

T = TypeVar("T")


class LLMClient(Protocol):
    """Ask a configured model for text or a typed result.

    `output_type=str` returns free text. Any Pydantic model or type (for example
    `list[Finding]`) returns a validated instance: native schema output where the
    model supports it, otherwise a tool or prompted fallback that is validated and
    retried once. If it still fails, `LLMOutputError` is raised.

    `tools` are plain Python callables the model may call. Their signature and
    docstring become the tool schema.

    Every provider failure is raised as one of the types in `app.llm.errors`.
    """

    async def generate(
        self,
        role: Role,
        prompt: str,
        *,
        instructions: str | None = None,
        output_type: type[T] = str,
        tools: Sequence[Callable[..., Any]] = (),
    ) -> LLMResult[T]: ...

    def capabilities(self, role: Role) -> ModelCapabilities: ...

    def require(
        self, role: Role, *, tools: bool = False, native_structured_output: bool = False
    ) -> None: ...

    def model_name(self, role: Role) -> str: ...

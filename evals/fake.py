"""Scripted stand-ins for a model. Free, deterministic, and no measure of quality.

Both implement the part of `app.llm.LLMClient` the review uses, so the real
`LLMService` builds the prompts and validates the reports.
"""

from collections.abc import Sequence

from app.llm import LLMResult, ModelCapabilities, Role, Usage
from app.models.analysis import BestPracticesReport, PerformanceReport, SecurityReport
from evals.dataset import ExpectedLabel

CATEGORY_OF_REPORT = {
    SecurityReport: "security",
    PerformanceReport: "performance",
    BestPracticesReport: "best_practice",
}


class EmptyClient:
    """`rules` mode: every findings step runs and reports nothing."""

    name = "rules-only"

    def model_name(self, role: Role) -> str:
        return self.name

    def capabilities(self, role: Role) -> ModelCapabilities:
        return ModelCapabilities(tools=False, native_structured_output=True, json_mode=True)

    def require(self, role: Role, **needs: bool) -> None:
        pass  # the review asks no capability of a scripted model

    def _findings(self, category: str, prompt: str) -> list[dict]:
        return []

    async def generate(
        self, role: Role, prompt: str, *, instructions=None, output_type=str, tools=()
    ):
        if output_type is str:
            output = "Scripted summary."
        else:
            category = CATEGORY_OF_REPORT[output_type]
            output = output_type(findings=self._findings(category, prompt))
        text = output if isinstance(output, str) else output.model_dump_json()
        # A rough, repeatable token estimate (4 characters each), not a provider count
        usage = Usage(
            input_tokens=len(prompt) // 4,
            output_tokens=len(text) // 4,
            requests=1,
            latency_ms=0.0,
            cost_usd=0.0,
        )
        return LLMResult(output=output, usage=usage, model=self.name)


class FakeClient(EmptyClient):
    """`fake` mode: reports a case's label when the prompt shows its anchor line.

    It knows the answers, so it only shows that the harness and the pipeline carry
    each change to the model and its findings back to the scorer. A bug that never
    reaches a prompt (for example, past the diff chunk limit) is not reported.
    """

    name = "fake:scripted"

    def __init__(self, labels: Sequence[ExpectedLabel]):
        self.labels = tuple(labels)

    def _findings(self, category: str, prompt: str) -> list[dict]:
        found = []
        for label in self.labels:
            if label.category != category or label.anchor not in prompt:
                continue
            finding = {
                "severity": label.severity,
                # Carries a keyword, as a real finding would name the problem
                "title": " ".join((label.title, *label.keywords[:1])),
                "description": label.title,
                "file": label.file,
                "line_number": label.start,
                "recommendation": "Fix the seeded bug.",
            }
            if category == "performance":
                finding["impact"] = label.title
            if category == "best_practice":
                finding["category"] = "code_quality"
            found.append(finding)
        return found

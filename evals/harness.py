"""Run cases through the real review pipeline and score the results.

Only the two outside edges are replaced: GitHub (the PR comes from the case files)
and, in `rules` and `fake` modes, the model. Rule checks, prompts, report validation,
diff chunking, merging, risk and verdict are the app's own code.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from app.llm import LLMClient
from app.models.analysis import CodeAnalysisResult
from app.models.github import GitHubUser, PullRequest, PullRequestFile
from app.services.code_analyzer import CodeAnalyzerService
from app.services.llm_service import LLMService
from evals.dataset import Case
from evals.fake import EmptyClient, FakeClient
from evals.scoring import DEFAULT_LINE_TOLERANCE, CaseOutcome, CaseScore, Finding, score_case

MODES = ("rules", "fake", "llm")


class RecordingClient:
    """Passes calls to a model client and keeps the usage each one reports."""

    def __init__(self, client: LLMClient):
        self.client = client
        self.calls: list = []  # a Usage per call that returned
        self.models: set[str] = set()
        self.failed: list[str] = []  # error type names

    def model_name(self, role):
        return self.client.model_name(role)

    def capabilities(self, role):
        return self.client.capabilities(role)

    def require(self, role, **needs):
        self.client.require(role, **needs)

    async def generate(self, role, prompt, **kwargs):
        try:
            result = await self.client.generate(role, prompt, **kwargs)
        except Exception as e:
            self.failed.append(type(e).__name__)
            raise
        self.calls.append(result.usage)
        self.models.add(result.model)
        return result

    def usage(self) -> dict:
        """Totals over the calls. A call that failed reports no tokens or cost.

        `cost_usd` is null when any returned call had an unknown price: a partial sum
        would make that model look cheaper than it is.
        """
        unknown = sum(u.cost_usd is None for u in self.calls)
        known = round(sum(u.cost_usd or 0.0 for u in self.calls), 6)
        return {
            "calls": len(self.calls) + len(self.failed),
            "failed_calls": len(self.failed),
            "requests": sum(u.requests for u in self.calls),
            "input_tokens": sum(u.input_tokens for u in self.calls),
            "output_tokens": sum(u.output_tokens for u in self.calls),
            "model_latency_ms": round(sum(u.latency_ms for u in self.calls), 1),
            "cost_usd": None if unknown else known,
            "known_cost_usd": known,
            "unknown_cost_calls": unknown,
        }


class _CaseAnalyzer(CodeAnalyzerService):
    """The app's analyzer, reading one case instead of GitHub."""

    def __init__(self, case: Case, llm_service: LLMService):
        # Not super().__init__(): it builds a model client from the app settings
        self.llm_service = llm_service
        self.case = case

    async def _fetch_pr_data(self, pr_url: str):
        files = [
            PullRequestFile(
                filename=f.filename,
                status=f.status,
                additions=len(f.additions),
                deletions=len(f.deletions),
                changes=len(f.additions) + len(f.deletions),
            )
            for f in self.case.files
        ]
        created = datetime(2026, 1, 1, tzinfo=UTC)
        pr = PullRequest(
            id=1,
            number=1,
            state="open",
            title=self.case.title,
            body=self.case.description,
            user=GitHubUser(login="eval-author", id=1),
            created_at=created,
            updated_at=created,
            html_url=pr_url,
            head={"ref": "change", "sha": "0" * 40},
            base={"ref": "main", "sha": "1" * 40},
            additions=sum(f.additions for f in files),
            deletions=sum(f.deletions for f in files),
            changed_files=len(files),
        )
        return pr, self.case.diff, files


@dataclass(frozen=True)
class CaseResult:
    case: Case
    score: CaseScore
    usage: dict
    answering_models: list[str]
    latency_seconds: float
    risk_level: str | None
    incomplete_reasons: list[str]
    diff_chars_total: int | None
    diff_chars_reviewed: int | None
    error: str | None = None  # exception type name when the pipeline raised


def _findings(result: CodeAnalysisResult) -> tuple[Finding, ...]:
    groups = (
        ("security", result.security_findings),
        ("performance", result.performance_findings),
        ("best_practice", result.best_practice_findings),
    )
    return tuple(
        Finding(
            category=category,
            file=issue.file,
            line=issue.line_number,
            title=issue.title,
            description=issue.description,
            severity=issue.severity.value,
            cwe_id=getattr(issue, "cwe_id", None),
        )
        for category, issues in groups
        for issue in issues
    )


async def run_case(
    case: Case, client: LLMClient, line_tolerance: int = DEFAULT_LINE_TOLERANCE
) -> CaseResult:
    recorder = RecordingClient(client)
    analyzer = _CaseAnalyzer(case, LLMService(client=recorder))
    result = error = None
    started = time.perf_counter()
    try:
        result = await analyzer.analyze_pr(f"https://github.com/prrover-evals/{case.id}/pull/1")
    except Exception as e:
        # One broken case must not lose the rest of a paid run. Type only, as the app does
        error = type(e).__name__
    latency = time.perf_counter() - started
    outcome = CaseOutcome(
        case_id=case.id,
        case_type=case.type,
        status=result.status.value if result else "error",
        verdict=result.approval_recommendation.value if result else None,
        labels=case.labels,
        findings=_findings(result) if result else (),
        forbidden_verdicts=case.forbidden_verdicts,
    )
    return CaseResult(
        case=case,
        score=score_case(outcome, line_tolerance),
        usage=recorder.usage(),
        answering_models=sorted(recorder.models),
        latency_seconds=round(latency, 3),
        risk_level=result.risk_level.value if result else None,
        incomplete_reasons=list(result.incomplete_reasons) if result else [],
        diff_chars_total=result.diff_chars_total if result else None,
        diff_chars_reviewed=result.diff_chars_reviewed_by_llm if result else None,
        error=error,
    )


async def run_cases(
    cases: list[Case],
    mode: str,
    client_for: Callable[[Case], LLMClient] | None = None,
    line_tolerance: int = DEFAULT_LINE_TOLERANCE,
    progress: Callable[[CaseResult], None] | None = None,
) -> list[CaseResult]:
    """Run the cases one after another, so each latency is measured on its own.

    `llm` mode needs `client_for`. `rules` mode makes no model call, so its usage is
    zero.
    """
    if mode not in MODES:
        raise ValueError(f"Unknown mode {mode!r}: use one of {MODES}")
    if mode == "llm" and client_for is None:
        raise ValueError("llm mode needs a model client")
    results = []
    for case in cases:
        if mode == "rules":
            # The empty client stands in for "no model", so there is no usage to report
            result = await run_case(case, EmptyClient(), line_tolerance)
            no_usage = RecordingClient(EmptyClient()).usage()
            result = replace(result, usage=no_usage, answering_models=[])
        else:
            client = client_for(case) if client_for else FakeClient(case.labels)
            result = await run_case(case, client, line_tolerance)
        results.append(result)
        if progress:
            progress(result)
    return results

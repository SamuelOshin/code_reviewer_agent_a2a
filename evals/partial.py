"""Save each case as it finishes, so a stopped run keeps what it paid for.

The file is JSON Lines: first the run (mode, settings, number of cases planned), then
one line per finished case with everything needed to score it again. It holds the
findings' full text, which the report does not.
"""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from evals.dataset import DatasetError, load_cases
from evals.harness import CaseResult
from evals.scoring import CaseOutcome, CaseScore, Finding, score_case

PARTIAL_VERSION = 1
# CaseResult fields stored as they are
_PLAIN = (
    "usage",
    "answering_models",
    "latency_seconds",
    "risk_level",
    "incomplete_reasons",
    "diff_chars_total",
    "diff_chars_reviewed",
    "error",
)
_SCORES = ("score", "model_score", "rules_score")


def _line(path: Path, data: dict, mode: str) -> None:
    with path.open(mode, encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(data) + "\n")


def start(path: Path, mode: str, config: dict, planned: int) -> None:
    """Create the file. Fails if it exists: it may hold an unfinished paid run."""
    path.parent.mkdir(parents=True, exist_ok=True)
    run = {"kind": "run", "version": PARTIAL_VERSION, "mode": mode, "config": config}
    _line(path, {**run, "planned": planned}, "x")


def _saved(score: CaseScore | None) -> dict | None:
    if score is None:
        return None
    outcome = score.outcome
    return {
        "status": outcome.status,
        "verdict": outcome.verdict,
        "forbidden_verdicts": list(outcome.forbidden_verdicts),
        "findings": [asdict(f) for f in outcome.findings],
    }


def append(path: Path, result: CaseResult) -> None:
    record: dict[str, Any] = {"kind": "case", "id": result.case.id, "digest": result.case.digest}
    record.update({name: getattr(result, name) for name in _PLAIN})
    record.update({name: _saved(getattr(result, name)) for name in _SCORES})
    _line(path, record, "a")


def load(path: Path) -> tuple[dict, list[CaseResult]]:
    """The run line and the saved results, scored again.

    A last line cut off mid-write is skipped. A case that changed since the run is
    refused, since its labels no longer describe what the model saw.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    run = json.loads(lines[0]) if lines else {}
    if (
        not isinstance(run, dict)
        or run.get("kind") != "run"
        or run.get("version") != PARTIAL_VERSION
    ):
        raise ValueError("not a saved-cases file")
    records = []
    for number, line in enumerate(lines[1:], start=2):
        try:
            records.append(json.loads(line))
        except ValueError:
            if number != len(lines):
                raise ValueError(f"line {number} is damaged") from None
    if not records:
        return run, []
    cases = {c.id: c for c in load_cases(only=[r["id"] for r in records])}
    tolerance = run["config"]["line_tolerance"]
    results = []
    for record in records:
        case = cases[record["id"]]
        if case.digest != record["digest"]:
            raise DatasetError(f"Case {case.id} has changed since this run")
        fields: dict[str, Any] = {name: record[name] for name in _PLAIN}
        for name in _SCORES:
            saved = record[name]
            fields[name] = saved and score_case(
                CaseOutcome(
                    case_id=case.id,
                    case_type=case.type,
                    status=saved["status"],
                    verdict=saved["verdict"],
                    labels=case.labels,
                    findings=tuple(Finding(**f) for f in saved["findings"]),
                    forbidden_verdicts=tuple(saved["forbidden_verdicts"]),
                ),
                tolerance,
            )
        results.append(CaseResult(case=case, **fields))
    return run, results

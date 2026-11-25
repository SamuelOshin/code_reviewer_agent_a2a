"""Build the JSON report of a run, its Markdown summary, and a comparison of runs."""

import statistics
from datetime import UTC, datetime

from evals.dataset import Case, fingerprint
from evals.harness import CaseResult
from evals.scoring import CATEGORIES, aggregate

SCHEMA_VERSION = 1
_TEXT_LIMIT = 200
_USAGE_COUNTS = (
    "calls",
    "failed_calls",
    "requests",
    "input_tokens",
    "output_tokens",
    "unknown_cost_calls",
)


def _finding(result: CaseResult, index: int) -> dict:
    finding = result.score.outcome.findings[index]
    return {
        "category": finding.category,
        "file": finding.file[:_TEXT_LIMIT],
        "line": finding.line,
        "severity": finding.severity,
        "title": finding.title[:_TEXT_LIMIT],
    }


def _case_row(result: CaseResult) -> dict:
    score, outcome = result.score, result.score.outcome
    return {
        "id": outcome.case_id,
        "type": outcome.case_type,
        "language": result.case.language,
        "tags": list(result.case.tags),
        "status": outcome.status,
        "error": result.error,
        "verdict": outcome.verdict,
        "verdict_ok": score.verdict_ok,
        "risk_level": result.risk_level,
        "passed": score.passed,
        "tp": score.tp,
        "fp": score.fp,
        "fn": score.fn,
        "duplicates": score.duplicates,
        "matched": [
            {"label": m.label_id, **_finding(result, m.finding_index)} for m in score.matches
        ],
        "missed": list(score.missed),
        "false_positives": [_finding(result, i) for i in score.false_positives],
        "incomplete_reasons": result.incomplete_reasons,
        "diff_chars_total": result.diff_chars_total,
        "diff_chars_reviewed_by_llm": result.diff_chars_reviewed,
        "latency_seconds": result.latency_seconds,
        "usage": result.usage,
        "answering_models": result.answering_models,
    }


def _usage_totals(results: list[CaseResult]) -> dict:
    rows = [r.usage for r in results]
    totals = {key: sum(u[key] for u in rows) for key in _USAGE_COUNTS}
    known = round(sum(u["known_cost_usd"] for u in rows), 6)
    totals["model_latency_ms"] = round(sum(u["model_latency_ms"] for u in rows), 1)
    totals["cost_usd"] = None if totals["unknown_cost_calls"] else known
    totals["known_cost_usd"] = known
    return totals


def _latency(results: list[CaseResult]) -> dict:
    times = [r.latency_seconds for r in results]
    if not times:
        return {"total": 0.0, "mean": None, "median": None, "max": None}
    return {
        "total": round(sum(times), 3),
        "mean": round(statistics.fmean(times), 3),
        "median": round(statistics.median(times), 3),
        "max": round(max(times), 3),
    }


def build_report(results: list[CaseResult], cases: list[Case], mode: str, config: dict) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": {"cases": len(cases), "fingerprint": fingerprint(cases)},
        "config": config,
        "metrics": aggregate([r.score for r in results]),
        "usage": _usage_totals(results),
        "latency_seconds": _latency(results),
        "answering_models": sorted({m for r in results for m in r.answering_models}),
        "cases": [_case_row(r) for r in results],
    }


# --- Markdown -----------------------------------------------------------------------


def _safe(text: object) -> str:
    """Model output goes into tables: keep it on one line and inert."""
    flat = " ".join(str(text).split())
    return flat.replace("|", "\\|").replace("<", "&lt;").replace("`", "'")


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _cost(usage: dict) -> str:
    if usage["cost_usd"] is not None:
        return f"${usage['cost_usd']:.4f}"
    return f"unknown (known part ${usage['known_cost_usd']:.4f})"


def _seconds(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f} s"


def _models(report: dict) -> str:
    by_role = report["config"].get("models_by_role", {})
    names = sorted(set(by_role.values()))
    if len(names) <= 1:
        return _safe(names[0] if names else "n/a")
    return "; ".join(f"{role}={_safe(name)}" for role, name in by_role.items())


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    return lines + ["| " + " | ".join(row) + " |" for row in rows]


def _headline_rows(report: dict) -> list[tuple[str, str]]:
    """The rows shared by a run's summary and a comparison."""
    metrics, usage = report["metrics"], report["usage"]
    cases, overall = metrics["cases"], metrics["overall"]
    clean, verdict = metrics["clean"], metrics["verdict"]
    rows = [
        ("Mode", report["mode"]),
        ("Model(s)", _models(report)),
        ("Answered by", _safe(", ".join(report["answering_models"]) or "no model")),
        ("Cases passed", f"{cases['passed']} / {cases['total']}"),
        (
            "Incomplete / failed / error",
            f"{cases['incomplete']} / {cases['failed']} / {cases['error']}",
        ),
        ("Precision", _percent(overall["precision"])),
        ("Recall", _percent(overall["recall"])),
        ("TP / FP / FN", f"{overall['tp']} / {overall['fp']} / {overall['fn']}"),
        ("Duplicate reports (in FP)", str(overall["duplicates"])),
        (
            "Clean-case false-positive rate",
            f"{_percent(clean['false_positive_rate'])} "
            f"({clean['flagged']} of {clean['evaluated']} evaluated, {clean['total']} clean)",
        ),
        (
            "Verdict accuracy",
            f"{_percent(verdict['accuracy'])} ({verdict['ok']} of {verdict['constrained']})",
        ),
    ]
    for category in CATEGORIES:
        data = metrics["by_category"][category]
        rows.append(
            (
                f"{category}: precision / recall / clean FP rate",
                f"{_percent(data['precision'])} / {_percent(data['recall'])} / "
                f"{_percent(data['clean_false_positive_rate'])}",
            )
        )
    rows += [
        ("Model calls (failed)", f"{usage['calls']} ({usage['failed_calls']})"),
        ("Tokens in / out", f"{usage['input_tokens']:,} / {usage['output_tokens']:,}"),
        ("Cost", _cost(usage)),
        ("Latency total", _seconds(report["latency_seconds"]["total"])),
        (
            "Latency per case (mean / median / max)",
            " / ".join(_seconds(report["latency_seconds"][k]) for k in ("mean", "median", "max")),
        ),
    ]
    return rows


def _notes(report: dict) -> list[str]:
    if report["mode"] == "fake":
        return [
            "> `fake` mode uses a scripted model that knows the labels. These numbers "
            "test the harness and say nothing about review quality. Tokens are estimates.",
            "",
        ]
    if report["mode"] == "rules":
        return ["> `rules` mode: rule checks only. No model was called.", ""]
    return []


def summary_markdown(report: dict) -> str:
    dataset = report["dataset"]
    lines = [
        f"# Eval run: {report['mode']}",
        "",
        f"{report['created_at']} · {dataset['cases']} cases · dataset "
        f"`{dataset['fingerprint']}` · line tolerance "
        f"{report['config'].get('line_tolerance', 'n/a')}",
        "",
        *_notes(report),
        *_table(["Measure", "Value"], [list(row) for row in _headline_rows(report)]),
        "",
        "## By case type",
        "",
        *_table(
            ["Type", "Passed", "Total"],
            [
                [kind, str(row["passed"]), str(row["total"])]
                for kind, row in report["metrics"]["by_type"].items()
            ],
        ),
        "",
        "## Cases",
        "",
        *_table(
            [
                "Case",
                "Status",
                "Verdict",
                "TP",
                "FP",
                "FN",
                "Result",
                "Tokens in / out",
                "Cost",
                "Latency",
            ],
            [
                [
                    c["id"],
                    c["status"],
                    (c["verdict"] or "n/a")
                    + (" (not allowed)" if c["verdict_ok"] is False else ""),
                    str(c["tp"]),
                    str(c["fp"]),
                    str(c["fn"]),
                    "pass" if c["passed"] else "fail",
                    f"{c['usage']['input_tokens']:,} / {c['usage']['output_tokens']:,}",
                    _cost(c["usage"]),
                    _seconds(c["latency_seconds"]),
                ]
                for c in report["cases"]
            ],
        ),
    ]
    misses = [f"- `{c['id']}`: {', '.join(c['missed'])}" for c in report["cases"] if c["missed"]]
    if misses:
        lines += ["", "## Missed labels", "", *misses]
    false_alarms = [
        f"- `{c['id']}`: {f['category']} {_safe(f['file'])}:{f['line']} "
        f"({f['severity']}) {_safe(f['title'])}"
        for c in report["cases"]
        for f in c["false_positives"]
    ]
    if false_alarms:
        lines += ["", "## False positives", "", *false_alarms]
    unfinished = [
        f"- `{c['id']}` ({c['status']}): {_safe(c['error'] or ' '.join(c['incomplete_reasons']))}"
        for c in report["cases"]
        if c["status"] != "complete"
    ]
    if unfinished:
        lines += ["", "## Unfinished reviews", "", *unfinished]
    return "\n".join(lines) + "\n"


def compare_markdown(reports: list[tuple[str, dict]]) -> str:
    """Runs side by side. `reports` is (name, report) pairs."""
    names = [name for name, _ in reports]
    data = [report for _, report in reports]
    warnings = []
    if len({r["dataset"]["fingerprint"] for r in data}) > 1:
        warnings.append("Different datasets: the quality numbers are not comparable.")
    if len({r["config"].get("line_tolerance") for r in data}) > 1:
        warnings.append("Different line tolerance: findings were matched by different rules.")
    limits = ("max_diff_chunks", "review_budget_seconds")
    if len({tuple(r["config"].get(k) for k in limits) for r in data}) > 1:
        warnings.append("Different review limits (chunks or time budget).")
    for name, report in reports:
        cases = report["metrics"]["cases"]
        unfinished = cases["total"] - cases["complete"]
        if unfinished:
            warnings.append(f"{_safe(name)}: {unfinished} review(s) did not complete.")
        if report["mode"] == "fake":
            warnings.append(f"{_safe(name)}: scripted model, not a quality result.")

    columns = [dict(_headline_rows(r)) for r in data]
    header = ["Measure", *(_safe(n) for n in names)]
    lines = ["# Eval comparison", ""]
    if warnings:
        lines += [*(f"> {w}" for w in warnings), ""]
    lines += _table(header, [[key, *(c[key] for c in columns)] for key in columns[0]])

    results = [{c["id"]: c for c in r["cases"]} for r in data]
    differing = []
    for case_id in sorted(set().union(*results)):
        cells = []
        for run_results in results:
            case = run_results.get(case_id)
            if case is None:
                cells.append("not run")
                continue
            word = "pass" if case["passed"] else "fail"
            cells.append(
                f"{word} (TP {case['tp']}, FP {case['fp']}, FN {case['fn']}, "
                f"{case['verdict'] or case['status']})"
            )
        if len({cell.split(" (")[0] for cell in cells}) > 1:
            differing.append([case_id, *cells])
    lines += ["", "## Cases with different results", ""]
    lines += _table(["Case", *header[1:]], differing) if differing else ["None."]
    return "\n".join(lines) + "\n"

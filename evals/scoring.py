"""Score review results against labelled cases (P3-01).

Matching rule
-------------
A finding matches a label when all of these hold:

1. Same category: `security`, `performance` or `best_practice` (the result list the
   finding is in).
2. Same file path (a leading `./`, or the `a/` / `b/` of a diff path, is ignored).
3. Line: the finding's line is within `line_tolerance` lines (default 2) of the
   label's inclusive line range.
4. Keywords: if the label lists keywords, at least one appears in the finding's title,
   description or CWE id as a whole word or phrase, ignoring case: no letter, digit or
   underscore directly before or after it. "sql" matches "SQL injection" but not
   "NoSQL" or "sqlalchemy", so each label lists the word forms it accepts.

A finding with no line number matches only a label that has keywords, and only through
one of them. These matches are weaker evidence, so they are also counted as
`matched_without_line`. Matching is one to one, and as many labels as possible are
matched (maximum bipartite matching), preferring findings that give a line, so the
counts do not depend on finding order.

Each matched pair is a true positive (TP). Every other finding is a false positive
(FP). Each unmatched label is a false negative (FN). A real problem that a case does
not label is counted as an FP, so precision is "precision against the labels".

An FP is also a `duplicate` when it repeats a matched finding: it satisfies the same
label as that finding (all four conditions above) and its line is within
`line_tolerance` of that finding's line. The review posts both when the rules and the
model title one bug differently. The strict numbers count duplicates as FPs; the
"excluding duplicates" numbers leave them out. A different problem next to a matched
one stays an FP in both, unless its text also hits one of the label's keywords. A
finding or match without a line makes no duplicate.

Metrics
-------
- precision = TP / (TP + FP); null when there are no findings (strict).
- precision excluding duplicates = TP / (TP + FP - duplicates).
- recall = TP / (TP + FN); null when there are no labels.
- Review status is `complete`, `incomplete`, `failed` or `error` (the pipeline
  raised). Findings and labels of every status count in precision and recall, because
  that is what a user would get.
- A review that is not `complete` never passes: not as a case, not for its verdict.
- Clean-case false-positive rate = clean cases with at least one finding / clean cases
  evaluated. A clean case is one with no labels. It is evaluated when its review
  completed or it raised a finding anyway, so an unfinished review that stayed silent
  can't lower the rate. Null when no clean case was evaluated.
- Verdict accuracy = constrained cases with an acceptable verdict / constrained cases.
  A constraint lists the verdicts a case must not get.
- Model contribution (runs with a model): the model's own findings scored alone, the
  same cases reviewed by the rules alone, and the combined review minus the rules-only
  one. Model-only passes ignore the verdict, which the app derives from the combined
  findings; rules-only and combined passes include it.
- A case passes when its review is `complete`, every label is matched, there is no
  false positive and the verdict constraint, if any, holds. It passes ignoring
  duplicates when the only false positives are duplicates.
- Severity does not weigh matches or the numbers above. False positives of high or
  critical severity are also counted on their own, and so is the clean-case rate for
  them: a clean case is flagged by a high or critical finding, and evaluated when its
  review completed or it raised one.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

CATEGORIES = ("security", "performance", "best_practice")
STATUSES = ("complete", "incomplete", "failed", "error")
DEFAULT_LINE_TOLERANCE = 2
HIGH_SEVERITIES = ("critical", "high")


@dataclass(frozen=True)
class Label:
    """One problem a case expects the review to report."""

    id: str
    category: str
    file: str
    start: int
    end: int
    keywords: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """One finding the review reported."""

    category: str
    file: str
    line: int | None
    title: str
    description: str = ""
    severity: str = ""
    cwe_id: str | None = None


@dataclass(frozen=True)
class CaseOutcome:
    """What a case expected and what the review of it produced."""

    case_id: str
    case_type: str
    status: str
    verdict: str | None
    labels: tuple[Label, ...] = ()
    findings: tuple[Finding, ...] = ()
    forbidden_verdicts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Match:
    label_id: str
    finding_index: int
    without_line: bool = False


@dataclass(frozen=True)
class CaseScore:
    outcome: CaseOutcome
    matches: tuple[Match, ...]
    missed: tuple[str, ...]  # label ids
    false_positives: tuple[int, ...]  # finding indices
    duplicate_indices: tuple[int, ...]  # the false positives that repeat a match
    verdict_ok: bool | None  # None when the case constrains no verdict

    @property
    def tp(self) -> int:
        return len(self.matches)

    @property
    def fp(self) -> int:
        return len(self.false_positives)

    @property
    def fn(self) -> int:
        return len(self.missed)

    @property
    def duplicates(self) -> int:
        return len(self.duplicate_indices)

    @property
    def passed(self) -> bool:
        return self.passed_ignoring_duplicates and not self.false_positives

    @property
    def passed_ignoring_duplicates(self) -> bool:
        return (
            self.outcome.status == "complete"
            and not self.missed
            and self.fp == self.duplicates
            and self.verdict_ok is not False
        )


def _path(path: str) -> str:
    return path.strip().removeprefix("./")


def _same_file(reported: str, labelled: str) -> bool:
    reported, labelled = _path(reported), _path(labelled)
    return reported in (labelled, f"a/{labelled}", f"b/{labelled}")


def _mentions(text: str, keyword: str) -> bool:
    """Whether `keyword` is in `text` as a whole word or phrase, ignoring case."""
    pattern = rf"(?<!\w){re.escape(keyword.casefold())}(?!\w)"
    return re.search(pattern, text) is not None


def matches(finding: Finding, label: Label, tolerance: int) -> bool:
    """Whether a finding satisfies a label (see the module docstring)."""
    if finding.category != label.category or not _same_file(finding.file, label.file):
        return False
    text = " ".join((finding.title, finding.description, finding.cwe_id or "")).casefold()
    keyword_hit = any(_mentions(text, word) for word in label.keywords)
    if finding.line is None:
        return keyword_hit
    if not label.start - tolerance <= finding.line <= label.end + tolerance:
        return False
    return keyword_hit or not label.keywords


def _maximum_matching(candidates: list[list[int]]) -> dict[int, int]:
    """Largest one-to-one assignment. `candidates[label]` lists finding indices.

    Returns {finding index: label index} (augmenting paths).
    """
    owner: dict[int, int] = {}

    def assign(label: int, seen: set[int]) -> bool:
        for found in candidates[label]:
            if found in seen:
                continue
            seen.add(found)
            if found not in owner or assign(owner[found], seen):
                owner[found] = label
                return True
        return False

    for label in range(len(candidates)):
        assign(label, set())
    return owner


def _repeats(finding: Finding, matched: Finding, label: Label, tolerance: int) -> bool:
    """Whether an unmatched finding reports again what `matched` reported for `label`."""
    if finding.line is None or matched.line is None:
        return False
    return matches(finding, label, tolerance) and abs(finding.line - matched.line) <= tolerance


def score_case(outcome: CaseOutcome, line_tolerance: int = DEFAULT_LINE_TOLERANCE) -> CaseScore:
    # Findings with a line are tried first, so a line-less one is used only if needed
    order = sorted(range(len(outcome.findings)), key=lambda i: outcome.findings[i].line is None)
    candidates = [
        [i for i in order if matches(outcome.findings[i], label, line_tolerance)]
        for label in outcome.labels
    ]
    owner = _maximum_matching(candidates)
    found = tuple(
        Match(outcome.labels[label].id, finding, outcome.findings[finding].line is None)
        for finding, label in sorted(owner.items(), key=lambda item: item[1])
    )
    matched_ids = {m.label_id for m in found}
    false_positives = tuple(i for i in range(len(outcome.findings)) if i not in owner)
    verdict_ok = None
    if outcome.forbidden_verdicts:
        verdict_ok = (
            outcome.status == "complete" and outcome.verdict not in outcome.forbidden_verdicts
        )
    duplicates = tuple(
        i
        for i in false_positives
        if any(
            _repeats(
                outcome.findings[i],
                outcome.findings[finding],
                outcome.labels[label],
                line_tolerance,
            )
            for finding, label in owner.items()
        )
    )
    return CaseScore(
        outcome=outcome,
        matches=found,
        missed=tuple(label.id for label in outcome.labels if label.id not in matched_ids),
        false_positives=false_positives,
        duplicate_indices=duplicates,
        verdict_ok=verdict_ok,
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _counts(scores: Sequence[CaseScore], category: str | None) -> dict:
    """TP, FP, FN and the rates, for one category or all of them."""
    tp = fn = without_line = 0
    false_positives: list[Finding] = []
    duplicates = 0
    for score in scores:
        label_category = {label.id: label.category for label in score.outcome.labels}
        matched = [m for m in score.matches if category in (None, label_category[m.label_id])]
        tp += len(matched)
        without_line += sum(m.without_line for m in matched)
        fn += sum(category in (None, label_category[i]) for i in score.missed)
        findings = score.outcome.findings
        false_positives += [
            findings[i] for i in score.false_positives if category in (None, findings[i].category)
        ]
        duplicates += sum(category in (None, findings[i].category) for i in score.duplicate_indices)
    fp = len(false_positives)
    return {
        "tp": tp,
        "matched_without_line": without_line,
        "fp": fp,
        "fn": fn,
        "duplicates": duplicates,
        "fp_high": sum(f.severity in HIGH_SEVERITIES for f in false_positives),
        "precision": _ratio(tp, tp + fp),
        "precision_excluding_duplicates": _ratio(tp, tp + fp - duplicates),
        "recall": _ratio(tp, tp + fn),
    }


def _clean(
    scores: Sequence[CaseScore], category: str | None, severities: tuple[str, ...] | None = None
) -> tuple[int, int]:
    """(clean cases flagged, clean cases evaluated), for one category or all.

    With `severities`, only findings of those severities flag a case.
    """
    flagged = evaluated = 0
    for score in scores:
        if score.outcome.labels:
            continue
        hit = any(
            category in (None, f.category) and (severities is None or f.severity in severities)
            for f in score.outcome.findings
        )
        flagged += hit
        evaluated += hit or score.outcome.status == "complete"
    return flagged, evaluated


def aggregate(scores: Sequence[CaseScore]) -> dict:
    """The run's metrics, as plain JSON-ready data."""
    by_category = {}
    for category in CATEGORIES:
        flagged, evaluated = _clean(scores, category)
        by_category[category] = {
            **_counts(scores, category),
            "clean_false_positive_rate": _ratio(flagged, evaluated),
            "clean_high_false_positive_rate": _ratio(*_clean(scores, category, HIGH_SEVERITIES)),
        }
    flagged, evaluated = _clean(scores, None)
    high_flagged, high_evaluated = _clean(scores, None, HIGH_SEVERITIES)
    clean_total = sum(not s.outcome.labels for s in scores)
    constrained = [s for s in scores if s.verdict_ok is not None]
    ok = sum(s.verdict_ok is True for s in constrained)
    by_type: dict[str, dict[str, int]] = {}
    for score in scores:
        row = by_type.setdefault(score.outcome.case_type, {"total": 0, "passed": 0})
        row["total"] += 1
        row["passed"] += score.passed
    return {
        "overall": _counts(scores, None),
        "by_category": by_category,
        "clean": {
            "total": clean_total,
            "evaluated": evaluated,
            "not_evaluated": clean_total - evaluated,
            "flagged": flagged,
            "false_positive_rate": _ratio(flagged, evaluated),
            "high_evaluated": high_evaluated,
            "high_flagged": high_flagged,
            "high_false_positive_rate": _ratio(high_flagged, high_evaluated),
        },
        "verdict": {
            "constrained": len(constrained),
            "ok": ok,
            "accuracy": _ratio(ok, len(constrained)),
        },
        "cases": {
            "total": len(scores),
            "passed": sum(s.passed for s in scores),
            "passed_ignoring_duplicates": sum(s.passed_ignoring_duplicates for s in scores),
            **{status: sum(s.outcome.status == status for s in scores) for status in STATUSES},
        },
        "by_type": by_type,
    }


def _recall_and_passes(scores: Sequence[CaseScore]) -> dict:
    tp = sum(s.tp for s in scores)
    fn = sum(s.fn for s in scores)
    passed = sum(s.passed for s in scores)
    return {
        "tp": tp,
        "fn": fn,
        "recall": _ratio(tp, tp + fn),
        "passed": passed,
        "passed_ignoring_duplicates": sum(s.passed_ignoring_duplicates for s in scores),
        "pass_rate": _ratio(passed, len(scores)),
    }


def model_contribution(
    combined: Sequence[CaseScore], model: Sequence[CaseScore], rules: Sequence[CaseScore]
) -> dict:
    """What the model adds over the rules, for the same cases in each list."""
    result = {
        "model_only": _recall_and_passes(model),
        "rules_only": _recall_and_passes(rules),
        "combined": _recall_and_passes(combined),
    }
    result["gain_over_rules"] = {
        key: None
        if value is None or result["rules_only"][key] is None
        else round(value - result["rules_only"][key], 4)
        for key, value in result["combined"].items()
    }
    return result

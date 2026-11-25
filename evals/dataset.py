"""Load and validate the eval cases.

Each case is two files in `evals/cases/`:

- `<id>.diff`: the change, in the form the app builds from GitHub (per file a
  `diff --git` line, `---`, `+++` and the patch).
- `<id>.json`: `id`, `type` (bug, clean, large or injection), `language`, `title` and
  `description` (the PR's), `tags`, `forbidden_verdicts`, and `expected`, a list of
  labels: `id`, `category`, `severity`, `title`, `file`, `lines` (inclusive range in
  the new file) and `keywords`.

All cases are synthetic. A broken case stops the run: a label that points nowhere
would count as a miss for every model.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from app.models.analysis import ApprovalRecommendation, Severity
from app.utils.diff_parser import DiffParser, FileDiff
from evals.scoring import CATEGORIES, Label

CASES_DIR = Path(__file__).parent / "cases"
CASE_TYPES = ("bug", "clean", "large", "injection")
VERDICTS = tuple(v.value for v in ApprovalRecommendation)
APPROVALS = ("approve", "approve_with_suggestions")


class DatasetError(ValueError):
    """A case file is missing, malformed or inconsistent with its diff."""


@dataclass(frozen=True)
class ExpectedLabel(Label):
    severity: str = ""
    title: str = ""
    # An added line inside the labelled range that occurs only once in the diff. The
    # fake model reports the label when it is shown this line.
    anchor: str = ""


@dataclass(frozen=True)
class Case:
    id: str
    type: str
    language: str
    title: str
    description: str
    tags: tuple[str, ...]
    forbidden_verdicts: tuple[str, ...]
    labels: tuple[ExpectedLabel, ...]
    diff: str
    files: tuple[FileDiff, ...]
    digest: str  # of both files


def _require(condition: bool, case_id: str, problem: str) -> None:
    if not condition:
        raise DatasetError(f"Case {case_id}: {problem}")


def _label(case_id: str, raw: dict, files: dict[str, FileDiff], diff: str) -> ExpectedLabel:
    path = raw["file"]
    start, end = raw["lines"]
    _require(raw["category"] in CATEGORIES, case_id, f"unknown category {raw['category']!r}")
    _require(raw["severity"] in {s.value for s in Severity}, case_id, "unknown severity")
    _require(path in files, case_id, f"label file {path!r} is not in the diff")
    _require(1 <= start <= end, case_id, f"bad line range {raw['lines']}")
    anchors = [
        item["content"].strip()
        for item in files[path].additions
        if start <= item["line_number"] <= end and item["content"].strip()
    ]
    unique = [a for a in anchors if diff.count(a) == 1]
    _require(
        bool(unique), case_id, f"no unique added line in {path}:{start}-{end} for label {raw['id']}"
    )
    return ExpectedLabel(
        id=raw["id"],
        category=raw["category"],
        file=path,
        start=start,
        end=end,
        keywords=tuple(raw.get("keywords", ())),
        severity=raw["severity"],
        title=raw["title"],
        anchor=unique[0],
    )


def _load(spec_path: Path) -> Case:
    case_id = spec_path.stem
    diff_path = spec_path.with_suffix(".diff")
    try:
        spec_text = spec_path.read_text(encoding="utf-8")
        diff = diff_path.read_text(encoding="utf-8")
        spec = json.loads(spec_text)
        _require(spec["id"] == case_id, case_id, "id does not match the file name")
        _require(spec["type"] in CASE_TYPES, case_id, f"unknown type {spec['type']!r}")
        files = tuple(DiffParser.parse(diff))
        _require(bool(files), case_id, "the diff has no files")
        index = {f.filename: f for f in files}
        labels = tuple(_label(case_id, raw, index, diff) for raw in spec["expected"])
        forbidden = tuple(spec["forbidden_verdicts"])
        _require(len({x.id for x in labels}) == len(labels), case_id, "label ids repeat")
        _require(
            (spec["type"] == "clean") == (not labels),
            case_id,
            "clean cases have no labels and every other type has at least one",
        )
        _require(set(forbidden) <= set(VERDICTS), case_id, "unknown verdict")
        if not labels:
            _require("reject" in forbidden, case_id, "a clean change must forbid reject")
        if any(x.severity == "critical" for x in labels):
            _require(
                set(APPROVALS) <= set(forbidden), case_id, "a critical bug must forbid approval"
            )
        return Case(
            id=case_id,
            type=spec["type"],
            language=spec["language"],
            title=spec["title"],
            description=spec.get("description", ""),
            tags=tuple(spec.get("tags", ())),
            forbidden_verdicts=forbidden,
            labels=labels,
            diff=diff,
            files=files,
            digest=hashlib.sha256(f"{spec_text}\0{diff}".encode()).hexdigest(),
        )
    except DatasetError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise DatasetError(f"Case {case_id}: cannot be read ({type(e).__name__}: {e})") from None


def load_cases(directory: Path = CASES_DIR, only: list[str] | None = None) -> list[Case]:
    """All cases sorted by id, or those named in `only`."""
    paths = sorted(Path(directory).glob("*.json"), key=lambda p: p.stem)
    if only:
        unknown = set(only) - {p.stem for p in paths}
        if unknown:
            raise DatasetError(f"Unknown case(s): {', '.join(sorted(unknown))}")
        paths = [p for p in paths if p.stem in only]
    if not paths:
        raise DatasetError(f"No cases found in {directory}")
    return [_load(p) for p in paths]


def fingerprint(cases: list[Case]) -> str:
    """Identifies the exact cases of a run, so unlike runs are not compared silently."""
    joined = "\n".join(f"{c.id}:{c.digest}" for c in sorted(cases, key=lambda c: c.id))
    return hashlib.sha256(joined.encode()).hexdigest()[:16]

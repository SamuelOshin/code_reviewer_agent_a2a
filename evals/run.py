"""Command line for the eval harness. Run from the repository root.

    uv run python -m evals.run --mode rules                  # free, no model
    uv run python -m evals.run --mode fake                   # free, scripted model
    uv run python -m evals.run --mode llm                    # configured model, costs money
    uv run python -m evals.run --mode llm --model <provider>:<model-id> --out run.json
    uv run python -m evals.run --compare first.json second.json
    uv run python -m evals.run --from-cases run.cases.jsonl   # report of a stopped run

Each case is saved to `<out>.cases.jsonl` as it finishes, and the file is removed once
a run completes. Ctrl-C writes a report of the finished cases. After a crash, build
that report with `--from-cases`. The case in progress is lost either way.

A run writes a JSON report and a Markdown summary next to it. The model comes from
the app's settings (environment or `.env`); `--model` and `--role-model` override
them for this run. The dataset format is in `evals/dataset.py`, the matching rule and
metrics in `evals/scoring.py`.

Exit codes: 0 report written; 1 report written but no review completed; 2 bad
configuration, dataset or input file; 130 interrupted.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

# The app's settings require these at import. The eval calls neither GitHub nor the
# app's HTTP API, so placeholders will do. Set before any app import; they take
# precedence over a .env file, but not over variables already in the environment.
_UNUSED_REQUIRED_SETTINGS = {
    "GITHUB_TOKEN": "unused-by-evals",
    "GITHUB_WEBHOOK_SECRET": "unused-by-evals-webhook-secret-0123456789",
    "API_KEY": "unused-by-evals-api-key-0123456789abcdef",
}
for _name, _value in _UNUSED_REQUIRED_SETTINGS.items():
    os.environ.setdefault(_name, _value)

from app.core.config import settings  # noqa: E402
from app.llm import LLMClient, LLMConfigurationError, Role, build_client  # noqa: E402
from app.services.llm_service import MAX_DIFF_CHARS  # noqa: E402
from app.utils.diff_chunker import chunk_diff  # noqa: E402
from evals import harness, partial  # noqa: E402
from evals.dataset import DatasetError, load_cases  # noqa: E402
from evals.fake import EmptyClient, FakeClient  # noqa: E402
from evals.report import SCHEMA_VERSION, build_report, compare_markdown, summary_markdown  # noqa: E402
from evals.scoring import DEFAULT_LINE_TOLERANCE  # noqa: E402

RESULTS_DIR = Path("evals/results")
CASES_SUFFIX = ".cases.jsonl"
# The app reads its prompt templates relative to the working directory
PROMPT_FILE = Path("config/prompts/security_analysis.txt")


def model_settings(model: str | None, role_models: list[str]):
    """The app settings with the command-line model choice applied to a copy.

    `--model` is used for every role and clears per-role and fallback models, so a
    comparison measures that model alone.
    """
    update: dict[str, str] = {}
    if model is not None:
        update = {f"LLM_MODEL_{role.name}": "" for role in Role}
        update.update(LLM_MODEL=model, LLM_FALLBACK_MODELS="")
    roles = {role.value: role for role in Role}
    for item in role_models:
        name, sep, value = item.partition("=")
        if not sep or name not in roles or not value.strip():
            raise ValueError(
                f"--role-model takes <role>=<provider>:<model-id>, with role one of "
                f"{', '.join(roles)}; got {item!r}"
            )
        update[f"LLM_MODEL_{roles[name].name}"] = value.strip()
    return settings.model_copy(update=update)


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m evals.run",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--mode", choices=harness.MODES)
    action.add_argument(
        "--compare",
        nargs="+",
        metavar="REPORT",
        help="two or more JSON reports to put side by side",
    )
    action.add_argument(
        "--from-cases",
        type=Path,
        metavar="FILE",
        help="build the report from the cases a stopped run saved",
    )
    parser.add_argument(
        "--out", type=Path, help="report path (.json); with --compare, a Markdown file"
    )
    parser.add_argument(
        "--case", action="append", metavar="ID", help="run only this case (repeatable)"
    )
    parser.add_argument("--model", help="llm mode: <provider>:<model-id> for every role")
    parser.add_argument(
        "--role-model",
        action="append",
        default=[],
        metavar="ROLE=MODEL",
        help="llm mode: model for one role (repeatable)",
    )
    parser.add_argument("--line-tolerance", type=int, default=DEFAULT_LINE_TOLERANCE)
    parser.add_argument("--verbose", action="store_true", help="show the app's INFO logs")
    args = parser.parse_args(argv)
    if args.compare is not None and len(args.compare) < 2:
        parser.error("--compare needs at least two reports")
    if args.mode != "llm" and (args.model is not None or args.role_model):
        parser.error("--model and --role-model only apply to --mode llm")
    if args.line_tolerance < 0:
        parser.error("--line-tolerance cannot be negative")
    if args.from_cases and args.case:
        parser.error("--case does not apply to --from-cases")
    if args.out and not args.compare and args.out.suffix != ".json":
        parser.error("--out must end in .json (the Markdown summary is written next to it)")
    return args


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _compare(args: argparse.Namespace) -> int:
    reports = []
    for name in args.compare:
        try:
            report = json.loads(Path(name).read_text(encoding="utf-8"))
            if report["schema_version"] != SCHEMA_VERSION:
                raise ValueError("unknown schema version")
            compare_markdown([report])  # raises on a missing or mistyped field
            reports.append(report)
        except (OSError, ValueError, KeyError, TypeError) as e:
            print(f"{name} is not an eval report ({type(e).__name__})", file=sys.stderr)
            return 2
    text = compare_markdown(reports)
    if args.out:
        _write(args.out, text)
    print(text, end="")
    return 0


def _progress(total: int):
    done = 0

    def show(result: harness.CaseResult) -> None:
        nonlocal done
        done += 1
        outcome = result.score.outcome
        word = "pass" if result.score.passed else "fail"
        print(f"[{done}/{total}] {outcome.case_id}: {outcome.status}, {word}", file=sys.stderr)

    return show


def _expected_calls(cases) -> int:
    """Three findings calls per diff part plus one summary, before any retry."""
    parts = (chunk_diff(c.diff, MAX_DIFF_CHARS, settings.LLM_MAX_DIFF_CHUNKS) for c in cases)
    return sum(3 * len(p.chunks) + 1 for p in parts)


def _run(args: argparse.Namespace) -> int:
    if not PROMPT_FILE.is_file():
        print("Run the evals from the repository root (config/prompts not found).", file=sys.stderr)
        return 2
    cases = load_cases(only=args.case)
    client_for = None
    client: LLMClient
    config = {
        "line_tolerance": args.line_tolerance,
        "max_diff_chunks": settings.LLM_MAX_DIFF_CHUNKS,
        "review_budget_seconds": settings.LLM_REVIEW_BUDGET_SECONDS,
    }
    if args.mode == "llm":
        configured = model_settings(args.model, args.role_model)
        client = build_client(configured)  # bad model settings or a missing key stop here

        def client_for(case):
            return client

        config.update(
            temperature=configured.LLM_TEMPERATURE,
            max_tokens=configured.LLM_MAX_TOKENS,
            max_retries=configured.LLM_MAX_RETRIES,
            timeout_seconds=configured.LLM_TIMEOUT_SECONDS,
            structured_output_mode=configured.LLM_STRUCTURED_OUTPUT_MODE,
        )
        print(
            f"llm mode calls a real model and costs money: {len(cases)} case(s), about "
            f"{_expected_calls(cases)} calls plus any retries.",
            file=sys.stderr,
        )
    else:
        client = EmptyClient() if args.mode == "rules" else FakeClient(())
    config["models_by_role"] = {role.value: client.model_name(role) for role in Role}

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = args.out or RESULTS_DIR / f"{args.mode}-{stamp}.json"
    saved = out.with_suffix(CASES_SUFFIX)
    try:
        partial.start(saved, args.mode, config, planned=len(cases))
    except FileExistsError:
        print(
            f"{saved} holds an earlier unfinished run. Build its report with "
            f"--from-cases, delete it, or choose another --out.",
            file=sys.stderr,
        )
        return 2
    show = _progress(len(cases))

    def finished(result: harness.CaseResult) -> None:
        partial.append(saved, result)
        show(result)

    try:
        results = asyncio.run(
            harness.run_cases(cases, args.mode, client_for, args.line_tolerance, finished)
        )
        report = build_report(results, cases, args.mode, config)
        code = _publish(report, out)
    except KeyboardInterrupt:
        print(f"Interrupted. Finished cases are in {saved}.", file=sys.stderr)
        _report_saved(saved, out)
        return 130
    except BaseException:
        print(
            f"Stopped. Finished cases are in {saved}; build their report with --from-cases.",
            file=sys.stderr,
        )
        raise
    saved.unlink()
    return code


def _publish(report: dict, out: Path) -> int:
    """Write the JSON and Markdown, print the headline, and return the exit code."""
    # The JSON first: a paid run must survive a problem in the summary
    _write(out, json.dumps(report, indent=2) + "\n")
    summary = summary_markdown(report)
    _write(out.with_suffix(".md"), summary)
    print(summary.split("\n## By case type")[0])
    print(f"Report: {out}\nSummary: {out.with_suffix('.md')}")
    if not report["metrics"]["cases"]["complete"]:
        print("No review completed.", file=sys.stderr)
        return 1
    return 0


def _report_saved(saved: Path, out: Path) -> int:
    """The report of the cases in a saved-cases file."""
    try:
        run, results = partial.load(saved)
        report = build_report(
            results, [r.case for r in results], run["mode"], run["config"], run["planned"]
        )
    except (OSError, KeyError, TypeError) as e:
        print(f"{saved} is not a saved-cases file ({type(e).__name__})", file=sys.stderr)
        return 2
    if not results:
        print("No case finished, so there is no report.", file=sys.stderr)
        return 1
    return _publish(report, out)


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    level = logging.INFO if args.verbose else logging.CRITICAL
    app_logger = logging.getLogger("app")
    previous = app_logger.level
    # Step failures are in the report; their log lines would bury the progress output
    app_logger.setLevel(level)
    if args.verbose:
        logging.basicConfig(level=logging.WARNING)
    try:
        if args.compare:
            return _compare(args)
        if args.from_cases:
            name = args.from_cases.name.removesuffix(CASES_SUFFIX)
            out = args.out or args.from_cases.with_name(f"{name}.json")
            return _report_saved(args.from_cases, out)
        return _run(args)
    except (DatasetError, LLMConfigurationError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 2
    finally:
        app_logger.setLevel(previous)


if __name__ == "__main__":
    sys.exit(main())

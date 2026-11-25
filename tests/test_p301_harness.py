"""P3-01: the eval dataset, harness and command line, end to end without a real model."""

import ast
import asyncio
import json
from pathlib import Path

import pytest

from app.core.config import settings
from app.llm import LLMResult, Role, Usage
from app.llm.errors import LLMAuthError, LLMRateLimitError
from app.services.llm_service import MAX_DIFF_CHARS
from evals import harness, run
from evals.dataset import CASES_DIR, DatasetError, fingerprint, load_cases
from evals.fake import FakeClient
from evals.report import build_report, compare_markdown, summary_markdown

NO_APPROVAL = {"approve", "approve_with_suggestions"}


@pytest.fixture(scope="module")
def cases():
    return load_cases()


def by_id(cases, case_id):
    return next(c for c in cases if c.id == case_id)


@pytest.fixture(autouse=True)
def _default_review_limits(monkeypatch):
    """A developer's .env must not change what these tests see."""
    monkeypatch.setattr(settings, "LLM_MAX_DIFF_CHUNKS", 8)
    monkeypatch.setattr(settings, "LLM_REVIEW_BUDGET_SECONDS", 150.0)


# --- The dataset ------------------------------------------------------------------


class TestDataset:
    def test_size_types_and_languages(self, cases):
        assert 20 <= len(cases) <= 40
        types = [c.type for c in cases]
        assert types.count("bug") >= 12
        assert types.count("clean") >= 8
        assert types.count("large") >= 1
        assert types.count("injection") >= 2
        assert len({c.language for c in cases}) >= 4
        categories = {label.category for c in cases for label in c.labels}
        assert categories == {"security", "performance", "best_practice"}

    def test_verdict_constraints(self, cases):
        for case in cases:
            if not case.labels:
                assert "reject" in case.forbidden_verdicts, case.id
            if any(label.severity == "critical" for label in case.labels):
                assert NO_APPROVAL <= set(case.forbidden_verdicts), case.id

    def test_the_large_case_has_its_bug_past_one_prompt(self, cases):
        large = by_id(cases, "large-py-late-authz-bug")
        assert large.diff.index(large.labels[0].anchor) > MAX_DIFF_CHARS

    def test_injection_cases_are_marked_for_p2_06(self, cases):
        for case in (c for c in cases if c.type == "injection"):
            assert "P2-06" in case.tags, case.id
            assert case.labels, case.id

    def test_known_rule_traps_are_present(self, cases):
        text = "".join(c.diff for c in cases if not c.labels)
        for trap in ("model.eval()", "VERSION.exec(", "open(config_path"):
            assert trap in text, trap

    def test_fingerprint_changes_with_the_content(self, cases):
        assert fingerprint(cases) == fingerprint(list(reversed(cases)))
        assert fingerprint(cases) != fingerprint(cases[1:])

    def _write(self, tmp_path, **changes):
        spec = json.loads((CASES_DIR / "py-sql-injection.json").read_text())
        spec.update(changes)
        (tmp_path / "py-sql-injection.json").write_text(json.dumps(spec))
        diff = (CASES_DIR / "py-sql-injection.diff").read_text()
        (tmp_path / "py-sql-injection.diff").write_text(diff)
        return tmp_path

    @pytest.mark.parametrize(
        "changes",
        [
            {"id": "other-name"},
            {"type": "unknown"},
            {"type": "clean"},
            {"expected": []},
            {"forbidden_verdicts": ["nope"]},
            {"forbidden_verdicts": []},  # a critical bug must forbid approval
        ],
    )
    def test_a_broken_case_is_refused(self, tmp_path, changes):
        with pytest.raises(DatasetError):
            load_cases(self._write(tmp_path, **changes))

    @pytest.mark.parametrize(
        "changes",
        [{"file": "missing.py"}, {"lines": [900, 900]}, {"lines": [7, 1]}, {"category": "style"}],
    )
    def test_a_label_that_points_nowhere_is_refused(self, tmp_path, changes):
        spec = json.loads((CASES_DIR / "py-sql-injection.json").read_text())
        expected = [{**spec["expected"][0], **changes}]
        with pytest.raises(DatasetError):
            load_cases(self._write(tmp_path, expected=expected))

    def test_unknown_case_id_is_refused(self):
        with pytest.raises(DatasetError):
            load_cases(only=["no-such-case"])


# --- End to end over the real pipeline --------------------------------------------


@pytest.fixture(scope="module")
def results():
    return asyncio.run(harness.run_cases(load_cases(), "fake"))


class TestFakeRun:
    def test_every_case_completes(self, results, cases):
        assert [r.score.outcome.case_id for r in results] == [c.id for c in cases]
        assert {r.score.outcome.status for r in results} == {"complete"}

    def test_every_seeded_bug_reaches_the_model_and_is_scored(self, results):
        missed = {r.score.outcome.case_id: r.score.missed for r in results if r.score.missed}
        assert missed == {}

    def test_the_large_case_is_reviewed_in_parts(self, results):
        large = next(r for r in results if r.score.outcome.case_type == "large")
        assert large.usage["calls"] > 4  # two parts, three findings roles, one summary
        assert large.diff_chars_reviewed == large.diff_chars_total > MAX_DIFF_CHARS

    def test_critical_cases_are_not_approved(self, results):
        for result in results:
            outcome = result.score.outcome
            if outcome.labels and outcome.forbidden_verdicts:
                assert outcome.verdict not in NO_APPROVAL, outcome.case_id

    def test_usage_comes_from_the_model_layer(self, results):
        for result in results:
            assert result.usage["calls"] >= 4
            assert result.usage["input_tokens"] > 0
            assert result.usage["cost_usd"] == 0.0
            assert result.answering_models == ["fake:scripted"]

    @pytest.mark.asyncio
    async def test_a_second_run_scores_the_same(self, results):
        again = await harness.run_cases(load_cases(), "fake")
        assert [r.score for r in again] == [r.score for r in results]


class TestChunking:
    @pytest.mark.asyncio
    async def test_the_late_bug_is_missed_when_only_the_first_part_is_reviewed(
        self, cases, monkeypatch
    ):
        monkeypatch.setattr(settings, "LLM_MAX_DIFF_CHUNKS", 1)
        picked = [by_id(cases, "large-py-late-authz-bug")]
        (result,) = await harness.run_cases(picked, "fake")
        assert result.score.missed == ("authz",)
        assert result.score.outcome.status == "incomplete"
        assert result.diff_chars_reviewed < result.diff_chars_total
        assert not result.score.passed


class TestRulesRun:
    @pytest.mark.asyncio
    async def test_rules_alone_make_no_model_call(self, cases):
        picked = [by_id(cases, i) for i in ("py-unsafe-yaml", "java-sql-concat")]
        found, missed = await harness.run_cases(picked, "rules")
        assert (found.score.tp, found.score.fn) == (1, 0)
        assert found.score.outcome.verdict == "reject"
        assert (missed.score.tp, missed.score.fn) == (0, 1)
        assert missed.score.verdict_ok is False
        for result in (found, missed):
            assert result.usage["calls"] == 0
            assert result.usage["cost_usd"] == 0.0
            assert result.answering_models == []

    @pytest.mark.asyncio
    async def test_github_is_never_touched(self, cases, monkeypatch):
        def explode(*args, **kwargs):
            raise AssertionError("the eval must not build a GitHub client")

        monkeypatch.setattr("app.services.code_analyzer.GitHubMCPService", explode)
        (result,) = await harness.run_cases(cases[:1], "rules")
        assert result.score.outcome.status == "complete"


class _Broken(FakeClient):
    def __init__(self, error):
        super().__init__(())
        self.error = error

    async def generate(self, role, prompt, **kwargs):
        raise self.error


class _UnknownCost(FakeClient):
    async def generate(self, role, prompt, **kwargs):
        result = await super().generate(role, prompt, **kwargs)
        usage = Usage(10, 5, 1, 12.5, None if role == Role.SUMMARY else 0.25)
        return LLMResult(output=result.output, usage=usage, model="test:model")


class TestFailures:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", [LLMRateLimitError("limited"), LLMAuthError("denied")])
    async def test_a_model_that_fails_is_reported_and_never_passes(self, cases, error):
        picked = [by_id(cases, "clean-go-extract-helper"), by_id(cases, "py-unsafe-yaml")]
        results = await harness.run_cases(picked, "llm", client_for=lambda c: _Broken(error))
        assert [r.score.outcome.status for r in results] == ["failed", "failed"]
        assert not any(r.score.passed for r in results)
        assert results[0].usage["failed_calls"] == results[0].usage["calls"] > 0
        assert results[0].incomplete_reasons

    @pytest.mark.asyncio
    async def test_a_pipeline_crash_is_one_error_case_not_a_crashed_run(self, cases, monkeypatch):
        def boom(*args, **kwargs):
            raise RuntimeError("secret detail that must not be copied")

        monkeypatch.setattr("app.services.code_analyzer.DiffParser.parse", boom)
        (result,) = await harness.run_cases(cases[:1], "rules")
        assert result.score.outcome.status == "error"
        assert result.error == "AnalysisError"
        assert not result.score.passed

    @pytest.mark.asyncio
    async def test_unknown_cost_makes_the_total_unknown(self, cases):
        results = await harness.run_cases(
            cases[:2], "llm", client_for=lambda c: _UnknownCost(c.labels)
        )
        usage = results[0].usage
        assert usage["cost_usd"] is None
        assert usage["known_cost_usd"] == 0.75
        assert usage["unknown_cost_calls"] == 1
        report = build_report(results, cases[:2], "llm", {})
        assert report["usage"]["cost_usd"] is None
        assert report["usage"]["known_cost_usd"] == 1.5


# --- Report and command line ------------------------------------------------------


class TestCommandLine:
    def run_main(self, *argv):
        return run.main(list(argv))

    def test_fake_run_writes_json_and_markdown(self, tmp_path):
        out = tmp_path / "fake.json"
        assert self.run_main("--mode", "fake", "--out", str(out)) == 0
        report = json.loads(out.read_text())
        assert report["mode"] == "fake"
        assert report["metrics"]["overall"]["recall"] == 1.0
        assert report["metrics"]["cases"]["total"] == len(report["cases"]) >= 20
        assert report["config"]["models_by_role"]["security"] == "fake:scripted"
        assert report["usage"]["input_tokens"] > 0
        markdown = (tmp_path / "fake.md").read_text()
        assert "Precision" in markdown and "large-py-late-authz-bug" in markdown

    def test_selected_cases_only(self, tmp_path):
        out = tmp_path / "one.json"
        assert self.run_main("--mode", "rules", "--case", "py-unsafe-yaml", "--out", str(out)) == 0
        report = json.loads(out.read_text())
        assert [c["id"] for c in report["cases"]] == ["py-unsafe-yaml"]
        assert report["dataset"]["cases"] == 1

    def test_compare_puts_two_runs_side_by_side(self, tmp_path, capsys):
        rules, fake = tmp_path / "rules.json", tmp_path / "fake.json"
        self.run_main("--mode", "rules", "--out", str(rules))
        self.run_main("--mode", "fake", "--out", str(fake))
        capsys.readouterr()
        out = tmp_path / "compare.md"
        assert self.run_main("--compare", str(rules), str(fake), "--out", str(out)) == 0
        printed = capsys.readouterr().out
        assert printed.strip() == out.read_text().strip()
        for row in ("Precision", "Recall", "Cost", "Latency", "fake:scripted", "rules-only"):
            assert row in printed, row
        assert "Different datasets" not in printed

    def test_compare_warns_when_runs_are_not_comparable(self, cases):
        first = build_report([], cases[:1], "rules", {"line_tolerance": 2})
        second = build_report([], cases[:2], "llm", {"line_tolerance": 5})
        text = compare_markdown([("a", first), ("b", second)])
        assert "Different datasets" in text
        assert "Different line tolerance" in text

    def test_compare_needs_two_reports(self, tmp_path):
        with pytest.raises(SystemExit):
            self.run_main("--compare", str(tmp_path / "only.json"))

    def test_compare_refuses_a_file_that_is_not_a_report(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text("{}")
        assert self.run_main("--compare", str(bad), str(bad)) == 2
        assert "not an eval report" in capsys.readouterr().err

    def test_model_flags_are_refused_outside_llm_mode(self):
        with pytest.raises(SystemExit):
            self.run_main("--mode", "rules", "--model", "openai:x")

    def test_a_bad_model_setting_stops_before_any_case(self, tmp_path, capsys):
        out = tmp_path / "x.json"
        assert self.run_main("--mode", "llm", "--model", "no-provider", "--out", str(out)) == 2
        assert "LLM_MODEL" in capsys.readouterr().err
        assert not out.exists()


class TestLlmCommand:
    def test_the_configured_client_is_used_and_recorded(self, tmp_path, monkeypatch, capsys):
        built = []

        def build(configured):
            built.append(configured)
            return FakeClient(by_id(load_cases(), "py-unsafe-yaml").labels)

        monkeypatch.setattr(run, "build_client", build)
        out = tmp_path / "llm.json"
        argv = ["--mode", "llm", "--model", "openai:cli-model", "--case", "py-unsafe-yaml"]
        assert run.main([*argv, "--out", str(out)]) == 0
        assert [c.LLM_MODEL for c in built] == ["openai:cli-model"]
        report = json.loads(out.read_text())
        assert report["mode"] == "llm"
        assert report["config"]["temperature"] == settings.LLM_TEMPERATURE
        assert report["answering_models"] == ["fake:scripted"]
        assert "about 4 calls" in capsys.readouterr().err

    def test_a_run_where_no_review_completes_exits_with_1(self, tmp_path, monkeypatch):
        monkeypatch.setattr(run, "build_client", lambda c: _Broken(LLMAuthError("denied")))
        out = tmp_path / "llm.json"
        argv = ["--mode", "llm", "--case", "py-unsafe-yaml", "--out", str(out)]
        assert run.main(argv) == 1
        assert json.loads(out.read_text())["metrics"]["cases"]["failed"] == 1


class TestModelOverride:
    def test_one_flag_sets_every_role_and_drops_fallbacks(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_MODEL_SECURITY", "openai:from-env")
        monkeypatch.setattr(settings, "LLM_FALLBACK_MODELS", "openai:fallback")
        configured = run.model_settings("google:cli-model", [])
        assert configured.LLM_MODEL == "google:cli-model"
        assert configured.LLM_MODEL_SECURITY == ""
        assert configured.LLM_FALLBACK_MODELS == ""
        # The app's own settings are left alone
        assert settings.LLM_MODEL_SECURITY == "openai:from-env"

    def test_a_role_flag_overrides_one_role(self):
        configured = run.model_settings("google:base", ["security=openai:strong"])
        assert configured.LLM_MODEL_SECURITY == "openai:strong"
        assert configured.LLM_MODEL_SUMMARY == ""

    def test_no_flags_keep_the_configured_models(self, monkeypatch):
        monkeypatch.setattr(settings, "LLM_MODEL_SECURITY", "openai:from-env")
        assert run.model_settings(None, []).LLM_MODEL_SECURITY == "openai:from-env"

    @pytest.mark.parametrize("value", ["nonsense", "unknown_role=openai:x", "security="])
    def test_a_bad_role_flag_is_refused(self, value):
        with pytest.raises(ValueError):
            run.model_settings(None, [value])


def test_summary_markdown_escapes_model_text(cases):
    class Evil(FakeClient):
        async def generate(self, role, prompt, **kwargs):
            result = await super().generate(role, prompt, **kwargs)
            for item in getattr(result.output, "findings", []):
                item.title = "a | b\nc <script>"
                item.file = "elsewhere.py"
            return result

    picked = [c for c in cases if c.labels][:3]
    results = asyncio.run(harness.run_cases(picked, "llm", client_for=lambda c: Evil(c.labels)))
    text = summary_markdown(build_report(results, picked, "llm", {}))
    assert "a \\| b c &lt;script>" in text
    assert "<script>" not in text


def test_the_harness_imports_no_provider_sdk():
    banned = {"openai", "anthropic", "google", "pydantic_ai"}
    for path in Path("evals").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert not {n.split(".")[0] for n in names} & banned, path

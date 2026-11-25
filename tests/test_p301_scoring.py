"""P3-01: the eval scorer (matching rule and metric definitions in evals/scoring.py)."""

import pytest

from evals.scoring import CaseOutcome, Finding, Label, aggregate, score_case

NO_APPROVAL = ("approve", "approve_with_suggestions")


def label(id="L1", category="security", file="a.py", start=10, end=10, keywords=()):
    return Label(id=id, category=category, file=file, start=start, end=end, keywords=keywords)


def finding(category="security", file="a.py", line=10, title="Issue", description="d", cwe=None):
    return Finding(
        category=category, file=file, line=line, title=title, description=description, cwe_id=cwe
    )


def outcome(labels=(), findings=(), status="complete", verdict="reject", forbidden=(), id="c1"):
    return CaseOutcome(
        case_id=id,
        case_type="bug" if labels else "clean",
        status=status,
        verdict=verdict,
        labels=tuple(labels),
        findings=tuple(findings),
        forbidden_verdicts=forbidden,
    )


class TestMatching:
    def test_same_category_file_and_line_match(self):
        score = score_case(outcome([label()], [finding()]))
        assert [(m.label_id, m.finding_index) for m in score.matches] == [("L1", 0)]
        assert (score.tp, score.fp, score.fn) == (1, 0, 0)

    def test_line_within_the_tolerance_matches_at_both_ends(self):
        for line in (8, 14):
            score = score_case(outcome([label(start=10, end=12)], [finding(line=line)]), 2)
            assert score.tp == 1, line

    def test_line_outside_the_tolerance_does_not_match(self):
        for line in (7, 15):
            score = score_case(outcome([label(start=10, end=12)], [finding(line=line)]), 2)
            assert (score.tp, score.fp, score.fn) == (0, 1, 1), line

    def test_zero_tolerance_needs_the_labelled_range(self):
        assert score_case(outcome([label()], [finding(line=11)]), 0).tp == 0
        assert score_case(outcome([label()], [finding(line=10)]), 0).tp == 1

    def test_another_category_or_file_does_not_match(self):
        others = (
            finding(category="performance"),
            finding(file="b.py"),
            finding(file="other/a.py"),
            finding(file="data.py"),
        )
        for wrong in others:
            score = score_case(outcome([label()], [wrong]))
            assert (score.tp, score.fp, score.fn) == (0, 1, 1)

    def test_diff_style_path_prefixes_are_ignored(self):
        for path in ("a/a.py", "b/a.py", "./a.py"):
            assert score_case(outcome([label()], [finding(file=path)])).tp == 1, path

    def test_a_real_directory_named_a_is_not_confused_with_a_prefix(self):
        score = score_case(outcome([label(file="a/x.py")], [finding(file="a/x.py")]))
        assert score.tp == 1

    def test_keywords_require_one_of_them_in_title_description_or_cwe(self):
        want = label(keywords=("sql", "CWE-89"))
        hits = (
            finding(title="SQL injection"),
            finding(description="builds a Sql string"),
            finding(cwe="CWE-89"),
        )
        for good in hits:
            assert score_case(outcome([want], [good])).tp == 1
        assert score_case(outcome([want], [finding(title="Weak hash")])).tp == 0

    def test_a_finding_without_a_line_matches_only_through_a_keyword(self):
        no_line = finding(line=None, title="Bare except hides errors")
        assert score_case(outcome([label(keywords=("except",))], [no_line])).tp == 1
        assert score_case(outcome([label()], [no_line])).tp == 0

    @pytest.mark.parametrize(
        "keyword,title",
        [
            ("sql", "Missing NoSQL index hint"),
            ("sql", "Use sqlalchemy session"),
            ("sql", "The sql_injection rule"),
            ("eval", "Retrieval is slow"),
            ("CWE-89", "CWE-890"),
        ],
    )
    def test_a_keyword_inside_another_word_does_not_match(self, keyword, title):
        for line in (10, None):
            found = finding(line=line, title=title)
            assert score_case(outcome([label(keywords=(keyword,))], [found])).tp == 0, line

    @pytest.mark.parametrize(
        "keyword,title",
        [
            ("sql", "SQL injection"),
            ("sql", "Raw (SQL) query"),
            ("n+1", "N+1 query problem"),
            ("o(n", "O(n) lookup in a loop"),
            ("os.system", "Calls os.system() with input"),
            ("event loop", "Blocks the Event Loop."),
        ],
    )
    def test_a_whole_word_or_phrase_matches(self, keyword, title):
        found = finding(title=title)
        assert score_case(outcome([label(keywords=(keyword,))], [found])).tp == 1

    def test_matches_without_a_line_are_counted_apart(self):
        labels = [
            label("L1", keywords=("sql",)),
            label("L2", "performance", keywords=("loop",)),
        ]
        findings = [
            finding(line=None, title="SQL injection"),
            finding("performance", title="Query in a loop"),
        ]
        score = score_case(outcome(labels, findings))
        assert [m.without_line for m in score.matches] == [True, False]
        metrics = aggregate([score])
        assert metrics["overall"]["tp"] == 2
        assert metrics["overall"]["matched_without_line"] == 1
        assert metrics["by_category"]["security"]["matched_without_line"] == 1
        assert metrics["by_category"]["performance"]["matched_without_line"] == 0

    def test_a_finding_with_a_line_is_preferred_over_one_without(self):
        want = label(keywords=("sql",))
        findings = [finding(line=None, title="SQL injection"), finding(title="SQL injection")]
        for order in (findings, findings[::-1]):
            score = score_case(outcome([want], order))
            assert [m.without_line for m in score.matches] == [False]

    def test_matching_is_one_to_one_and_extra_reports_are_false_positives(self):
        score = score_case(outcome([label()], [finding(), finding(title="Same again")]))
        assert (score.tp, score.fp, score.fn) == (1, 1, 0)
        assert score.duplicates == 1

    def test_one_finding_cannot_cover_two_labels(self):
        labels = [label("L1", start=10, end=10), label("L2", start=11, end=11)]
        score = score_case(outcome(labels, [finding(line=10)]))
        assert (score.tp, score.fn) == (1, 1)
        assert score.duplicates == 0

    def test_the_most_labels_possible_are_matched(self):
        # A greedy pass would give the first finding (in reach of both) to L1 and
        # leave the second finding, which can only match L1, unmatched
        labels = [label("L1", start=10, end=10), label("L2", start=13, end=13)]
        findings = [finding(line=11), finding(line=9)]
        score = score_case(outcome(labels, findings), 2)
        assert (score.tp, score.fp, score.fn) == (2, 0, 0)

    def test_result_does_not_depend_on_finding_order(self):
        labels = [label("L1", start=10, end=10), label("L2", start=13, end=13)]
        findings = [finding(line=9), finding(line=11)]
        for order in (findings, findings[::-1]):
            assert score_case(outcome(labels, order), 2).tp == 2


class TestEdgeCases:
    def test_zero_predictions(self):
        score = score_case(outcome([label()], []))
        assert (score.tp, score.fp, score.fn) == (0, 0, 1)
        metrics = aggregate([score])
        assert metrics["overall"]["precision"] is None
        assert metrics["overall"]["recall"] == 0.0

    def test_empty_labels_and_no_findings_is_a_pass_with_undefined_rates(self):
        score = score_case(outcome([], [], verdict="approve", forbidden=("reject",)))
        assert score.passed
        metrics = aggregate([score])
        assert metrics["overall"]["precision"] is None
        assert metrics["overall"]["recall"] is None
        assert metrics["clean"]["false_positive_rate"] == 0.0

    def test_empty_labels_make_every_finding_a_false_positive(self):
        score = score_case(outcome([], [finding(), finding(category="performance")]))
        assert (score.tp, score.fp, score.fn) == (0, 2, 0)
        assert not score.passed
        metrics = aggregate([score])
        assert metrics["overall"]["precision"] == 0.0
        assert metrics["overall"]["recall"] is None
        assert metrics["clean"]["false_positive_rate"] == 1.0

    def test_no_cases(self):
        metrics = aggregate([])
        assert metrics["overall"]["precision"] is None
        assert metrics["overall"]["recall"] is None
        assert metrics["clean"]["false_positive_rate"] is None
        assert metrics["verdict"]["accuracy"] is None
        assert metrics["cases"]["total"] == 0


class TestIncompleteReviews:
    def test_never_passes_even_with_perfect_findings_and_verdict(self):
        for status in ("incomplete", "failed", "error"):
            score = score_case(
                outcome([label()], [finding()], status=status, forbidden=NO_APPROVAL)
            )
            assert not score.passed
            assert score.verdict_ok is False
            assert score.tp == 1  # findings still count towards precision and recall

    def test_a_silent_incomplete_clean_review_is_not_a_clean_result(self):
        silent = score_case(outcome([], [], status="incomplete", verdict="incomplete", id="x"))
        ok = score_case(outcome([], [], verdict="approve", id="y"))
        metrics = aggregate([silent, ok])
        assert metrics["clean"]["evaluated"] == 1
        assert metrics["clean"]["not_evaluated"] == 1
        assert metrics["clean"]["false_positive_rate"] == 0.0

    def test_only_incomplete_clean_reviews_give_no_false_positive_rate(self):
        score = score_case(outcome([], [], status="failed", verdict="incomplete"))
        assert aggregate([score])["clean"]["false_positive_rate"] is None

    def test_an_incomplete_clean_review_that_raised_a_false_alarm_counts_against(self):
        noisy = score_case(outcome([], [finding()], status="incomplete"))
        ok = score_case(outcome([], [], verdict="approve", id="y"))
        assert aggregate([noisy, ok])["clean"]["false_positive_rate"] == 0.5

    def test_labels_of_a_failed_case_are_missed(self):
        score = score_case(outcome([label()], [], status="error", verdict=None))
        assert aggregate([score])["overall"]["recall"] == 0.0

    def test_statuses_are_counted_separately(self):
        scores = [
            score_case(outcome(status=s, id=s))
            for s in ("complete", "incomplete", "incomplete", "failed", "error")
        ]
        counts = aggregate(scores)["cases"]
        assert counts == {
            "total": 5,
            "passed": 1,
            "complete": 1,
            "incomplete": 2,
            "failed": 1,
            "error": 1,
        }


class TestVerdict:
    def test_forbidden_verdict_fails_the_case(self):
        score = score_case(
            outcome([label()], [finding()], verdict="approve", forbidden=NO_APPROVAL)
        )
        assert score.verdict_ok is False
        assert not score.passed

    def test_allowed_verdict_passes(self):
        score = score_case(outcome([label()], [finding()], forbidden=NO_APPROVAL))
        assert score.verdict_ok is True
        assert score.passed

    def test_a_case_without_a_constraint_is_left_out_of_verdict_accuracy(self):
        unconstrained = score_case(outcome([label()], [finding()]))
        wrong = score_case(outcome([label()], [], verdict="approve", forbidden=NO_APPROVAL, id="b"))
        assert unconstrained.verdict_ok is None
        verdict = aggregate([unconstrained, wrong])["verdict"]
        assert verdict == {"constrained": 1, "ok": 0, "accuracy": 0.0}


class TestAggregate:
    def test_per_category_and_overall_numbers(self):
        scores = [
            score_case(
                outcome(
                    [label("s", "security"), label("p", "performance", start=30, end=30)],
                    [finding(), finding(line=99)],
                    id="bugs",
                )
            ),
            score_case(outcome([], [finding(category="best_practice")], id="clean-1")),
            score_case(outcome([], [], id="clean-2")),
        ]
        metrics = aggregate(scores)
        security = metrics["by_category"]["security"]
        assert (security["tp"], security["fp"], security["fn"]) == (1, 1, 0)
        assert security["precision"] == 0.5
        assert security["recall"] == 1.0
        assert security["clean_false_positive_rate"] == 0.0
        performance = metrics["by_category"]["performance"]
        assert performance["precision"] is None
        assert performance["recall"] == 0.0
        assert metrics["by_category"]["best_practice"]["clean_false_positive_rate"] == 0.5
        assert (metrics["overall"]["tp"], metrics["overall"]["fp"], metrics["overall"]["fn"]) == (
            1,
            2,
            1,
        )
        assert metrics["overall"]["precision"] == round(1 / 3, 4)
        assert metrics["clean"]["false_positive_rate"] == 0.5
        assert metrics["by_type"]["clean"] == {"total": 2, "passed": 1}

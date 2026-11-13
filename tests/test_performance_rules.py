"""Unit tests for PerformanceChecker (F-08 regression tests)."""

from app.models.analysis import PerformanceIssue
from app.utils.performance_rules import PerformanceChecker


def _changes(lines, start=10):
    return [{
        "filename": "app/x.py",
        "additions": [{"line_number": start + i, "content": c} for i, c in enumerate(lines)],
    }]


def test_multiline_pattern_reported_once_at_start_line():
    lines = [
        "x = 1",
        "for user in users:",
        "    profile = Profile.objects.get(id=user.id)",
        "y = 2",
        "z = 3",
    ]
    findings = [f for f in PerformanceChecker.check(_changes(lines))
                if "n_plus_one_query" in f.description]
    assert len(findings) == 1
    assert findings[0].line_number == 11  # 'for' is the 2nd added line (start=10)
    assert findings[0].code_snippet == "for user in users:"


def test_non_matching_lines_get_no_findings():
    assert PerformanceChecker.check(_changes(["a = 1", "b = 2", "c = 3"])) == []


def test_single_line_pattern_reported_on_its_own_line():
    findings = PerformanceChecker.check(_changes(["a = 1", "time.sleep(5)", "b = 2"]))
    sleeps = [f for f in findings if "blocking_io" in f.description]
    assert [f.line_number for f in sleeps] == [11]


def test_issue_sets_severity_and_impact():
    findings = PerformanceChecker.check(_changes(["time.sleep(5)"]))
    assert isinstance(findings[0], PerformanceIssue)
    assert findings[0].impact == "HIGH"
    assert findings[0].severity == "high"


def test_check_file_content_returns_findings():
    findings = PerformanceChecker.check_file_content("a.py", "a = 1\ntime.sleep(1)\n")
    assert [f.line_number for f in findings] == [2]

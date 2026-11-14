"""P1-27: PR URLs, owners and repos are logged escaped and capped. No network."""

import asyncio
import contextlib
import logging
from unittest.mock import MagicMock

# Imported at module level: importing app.main runs setup_logging(), which replaces
# the root handlers, including the one caplog installs for a test
from app.main import handle_analyze_pr
from app.services.github_mcp import GitHubMCPService, _pr_ref


def _no_raw(lines, marker):
    assert lines, "expected at least one log line"
    for line in lines:
        assert "\n" not in line
        assert marker * 300 not in line


def test_analyze_pr_logs_a_forged_url_escaped(caplog, monkeypatch):
    # A stub analyzer, so a real one left on app.state by another test can't call
    # GitHub from here (P1-27)
    from app.main import app

    class StubAnalyzer:
        async def analyze_pr(self, url):
            raise RuntimeError("stub")

    monkeypatch.setattr(app.state, "code_analyzer", StubAnalyzer(), raising=False)
    forged = "x\nFORGED-LINE " + "Z" * 400
    with caplog.at_level(logging.INFO), contextlib.suppress(Exception):
        asyncio.run(handle_analyze_pr(forged))
    lines = [r.getMessage() for r in caplog.records if "analyze_pr called" in r.getMessage()]
    _no_raw(lines, "Z")


def test_pr_ref_escapes_and_caps():
    ref = _pr_ref("o\nFORGED", "r" * 5000)
    assert "\n" not in ref and len(ref) <= 200


def test_github_logs_cap_a_long_owner(caplog):
    service = GitHubMCPService()
    client = MagicMock()
    client.get_repo.side_effect = RuntimeError("boom")
    service._client = client
    owner = "o" * 5000
    with caplog.at_level(logging.INFO), contextlib.suppress(Exception):
        asyncio.run(service.get_pull_request(owner, "r", 1))
    lines = [r.getMessage() for r in caplog.records if "PR" in r.getMessage() and "o" * 50 in r.getMessage()]
    assert lines
    for line in lines:
        assert len(line) < 400


def test_extracted_url_is_logged_capped(caplog):
    from app.services.message_handler import MessageHandler

    handler = MessageHandler.__new__(MessageHandler)
    owner = "o" * 5000
    with caplog.at_level(logging.INFO):
        url = handler._extract_pr_url(f"review https://github.com/{owner}/r/pull/1", [])
    assert url == f"https://github.com/{owner}/r/pull/1"  # the URL itself is unchanged
    lines = [r.getMessage() for r in caplog.records if "Found PR URL" in r.getMessage()]
    assert lines and all(len(line) < 400 for line in lines)

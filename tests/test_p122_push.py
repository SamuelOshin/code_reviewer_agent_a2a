"""P1-22: PR path case and push status after a stored result. No network."""

import asyncio

import pytest

from app.services import message_handler as mh
from app.services.github_mcp import GitHubMCPService
from app.services.message_handler import MessageHandler
from tests.test_p121_followups import PUSH_CONFIG, _handler_with_ok_analysis, _install_fake_webhook

extract = MessageHandler.__new__(MessageHandler)._extract_pr_url
parse = GitHubMCPService.__new__(GitHubMCPService).parse_pr_url


# --- 1. the "/pull/" segment is case insensitive in both functions ----------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see https://github.com/O/R/PULL/1", "https://github.com/O/R/pull/1"),
        ("see https://github.com/O/R/Pull/1", "https://github.com/O/R/pull/1"),
        ("HTTPS://GITHUB.COM/O/R/PULL/1", "https://github.com/O/R/pull/1"),
        ("github.com/Pull/Pull/PULL/7", "https://github.com/Pull/Pull/pull/7"),
    ],
)
def test_pull_segment_is_lowercased_and_parsed(text, expected):
    url = extract(text, [])
    assert url == expected
    owner, repo, number = parse(url)
    assert (owner, repo) == (expected.split("/")[3], expected.split("/")[4])
    assert number == int(expected.rsplit("/", 1)[1])


# --- 2. one short failed post only where a smaller message can succeed ------------------


@pytest.mark.parametrize("status", [500, 502, 302, 400, 401, 404])
def test_no_failed_post_after_other_webhook_statuses(monkeypatch, status):
    sent = _install_fake_webhook(monkeypatch, [status, 200])
    asyncio.run(_handler_with_ok_analysis()._process_and_push("u", "t1", "m1", {}, PUSH_CONFIG))
    assert len(sent) == 1  # the webhook may have stored the result: no "failed" overwrite


@pytest.mark.parametrize("status", [413, 429])
def test_failed_post_after_413_and_429(monkeypatch, status):
    sent = _install_fake_webhook(monkeypatch, [status, 200])
    asyncio.run(_handler_with_ok_analysis()._process_and_push("u", "t1", "m1", {}, PUSH_CONFIG))
    assert len(sent) == 2
    assert sent[1]["result"]["status"]["state"] == "failed"
    assert sent[1]["result"]["id"] == "t1"


def test_extra_post_is_revalidated(monkeypatch):
    sent = _install_fake_webhook(monkeypatch, [413, 200])
    calls = []

    async def counting(url):
        calls.append(url)

    monkeypatch.setattr(mh, "validate_push_url", counting)
    asyncio.run(_handler_with_ok_analysis()._process_and_push("u", "t1", "m1", {}, PUSH_CONFIG))
    assert len(sent) == 2
    assert len(calls) >= 2  # the guard runs again before the extra post

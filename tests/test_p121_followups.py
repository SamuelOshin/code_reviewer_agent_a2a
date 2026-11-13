"""P1-21: follow-ups from the P1-19/P1-20 review. No network."""

import asyncio
import logging

import httpx
import pytest

from app.core import logging as app_logging
from app.core.config import settings
from app.core.exceptions import GitHubMCPError
from app.llm.errors import LLMRateLimitError
from app.services import message_handler as mh
from app.services.github_mcp import GitHubMCPService
from app.services.jsonrpc_handler import BATCH_CONCURRENCY, JSONRPCHandler
from app.services.message_handler import MessageHandler

extract = MessageHandler.__new__(MessageHandler)._extract_pr_url
parse = GitHubMCPService.__new__(GitHubMCPService).parse_pr_url

PUSH_CONFIG = {"url": "https://example.test/hook"}


# --- 1. push failures get their own category --------------------------------------------


def _install_fake_webhook(monkeypatch, statuses):
    """Fake httpx client: answers the n-th post with statuses[n]. Records payloads."""
    sent = []

    async def no_validate(_url):
        return None

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            sent.append(json)
            status = statuses[min(len(sent) - 1, len(statuses) - 1)]
            if isinstance(status, Exception):
                raise status
            return httpx.Response(status, request=httpx.Request("POST", url))

    monkeypatch.setattr(mh, "validate_push_url", no_validate)
    monkeypatch.setattr(mh.httpx, "AsyncClient", FakeClient)
    return sent


def _text(payload):
    return payload["result"]["status"]["message"]["parts"][0]["text"]


def _handler_with_ok_analysis():
    handler = MessageHandler.__new__(MessageHandler)

    async def ok(pr_url, task_id, message_id, message):
        return {
            "id": task_id,
            "contextId": "c",
            "kind": "task",
            "history": [],
            "status": {"state": "completed"},
        }

    handler._analyze_and_return = ok
    return handler


def test_webhook_429_gets_push_failure_message_not_rate_limit(monkeypatch):
    sent = _install_fake_webhook(monkeypatch, [429, 200])
    handler = _handler_with_ok_analysis()

    asyncio.run(handler._process_and_push("u", "t1", "m1", {}, PUSH_CONFIG))

    assert len(sent) == 2  # the result, then one small error message
    text = _text(sent[1])
    assert "Could Not Deliver the Result" in text
    assert "rate limit" not in text
    assert "Error id:" in text


def test_unreachable_webhook_is_not_pushed_to_again(monkeypatch):
    sent = _install_fake_webhook(monkeypatch, [httpx.ConnectError("secret detail")])
    handler = _handler_with_ok_analysis()

    asyncio.run(handler._process_and_push("u", "t1", "m1", {}, PUSH_CONFIG))

    assert len(sent) == 1  # no second post to a webhook that did not answer


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (httpx.ConnectError("x"), "push"),
        (httpx.HTTPStatusError("x", request=httpx.Request("POST", "https://a.test"),
                               response=httpx.Response(429)), "push"),
        (LLMRateLimitError("x"), "rate_limit"),
        (GitHubMCPError("x"), "github"),
    ],
)
def test_error_category_push(error, category):
    assert mh._error_category(error) == category


@pytest.mark.parametrize(
    ("error", "title"),
    [
        (LLMRateLimitError("SECRET-DETAIL"), "Analysis Temporarily Unavailable"),
        (GitHubMCPError("SECRET-DETAIL"), "Unable to Access Pull Request"),
    ],
)
def test_failed_analysis_reaches_the_client_with_its_category(monkeypatch, error, title):
    # The analyzer raises directly here. In production CodeAnalyzerService turns model
    # errors (rate limits included) into a failed step, so only the GitHub case is
    # reachable end to end; the rate-limit text is kept for an analyzer that raises.
    handler = MessageHandler.__new__(MessageHandler)

    class Analyzer:
        async def analyze_pr(self, url):
            raise error

    handler.analyzer = Analyzer()
    result = asyncio.run(handler._analyze_and_return("u", "t1", "m1", {}))

    text = result["status"]["message"]["parts"][0]["text"]
    assert result["status"]["state"] == "failed"
    assert title in text
    assert "SECRET-DETAIL" not in text


def test_uncategorised_analysis_failure_keeps_short_text():
    handler = MessageHandler.__new__(MessageHandler)

    class Analyzer:
        async def analyze_pr(self, url):
            raise RuntimeError("SECRET-DETAIL")

    handler.analyzer = Analyzer()
    result = asyncio.run(handler._analyze_and_return("u", "t1", "m1", {}))
    text = result["status"]["message"]["parts"][0]["text"]
    assert text.startswith("Failed to analyze PR")
    assert "SECRET-DETAIL" not in text


# --- 2. batch slot wait is bounded -------------------------------------------------------


def test_batch_call_waiting_for_a_slot_past_the_timeout_gets_32004(monkeypatch):
    monkeypatch.setattr(settings, "A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)
    handler = JSONRPCHandler()
    release = asyncio.Event()

    async def hold():
        await release.wait()
        return "ok"

    async def quick():
        return "ok"

    handler.register_method("hold", hold)
    handler.register_method("quick", quick)

    async def main():
        # BATCH_CONCURRENCY calls take every slot and keep them
        holders = asyncio.create_task(
            handler.handle_batch(
                [{"jsonrpc": "2.0", "method": "hold", "id": i} for i in range(BATCH_CONCURRENCY)]
            )
        )
        await asyncio.sleep(0.01)
        waiting = await handler.handle_batch([{"jsonrpc": "2.0", "method": "quick", "id": "w"}])
        release.set()
        return waiting, await holders

    waiting, holders = asyncio.run(main())

    assert waiting[0]["id"] == "w"
    assert waiting[0]["error"]["code"] == -32004
    assert all(r["result"] == "ok" for r in holders)


@pytest.mark.parametrize("bad_id", [{"a": 1}, [1], 1.5, True])
def test_malformed_id_on_a_timed_out_wait_fails_only_that_call(monkeypatch, bad_id):
    # Bobby Review: the -32004 response is built outside handle_request, so a bad id
    # used to raise and fail the whole batch
    monkeypatch.setattr(settings, "A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)
    handler = JSONRPCHandler()
    release = asyncio.Event()

    async def hold():
        await release.wait()
        return "ok"

    handler.register_method("hold", hold)
    handler.register_method("quick", lambda: "ok")

    async def main():
        holders = asyncio.create_task(
            handler.handle_batch(
                [{"jsonrpc": "2.0", "method": "hold", "id": i} for i in range(BATCH_CONCURRENCY)]
            )
        )
        await asyncio.sleep(0.01)
        waiting = await handler.handle_batch(
            [
                {"jsonrpc": "2.0", "method": "quick", "id": bad_id},
                {"jsonrpc": "2.0", "method": "quick", "id": "ok-id"},
            ]
        )
        release.set()
        await holders
        return waiting

    waiting = asyncio.run(main())
    assert [r["error"]["code"] for r in waiting] == [-32004, -32004]
    assert waiting[0].get("id") is None
    assert waiting[1]["id"] == "ok-id"


def test_slot_is_released_after_a_timed_out_wait(monkeypatch):
    monkeypatch.setattr(settings, "A2A_BLOCKING_TIMEOUT_SECONDS", 0.05)
    handler = JSONRPCHandler()

    async def quick():
        return "ok"

    handler.register_method("quick", quick)
    req = [{"jsonrpc": "2.0", "method": "quick", "id": i} for i in range(BATCH_CONCURRENCY * 3)]
    responses = asyncio.run(handler.handle_batch(req))
    assert all(r["result"] == "ok" for r in responses)


# --- 3. extractor and parse_pr_url agree ------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "http://github.com/Own/Repo/pull/5",
        "GitHub.com/Own/Repo/pull/5",
        "HTTPS://GITHUB.COM/Own/Repo/pull/5",
        "https://GitHub.com/Own/Repo/pull/5",
        "HTTP://github.com/Own/Repo/pull/5",
    ],
)
def test_extractor_normalises_and_parse_pr_url_accepts_the_result(text):
    url = extract(text, [])
    assert url == "https://github.com/Own/Repo/pull/5"  # owner/repo case kept
    assert parse(url) == ("Own", "Repo", 5)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/o/r/pull/5",
        "GitHub.com/o/r/pull/5",
        "HTTPS://GITHUB.COM/o/r/pull/5",
    ],
)
def test_parse_pr_url_stays_strict_about_non_canonical_forms(url):
    with pytest.raises(GitHubMCPError):
        parse(url)


# --- 4. PR number 0 ---------------------------------------------------------------------


@pytest.mark.parametrize("number", ["0", "00", "0000000000"])
def test_pull_zero_is_rejected_by_both(number):
    url = f"https://github.com/o/r/pull/{number}"
    assert extract(url, []) is None
    assert extract(f"github.com/o/r/pull/{number}/files", []) is None
    with pytest.raises(GitHubMCPError):
        parse(url)


def test_numbers_with_a_zero_are_still_fine():
    assert extract("https://github.com/o/r/pull/10", []) == "https://github.com/o/r/pull/10"
    assert extract("https://github.com/o/r/pull/007", []) == "https://github.com/o/r/pull/007"
    assert parse("https://github.com/o/r/pull/10")[2] == 10
    assert parse("https://github.com/o/r/pull/007")[2] == 7


# --- 5. google-auth logger --------------------------------------------------------------


class TestGoogleLogger:
    @pytest.fixture(autouse=True)
    def restore_loggers(self):
        names = ("", "google", "google.auth")
        saved = {n: (logging.getLogger(n).level, list(logging.getLogger(n).handlers)) for n in names}
        yield
        for n, (level, handlers) in saved.items():
            logging.getLogger(n).setLevel(level)
            logging.getLogger(n).handlers = handlers

    def test_google_auth_stays_at_info_or_higher_under_debug(self, monkeypatch):
        monkeypatch.setattr(app_logging.settings, "LOG_LEVEL", "DEBUG")
        app_logging.setup_logging()
        assert not logging.getLogger("google.auth").isEnabledFor(logging.DEBUG)

    def test_a_higher_configured_level_is_not_lowered(self, monkeypatch):
        monkeypatch.setattr(app_logging.settings, "LOG_LEVEL", "ERROR")
        app_logging.setup_logging()
        assert logging.getLogger("google").level == logging.ERROR

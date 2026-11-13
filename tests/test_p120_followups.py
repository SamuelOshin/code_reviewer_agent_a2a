"""P1-20: parser and batch follow-ups from the P1-16 to P1-18 review. No network."""

import asyncio

import pytest

from app.core.exceptions import GitHubMCPError
from app.llm.errors import LLMRateLimitError
from app.services import message_handler as mh
from app.services.github_mcp import GitHubMCPService
from app.services.jsonrpc_handler import BATCH_CONCURRENCY, JSONRPCHandler
from app.services.message_handler import MessageHandler

extract = MessageHandler.__new__(MessageHandler)._extract_pr_url
parse = GitHubMCPService.__new__(GitHubMCPService).parse_pr_url

# --- 1. huge PR number ------------------------------------------------------------------


def test_huge_pr_number_raises_github_error_not_value_error():
    with pytest.raises(GitHubMCPError):
        parse("https://github.com/o/r/pull/" + "9" * 5000)


def test_ten_digit_pr_number_still_parses_and_eleven_does_not():
    assert parse("https://github.com/o/r/pull/1234567890")[2] == 1234567890
    with pytest.raises(GitHubMCPError):
        parse("https://github.com/o/r/pull/12345678901")


# --- 2. extractor boundaries ------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "evilgithub.com/o/r/pull/1",
        "see notgithub.com/o/r/pull/1",
        "https://evilgithub.com/o/r/pull/1",
        "see https://github.com/o/r/pull/" + "9" * 5000,
    ],
)
def test_extractor_rejects_lookalike_hosts_and_huge_numbers(text):
    assert extract(text, []) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see https://github.com/o/r/pull/1.", "https://github.com/o/r/pull/1"),
        ("(github.com/o/r/pull/1)", "https://github.com/o/r/pull/1"),
        ("<github.com/o/r/pull/1>", "https://github.com/o/r/pull/1"),
        ('"github.com/o/r/pull/1"', "https://github.com/o/r/pull/1"),
        ("github.com/o/r/pull/1", "https://github.com/o/r/pull/1"),
        ("review //github.com/o/r/pull/1", "https://github.com/o/r/pull/1"),
        ("https://github.com/o/r/pull/7/files", "https://github.com/o/r/pull/7"),
    ],
)
def test_extractor_finds_real_urls(text, expected):
    assert extract(text, []) == expected


@pytest.mark.parametrize("suffix", ["-x", "abc", "_1", "٣"])  # last is Arabic-Indic 3
def test_both_parsers_reject_the_same_bad_suffixes(suffix):
    url = f"https://github.com/o/r/pull/12{suffix}"
    assert extract(url, []) is None
    with pytest.raises(GitHubMCPError):
        parse(url)


# --- 3. batch concurrency is process-wide -----------------------------------------------


def test_concurrent_batches_share_one_limit():
    handler = JSONRPCHandler()
    running = peak = 0

    async def probe():
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.01)
        running -= 1
        return "ok"

    handler.register_method("probe", probe)

    def batch(offset: int):
        return [
            {"jsonrpc": "2.0", "method": "probe", "id": offset + i} for i in range(10)
        ]

    async def main():
        return await asyncio.gather(*(handler.handle_batch(batch(k * 100)) for k in range(4)))

    results = asyncio.run(main())

    assert peak == BATCH_CONCURRENCY == 5
    for k, responses in enumerate(results):  # order and results kept per batch
        assert [r["id"] for r in responses] == [k * 100 + i for i in range(10)]
        assert all(r["result"] == "ok" for r in responses)


def test_semaphore_works_on_a_new_event_loop_each_time():
    handler = JSONRPCHandler()

    async def fine():
        return "ok"

    handler.register_method("fine", fine)
    req = [{"jsonrpc": "2.0", "method": "fine", "id": 1}]
    assert asyncio.run(handler.handle_batch(req))[0]["result"] == "ok"
    assert asyncio.run(handler.handle_batch(req))[0]["result"] == "ok"


# --- 4. _push_error classifies by type, not text ----------------------------------------


class _Status(Exception):
    def __init__(self, status_code: int):
        super().__init__("boom")
        self.status_code = status_code


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (LLMRateLimitError("quota"), "rate_limit"),
        (_Status(429), "rate_limit"),
        (GitHubMCPError("Failed to fetch PR (status 404)"), "github"),
        (RuntimeError("error id 4040429abc"), "other"),  # digits in text mean nothing
        (RuntimeError("Resource exhausted GitHub 404 429"), "other"),
        (_Status(404), "other"),
        (None, "other"),
    ],
)
def test_error_category_ignores_message_text(error, category):
    assert mh._error_category(error) == category


@pytest.mark.parametrize(
    ("error", "expected_title"),
    [
        (RuntimeError("error id 404-429"), "Analysis Failed"),
        (GitHubMCPError("x"), "Unable to Access Pull Request"),
        (LLMRateLimitError("x"), "Analysis Temporarily Unavailable"),
    ],
)
def test_push_error_message_follows_category_and_never_echoes_text(
    monkeypatch, error, expected_title
):
    sent = {}

    async def no_validate(_url):
        return None

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            sent["payload"] = json
            return FakeResponse()

    monkeypatch.setattr(mh, "validate_push_url", no_validate)
    monkeypatch.setattr(mh.httpx, "AsyncClient", FakeClient)

    error_text = "SECRET-DETAIL " + str(error)
    err = type(error)(error_text) if error.args else error
    handler = MessageHandler.__new__(MessageHandler)
    asyncio.run(
        handler._push_error(
            "t1", "m1", {}, {"url": "https://example.test/hook"}, err, "abc123"
        )
    )

    text = sent["payload"]["result"]["status"]["message"]["parts"][0]["text"]
    assert expected_title in text
    assert "abc123" in text
    assert "SECRET-DETAIL" not in str(sent["payload"])

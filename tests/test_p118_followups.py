"""P1-18: smaller follow-ups from the PR #3 review. No network, no real sleeps."""

import asyncio
import ipaddress
import time

import pytest

from app.core import push_url
from app.services import jsonrpc_handler
from app.services.github_mcp import GitHubMCPError, GitHubMCPService
from app.services.jsonrpc_handler import JSONRPCHandler
from app.services.message_handler import MessageHandler

# --- 1. batch concurrency ---------------------------------------------------------------


def test_batch_runs_concurrently_and_keeps_request_order():
    handler = JSONRPCHandler()

    async def slow(n: int):
        await asyncio.sleep(0.05 if n % 2 else 0.01)  # later calls can finish first
        return {"n": n}

    handler.register_method("slow", slow)
    batch = [
        {"jsonrpc": "2.0", "method": "slow", "params": {"n": i}, "id": i} for i in range(5)
    ]
    start = time.monotonic()
    responses = asyncio.run(handler.handle_batch(batch))
    elapsed = time.monotonic() - start

    assert [r["id"] for r in responses] == list(range(5))
    assert [r["result"]["n"] for r in responses] == list(range(5))
    assert elapsed < 0.2  # sequential would be 0.01*3 + 0.05*2 = 0.13; concurrent ~0.05


def test_batch_concurrency_is_bounded(monkeypatch):
    monkeypatch.setattr(jsonrpc_handler, "BATCH_CONCURRENCY", 2)
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
    batch = [{"jsonrpc": "2.0", "method": "probe", "id": i} for i in range(8)]
    responses = asyncio.run(handler.handle_batch(batch))

    assert peak == 2
    assert [r["id"] for r in responses] == list(range(8))


def test_batch_errors_stay_per_call():
    handler = JSONRPCHandler()

    async def boom():
        raise RuntimeError("secret detail")

    async def fine():
        return "ok"

    handler.register_method("boom", boom)
    handler.register_method("fine", fine)
    batch = [
        {"jsonrpc": "2.0", "method": "fine", "id": 1},
        {"jsonrpc": "2.0", "method": "boom", "id": 2},
        {"jsonrpc": "2.0", "method": "nope", "id": 3},
        {"jsonrpc": "2.0", "method": "fine", "id": 4},
    ]
    responses = asyncio.run(handler.handle_batch(batch))

    assert [r["id"] for r in responses] == [1, 2, 3, 4]
    assert responses[0]["result"] == "ok" and responses[3]["result"] == "ok"
    assert responses[1]["error"]["code"] == -32603
    assert responses[2]["error"]["code"] == -32601


# --- 2. no new GitHub calls after a timeout/cancel --------------------------------------


def test_cancelled_call_does_not_start_a_queued_github_call():
    import concurrent.futures
    import threading

    service = GitHubMCPService()
    gate = threading.Event()
    started = []

    async def scenario():
        loop = asyncio.get_running_loop()
        # A one-thread pool that is busy, so the next call waits in the queue
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop.set_default_executor(pool)
        blocker = loop.run_in_executor(None, gate.wait)
        task = asyncio.ensure_future(service._run_sync(lambda: started.append("ran")))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        gate.set()
        await blocker
        pool.shutdown(wait=True)

    asyncio.run(scenario())
    assert started == []


def test_closed_service_refuses_new_calls():
    service = GitHubMCPService()
    service._closed = True
    with pytest.raises(GitHubMCPError):
        asyncio.run(service._run_sync(lambda: "x"))


def test_github_client_has_request_timeout_and_bounded_retry(monkeypatch):
    from app.services import github_mcp

    seen = {}

    class FakeGithub:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(github_mcp, "Github", FakeGithub)
    monkeypatch.setenv("SKIP_GITHUB_CONNECTION_TEST", "true")

    async def go():
        async with GitHubMCPService():
            pass

    asyncio.run(go())
    assert seen["timeout"] == github_mcp.GITHUB_REQUEST_TIMEOUT
    assert seen["retry"].total == github_mcp.GITHUB_RETRY_TOTAL
    # Without a cap, GithubRetry sleeps until the rate-limit reset (up to an hour)
    assert seen["retry"].max_rate_limit_wait == github_mcp.GITHUB_RATE_LIMIT_MAX_WAIT
    # urllib3 rebuilds the Retry on each attempt; the cap must survive that
    assert seen["retry"].new(total=2).max_rate_limit_wait == github_mcp.GITHUB_RATE_LIMIT_MAX_WAIT


# --- 3. push URL guard: ranges ipaddress calls global -----------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "fec0::1",  # deprecated site-local
        "feff::1",
        "2002:7f00:1::1",  # 6to4 of 127.0.0.1
        "2002:0a00:0001::1",  # 6to4 of 10.0.0.1
        "2002:c0a8:0101::1",  # 6to4 of 192.168.1.1
        "2002:a9fe:a9fe::1",  # 6to4 of 169.254.169.254
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    ],
)
def test_non_public_ipv6_forms_are_rejected(address):
    assert push_url._is_public(ipaddress.ip_address(address)) is False


def test_6to4_of_a_public_address_is_allowed_and_normal_ipv6_still_is():
    assert push_url._is_public(ipaddress.ip_address("2002:0808:0808::1")) is True  # 8.8.8.8
    assert push_url._is_public(ipaddress.ip_address("2606:4700:4700::1111")) is True


# --- 4. parse_pr_url anchoring ----------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/o/r/pull/12abc",
        "https://github.com/o/r/pull/12.5",
        "https://github.com/o/r/pull/12_x",
        "https://github.com/o/r/pull/",
    ],
)
def test_parse_pr_url_rejects_trailing_garbage(url):
    with pytest.raises(GitHubMCPError):
        GitHubMCPService().parse_pr_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/o/r/pull/12",
        "https://github.com/o/r/pull/12/files",
        "https://github.com/o/r/pull/12?x=1",
        "https://github.com/o/r/pull/12#issuecomment-1",
    ],
)
def test_parse_pr_url_accepts_clean_endings(url):
    assert GitHubMCPService().parse_pr_url(url) == ("o", "r", 12)


def test_a2a_url_extractor_matches_the_same_rule():
    extract = MessageHandler.__new__(MessageHandler)._extract_pr_url
    assert extract("see https://github.com/o/r/pull/12abc please", []) is None
    assert extract("see https://github.com/o/r/pull/12.", []) == "https://github.com/o/r/pull/12"
    assert extract("(github.com/o/r/pull/12)", []) == "https://github.com/o/r/pull/12"
    assert extract("https://github.com/o/r/pull/12?x=1", []) == "https://github.com/o/r/pull/12"

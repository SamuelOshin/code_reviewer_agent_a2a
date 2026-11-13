"""P1-19: retry budget per signed body, replay cache size, PyGithub DEBUG logging.

Nothing here touches the network or a real model; the clock is patched, never slept.
"""

import logging
import uuid

import pytest

from app.core import logging as app_logging
from app.routes import webhooks
from tests.test_p116_replay import comments, send
from tests.test_webhooks import analyzer, github, pr_payload  # noqa: F401  (fixtures)


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(webhooks.time, "monotonic", lambda: now[0])
    return now


# --- 1. a body that keeps failing runs a bounded number of times -------------------------


class TestRetryBudget:
    def test_always_failing_body_runs_at_most_the_budget(self, client, webhook_secret, analyzer, github):  # noqa: F811
        analyzer.analyze_pr.side_effect = RuntimeError("model down")
        statuses = [
            send(client, webhook_secret, str(uuid.uuid4())).json()["status"] for _ in range(6)
        ]
        assert statuses[: webhooks.MAX_RUNS_PER_BODY] == ["queued"] * webhooks.MAX_RUNS_PER_BODY
        assert set(statuses[webhooks.MAX_RUNS_PER_BODY :]) == {"duplicate"}
        assert analyzer.analyze_pr.await_count == webhooks.MAX_RUNS_PER_BODY == 3
        assert comments(github) == 0

    def test_same_delivery_id_is_also_stopped_once_spent(self, client, webhook_secret, analyzer, github):  # noqa: F811
        analyzer.analyze_pr.side_effect = RuntimeError("model down")
        for _ in range(5):
            send(client, webhook_secret, "d-1")
        assert analyzer.analyze_pr.await_count == 3

    def test_unpostable_comment_spends_the_same_budget(self, client, webhook_secret, analyzer, github):  # noqa: F811
        github.get_repo.return_value.get_issue.return_value.create_comment.side_effect = RuntimeError("403")
        for _ in range(5):
            send(client, webhook_secret, "d-1")
        assert analyzer.analyze_pr.await_count == 3

    def test_other_bodies_keep_their_own_budget(self, client, webhook_secret, analyzer, github):  # noqa: F811
        analyzer.analyze_pr.side_effect = RuntimeError("model down")
        for _ in range(4):
            send(client, webhook_secret)
        assert send(client, webhook_secret, payload=pr_payload("synchronize")).json()["status"] == "queued"

    def test_rejected_payload_keeps_getting_400(self, client, webhook_secret, analyzer, github):  # noqa: F811
        # Nothing ran, so a 400 must not spend the budget and turn into "duplicate"
        bad = {"action": "opened", "pull_request": {"number": 1}}  # no html_url
        codes = [send(client, webhook_secret, str(uuid.uuid4()), payload=bad).status_code for _ in range(5)]
        assert codes == [400] * 5

    def test_body_that_recovers_stops_costing_budget(self, client, webhook_secret, analyzer, github):  # noqa: F811
        analyzer.analyze_pr.side_effect = RuntimeError("model down")
        send(client, webhook_secret)
        analyzer.analyze_pr.side_effect = None
        assert send(client, webhook_secret).json()["status"] == "queued"
        assert send(client, webhook_secret).json()["status"] == "duplicate"
        assert comments(github) == 1


# --- 2. the budget store ------------------------------------------------------------------


class TestBudgetStore:
    def test_release_does_not_reset_the_budget(self, clock):
        cache = webhooks.DeliveryCache()
        for _ in range(webhooks.MAX_RUNS_PER_BODY):
            assert not cache.claim("d-1", "h-1")
            cache.forget("d-1", "h-1")
        assert cache.claim("d-2", "h-1")  # spent: stays claimed
        cache.forget("d-2", "h-1")  # a further release changes nothing
        assert cache.claim("d-3", "h-1")

    def test_budget_is_bounded_by_size(self, clock):
        cache = webhooks.DeliveryCache(ttl_seconds=3600, max_entries=3)
        for i in range(10):
            clock[0] += 1
            cache.claim(f"d-{i}", f"h-{i}")
            cache.forget(f"d-{i}", f"h-{i}")
        assert len(cache._budget) <= 3

    def test_budget_is_bounded_by_ttl(self, clock):
        cache = webhooks.DeliveryCache(ttl_seconds=10, max_entries=8)
        cache.claim("d-1", "h-1")
        cache.forget("d-1", "h-1")
        clock[0] += 11
        cache.claim("d-2", "h-2")
        cache.forget("d-2", "h-2")
        assert "h-1" not in cache._budget and "h-2" in cache._budget

    def test_body_works_again_after_the_ttl(self, clock):
        cache = webhooks.DeliveryCache(ttl_seconds=10, max_entries=8)
        for _ in range(webhooks.MAX_RUNS_PER_BODY):
            assert not cache.claim("d-1", "h-1")
            clock[0] += 1
            cache.forget("d-1", "h-1")
        assert cache.claim("d-1", "h-1")
        clock[0] += 11
        assert not cache.claim("d-1", "h-1")  # claim and budget both aged out
        cache.forget("d-1", "h-1")
        assert not cache.claim("d-1", "h-1")  # a fresh budget, not an exhausted one

    def test_expired_budget_behind_a_newer_one_is_still_dropped(self, clock):
        # Bobby Review: A fails, X fails, A fails again. A's count must age out with
        # A's first failure even though X's entry is newer (no reordering on update)
        cache = webhooks.DeliveryCache(ttl_seconds=100, max_entries=8)

        def fail(delivery, body):
            assert not cache.claim(delivery, body)
            cache.forget(delivery, body)

        fail("a-1", "A")
        clock[0] += 50
        fail("x-1", "X")
        clock[0] += 10
        fail("a-2", "A")
        clock[0] = 1000 + 101  # A's window is over, X's is not
        for i in range(webhooks.MAX_RUNS_PER_BODY):
            fail(f"a-3{i}", "A")  # a full fresh budget
        assert cache.claim("a-4", "A")

    def test_uncharged_release_spends_nothing(self, clock):
        cache = webhooks.DeliveryCache()
        for _ in range(5):
            assert not cache.claim("d-1", "h-1")
            cache.forget("d-1", "h-1", charge=False)
        assert "h-1" not in cache._budget

    def test_default_size_is_larger_than_before(self):
        assert webhooks.DeliveryCache()._max == webhooks.DEFAULT_MAX_ENTRIES > 2048


# --- 3. PyGithub and urllib3 stay quiet at DEBUG -----------------------------------------


class TestLibraryLogLevels:
    @pytest.fixture(autouse=True)
    def restore_loggers(self):
        names = ("", "github", "urllib3", "httpx", "httpcore", "anthropic", "google_genai")
        saved = {n: (logging.getLogger(n).level, list(logging.getLogger(n).handlers)) for n in names}
        yield
        for n, (level, handlers) in saved.items():
            logging.getLogger(n).setLevel(level)
            logging.getLogger(n).handlers = handlers

    @pytest.mark.parametrize("name", ["github", "urllib3", "anthropic", "google_genai"])
    def test_stays_at_info_or_higher_under_debug(self, monkeypatch, name):
        monkeypatch.setattr(app_logging.settings, "LOG_LEVEL", "DEBUG")
        app_logging.setup_logging()
        assert logging.getLogger("").level == logging.DEBUG
        assert logging.getLogger(name).getEffectiveLevel() >= logging.INFO
        assert not logging.getLogger(name).isEnabledFor(logging.DEBUG)

    def test_a_higher_configured_level_is_not_lowered(self, monkeypatch):
        monkeypatch.setattr(app_logging.settings, "LOG_LEVEL", "ERROR")
        app_logging.setup_logging()
        assert logging.getLogger("github").level == logging.ERROR

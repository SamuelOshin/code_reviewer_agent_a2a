"""P1-16: webhook replay protection on the signed body, retry after a failed review,
secret stripping, delivery id validation and clean log lines in webhooks.py.

Nothing here touches the network or a real model; the clock is patched, never slept.
"""

import json
import logging
import uuid

import pytest
from pydantic import ValidationError

from app.core.config import MIN_WEBHOOK_SECRET_LENGTH, Settings
from app.models.analysis import AnalysisStatus
from app.routes import webhooks
from tests.test_webhooks import analyzer, github, make_result, pr_payload, sign  # noqa: F401  (fixtures)


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.setattr(webhooks, "delivery_cache", webhooks.DeliveryCache())


def send(client, secret, delivery=None, payload=None, event="pull_request", body=None):
    if body is None:
        body = json.dumps(payload or pr_payload()).encode()
    headers = {
        "X-GitHub-Event": event,
        "X-Hub-Signature-256": sign(secret, body),
        "Content-Type": "application/json",
    }
    if delivery is not None:
        headers["X-GitHub-Delivery"] = delivery
    return client.post("/webhooks/github", content=body, headers=headers)


def comments(github):  # noqa: F811
    return github.get_repo.return_value.get_issue.return_value.create_comment.call_count


# --- 1. the signed body is the replay key ----------------------------------------------


class TestBodyHashReplay:
    def test_same_body_with_a_new_delivery_id_runs_once(self, client, webhook_secret, analyzer, github):  # noqa: F811
        first = send(client, webhook_secret, str(uuid.uuid4()))
        replay = send(client, webhook_secret, str(uuid.uuid4()))
        assert first.json()["status"] == "queued"
        assert replay.status_code == 200 and replay.json()["status"] == "duplicate"
        assert analyzer.analyze_pr.await_count == 1
        assert comments(github) == 1

    def test_same_body_without_a_delivery_header_runs_once(self, client, webhook_secret, analyzer, github):  # noqa: F811
        assert send(client, webhook_secret).json()["status"] == "queued"
        assert send(client, webhook_secret).json()["status"] == "duplicate"
        assert analyzer.analyze_pr.await_count == 1

    def test_same_id_with_a_different_body_is_a_replay(self, client, webhook_secret, analyzer, github):  # noqa: F811
        send(client, webhook_secret, "d-1")
        other = pr_payload("synchronize")
        assert send(client, webhook_secret, "d-1", payload=other).json()["status"] == "duplicate"

    def test_a_new_event_with_a_new_body_and_id_runs(self, client, webhook_secret, analyzer, github):  # noqa: F811
        send(client, webhook_secret, "d-1")
        assert send(client, webhook_secret, "d-2", payload=pr_payload("synchronize")).json()["status"] == "queued"
        assert analyzer.analyze_pr.await_count == 2

    def test_forged_body_cannot_claim_the_hash(self, client, webhook_secret, analyzer, github):  # noqa: F811
        body = json.dumps(pr_payload()).encode()
        bad = client.post("/webhooks/github", content=body, headers={
            "X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sign("wrong-secret", body)})
        assert bad.status_code == 401
        assert send(client, webhook_secret, body=body).json()["status"] == "queued"


# --- 2. failed reviews can be redelivered; successful ones stay claimed -----------------


class TestRetryAfterFailure:
    def test_failed_analysis_can_be_redelivered(self, client, webhook_secret, analyzer, github):  # noqa: F811
        analyzer.analyze_pr.side_effect = RuntimeError("model down")
        assert send(client, webhook_secret, "d-1").json()["status"] == "queued"
        analyzer.analyze_pr.side_effect = None
        again = send(client, webhook_secret, "d-1")
        assert again.json()["status"] == "queued"
        assert analyzer.analyze_pr.await_count == 2
        assert comments(github) == 1

    def test_failed_analysis_also_frees_a_fresh_id_with_the_same_body(self, client, webhook_secret, analyzer, github):  # noqa: F811
        analyzer.analyze_pr.side_effect = RuntimeError("model down")
        send(client, webhook_secret, "d-1")
        analyzer.analyze_pr.side_effect = None
        assert send(client, webhook_secret, "d-2").json()["status"] == "queued"

    def test_successful_review_cannot_be_redelivered(self, client, webhook_secret, analyzer, github):  # noqa: F811
        send(client, webhook_secret, "d-1")
        assert send(client, webhook_secret, "d-1").json()["status"] == "duplicate"
        assert send(client, webhook_secret, "d-2").json()["status"] == "duplicate"
        assert analyzer.analyze_pr.await_count == 1

    @pytest.mark.parametrize("status", [AnalysisStatus.FAILED, AnalysisStatus.INCOMPLETE])
    def test_fail_closed_result_can_be_redelivered(self, client, webhook_secret, analyzer, github, status):  # noqa: F811
        result = make_result()
        result.status = status
        analyzer.analyze_pr.return_value = result
        send(client, webhook_secret, "d-1")
        assert send(client, webhook_secret, "d-1").json()["status"] == "queued"

    def test_unpostable_comment_can_be_redelivered(self, client, webhook_secret, analyzer, github):  # noqa: F811
        github.get_repo.return_value.get_issue.return_value.create_comment.side_effect = RuntimeError("403")
        send(client, webhook_secret, "d-1")
        assert send(client, webhook_secret, "d-1").json()["status"] == "queued"

    def test_rejected_payload_does_not_burn_the_keys(self, client, webhook_secret, analyzer, github):  # noqa: F811
        bad = {"action": "opened", "pull_request": {"number": 1}}  # no html_url
        assert send(client, webhook_secret, "d-9", payload=bad).status_code == 400
        assert send(client, webhook_secret, "d-9", payload=bad).status_code == 400  # not "duplicate"


# --- 3. the webhook secret is stripped before the length check --------------------------


GOOD = "s" * MIN_WEBHOOK_SECRET_LENGTH


def make_settings(secret):
    return Settings(_env_file=None, GITHUB_TOKEN="x", GITHUB_WEBHOOK_SECRET=secret, API_KEY="k" * 32)


class TestSecretStripping:
    @pytest.mark.parametrize("secret", ["  " + "a" * 20 + "  " * 6,"a" * 20 + "\n" * 20, " " * 40])
    def test_padded_short_secret_is_refused(self, secret):
        assert len(secret) >= MIN_WEBHOOK_SECRET_LENGTH
        with pytest.raises(ValidationError, match="GITHUB_WEBHOOK_SECRET"):
            make_settings(secret)

    @pytest.mark.parametrize("secret", [f"{GOOD}\n", f"  {GOOD}  ", f"\t{GOOD}\r\n"])
    def test_padded_long_secret_is_accepted_and_stored_stripped(self, secret):
        # The stripped value is also the HMAC key: what was length-checked is what signs
        assert make_settings(secret).GITHUB_WEBHOOK_SECRET == GOOD

    def test_exactly_minimum_length_still_passes(self):
        assert make_settings(GOOD).GITHUB_WEBHOOK_SECRET == GOOD

    def test_api_key_still_refuses_whitespace_padding(self):
        with pytest.raises(ValidationError, match="API_KEY"):
            Settings(_env_file=None, GITHUB_TOKEN="x", GITHUB_WEBHOOK_SECRET=GOOD, API_KEY=" " + "k" * 32)


# --- 4. the delivery id is validated ----------------------------------------------------


class TestDeliveryIdValidation:
    @pytest.mark.parametrize("bad", ["a" * 65, "x" * 5000, "has space", "semi;colon", "slash/id", ""])
    def test_oversized_or_malformed_id_is_400(self, client, webhook_secret, analyzer, bad):  # noqa: F811
        res = send(client, webhook_secret, bad)
        assert res.status_code == 400
        analyzer.analyze_pr.assert_not_called()

    @pytest.mark.parametrize("good", [str(uuid.uuid4()), "d-1", "a" * 64, "A.b_c-9"])
    def test_uuid_and_bounded_ids_are_accepted(self, client, webhook_secret, analyzer, github, good):  # noqa: F811
        assert send(client, webhook_secret, good).status_code == 200

    def test_a_bad_id_does_not_claim_the_body(self, client, webhook_secret, analyzer, github):  # noqa: F811
        assert send(client, webhook_secret, "a" * 65).status_code == 400
        assert send(client, webhook_secret, "d-1").json()["status"] == "queued"

    def test_unsigned_request_gets_401_not_a_validation_hint(self, client, webhook_secret):
        body = b"{}"
        res = client.post("/webhooks/github", content=body, headers={
            "X-GitHub-Event": "ping", "X-GitHub-Delivery": "a" * 65})
        assert res.status_code == 401

    def test_ping_with_a_bad_id_is_also_400(self, client, webhook_secret):
        assert send(client, webhook_secret, "bad id", payload={"zen": "x"}, event="ping").status_code == 400


# --- 5. bounds: TTL and size, with a patched clock --------------------------------------


class TestCacheBounds:
    @pytest.fixture
    def clock(self, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr(webhooks.time, "monotonic", lambda: now[0])
        return now

    def test_body_hash_expires_after_the_ttl(self, clock):
        cache = webhooks.DeliveryCache(ttl_seconds=10, max_entries=8)
        assert not cache.claim("d-1", "h-1")
        clock[0] += 5
        assert cache.claim("d-new", "h-1")  # still a replay, found by the body hash
        clock[0] += 6
        assert not cache.claim("d-new", "h-1")  # both keys aged out

    def test_delivery_id_expires_after_the_ttl(self, clock):
        cache = webhooks.DeliveryCache(ttl_seconds=10, max_entries=8)
        cache.claim("d-1", "h-1")
        clock[0] += 5
        assert cache.claim("d-1", "h-other")
        clock[0] += 6
        assert not cache.claim("d-1", "h-other")

    def test_both_sets_are_bounded_by_size(self, clock):
        cache = webhooks.DeliveryCache(ttl_seconds=3600, max_entries=3)
        for i in range(10):
            clock[0] += 1
            cache.claim(f"d-{i}", f"h-{i}")
        assert len(cache._seen) <= 3 and len(cache._bodies) <= 3
        assert not cache.claim("d-new", "h-0")  # oldest body evicted
        assert cache.claim("d-new2", "h-9")  # newest body still remembered

    def test_flooding_ids_does_not_evict_body_hashes(self, clock):
        cache = webhooks.DeliveryCache(ttl_seconds=3600, max_entries=3)
        cache.claim("d-0", "h-0")
        for i in range(1, 6):
            clock[0] += 1
            cache.claim(f"d-{i}", None)  # id-only claims (no body hash)
        assert cache.claim("fresh", "h-0")

    def test_forget_releases_both_keys(self, clock):
        cache = webhooks.DeliveryCache()
        cache.claim("d-1", "h-1")
        cache.forget("d-1", "h-1")
        assert not cache.claim("d-1", "h-1")

    def test_a_replay_does_not_extend_the_claim(self, clock):
        cache = webhooks.DeliveryCache(ttl_seconds=10, max_entries=8)
        cache.claim("d-1", "h-1")
        clock[0] += 8
        assert cache.claim("d-1", "h-1")
        clock[0] += 3
        assert not cache.claim("d-1", "h-1")


# --- 6. log lines in webhooks.py carry no exception text --------------------------------


class TestCleanLogs:
    def test_failed_analysis_logs_type_and_error_id_only(self, client, webhook_secret, analyzer, github, caplog):  # noqa: F811
        analyzer.analyze_pr.side_effect = RuntimeError("sentinel-secret-text")
        with caplog.at_level(logging.DEBUG):
            send(client, webhook_secret, "d-1")
        text = caplog.text
        assert "sentinel-secret-text" not in text
        assert "RuntimeError" in text and "error_id=" in text

    def test_unpostable_comment_logs_no_exception_text(self, client, webhook_secret, analyzer, github, caplog):  # noqa: F811
        github.get_repo.return_value.get_issue.return_value.create_comment.side_effect = RuntimeError("sentinel-post")
        with caplog.at_level(logging.DEBUG):
            send(client, webhook_secret, "d-1")
        assert "sentinel-post" not in caplog.text
        assert "error_id=" in caplog.text

    def test_invalid_json_logs_no_body_text(self, client, webhook_secret, caplog):
        with caplog.at_level(logging.DEBUG):
            res = send(client, webhook_secret, body=b"not json sentinel-body", event="ping")
        assert res.status_code == 400
        assert "sentinel-body" not in caplog.text
        assert "error_id=" in caplog.text

    def test_no_raw_exception_formatting_left_in_the_file(self):
        import inspect
        assert "{e}" not in inspect.getsource(webhooks)

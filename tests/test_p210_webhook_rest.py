"""P2-10: a webhook without an event header is a 400; action and PR number are logged
escaped. No network."""

import json
import logging

from tests.test_p116_replay import send
from tests.test_webhooks import analyzer, github, pr_payload, sign  # noqa: F401  (fixtures)


def test_missing_event_header_is_a_400(client, webhook_secret):
    body = json.dumps({"zen": "x"}).encode()
    res = client.post(
        "/webhooks/github",
        content=body,
        headers={"X-Hub-Signature-256": sign(webhook_secret, body), "Content-Type": "application/json"},
    )
    assert res.status_code == 400
    assert res.json()["detail"] == "Missing X-GitHub-Event header"


def test_unsigned_request_without_event_header_is_still_a_401(client):
    res = client.post("/webhooks/github", content=b"{}", headers={"Content-Type": "application/json"})
    assert res.status_code == 401


def test_action_is_logged_and_echoed_escaped(client, webhook_secret, caplog):
    payload = pr_payload()
    payload["action"] = "x\nFORGED " + "A" * 500
    with caplog.at_level(logging.INFO):
        res = send(client, webhook_secret, payload=payload)
    assert res.json()["status"] == "ignored"
    assert "\n" not in res.json()["message"] and len(res.json()["message"]) < 200
    lines = [r.getMessage() for r in caplog.records if "Received pull_request event" in r.getMessage()]
    assert lines and all("\n" not in line and len(line) < 250 for line in lines)


def test_normal_action_reply_reads_as_before(client, webhook_secret):
    res = send(client, webhook_secret, payload=pr_payload("closed"))
    assert res.json()["message"] == "Action 'closed' does not trigger analysis"

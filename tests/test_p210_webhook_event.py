"""P2-10: the unsigned X-GitHub-Event header is logged and echoed escaped and capped."""

import json
import logging

from tests.test_p116_replay import send
from tests.test_webhooks import analyzer, github, pr_payload, sign  # noqa: F401  (fixtures)


def test_forged_event_header_is_escaped_and_capped(client, webhook_secret, caplog):
    # Header values can't carry \n through httpx, but U+0085 (NEL) splits a line too
    forged = "a\x85FORGED " + "Z" * 5000
    body = json.dumps(pr_payload()).encode()
    headers = {
        "X-GitHub-Event": forged.encode("latin-1"),  # raw bytes: httpx would refuse  in a str
        "X-Hub-Signature-256": sign(webhook_secret, body),
        "Content-Type": "application/json",
    }
    with caplog.at_level(logging.INFO):
        res = client.post("/webhooks/github", content=body, headers=headers)
    assert res.status_code == 200 and res.json()["status"] == "ignored"
    assert len(res.json()["message"]) < 200
    assert "\x85" not in res.json()["message"]
    lines = [r.getMessage() for r in caplog.records if "Ignoring event type" in r.getMessage()]
    assert lines
    for line in lines:
        assert "\x85" not in line and len(line) < 200


def test_normal_event_name_is_still_readable(client, webhook_secret):
    res = send(client, webhook_secret, event="issues")
    assert res.json()["message"] == "Event type 'issues' not handled"

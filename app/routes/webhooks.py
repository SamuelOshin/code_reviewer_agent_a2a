# app/routes/webhooks.py

"""GitHub Webhook Handlers

Handles incoming GitHub webhook events, specifically pull_request events.
Includes HMAC signature verification for security.
"""

import hashlib
import hmac
import logging
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.errors import new_error_id
from app.services.code_analyzer import CodeAnalyzerService
from app.services.github_mcp import GitHubMCPService
from app.utils.formatters import SummaryFormatter

logger = logging.getLogger(__name__)

# GitHub rejects comment bodies over 65,536 characters; stay safely below
MAX_COMMENT_CHARS = 60000
TRUNCATION_NOTE = " ...[comment truncated to fit GitHub's size limit]"


def _truncate_comment(body: str) -> str:
    if len(body) <= MAX_COMMENT_CHARS:
        return body
    return body[: MAX_COMMENT_CHARS - len(TRUNCATION_NOTE)] + TRUNCATION_NOTE

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


# GitHub sends X-GitHub-Delivery as a UUID (36 characters). Accept a bounded, URL-safe
# charset a little wider than that and reject the rest, so a signed request cannot make
# the server hold or log an arbitrary-size header value.
DELIVERY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# Times one signed body may run per TTL window when its analysis keeps failing before a
# comment is posted (P1-19). The first run plus two retries; the third failure is final.
MAX_RUNS_PER_BODY = 3
# Entries kept per key store. Each is a 64-character string and a float, so 8192 is a
# few MB at most, while an hour of traffic would need more than 8192 distinct pull
# request events before the oldest body becomes replayable early.
DEFAULT_MAX_ENTRIES = 8192


class DeliveryCache:
    """Remembers recent webhook deliveries so a replay runs once (P1-15, P1-16).

    Two keys, either of which marks a replay:

    * the X-GitHub-Delivery id, and
    * the SHA-256 of the raw request body, taken after the signature check passed.

    The body hash is the reliable key. GitHub's HMAC covers the body but not the
    delivery header, so a captured, validly signed body can be resent with a fresh
    delivery id. A GitHub "Redeliver" reuses both the same body and the same id,
    while a genuinely new event always has a different body (new timestamps, head
    sha, delivery-specific fields). Keying on the body therefore catches the replay
    without ever blocking a real new event.

    Each key set is bounded by age and by size (oldest evicted first), so memory
    cannot grow without limit. In-memory only: a restart empties it and several
    replicas each keep their own, so a replay that lands after a restart or on
    another replica is processed again. Sharing it would need an external store.

    Retry budget (P1-19): a failed run releases its keys so a manual "Redeliver"
    can retry, but a captured body must not be resendable without limit. Each body
    may run MAX_RUNS_PER_BODY times per TTL window; the last failure is not
    released, so further resends get "duplicate". The budget is its own bounded
    store, keyed by body hash, and is never reset by forget(). The delivery id is
    released and kept together with the body: a Redeliver reuses both, and a fresh
    id on the same body is stopped by the body key, so the id adds no extra runs.

    Remaining limit: once max_entries distinct deliveries arrive within the TTL, the
    oldest entry is evicted and that body is replayable again inside the window.
    """

    def __init__(self, ttl_seconds: float = 3600.0, max_entries: int = DEFAULT_MAX_ENTRIES):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()  # delivery ids
        self._bodies: OrderedDict[str, float] = OrderedDict()  # body SHA-256 digests
        # body digest -> (failed runs so far, time of the first failure)
        self._budget: OrderedDict[str, tuple[int, float]] = OrderedDict()
        self._lock = threading.Lock()

    def _purge(self, store: "OrderedDict[str, Any]", now: float) -> None:
        while store:
            oldest, value = next(iter(store.items()))
            started = value[1] if isinstance(value, tuple) else value
            if now - started <= self._ttl and len(store) < self._max:
                break
            del store[oldest]

    def claim(self, delivery_id: str | None, body_hash: str | None) -> bool:
        """Return True if this is a replay. Otherwise claim both keys and return False."""
        now = time.monotonic()
        with self._lock:
            self._purge(self._seen, now)
            self._purge(self._bodies, now)
            if (delivery_id and delivery_id in self._seen) or (
                body_hash and body_hash in self._bodies
            ):
                return True
            if delivery_id:
                self._seen[delivery_id] = now
            if body_hash:
                self._bodies[body_hash] = now
            return False

    def seen_before(self, delivery_id: str) -> bool:
        """True if the id was already claimed; otherwise claim it and return False."""
        return self.claim(delivery_id, None)

    def forget(
        self, delivery_id: str | None, body_hash: str | None = None, *, charge: bool = True
    ) -> None:
        """Release both keys so a redelivery of a failed or rejected event can run.

        With charge (a failed run), spends one run of the body's budget; when the
        budget is used up, both keys stay claimed so the body is ignored until its TTL
        passes. A payload rejected before any work is released without charge.
        """
        now = time.monotonic()
        with self._lock:
            if body_hash and charge:
                self._purge(self._budget, now)
                runs, first = self._budget.get(body_hash, (0, now))
                runs += 1
                # Updating an existing key keeps its place, so the store stays ordered
                # by first failure and _purge (front first) drops expired entries.
                # Moving it to the end let an expired count hide behind a newer one.
                self._budget[body_hash] = (runs, first)
                if runs >= MAX_RUNS_PER_BODY:
                    return
            if delivery_id:
                self._seen.pop(delivery_id, None)
            if body_hash:
                self._bodies.pop(body_hash, None)


delivery_cache = DeliveryCache()


def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    """
    Verify GitHub webhook signature using HMAC
    
    Args:
        payload_body: Raw request body
        signature_header: X-Hub-Signature-256 header value
        
    Returns:
        True if signature is valid. GITHUB_WEBHOOK_SECRET is required at startup
        (P1-07); an empty secret here still fails closed.
    """
    if not settings.GITHUB_WEBHOOK_SECRET or not signature_header:
        return False
    
    # GitHub sends signature as "sha256=<hex_digest>"
    try:
        hash_algorithm, signature = signature_header.split("=", 1)
    except ValueError:
        return False
    
    if hash_algorithm != "sha256":
        return False
    
    # Calculate expected signature
    mac = hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = mac.hexdigest()
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(signature, expected_signature)


@router.post("/github")
async def handle_github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
    x_github_delivery: str = Header(None)
):
    """
    Handle GitHub webhook events
    
    Args:
        request: FastAPI request object
        background_tasks: FastAPI background tasks
        x_hub_signature_256: GitHub signature header
        x_github_event: GitHub event type header
        x_github_delivery: GitHub delivery id; a replayed id is a 2xx no-op
        
    Returns:
        JSON response with status
    """
    try:
        # Read raw body for signature verification
        body = await request.body()
        
        # Verify signature
        if not verify_github_signature(body, x_hub_signature_256):
            logger.warning("Invalid GitHub webhook signature")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse JSON payload
        try:
            payload = await request.json()
        except Exception as e:
            # Exception text can echo the request body; log the type and an id only
            logger.error(f"Failed to parse webhook payload: {type(e).__name__} (error_id={new_error_id()})")
            raise HTTPException(status_code=400, detail="Invalid JSON payload") from e

        # Checked after the signature so unauthenticated callers learn nothing. A
        # missing header is fine: the body hash still catches a replay.
        if x_github_delivery is not None and not DELIVERY_ID_RE.fullmatch(x_github_delivery):
            logger.warning("Rejected webhook with a malformed X-GitHub-Delivery header")
            raise HTTPException(status_code=400, detail="Invalid X-GitHub-Delivery header")
        
        # Handle different event types
        if x_github_event == "pull_request":
            # Claim only after the signature passed, so a forged request cannot use
            # up a real delivery's id or body
            body_hash = hashlib.sha256(body).hexdigest()
            if delivery_cache.claim(x_github_delivery, body_hash):
                logger.info("Ignoring replayed webhook delivery")
                return JSONResponse({
                    "status": "duplicate",
                    "message": "Delivery already processed"
                })

            def release() -> None:
                delivery_cache.forget(x_github_delivery, body_hash)

            try:
                return await handle_pull_request_event(payload, background_tasks, release)
            except HTTPException:
                # Rejected payload: nothing ran, so release without spending the budget
                # and every resend gets the same 400 (P1-19)
                delivery_cache.forget(x_github_delivery, body_hash, charge=False)
                raise
        
        elif x_github_event == "ping":
            logger.info("Received ping event from GitHub")
            return JSONResponse({
                "status": "ok",
                "message": "Webhook is working!"
            })
        
        else:
            logger.info(f"Ignoring event type: {x_github_event}")
            return JSONResponse({
                "status": "ignored",
                "message": f"Event type '{x_github_event}' not handled"
            })
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in webhook handler: {type(e).__name__} (error_id={new_error_id()})")
        raise HTTPException(status_code=500, detail="Internal server error") from e


async def handle_pull_request_event(
    payload: dict[str, Any],
    background_tasks: BackgroundTasks,
    release: Callable[[], None] | None = None,
) -> JSONResponse:
    """
    Handle pull_request events
    
    Args:
        payload: Webhook payload
        background_tasks: FastAPI background tasks
        release: forgets the delivery's replay keys; called if the review fails
        
    Returns:
        JSON response
    """
    action = payload.get("action")
    pull_request = payload.get("pull_request", {})
    
    logger.info(f"Received pull_request event: action={action}, pr_number={pull_request.get('number')}")
    
    # Only analyze on specific actions
    trigger_actions = ["opened", "synchronize", "reopened"]
    
    if action not in trigger_actions:
        return JSONResponse({
            "status": "ignored",
            "message": f"Action '{action}' does not trigger analysis"
        })
    
    # Extract PR URL
    pr_url = pull_request.get("html_url")
    pr_number = pull_request.get("number")
    
    if not pr_url:
        logger.error("No PR URL in webhook payload")
        raise HTTPException(status_code=400, detail="Missing PR URL in payload")
    
    # Queue analysis as background task. The signature was verified above, so the
    # event really came from GitHub and the summary can be posted back.
    background_tasks.add_task(
        analyze_pr_background,
        pr_url=pr_url,
        pr_number=pr_number,
        release=release,
    )
    
    return JSONResponse({
        "status": "queued",
        "message": f"Analysis queued for PR #{pr_number}",
        "pr_url": pr_url
    })


async def analyze_pr_background(
    pr_url: str, pr_number: int, release: Callable[[], None] | None = None
):
    """
    Background task to analyze a PR

    The result is logged and posted back to the PR as one summary comment. A
    failure to post is logged (without the token) and never raised.

    Args:
        pr_url: PR URL
        pr_number: PR number
        release: called when no comment was posted (the analysis raised, or posting
            failed), so a manual GitHub "Redeliver" is not ignored as a replay (P1-16).
            Once a comment is posted the delivery stays claimed, even for a failed or
            incomplete result: an incomplete result is deterministic for a large diff,
            so releasing it would let a captured body re-run the model and re-comment.
    """
    failed = False
    try:
        logger.info(f"Starting background analysis for PR #{pr_number}")

        analyzer = CodeAnalyzerService()
        analysis_result = await analyzer.analyze_pr(pr_url)
        logger.info(
            f"Background analysis completed for PR #{pr_number}: "
            f"risk={analysis_result.risk_level.value}, "
            f"recommendation={analysis_result.approval_recommendation.value}, "
            f"security={len(analysis_result.security_findings)}, "
            f"performance={len(analysis_result.performance_findings)}, "
            f"best_practices={len(analysis_result.best_practice_findings)}"
        )

        comment = _truncate_comment(SummaryFormatter.format_for_github_comment(analysis_result))
        try:
            async with GitHubMCPService() as github:
                owner, repo, number = github.parse_pr_url(pr_url)
                await github.post_pr_comment(owner, repo, number, comment)
        except Exception as e:
            # Exception text can echo request details; log the type and an id only
            failed = True
            logger.error(
                f"Failed to post comment for PR #{pr_number}: {type(e).__name__} "
                f"(error_id={new_error_id()})"
            )

    except Exception as e:
        failed = True
        logger.error(
            f"Background analysis failed for PR #{pr_number}: {type(e).__name__} "
            f"(error_id={new_error_id()})"
        )
    finally:
        if failed and release is not None:
            release()

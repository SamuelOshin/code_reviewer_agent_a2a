"""Safe error reporting helpers (F-05).

Clients get a generic message plus a short error id. The full exception is logged
server-side under the same id, so an operator can find it without the client ever
seeing internal text (paths, URLs, tokens, upstream response bodies).
"""

import uuid
from urllib.parse import urlsplit


def new_error_id() -> str:
    """Short id shown to the client and logged next to the full error."""
    return uuid.uuid4().hex[:8]


def safe_webhook_target(url: object) -> str:
    """Return only scheme://host of a push URL for logging.

    Push URLs may carry credentials (user:pass@host) or secret query tokens, so the
    path, query and userinfo are never logged.
    """
    try:
        parts = urlsplit(str(url))
        return f"{parts.scheme or 'unknown'}://{parts.hostname or 'unknown'}"
    except Exception:
        return "unknown"

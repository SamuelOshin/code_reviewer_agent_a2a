"""Bearer API key check for /rpc and /a2a/* (P1-07, F-04).

These endpoints run reviews with the server's GITHUB_TOKEN, so an open endpoint
would let anyone read private PRs that token can see. One static key from
settings is enough for a single-owner service; per-client keys can come later.
"""

import hmac
import logging

from fastapi import HTTPException, Request, status

from app.core.config import settings

logger = logging.getLogger(__name__)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Missing or invalid API key",
    headers={"WWW-Authenticate": "Bearer"},
)


def _bearer_token(header: str | None) -> str | None:
    """Return the token from "Bearer <token>"; the scheme is case-insensitive (RFC 7235)."""
    if not header:
        return None
    scheme, _, token = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    return token.strip() or None


def is_valid_api_key(presented: str | None) -> bool:
    """Constant-time comparison against settings.API_KEY. Fails closed if none is set."""
    expected = settings.API_KEY
    if not expected or not presented:
        return False
    # Compare bytes: compare_digest rejects non-ASCII str, and bytes keep it constant time
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


async def require_api_key(request: Request) -> None:
    """FastAPI dependency: reject the request unless it carries the configured key."""
    if not is_valid_api_key(_bearer_token(request.headers.get("authorization"))):
        # Never log the presented value
        logger.warning("Rejected unauthenticated request to %s", request.url.path)
        raise _UNAUTHORIZED

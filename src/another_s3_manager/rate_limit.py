"""Rate limiting via slowapi.

Per-IP limits, in-memory backend (single-container deployment — no Redis).
The limiter is a module-level singleton, registered into the FastAPI app in main.py.
"""

import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from another_s3_manager.constants import RATE_LIMIT_DEFAULT, RATE_LIMIT_PROXY_HEADER


def _client_ip(request: Request) -> str:
    """Return the client IP, honoring a configured reverse-proxy header.

    When `RATE_LIMIT_PROXY_HEADER` env is set (e.g. `X-Forwarded-For`), read the first
    address from that header. Otherwise fall back to the direct socket address.

    For `X-Forwarded-For` style headers (which can be a comma-separated chain of proxies),
    we take the first entry — that's the original client.
    """
    if RATE_LIMIT_PROXY_HEADER:
        forwarded = request.headers.get(RATE_LIMIT_PROXY_HEADER)
        if forwarded:
            # X-Forwarded-For may carry "client, proxy1, proxy2" — take the first
            return forwarded.split(",")[0].strip()
    return get_remote_address(request)


# Single per-IP limit applied to ALL endpoints via SlowAPIMiddleware.
# We do NOT use @limiter.limit(...) decorators on individual endpoints — they crash
# at runtime when handlers return dicts (FastAPI serializes those into JSONResponse
# only AFTER the decorator runs, and the decorator demands a Response). Middleware
# operates AFTER FastAPI serialization, so it works fine.
# Disabled in tests via RATE_LIMIT_ENABLED=false to allow direct endpoint calls
# with mocked Request objects.
# headers_enabled + retry_after="delta-seconds" → 429 responses get Retry-After (seconds)
# and X-RateLimit-Limit/Remaining/Reset headers for client-side countdown UX.
_enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() != "false"
limiter = Limiter(
    key_func=_client_ip,
    default_limits=[RATE_LIMIT_DEFAULT],
    enabled=_enabled,
    headers_enabled=True,
    retry_after="delta-seconds",
)

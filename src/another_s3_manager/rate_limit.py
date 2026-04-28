"""Rate limiting via slowapi.

Per-IP limits, in-memory backend (single-container deployment — no Redis).
The limiter is a module-level singleton, registered into the FastAPI app in main.py.
"""

import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from another_s3_manager.constants import RATE_LIMIT_PROXY_HEADER, RATE_LIMIT_READ


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


# Default limit covers all endpoints (mostly reads). Mutating endpoints + /api/login
# override with stricter limits via @limiter.limit(...) decorators in main.py.
# Disabled in tests via RATE_LIMIT_ENABLED=false to allow direct endpoint calls
# with mocked Request objects.
# headers_enabled + retry_after="delta-seconds" → 429 responses get Retry-After (seconds)
# and X-RateLimit-Limit/Remaining/Reset headers, which the React UI uses for countdown UX.
_enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() != "false"
limiter = Limiter(
    key_func=_client_ip,
    default_limits=[RATE_LIMIT_READ],
    enabled=_enabled,
    headers_enabled=True,
    retry_after="delta-seconds",
)

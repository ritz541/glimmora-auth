"""In-memory sliding window rate limiter for auth endpoints."""

import asyncio
import time
from collections import defaultdict, deque
from typing import Dict

from fastapi import HTTPException, Request, status


class _SlidingWindowCounter:
    """In-memory sliding window rate limiter.

    Thread-safe via asyncio.Lock. Entries are pruned on each check.
    Uses collections.deque for O(1) head removal.

    Design notes:
    - Per-process: each uvicorn/gunicorn worker gets its own counter.
      Effective limits are multiplied by the number of workers.
      For multi-worker deployments, consider a shared backend (Redis).
    - IP-based: uses request.client.host directly. Behind a reverse proxy,
      this will always be the proxy's IP unless the ASGI server is
      configured to pass X-Forwarded-For.
    """

    def __init__(self) -> None:
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, max_requests: int, window_seconds: float) -> bool:
        """Check if *key* has exceeded its limit.

        Returns True if the request is allowed (under the limit),
        False if it should be rejected (over the limit).
        Appends the current timestamp on success.
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            timestamps = self._windows[key]
            # Prune expired entries
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if len(timestamps) >= max_requests:
                return False

            timestamps.append(now)
            return True


_counter = _SlidingWindowCounter()


def _parse_limit(limit_str: str) -> tuple[int, float]:
    """Parse a limit string like ``\"10/minute\"`` into ``(count, window_seconds)``.

    Supported units: second(s), minute(s), hour(s), day(s).
    """
    parts = limit_str.strip().split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid rate limit format: {limit_str!r} (expected e.g. '10/minute')")

    try:
        count = int(parts[0].strip())
    except ValueError:
        raise ValueError(f"Invalid rate limit count: {parts[0]!r}")

    unit = parts[1].strip().rstrip("s")  # "minutes" -> "minute"
    window_map = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
    window_seconds = window_map.get(unit)
    if window_seconds is None:
        raise ValueError(
            f"Unsupported rate limit unit: {parts[1]!r} "
            f"(supported: second, minute, hour, day)"
        )

    return count, window_seconds


# Default limits — sensible for most apps
DEFAULT_RATE_LIMITS: Dict[str, str] = {
    "register": "5/hour",
    "login": "10/minute",
    "forgot-password": "3/hour",
    "resend-verification": "3/hour",
    "refresh": "10/minute",
}


async def rate_limit_dependency(request: Request) -> None:
    """FastAPI dependency that applies rate limits configured on the app.

    Reads ``request.app.state._auth_rate_limits`` (set by ``setup_auth()``).
    If no rate limits are configured, this is a no-op.
    """
    rate_limits: Dict[str, str] | None = getattr(
        request.app.state, "_auth_rate_limits", None
    )
    if rate_limits is None:
        return  # Rate limiting not configured — no-op

    # Determine the endpoint name from the request path
    path: str = request.scope.get("path", "")
    endpoint_name = path.rstrip("/").rsplit("/", 1)[-1]

    limit_str = rate_limits.get(endpoint_name)
    if limit_str is None:
        return  # No limit configured for this endpoint

    # Build a key from the client IP
    ip = request.client.host if request.client else "unknown"
    key = f"{endpoint_name}:{ip}"

    try:
        count, window = _parse_limit(limit_str)
    except ValueError:
        return  # Malformed limit — fail open

    ok = await _counter.check(key, count, window)
    if not ok:
        logger = __import__("logging").getLogger("glimmora_auth")
        logger.warning("Rate limit exceeded for %s (ip=%s)", endpoint_name, ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )

"""
Rate limiting — in-process sliding window with optional Redis backend.

Covers requirements §5 (per-IP limits, per-client failure limits),
§9 (distributed-safe via Redis).

Design:
  rate_check(key, endpoint)        → bool  — True if within limit (always records)
  is_over_fail_limit(client_id)    → bool  — True if client already exceeded failures
  record_fail(client_id)           → None  — record one failed verify attempt

Separation of check vs record for failures allows the route handler to:
  1. Reject early if already over limit (before expensive DB/ZKP work)
  2. Only record a failure when verification actually fails (not on success)
"""

import collections
import os
import threading
import time

# ---------------------------------------------------------------------------
# Redis availability probe (shares environment variable with session_store)
# ---------------------------------------------------------------------------
try:
    import redis as _redis_lib

    _REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    _r = _redis_lib.from_url(
        _REDIS_URL,
        socket_connect_timeout=1,
        socket_timeout=1,
        decode_responses=True,
    )
    _r.ping()
    _REDIS_OK = True
except Exception:
    _r = None
    _REDIS_OK = False

# ---------------------------------------------------------------------------
# Limits configuration
# ---------------------------------------------------------------------------
# (window_seconds, max_requests)
RATE_LIMITS: dict[str, tuple[int, int]] = {
    "commit":   (1,  10),    # 10 req / 1 s per IP
    "verify":   (1,   5),    # 5  req / 1 s per IP
    "register": (60, 10),    # 10 req / 60 s per IP
}

_FAIL_WINDOW_S  = 60   # sliding window for failed verifies
_FAIL_MAX       = 5    # max failures per client_id within window

# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------
_rate_buckets: dict[str, collections.deque] = {}
_rate_lock  = threading.Lock()

_fail_buckets: dict[str, collections.deque] = {}
_fail_lock  = threading.Lock()


def _mem_rate_check(key: str, endpoint: str) -> bool:
    window_s, max_req = RATE_LIMITS[endpoint]
    now = time.monotonic()
    with _rate_lock:
        dq = _rate_buckets.setdefault(key, collections.deque())
        cutoff = now - window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= max_req:
            return False
        dq.append(now)
        return True


def _mem_is_over_fail_limit(client_id: str) -> bool:
    now = time.monotonic()
    with _fail_lock:
        dq = _fail_buckets.get(client_id)
        if dq is None:
            return False
        cutoff = now - _FAIL_WINDOW_S
        # Prune without modifying — use a view
        active = sum(1 for ts in dq if ts >= cutoff)
        return active >= _FAIL_MAX


def _mem_record_fail(client_id: str) -> None:
    now = time.monotonic()
    with _fail_lock:
        dq = _fail_buckets.setdefault(client_id, collections.deque())
        cutoff = now - _FAIL_WINDOW_S
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)


# ---------------------------------------------------------------------------
# Redis implementation  §9
# ---------------------------------------------------------------------------
def _redis_rate_check(key: str, endpoint: str) -> bool:
    """Sliding-window rate check using a Redis sorted set."""
    window_s, max_req = RATE_LIMITS[endpoint]
    now = time.time()
    rkey = f"acas:rate:{endpoint}:{key}"
    pipe = _r.pipeline()
    pipe.zremrangebyscore(rkey, 0, now - window_s)
    pipe.zadd(rkey, {str(now): now})
    pipe.zcard(rkey)
    pipe.expire(rkey, window_s + 1)
    results = pipe.execute()
    return results[2] <= max_req


def _redis_is_over_fail_limit(client_id: str) -> bool:
    now = time.time()
    rkey = f"acas:fail:{client_id}"
    _r.zremrangebyscore(rkey, 0, now - _FAIL_WINDOW_S)
    count = _r.zcard(rkey)
    return int(count) >= _FAIL_MAX


def _redis_record_fail(client_id: str) -> None:
    now = time.time()
    rkey = f"acas:fail:{client_id}"
    pipe = _r.pipeline()
    pipe.zadd(rkey, {str(now): now})
    pipe.expire(rkey, _FAIL_WINDOW_S + 1)
    pipe.execute()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def rate_check(key: str, endpoint: str) -> bool:
    """Return True if the request is within limits (and record the attempt).

    Uses Redis if available, falls back to in-process sliding window.
    Caller should pass app.config.get("TESTING") guard if needed.
    """
    if _REDIS_OK:
        try:
            return _redis_rate_check(key, endpoint)
        except Exception:
            pass
    return _mem_rate_check(key, endpoint)


def is_over_fail_limit(client_id: str) -> bool:
    """Return True if client_id has exceeded the failure threshold.

    Read-only — does NOT record a new failure.
    """
    if _REDIS_OK:
        try:
            return _redis_is_over_fail_limit(client_id)
        except Exception:
            pass
    return _mem_is_over_fail_limit(client_id)


def record_fail(client_id: str) -> None:
    """Record one failed verification attempt for client_id."""
    if _REDIS_OK:
        try:
            _redis_record_fail(client_id)
            return
        except Exception:
            pass
    _mem_record_fail(client_id)

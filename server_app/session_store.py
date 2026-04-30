"""
Session store — Redis-backed with in-memory LRU fallback.

Covers requirements §2 (lifecycle, concurrency), §4 (persistent backend),
§9 (t-reuse guard), §10 (proof replay protection).
"""

import collections
import json
import os
import secrets
import threading
import time
from typing import Optional

from schnorr_crypto import compute_challenge

# ---------------------------------------------------------------------------
# Redis availability probe
# ---------------------------------------------------------------------------
try:
    import redis as _redis_lib

    _REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    _r = _redis_lib.from_url(
        _REDIS_URL,
        socket_connect_timeout=1,
        socket_timeout=1,
        decode_responses=False,
    )
    _r.ping()
    REDIS_AVAILABLE = True
except Exception:
    _r = None
    REDIS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_SESSIONS         = 10_000    # §2.6 global session cap
SESSION_TTL          = 5         # seconds between commit and verify
COMMIT_RACE_WINDOW   = 0.050     # 50 ms — race vs hijack threshold  §2
_RECENT_T_WINDOW     = 100       # commitment values remembered per client §9

SESSION_STATE_CHALLENGE_ISSUED = "challenge_issued"
SESSION_STATE_CONSUMED         = "consumed"

# Redis key namespaces
_NS_SESSION  = "acas:sess:"
_NS_CLIENT   = "acas:client:"
_NS_RECENT_T = "acas:recent_t:"
_NS_USED     = "acas:used:"


# ===========================================================================
# In-memory implementation (always used as fallback)
# ===========================================================================
class _MemorySessionStore:
    """OrderedDict-backed LRU store with full lifecycle + replay protection."""

    def __init__(self):
        self._store: collections.OrderedDict = collections.OrderedDict()
        self._client_sessions: dict[str, str] = {}
        self._lock = threading.Lock()
        self._recent_t: dict[str, collections.deque] = {}
        self._recent_t_lock = threading.Lock()
        self._used_proofs: dict[str, float] = {}   # key → first-seen timestamp
        self._used_lock = threading.Lock()

    # ── dict-like protocol ──────────────────────────────────────────────
    def __contains__(self, session_id: str) -> bool:
        return session_id in self._store

    def __getitem__(self, session_id: str) -> dict:
        return self._store[session_id]

    def __delitem__(self, session_id: str) -> None:
        with self._lock:
            self._delete_locked(session_id)

    def _delete_locked(self, session_id: str) -> None:
        """Must be called with self._lock held."""
        sess = self._store.pop(session_id, None)
        if sess:
            self._client_sessions.pop(sess["client_id"], None)

    def _evict_if_needed(self) -> None:
        """Evict oldest entries until under MAX_SESSIONS (called under lock)."""
        while len(self._store) > MAX_SESSIONS:
            oldest, _ = next(iter(self._store.items()))
            self._delete_locked(oldest)

    def get(self, session_id: str, default=None):
        return self._store.get(session_id, default)

    def pop(self, session_id: str, *args):
        with self._lock:
            sess = self._store.pop(session_id, *args)
            if sess and isinstance(sess, dict):
                self._client_sessions.pop(sess.get("client_id", ""), None)
            return sess

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._client_sessions.clear()
        with self._recent_t_lock:
            self._recent_t.clear()
        with self._used_lock:
            self._used_proofs.clear()

    def __len__(self) -> int:
        return len(self._store)

    def keys(self):
        return self._store.keys()

    def values(self):
        return self._store.values()

    def items(self):
        return self._store.items()

    # ── commitment (t) reuse guard  §9 ─────────────────────────────────
    def check_and_record_t(self, client_id: str, t: int) -> bool:
        """Return True if t is fresh for this client, False if recently reused."""
        with self._recent_t_lock:
            dq = self._recent_t.setdefault(
                client_id, collections.deque(maxlen=_RECENT_T_WINDOW)
            )
            if t in dq:
                return False
            dq.append(t)
            return True

    # ── proof replay protection  §10 ───────────────────────────────────
    def check_and_record_proof(self, session_id: str, s: int) -> bool:
        """Return True if (session_id, s) has not been seen before.  §10

        Entries expire after 1 hour; stale entries are pruned on each call.
        """
        key = f"{session_id}:{s:x}"
        now = time.time()
        with self._used_lock:
            stale = [k for k, ts in self._used_proofs.items() if now - ts > 3600]
            for k in stale:
                del self._used_proofs[k]
            if key in self._used_proofs:
                return False
            self._used_proofs[key] = now
            return True

    # ── atomic session creation  §2.7 ──────────────────────────────────
    def create_session(
        self,
        client_id: str,
        t: int,
        client_ip: str,
        user_agent: str,
    ) -> tuple[str, int]:
        """Atomically create a session; raise ValueError("race"|"hijack") if blocked."""
        with self._lock:
            existing_sid = self._client_sessions.get(client_id)
            if existing_sid:
                existing = self._store.get(existing_sid)
                if existing:
                    age = time.time() - existing["created_at"]
                    if age <= COMMIT_RACE_WINDOW:
                        raise ValueError("race")
                    else:
                        self._delete_locked(existing_sid)
                        raise ValueError("hijack")

            session_id   = secrets.token_urlsafe(32)
            server_nonce = secrets.token_bytes(32)
            challenge_c  = compute_challenge(
                session_id, client_id, t, server_nonce, client_ip, user_agent
            )
            self._store[session_id] = {
                "client_id":  client_id,
                "t":          t,
                "c":          challenge_c,
                "nonce":      server_nonce,
                "ctx_ip":     client_ip,
                "ctx_ua":     user_agent,
                "state":      SESSION_STATE_CHALLENGE_ISSUED,
                "created_at": time.time(),
            }
            self._client_sessions[client_id] = session_id
            self._store.move_to_end(session_id)
            self._evict_if_needed()
            return session_id, challenge_c


# ===========================================================================
# Redis implementation  §4
# ===========================================================================
class _RedisSessionStore:
    """Redis-backed session store — atomic ops via pipelines / SETNX.  §4"""

    # ── helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _sess_key(sid: str) -> str:
        return f"{_NS_SESSION}{sid}"

    @staticmethod
    def _client_key(client_id: str) -> str:
        return f"{_NS_CLIENT}{client_id}"

    def _load(self, session_id: str) -> Optional[dict]:
        raw = _r.get(self._sess_key(session_id))
        if raw is None:
            return None
        sess = json.loads(raw)
        sess["nonce"] = bytes.fromhex(sess["nonce"])   # restore bytes
        return sess

    # ── dict-like protocol ──────────────────────────────────────────────
    def __contains__(self, session_id: str) -> bool:
        return bool(_r.exists(self._sess_key(session_id)))

    def __getitem__(self, session_id: str) -> dict:
        sess = self._load(session_id)
        if sess is None:
            raise KeyError(session_id)
        return sess

    def __delitem__(self, session_id: str) -> None:
        raw = _r.get(self._sess_key(session_id))
        if raw:
            sess = json.loads(raw)
            pipe = _r.pipeline()
            pipe.delete(self._sess_key(session_id))
            pipe.delete(self._client_key(sess["client_id"]))
            pipe.execute()

    def get(self, session_id: str, default=None):
        return self._load(session_id) or default

    def clear(self) -> None:
        for ns in (_NS_SESSION, _NS_CLIENT, _NS_RECENT_T, _NS_USED):
            for key in _r.scan_iter(f"{ns}*"):
                _r.delete(key)

    def __len__(self) -> int:
        return sum(1 for _ in _r.scan_iter(f"{_NS_SESSION}*"))

    def keys(self):
        prefix_len = len(_NS_SESSION)
        return [k.decode()[prefix_len:] for k in _r.scan_iter(f"{_NS_SESSION}*")]

    def values(self):
        return [self._load(k) for k in self.keys()]

    def items(self):
        return [(k, self._load(k)) for k in self.keys()]

    @property
    def _client_sessions(self) -> dict[str, str]:
        """Compatibility shim for test code that reads server.sessions._client_sessions."""
        prefix_len = len(_NS_CLIENT)
        result = {}
        for key in _r.scan_iter(f"{_NS_CLIENT}*"):
            cid = key.decode()[prefix_len:]
            sid = _r.get(key)
            if sid:
                result[cid] = sid.decode()
        return result

    # ── commitment reuse guard  §9 ──────────────────────────────────────
    def check_and_record_t(self, client_id: str, t: int) -> bool:
        key = f"{_NS_RECENT_T}{client_id}"
        t_hex = f"{t:x}".encode()
        members = _r.lrange(key, 0, -1)
        if t_hex in members:
            return False
        pipe = _r.pipeline()
        pipe.rpush(key, t_hex)
        pipe.ltrim(key, -_RECENT_T_WINDOW, -1)
        pipe.expire(key, 86400)
        pipe.execute()
        return True

    # ── proof replay protection  §10 ───────────────────────────────────
    def check_and_record_proof(self, session_id: str, s: int) -> bool:
        """Atomic NX set — returns True only if key did not exist. §10"""
        key = f"{_NS_USED}{session_id}:{s:x}"
        return bool(_r.set(key, b"1", ex=3600, nx=True))

    # ── atomic session creation  §2 ─────────────────────────────────────
    def create_session(
        self,
        client_id: str,
        t: int,
        client_ip: str,
        user_agent: str,
    ) -> tuple[str, int]:
        existing_sid_raw = _r.get(self._client_key(client_id))
        if existing_sid_raw:
            existing_sid = existing_sid_raw.decode()
            existing_raw = _r.get(self._sess_key(existing_sid))
            if existing_raw:
                existing = json.loads(existing_raw)
                age = time.time() - existing["created_at"]
                if age <= COMMIT_RACE_WINDOW:
                    raise ValueError("race")
                pipe = _r.pipeline()
                pipe.delete(self._sess_key(existing_sid))
                pipe.delete(self._client_key(client_id))
                pipe.execute()
                raise ValueError("hijack")

        session_id   = secrets.token_urlsafe(32)
        server_nonce = secrets.token_bytes(32)
        challenge_c  = compute_challenge(
            session_id, client_id, t, server_nonce, client_ip, user_agent
        )
        sess = {
            "client_id":  client_id,
            "t":          t,
            "c":          challenge_c,
            "nonce":      server_nonce.hex(),   # JSON-safe
            "ctx_ip":     client_ip,
            "ctx_ua":     user_agent,
            "state":      SESSION_STATE_CHALLENGE_ISSUED,
            "created_at": time.time(),
        }
        ttl = SESSION_TTL + 10
        pipe = _r.pipeline()
        pipe.setex(self._sess_key(session_id), ttl, json.dumps(sess))
        pipe.setex(self._client_key(client_id), ttl, session_id.encode())
        pipe.execute()
        return session_id, challenge_c


# ===========================================================================
# Factory
# ===========================================================================
def make_session_store():
    """Return a RedisSessionStore if Redis is reachable, else MemorySessionStore."""
    if REDIS_AVAILABLE:
        print("[session_store] Using Redis backend")
        return _RedisSessionStore()
    print("[session_store] Redis unavailable — using in-memory LRU fallback")
    return _MemorySessionStore()

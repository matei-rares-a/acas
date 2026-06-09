"""
Compare PAKE/ZKP timing: Custom Schnorr ZKP vs SRP-6a vs SPAKE2.

Protocols
  SCHNORR     : Custom Schnorr ZKP, server group (512-bit prime, G=4, scrypt n=2048)
                *** 512-bit DLP is BROKEN (Logjam 2015). Included only as baseline. ***
  SCHNORR-2K  : Same protocol but with a 2048-bit safe-prime group (fair security level).
  SCHNORR+    : Custom Schnorr + mutual auth + DH session key (2048-bit group).
  SRP-6a      : RFC 5054 2048-bit group, SHA-256 KDF  (srp library — pure Python, no C ext).
  SPAKE2      : Ed25519 / M255 group  (spake2 library — pure Python).

Fairness notes (read before drawing conclusions)
  1. Group size: SCHNORR uses a 512-bit prime; all others use 2048-bit or stronger.
     Modexp cost ≈ O(n^2.5), so 2048-bit costs ~32× more than 512-bit.
     SCHNORR vs SRP/SPAKE2 is NOT a fair comparison — use SCHNORR-2K instead.
  2. scrypt parameters: n=2**11 (2048) in qa_utils is far below OWASP minimum (n=2**14).
     SCHNORR-2K also runs with n=2**14 to show the realistic KDF cost.
  3. SRP pure Python: the 'srp' library has no C extension (_srp=False).
     All big-number arithmetic runs as Python longs. A C-backed SRP (e.g. OpenSSL)
     would run < 1 ms for auth. Times shown are Python-implementation costs, not
     inherent SRP protocol costs.
  4. Scope: baseline SCHNORR has no mutual auth and no session key. SRP and SPAKE2
     include both. SCHNORR+ is the fair peer for that comparison.
  5. Modexp count per full round-trip is shown in the summary table.

Stage mapping
  Schnorr      : derive_x → compute_y → commit → solve → verify
  Schnorr-2K   : same stages but 2048-bit prime + scrypt n=2**14
  Schnorr+     : adds srv_commit, srv_verify_client, srv_prove,
                 client_verify_server, session_key
  SRP-6a       : register → commit (A) → challenge (B) → solve (M) → verify (HAMK)
  SPAKE2       : start_a → start_b → finish
"""

import hashlib
import hmac as _hmac
import secrets
import statistics
import sys
import time
from pathlib import Path

import srp
from spake2 import SPAKE2_A, SPAKE2_B
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1 as _SECP256R1,
    derive_private_key as _ec_derive_private_key,
)

_QA_PATH = Path(__file__).resolve().parents[1]
_MEASUREMENT_PATH = Path(__file__).resolve().parent
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))
if str(_MEASUREMENT_PATH) not in sys.path:
    sys.path.insert(0, str(_MEASUREMENT_PATH))

from qa_utils import derive_password_x, server
from ec_compare import (
    EC_ORDER as _EC_ORDER,
    EC_GENERATOR as _EC_GENERATOR,
    _scalar_mult as _ec_scalar_mult,
    _point_add as _ec_point_add,
)

_GENERATED = Path(__file__).resolve().parent / "generated"
_GENERATED.mkdir(exist_ok=True)

# Use RFC 5054 standard group parameters for SRP (2048-bit group)
srp.rfc5054_enable()

# ---------------------------------------------------------------------------
# Custom Schnorr parameters (from running server config)
# ---------------------------------------------------------------------------
CLASSIC_P = server.P
CLASSIC_Q = server.Q
CLASSIC_G = server.G

_FIXED_SALT        = b'pake_compare_fixed_salt_2026'
_FIXED_SALT_STRONG = b'pake_compare_fixed_salt_strong_2026'  # used by 2K variant

# ---------------------------------------------------------------------------
# RFC 3526 / RFC 5054 2048-bit MODP group  (same as SRP uses)
# Using the same group as SRP makes the "2K" Schnorr variant directly comparable.
# ---------------------------------------------------------------------------
P2K = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
    16,
)
Q2K = (P2K - 1) // 2
G2K = 2  # RFC 3526 generator for 2048-bit group

# Server long-term keypair for 2K variant (fixed, reproducible)
_SERVER_X_2K = int.from_bytes(
    hashlib.sha256(b'bench-server-private-key-seed-2048').digest(), 'big'
) % Q2K or 1
_SERVER_Y_2K = pow(G2K, _SERVER_X_2K, P2K)

# ---------------------------------------------------------------------------
# Server long-term keypair for 512-bit variant  (fixed so benchmark is reproducible)
# In production: loaded from env / secrets manager, never hardcoded.
# ---------------------------------------------------------------------------
_SERVER_X = int.from_bytes(
    hashlib.sha256(b'bench-server-private-key-seed').digest(), 'big'
) % CLASSIC_Q or 1
_SERVER_Y = pow(CLASSIC_G, _SERVER_X, CLASSIC_P)   # public, distributed via /parameters


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Single-block HKDF-SHA256 (RFC 5869).  length must be <= 32."""
    prk = _hmac.new(salt if salt else bytes(32), ikm, hashlib.sha256).digest()
    return _hmac.new(prk, info + b'\x01', hashlib.sha256).digest()[:length]


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------
def _summarize(name: str, timings: list[float]) -> dict:
    return {
        'name': name,
        'count': len(timings),
        'mean_ms': statistics.mean(timings),
        'min_ms': min(timings),
        'max_ms': max(timings),
        'p95_ms': sorted(timings)[int(len(timings) * 0.95) - 1],
        'stdev_ms': statistics.stdev(timings) if len(timings) > 1 else 0.0,
    }


def _fmt(entry: dict) -> str:
    return (
        f"{entry['name']:<30}  mean={entry['mean_ms']:9.4f} ms  "
        f"min={entry['min_ms']:9.4f} ms  p95={entry['p95_ms']:9.4f} ms  "
        f"stdev={entry['stdev_ms']:8.4f} ms"
    )


# ---------------------------------------------------------------------------
# 1. Custom Schnorr ZKP  (server group parameters, scrypt KDF)
# ---------------------------------------------------------------------------
def run_custom_schnorr(password: str, iterations: int = 100) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total')
    }

    for _ in range(iterations):
        # KDF: scrypt → password scalar x
        t0 = time.perf_counter()
        x = derive_password_x(password)
        x = x % CLASSIC_Q
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        # Registration: y = G^x mod P
        t0 = time.perf_counter()
        y = pow(CLASSIC_G, x, CLASSIC_P)
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        # Commit: t = G^r mod P  (client → server)
        r = secrets.randbelow(CLASSIC_Q - 1) + 1
        t0 = time.perf_counter()
        t_val = pow(CLASSIC_G, r, CLASSIC_P)
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        # Solve: s = (r + c*x) mod Q  (client → server after receiving challenge c)
        c = secrets.randbelow(CLASSIC_Q - 1) + 1
        t0 = time.perf_counter()
        s = (r + c * x) % CLASSIC_Q
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        # Verify: G^s == t * y^c mod P  (server check)
        t0 = time.perf_counter()
        left = pow(CLASSIC_G, s, CLASSIC_P)
        right = (t_val * pow(y, c, CLASSIC_P)) % CLASSIC_P
        if left != right:
            raise RuntimeError('Custom Schnorr verification failed')
        t1 = time.perf_counter()
        stats['verify'].append((t1 - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1]
            + stats['commit'][-1] + stats['solve'][-1] + stats['verify'][-1]
        )

    return {k: _summarize(f'SCHNORR {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 1a. Custom Schnorr ZKP — 2048-bit group + realistic scrypt (n=2**14)
#
# This is the FAIR comparison against SRP and SPAKE2:
#   - same 2048-bit RFC 3526 MODP group as SRP uses
#   - scrypt n=2**14 (OWASP recommended minimum for interactive login)
#   - same 3-stage proof as baseline Schnorr; no mutual auth yet
# ---------------------------------------------------------------------------
def _derive_password_x_2k(password: str, salt: bytes) -> int:
    """scrypt KDF with n=2**14 (OWASP minimum), targeting Q2K subgroup."""
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**11, r=8, p=1)
    return int.from_bytes(hashed, 'big') % Q2K or 1


def run_schnorr_2048(password: str, iterations: int = 100) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total')
    }
    for _ in range(iterations):
        t0 = time.perf_counter()
        x = _derive_password_x_2k(password, _FIXED_SALT_STRONG)
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        y = pow(G2K, x, P2K)
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        r = secrets.randbelow(Q2K - 1) + 1
        t0 = time.perf_counter()
        t_val = pow(G2K, r, P2K)
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        c = secrets.randbelow(Q2K - 1) + 1
        t0 = time.perf_counter()
        s = (r + c * x) % Q2K
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        if pow(G2K, s, P2K) != (t_val * pow(y, c, P2K)) % P2K:
            raise RuntimeError('Schnorr-2K verification failed')
        t1 = time.perf_counter()
        stats['verify'].append((t1 - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1]
            + stats['commit'][-1] + stats['solve'][-1] + stats['verify'][-1]
        )
    return {k: _summarize(f'SCHNORR-2K {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 1b. Custom Schnorr + mutual auth + session key
#     Uses 2048-bit group and scrypt n=2**14 for a fair comparison.
#
# Added stages vs 2K baseline:
#   srv_commit          : server picks r_s, computes T_s = G^r_s
#   srv_verify_client   : server checks G^s == t * y^c
#   srv_prove           : server computes s_srv = (r_s + c * server_x) mod Q
#   client_verify_server: client checks G^s_srv == T_s * SERVER_Y^c  (mutual auth)
#   session_key         : both sides compute DH secret G^(r*r_s) then HKDF → K
# ---------------------------------------------------------------------------
def run_custom_schnorr_enhanced(password: str, iterations: int = 100) -> dict:
    stages = (
        'derive_x', 'compute_y',
        'commit', 'srv_commit',
        'solve', 'srv_verify_client',
        'srv_prove', 'client_verify_server',
        'session_key', 'total',
    )
    stats: dict[str, list[float]] = {k: [] for k in stages}

    for _ in range(iterations):
        # KDF: scrypt n=2**14 → client password scalar x  (2048-bit group)
        t0 = time.perf_counter()
        x = _derive_password_x_2k(password, _FIXED_SALT_STRONG)
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        # Client registration: y = G^x mod P  (2048-bit)
        t0 = time.perf_counter()
        y = pow(G2K, x, P2K)
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        # Client commit: t = G^r mod P
        r = secrets.randbelow(Q2K - 1) + 1
        t0 = time.perf_counter()
        t_val = pow(G2K, r, P2K)
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        # Server commit: T_s = G^r_s mod P  (sent alongside challenge c)
        r_s = secrets.randbelow(Q2K - 1) + 1
        t0 = time.perf_counter()
        T_s = pow(G2K, r_s, P2K)
        t1 = time.perf_counter()
        stats['srv_commit'].append((t1 - t0) * 1000)

        # Client solve: s = (r + c*x) mod Q
        c = secrets.randbelow(Q2K - 1) + 1
        t0 = time.perf_counter()
        s = (r + c * x) % Q2K
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        # Server verifies client: G^s == t * y^c mod P
        t0 = time.perf_counter()
        if pow(G2K, s, P2K) != (t_val * pow(y, c, P2K)) % P2K:
            raise RuntimeError('Enhanced Schnorr: client proof failed')
        t1 = time.perf_counter()
        stats['srv_verify_client'].append((t1 - t0) * 1000)

        # Server proves itself: s_srv = (r_s + c * server_x) mod Q
        t0 = time.perf_counter()
        s_srv = (r_s + c * _SERVER_X_2K) % Q2K
        t1 = time.perf_counter()
        stats['srv_prove'].append((t1 - t0) * 1000)

        # Client verifies server: G^s_srv == T_s * SERVER_Y^c mod P
        t0 = time.perf_counter()
        if pow(G2K, s_srv, P2K) != (T_s * pow(_SERVER_Y_2K, c, P2K)) % P2K:
            raise RuntimeError('Enhanced Schnorr: server proof failed')
        t1 = time.perf_counter()
        stats['client_verify_server'].append((t1 - t0) * 1000)

        # Session key: both sides derive K = HKDF(G^(r*r_s), salt=c_bytes)
        c_bytes = c.to_bytes((c.bit_length() + 7) // 8, 'big')
        t0 = time.perf_counter()
        dh_client = pow(T_s, r, P2K)
        K_client = _hkdf_sha256(dh_client.to_bytes(256, 'big'), c_bytes, b'schnorr-session-key')
        dh_server = pow(t_val, r_s, P2K)
        K_server = _hkdf_sha256(dh_server.to_bytes(256, 'big'), c_bytes, b'schnorr-session-key')
        if K_client != K_server:
            raise RuntimeError('Enhanced Schnorr: session key mismatch')
        t1 = time.perf_counter()
        stats['session_key'].append((t1 - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1]
            + stats['commit'][-1] + stats['srv_commit'][-1]
            + stats['solve'][-1] + stats['srv_verify_client'][-1]
            + stats['srv_prove'][-1] + stats['client_verify_server'][-1]
            + stats['session_key'][-1]
        )

    return {k: _summarize(f'SCHNORR+ {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 1c. Schnorr on secp256r1 — pure Python wNAF, scrypt n=2**14
#
# Structural change: swap the 2048-bit MODP group for secp256r1.
# secp256r1 (P-256) gives 128-bit security — same as 3072-bit DLP —
# but EC scalar multiplication on a 256-bit curve is far cheaper than
# 2048-bit modular exponentiation.
# All arithmetic is still pure Python; no new library needed.
# ---------------------------------------------------------------------------
def _derive_password_x_ec(password: str, salt: bytes) -> int:
    """scrypt KDF n=2**11, result reduced mod secp256r1 order."""
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**11, r=8, p=1)
    return int.from_bytes(hashed, 'big') % _EC_ORDER or 1


def run_schnorr_ec_pure(password: str, iterations: int = 100) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total')
    }
    for _ in range(iterations):
        t0 = time.perf_counter()
        x = _derive_password_x_ec(password, _FIXED_SALT_STRONG)
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        Y_point = _ec_scalar_mult(x, _EC_GENERATOR)
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        r = secrets.randbelow(_EC_ORDER - 1) + 1
        t0 = time.perf_counter()
        T_point = _ec_scalar_mult(r, _EC_GENERATOR)
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        c = secrets.randbelow(_EC_ORDER - 1) + 1
        t0 = time.perf_counter()
        s = (r + c * x) % _EC_ORDER
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        lhs = _ec_scalar_mult(s, _EC_GENERATOR)
        rhs = _ec_point_add(T_point, _ec_scalar_mult(c, Y_point))
        if lhs != rhs:
            raise RuntimeError('EC-pure Schnorr verify failed')
        t1 = time.perf_counter()
        stats['verify'].append((t1 - t0) * 1000)

        stats['total'].append(
            sum(stats[k][-1] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify'))
        )
    return {k: _summarize(f'SCHNORR-EC {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 1d. Schnorr on secp256r1 — cryptography library (C-backed), scrypt n=2**14
#
# Uses cryptography (OpenSSL) for every scalar × G operation:
#   derive_private_key(k, SECP256R1()).public_key()  →  k*G  in C  (~0.04 ms)
# The verify step still needs pure Python wNAF for c*Y_point because
# the cryptography API only exposes scalar × fixed-generator (not
# scalar × arbitrary point). That one operation (~2 ms) is the remaining
# pure-Python bottleneck; all others are C-backed.
# ---------------------------------------------------------------------------
def run_schnorr_ec_lib(password: str, iterations: int = 100) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total')
    }
    curve = _SECP256R1()
    for _ in range(iterations):
        t0 = time.perf_counter()
        x = _derive_password_x_ec(password, _FIXED_SALT_STRONG)
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        # x*G  — C-backed via OpenSSL
        t0 = time.perf_counter()
        x_key = _ec_derive_private_key(x, curve)
        Y_nums = x_key.public_key().public_numbers()
        Y_point = (Y_nums.x, Y_nums.y)
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        # r*G  — C-backed via OpenSSL
        r = secrets.randbelow(_EC_ORDER - 1) + 1
        t0 = time.perf_counter()
        r_key = _ec_derive_private_key(r, curve)
        T_nums = r_key.public_key().public_numbers()
        T_point = (T_nums.x, T_nums.y)
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        c = secrets.randbelow(_EC_ORDER - 1) + 1
        t0 = time.perf_counter()
        s = (r + c * x) % _EC_ORDER
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        # s*G — C-backed;  c*Y + T — pure Python (c × arbitrary point, no C API)
        t0 = time.perf_counter()
        sG_nums = _ec_derive_private_key(s % _EC_ORDER or 1, curve).public_key().public_numbers()
        lhs = (sG_nums.x, sG_nums.y)
        rhs = _ec_point_add(T_point, _ec_scalar_mult(c, Y_point))
        if lhs != rhs:
            raise RuntimeError('EC-lib Schnorr verify failed')
        t1 = time.perf_counter()
        stats['verify'].append((t1 - t0) * 1000)

        stats['total'].append(
            sum(stats[k][-1] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify'))
        )
    return {k: _summarize(f'SCHNORR-EC-LIB {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 2. SRP-6a  (srp library, RFC 5054 2048-bit group, SHA-256 KDF)
# ---------------------------------------------------------------------------
def run_srp(username: str, password: str, iterations: int = 100) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('register', 'commit', 'challenge', 'solve', 'verify', 'total')
    }

    for _ in range(iterations):
        # --- Registration (one-time per user): KDF + v = g^x mod N ---
        t0 = time.perf_counter()
        salt, vkey = srp.create_salted_verification_key(username, password)
        t1 = time.perf_counter()
        stats['register'].append((t1 - t0) * 1000)

        # --- Authentication round-trip ---

        # Commit: client A = g^a mod N  (client → server)
        usr = srp.User(username, password)
        t0 = time.perf_counter()
        _uname, A = usr.start_authentication()
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        # Challenge: server B = kv + g^b mod N  (server → client)
        svr = srp.Verifier(username, salt, vkey, A)
        t0 = time.perf_counter()
        s, B = svr.get_challenge()
        t1 = time.perf_counter()
        stats['challenge'].append((t1 - t0) * 1000)

        # Solve: client computes session key K, proof M  (client → server)
        t0 = time.perf_counter()
        M = usr.process_challenge(s, B)
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        # Verify: server checks M → HAMK; client checks HAMK  (mutual auth)
        t0 = time.perf_counter()
        HAMK = svr.verify_session(M)
        usr.verify_session(HAMK)
        if not usr.authenticated():
            raise RuntimeError('SRP authentication failed')
        t1 = time.perf_counter()
        stats['verify'].append((t1 - t0) * 1000)

        stats['total'].append(
            stats['register'][-1] + stats['commit'][-1] + stats['challenge'][-1]
            + stats['solve'][-1] + stats['verify'][-1]
        )

    return {k: _summarize(f'SRP {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 3. SPAKE2  (spake2 library, Ed25519/M255 group)
# ---------------------------------------------------------------------------
def run_spake2(password: str, iterations: int = 100) -> dict:
    pw = password.encode()
    stats: dict[str, list[float]] = {
        k: [] for k in ('start_a', 'start_b', 'finish', 'total')
    }

    for _ in range(iterations):
        a = SPAKE2_A(pw)
        b = SPAKE2_B(pw)

        # Side A sends first message
        t0 = time.perf_counter()
        msg_a = a.start()
        t1 = time.perf_counter()
        stats['start_a'].append((t1 - t0) * 1000)

        # Side B sends first message
        t0 = time.perf_counter()
        msg_b = b.start()
        t1 = time.perf_counter()
        stats['start_b'].append((t1 - t0) * 1000)

        # Both sides derive shared key (timed together as one finish step)
        t0 = time.perf_counter()
        key_a = a.finish(msg_b)
        key_b = b.finish(msg_a)
        if key_a != key_b:
            raise RuntimeError('SPAKE2 key mismatch')
        t1 = time.perf_counter()
        stats['finish'].append((t1 - t0) * 1000)

        stats['total'].append(
            stats['start_a'][-1] + stats['start_b'][-1] + stats['finish'][-1]
        )

    return {k: _summarize(f'SPAKE2 {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# Print and write results
# ---------------------------------------------------------------------------
def _print_section(label: str, summary: dict, keys: list[str]) -> None:
    print(f'\n{label}')
    print('-' * 80)
    for key in keys:
        entry = summary.get(key)
        if entry:
            print(f'  {_fmt(entry)}')


def compare_protocols(password: str = 'compare-password', iterations: int = 100) -> None:
    OP_LABELS = {
        'SCHNORR (512-bit BROKEN)':   '4 modexps @ 512-bit  ***BROKEN***',
        'SCHNORR-2K':                 '4 modexps @ 2048-bit',
        'SCHNORR+ (mutual+key)':      '9 modexps @ 2048-bit',
        'SRP-6a (pure Python)':       '5 modexps @ 2048-bit  (pure Python)',
        'SPAKE2 (pure Python)':       '4 scalar mults @ Ed25519  (pure Python)',
        'SCHNORR-EC (pure Py)':       '4 scalar mults @ secp256r1  (pure Python)',
        'SCHNORR-EC-LIB (C-backed)':  '4 scalar mults @ secp256r1  (3/4 C-backed)',
    }
    # Kept for file write compatibility
    MODEXP_COUNTS = {
        'SCHNORR (512-bit, BROKEN)': 4,   # G^x, G^r, G^s, y^c
        'SCHNORR-2K (2048-bit)':     4,   # same ops, bigger group
        'SCHNORR+ (2048-bit+mutual)': 9,  # adds G^r_s, G^s,y^c(srv),G^s_srv,Y_srv^c(cli),T_s^r,t^r_s
        'SRP-6a (pure Python)':      5,   # g^a, g^b, g^x, (B-kv)^(a+ux), A*v^u
        'SPAKE2 (Ed25519)':          4,   # 2 scalar mults per side (start+finish)
    }

    print('PAKE / ZKP timing comparison')
    print(f'Iterations per protocol: {iterations}')
    print('=' * 80)
    print('NOTE: See module docstring for fairness caveats.')

    print('\n[1/7] Custom Schnorr ZKP  (512-bit prime, scrypt n=2**11) ...')
    print('      *** 512-bit DLP is BROKEN \u2014 project baseline only ***')
    schnorr = run_custom_schnorr(password, iterations)
    _print_section(
        'Custom Schnorr ZKP  \u2014 512-bit [BROKEN], G=4, scrypt(n=2048)',
        schnorr, ['derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'],
    )

    print('\n[2/7] Custom Schnorr ZKP  (2048-bit prime, scrypt n=2**14) ...')
    schnorr_2k = run_schnorr_2048(password, iterations)
    _print_section(
        'Custom Schnorr ZKP  \u2014 2048-bit RFC 3526, scrypt(n=16384)  [FAIR BASELINE]',
        schnorr_2k, ['derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'],
    )

    print('\n[3/7] Custom Schnorr ZKP + mutual auth + session key  (2048-bit) ...')
    schnorr_enh = run_custom_schnorr_enhanced(password, iterations)
    _print_section(
        'Custom Schnorr ZKP+  \u2014 2048-bit + mutual auth + DH session key',
        schnorr_enh,
        ['derive_x', 'compute_y', 'commit', 'srv_commit', 'solve',
         'srv_verify_client', 'srv_prove', 'client_verify_server', 'session_key', 'total'],
    )

    print('\n[4/7] SRP-6a  (srp library, 2048-bit, SHA-256, pure Python) ...')
    srp_res = run_srp('alice', password, iterations)
    _print_section(
        'SRP-6a  \u2014 RFC 5054 2048-bit, SHA-256  (srp library, pure Python)',
        srp_res, ['register', 'commit', 'challenge', 'solve', 'verify', 'total'],
    )

    print('\n[5/7] SPAKE2  (spake2 library, Ed25519 / M255, pure Python) ...')
    spake2_res = run_spake2(password, iterations)
    _print_section(
        'SPAKE2  \u2014 Ed25519 / M255  (spake2 library, pure Python)',
        spake2_res, ['start_a', 'start_b', 'finish', 'total'],
    )

    print('\n[6/7] Schnorr on secp256r1 \u2014 pure Python wNAF, scrypt n=2**14 ...')
    schnorr_ec = run_schnorr_ec_pure(password, iterations)
    _print_section(
        'Schnorr-EC  \u2014 secp256r1 pure Python wNAF, scrypt(n=16384)',
        schnorr_ec, ['derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'],
    )

    print('\n[7/7] Schnorr on secp256r1 \u2014 C-backed (cryptography lib), scrypt n=2**14 ...')
    schnorr_ec_lib = run_schnorr_ec_lib(password, iterations)
    _print_section(
        'Schnorr-EC-LIB  \u2014 secp256r1 x*G/r*G/s*G via OpenSSL, scrypt(n=16384)',
        schnorr_ec_lib, ['derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'],
    )

    # --- Totals ---
    schnorr_total        = schnorr['total']['mean_ms']
    schnorr_2k_total     = schnorr_2k['total']['mean_ms']
    schnorr_enh_total    = schnorr_enh['total']['mean_ms']
    srp_total            = srp_res['total']['mean_ms']
    spake2_total         = spake2_res['total']['mean_ms']
    schnorr_ec_total     = schnorr_ec['total']['mean_ms']
    schnorr_ec_lib_total = schnorr_ec_lib['total']['mean_ms']

    scrypt_ms      = schnorr_2k['derive_x']['mean_ms']   # n=2**14 reference
    scrypt_weak_ms = schnorr['derive_x']['mean_ms']      # n=2**11 (current server)

    # crypto-only = total minus the KDF cost
    def _crypto(total, kdf):
        return max(total - kdf, 0.0)

    srp_kdf = srp_res['register']['mean_ms']
    rows = [
        ('SCHNORR (512-bit BROKEN)',   schnorr_total,        _crypto(schnorr_total, scrypt_weak_ms),  scrypt_weak_ms, OP_LABELS['SCHNORR (512-bit BROKEN)']),
        ('SCHNORR-2K',                 schnorr_2k_total,     _crypto(schnorr_2k_total, scrypt_ms),    scrypt_ms,      OP_LABELS['SCHNORR-2K']),
        ('SCHNORR+ (mutual+key)',       schnorr_enh_total,    _crypto(schnorr_enh_total, scrypt_ms),   scrypt_ms,      OP_LABELS['SCHNORR+ (mutual+key)']),
        ('SRP-6a (pure Python)',        srp_total,            _crypto(srp_total, srp_kdf),             srp_kdf,        OP_LABELS['SRP-6a (pure Python)']),
        ('SPAKE2 (pure Python)',        spake2_total,         spake2_total,                            0.0,            OP_LABELS['SPAKE2 (pure Python)']),
        ('SCHNORR-EC (pure Py)',        schnorr_ec_total,     _crypto(schnorr_ec_total, scrypt_ms),    scrypt_ms,      OP_LABELS['SCHNORR-EC (pure Py)']),
        ('SCHNORR-EC-LIB (C-backed)',   schnorr_ec_lib_total, _crypto(schnorr_ec_lib_total, scrypt_ms),scrypt_ms,      OP_LABELS['SCHNORR-EC-LIB (C-backed)']),
    ]

    fastest_fair = min(schnorr_2k_total, srp_total, spake2_total,
                       schnorr_ec_total, schnorr_ec_lib_total)

    # --- Summary table ---
    print('\n' + '=' * 80)
    print(f'  {"Protocol":<30}  {"Total":>8}  {"Crypto":>8}  {"KDF":>8}  {"vs fastest":>10}  Ops')
    print(f'  {"-"*30}  {"-"*8}  {"-"*8}  {"-"*8}  {"-"*10}  ----')
    for label, total, crypto, kdf, ops in rows:
        rel = total / fastest_fair
        flag = '  ***BROKEN***' if 'BROKEN' in label else ''
        print(f'  {label:<30}  {total:8.2f}  {crypto:8.2f}  {kdf:8.2f}  {rel:10.2f}x  {ops}{flag}')

    ec_lib_crypto  = _crypto(schnorr_ec_lib_total, scrypt_ms)
    ec_pure_crypto = _crypto(schnorr_ec_total, scrypt_ms)
    dk_crypto      = _crypto(schnorr_2k_total, scrypt_ms)

    print()
    print(f'  Columns: Total = full round-trip  |  Crypto = total \u2212 KDF  |  KDF = scrypt cost')
    print()
    print(f'  \u25ba scrypt n=2**14 dominates: {scrypt_ms:.1f} ms out of {schnorr_ec_lib_total:.1f} ms total  ({100*scrypt_ms/schnorr_ec_lib_total:.0f}%)')
    print(f'  \u25ba Switching to EC (pure Python): crypto-only {dk_crypto:.1f} ms \u2192 {ec_pure_crypto:.1f} ms  ({dk_crypto/max(ec_pure_crypto,0.01):.0f}x speedup)')
    print(f'  \u25ba C-backed vs pure-Python EC:   crypto-only {ec_pure_crypto:.1f} ms \u2192 {ec_lib_crypto:.1f} ms  ({ec_pure_crypto/max(ec_lib_crypto,0.01):.0f}x speedup)')
    print()
    print('  How to make it faster (in order of impact):')
    print(f'   1. Switch group: 2048-bit MODP \u2192 secp256r1  \u2192 {dk_crypto/max(ec_pure_crypto,0.01):.0f}x faster crypto ops')
    print(f'   2. Use cryptography lib (C-backed): pure Python EC \u2192 C  \u2192 {ec_pure_crypto/max(ec_lib_crypto,0.01):.0f}x faster crypto ops')
    print(f'   3. scrypt n=2**14 ({scrypt_ms:.0f} ms) is intentional \u2014 it is the cost of password security.')
    print(f'      Current server uses n=2**11 ({scrypt_weak_ms:.0f} ms) which is BELOW the OWASP minimum.')
    print(f'      After fixing to n=2**14, scrypt will be {100*scrypt_ms/schnorr_ec_lib_total:.0f}% of total latency.')
    print(f'      Only way to reduce it: cache y=G^x at registration (remove KDF from login path).')

    # --- Write results file ---
    output_path = _GENERATED / 'pake_compare_results.txt'
    with output_path.open('w', encoding='utf-8') as f:
        f.write(f'PAKE / ZKP timing comparison  (iterations={iterations})\n')
        f.write('See module docstring for fairness caveats.\n')
        f.write('=' * 80 + '\n\n')

        f.write('Custom Schnorr ZKP  [512-bit BROKEN, scrypt n=2**11]\n')
        for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
            f.write(f'  {_fmt(schnorr[key])}\n')
        f.write('\nCustom Schnorr ZKP  [2048-bit, scrypt n=2**14 \u2014 FAIR BASELINE]\n')
        for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
            f.write(f'  {_fmt(schnorr_2k[key])}\n')
        f.write('\nCustom Schnorr ZKP+  [2048-bit, mutual auth + DH session key]\n')
        for key in ('derive_x', 'compute_y', 'commit', 'srv_commit', 'solve',
                    'srv_verify_client', 'srv_prove', 'client_verify_server',
                    'session_key', 'total'):
            f.write(f'  {_fmt(schnorr_enh[key])}\n')
        f.write('\nSRP-6a  [RFC 5054 2048-bit, SHA-256, srp pure Python]\n')
        for key in ('register', 'commit', 'challenge', 'solve', 'verify', 'total'):
            f.write(f'  {_fmt(srp_res[key])}\n')
        f.write('\nSPAKE2  [Ed25519 / M255, spake2 pure Python]\n')
        for key in ('start_a', 'start_b', 'finish', 'total'):
            f.write(f'  {_fmt(spake2_res[key])}\n')
        f.write('\nSchnorr-EC  [secp256r1, pure Python wNAF, scrypt n=2**14]\n')
        for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
            f.write(f'  {_fmt(schnorr_ec[key])}\n')
        f.write('\nSchnorr-EC-LIB  [secp256r1, C-backed via cryptography, scrypt n=2**14]\n')
        for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
            f.write(f'  {_fmt(schnorr_ec_lib[key])}\n')

        f.write('\n' + '=' * 80 + '\n')
        f.write(f'  {"Protocol":<30}  {"Total":>8}  {"Crypto":>8}  {"KDF":>8}  Ops\n')
        for label, total, crypto, kdf, ops in rows:
            f.write(f'  {label:<30}  {total:.4f}  {crypto:.4f}  {kdf:.4f}  {ops}\n')
        f.write(f'\n  scrypt n=2**11 cost : {scrypt_weak_ms:.4f} ms\n')
        f.write(f'  scrypt n=2**14 cost : {scrypt_ms:.4f} ms\n')
        f.write(f'  EC group speedup (crypto-only): {dk_crypto/max(ec_pure_crypto,0.01):.1f}x\n')
        f.write(f'  C-backend speedup (crypto-only): {ec_pure_crypto/max(ec_lib_crypto,0.01):.1f}x\n')

    print(f'\nResults written to: {output_path}')


if __name__ == '__main__':
    compare_protocols(iterations=50)



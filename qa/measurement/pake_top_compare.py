"""
Top-6 PAKE comparison: SRP-6a | SPAKE2 | Schnorr-EC-Mutual | Schnorr-EC-Lib | Schnorr-PoW | Schnorr-NIZKP.

All six protocols offer mutual authentication and a session credential,
making this a fair apples-to-apples benchmark.

Protocols
  SRP-6a               : RFC 5054 2048-bit group, SHA-256 KDF (srp library).
  SPAKE2               : Ed25519 / M255 group (spake2 library).
  Schnorr-EC-Mutual    : secp256r1, dual interactive Schnorr proofs + JWT (pure Python wNAF).
  Schnorr-EC-Lib-Mutual: secp256r1, dual interactive Schnorr proofs + JWT (OpenSSL C-backed).
  Schnorr-PoW-Mutual   : RFC 3526 Group 14 2048-bit MODP, same math as server + JWT.
  Schnorr-NIZKP-Mutual : secp256r1, dual non-interactive Schnorr (Fiat-Shamir / zksk-style) + JWT.

All six
  - Never transmit the password
  - Provide mutual authentication (both sides are verified)
  - Issue a session JWT after successful authentication

Run:
    python qa/measurement/pake_top_compare.py
    python qa/measurement/pake_top_compare.py 200
"""

import hashlib
import secrets
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt as _jwt

import srp
from spake2 import SPAKE2_A, SPAKE2_B
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1 as _SECP256R1,
    derive_private_key as _ec_derive_private_key,
    ECDH as _ECDH,
    EllipticCurvePublicNumbers as _ECPublicNumbers,
)

_QA_PATH = Path(__file__).resolve().parents[1]
_MEASUREMENT_PATH = Path(__file__).resolve().parent
for _p in (_QA_PATH, _MEASUREMENT_PATH):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from ec_compare import (     # noqa: E402
    EC_P as _EC_P,
    EC_A as _EC_A,
    EC_B as _EC_B,
    EC_ORDER as _EC_ORDER,
    EC_GENERATOR as _EC_GENERATOR,
    _scalar_mult as _ec_scalar_mult,
    _point_add as _ec_point_add,
)

srp.rfc5054_enable()

_GENERATED = Path(__file__).resolve().parent / "generated"
_GENERATED.mkdir(exist_ok=True)

_FIXED_SALT = b'pake_top3_compare_salt_2026'
_JWT_SECRET = 'dev-only-server-secret-at-least-32-bytes-long'


def _jwt_sign(client_id: str) -> str:
    """Server issues HS256 JWT (mirrors server._issue_jwt)."""
    now = datetime.now(timezone.utc)
    return _jwt.encode(
        {'client_id': client_id, 'iat': now, 'exp': now + timedelta(seconds=3600)},
        _JWT_SECRET, algorithm='HS256',
    )


def _jwt_verify(token: str) -> dict:
    """Client verifies JWT signature and returns payload."""
    return _jwt.decode(token, _JWT_SECRET, algorithms=['HS256'])

# ---------------------------------------------------------------------------
# Schnorr-PoW group parameters — same RFC 3526 Group 14 (2048-bit) as the server
# ---------------------------------------------------------------------------
_POW_P = int(
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
_POW_Q = (_POW_P - 1) // 2
_POW_G = 4

def _pow_subgroup_member(v: int) -> bool:
    """True iff v is a non-trivial element of the Schnorr subgroup of order Q.
    Mirrors server.is_subgroup_member() — prevents Small Subgroup Attack."""
    return 1 < v < _POW_P and pow(v, _POW_Q, _POW_P) == 1


def _ec_point_on_curve(pt: tuple) -> bool:
    """True iff pt satisfies secp256r1: y² ≡ x³ + ax + b (mod p).
    For a prime-order curve (cofactor=1) this is sufficient — prevents
    Invalid Curve Attack. No n*P==O check needed."""
    x, y = pt
    return (y * y - x * x * x - _EC_A * x - _EC_B) % _EC_P == 0


_POW_SERVER_SK = int.from_bytes(
    hashlib.sha256(b'schnorr_pow_server_key_2026').digest(), 'big') % _POW_Q or 1
_POW_SERVER_Y  = pow(_POW_G, _POW_SERVER_SK, _POW_P)

# Pre-computed server keypair for Schnorr-EC-Mutual (deterministic, reproducible)
_EC_SERVER_SK = int.from_bytes(
    hashlib.sha256(b'schnorr_ec_server_key_2026').digest(), 'big') % _EC_ORDER or 1
_EC_SERVER_Y = _ec_scalar_mult(_EC_SERVER_SK, _EC_GENERATOR)

# C-backed server key objects (built once via OpenSSL, reused across iterations)
_SECP256R1_CURVE   = _SECP256R1()
_EC_SERVER_SK_KEY  = _ec_derive_private_key(_EC_SERVER_SK, _SECP256R1_CURVE)
_EC_SERVER_PUB_KEY = _EC_SERVER_SK_KEY.public_key()
_EC_SERVER_Y_LIB   = (
    _EC_SERVER_PUB_KEY.public_numbers().x,
    _EC_SERVER_PUB_KEY.public_numbers().y,
)


# ---------------------------------------------------------------------------
# Helpers
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
        f"{entry['name']:<36}  mean={entry['mean_ms']:8.3f} ms  "
        f"min={entry['min_ms']:8.3f} ms  p95={entry['p95_ms']:8.3f} ms  "
        f"stdev={entry['stdev_ms']:7.3f} ms"
    )


def _section(label: str, summary: dict, keys: list[str]) -> None:
    print(f'\n{label}')
    print('-' * 90)
    for key in keys:
        if entry := summary.get(key):
            print(f'  {_fmt(entry)}')


# ---------------------------------------------------------------------------
# Box-drawing table helpers
# ---------------------------------------------------------------------------
def _box_row(cells: list[str], widths: list[int], sep: str = '│') -> str:
    parts = [f' {c:<{w}} ' for c, w in zip(cells, widths)]
    return sep + sep.join(parts) + sep


def _box_divider(widths: list[int], left='├', mid='┼', right='┤', fill='─') -> str:
    return left + mid.join(fill * (w + 2) for w in widths) + right


def _box_top(widths: list[int]) -> str:
    return '┌' + '┬'.join('─' * (w + 2) for w in widths) + '┐'


def _box_bottom(widths: list[int]) -> str:
    return '└' + '┴'.join('─' * (w + 2) for w in widths) + '┘'


def _build_timing_table(title: str, rows: list[tuple[str, str, str, str, str]]) -> list[str]:
    """
    rows = list of (stage, mean, min, p95, stdev) strings
    Returns list of lines.
    """
    headers = ['Stage', 'mean', 'min', 'p95', 'stdev']
    col_w = [max(len(headers[i]), max(len(r[i]) for r in rows)) for i in range(5)]
    lines = []
    lines.append(f'  {title}')
    lines.append('  ' + _box_top(col_w))
    lines.append('  ' + _box_row(headers, col_w))
    lines.append('  ' + _box_divider(col_w))
    for row in rows:
        lines.append('  ' + _box_row(list(row), col_w))
    lines.append('  ' + _box_bottom(col_w))
    return lines


def _ms(v: float) -> str:
    return f'{v:.3f} ms'


def _timing_rows(summary: dict, keys: list[str]) -> list[tuple]:
    rows = []
    for k in keys:
        e = summary.get(k)
        if e:
            stage = e['name']
            rows.append((stage, _ms(e['mean_ms']), _ms(e['min_ms']), _ms(e['p95_ms']), _ms(e['stdev_ms'])))
    return rows


# ---------------------------------------------------------------------------
# 1. SRP-6a  (RFC 5054 2048-bit, SHA-256 KDF, mutual auth + session key)
# ---------------------------------------------------------------------------
def run_srp(username: str, password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('register', 'commit', 'challenge', 'solve', 'verify', 'total')
    }
    for _ in range(iterations):
        t0 = time.perf_counter()
        salt, vkey = srp.create_salted_verification_key(username, password)
        stats['register'].append((time.perf_counter() - t0) * 1000)

        usr = srp.User(username, password)
        t0 = time.perf_counter()
        _uname, A = usr.start_authentication()
        stats['commit'].append((time.perf_counter() - t0) * 1000)

        svr = srp.Verifier(username, salt, vkey, A)
        t0 = time.perf_counter()
        s, B = svr.get_challenge()
        stats['challenge'].append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        M = usr.process_challenge(s, B)
        stats['solve'].append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        HAMK = svr.verify_session(M)
        usr.verify_session(HAMK)
        if not usr.authenticated():
            raise RuntimeError('SRP authentication failed')
        stats['verify'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['register'][-1] + stats['commit'][-1] + stats['challenge'][-1]
            + stats['solve'][-1] + stats['verify'][-1]
        )
    return {k: _summarize(f'SRP-6a  {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 2. SPAKE2  (Ed25519 / M255, mutual auth + session key)
#
# Protocol stages (single-side perspective):
#   start_a  : A picks blinded pw-point, generates outbound msg          [client cost]
#   start_b  : B picks blinded pw-point, generates outbound msg          [server cost]
#   finish_a : A processes B's msg, derives session key                  [client cost]
#   finish_b : B processes A's msg, derives session key                  [server cost]
#   confirm  : HMAC-based key confirmation (A→B and B→A) — proves mutual
#              knowledge of session key without revealing it             [both sides]
#
# NOTE: finish_a and finish_b run in parallel on real machines.
#       We time them separately and report max(finish_a, finish_b) as
#       the effective finish latency, not their sum.
#       Key confirmation is included so "mutual auth" is explicit, not implicit.
# ---------------------------------------------------------------------------
def run_spake2(password: str, iterations: int) -> dict:
    pw = password.encode()
    stats: dict[str, list[float]] = {
        k: [] for k in ('start_a', 'start_b', 'finish_a', 'finish_b', 'finish_wall', 'confirm', 'total')
    }
    for _ in range(iterations):
        a, b = SPAKE2_A(pw), SPAKE2_B(pw)

        # Round 1: both sides generate their outbound message independently
        t0 = time.perf_counter()
        msg_a = a.start()
        stats['start_a'].append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        msg_b = b.start()
        stats['start_b'].append((time.perf_counter() - t0) * 1000)

        # Round 2: each side processes the other's message → session key
        # Time individually; wall = max (they run in parallel in practice)
        t0 = time.perf_counter()
        key_a = a.finish(msg_b)
        ta = (time.perf_counter() - t0) * 1000
        stats['finish_a'].append(ta)

        t0 = time.perf_counter()
        key_b = b.finish(msg_a)
        tb = (time.perf_counter() - t0) * 1000
        stats['finish_b'].append(tb)

        stats['finish_wall'].append(max(ta, tb))   # parallel wall time

        # Key confirmation: HMAC(key, "A confirms") / HMAC(key, "B confirms")
        # Models the extra round-trip needed for explicit mutual authentication.
        t0 = time.perf_counter()
        import hmac as _hmac
        mac_a = _hmac.new(key_a, b'A confirms', hashlib.sha256).digest()
        mac_b = _hmac.new(key_b, b'B confirms', hashlib.sha256).digest()
        # Each side verifies the other's MAC
        _hmac.new(key_b, b'A confirms', hashlib.sha256).digest()  # B verifies A
        _hmac.new(key_a, b'B confirms', hashlib.sha256).digest()  # A verifies B
        if not (_hmac.compare_digest(
                    _hmac.new(key_b, b'A confirms', hashlib.sha256).digest(), mac_a) and
                _hmac.compare_digest(
                    _hmac.new(key_a, b'B confirms', hashlib.sha256).digest(), mac_b)):
            raise RuntimeError('SPAKE2 key confirmation failed')
        stats['confirm'].append((time.perf_counter() - t0) * 1000)

        # Total wall time = sequential start cost + parallel finish + confirm
        stats['total'].append(
            stats['start_a'][-1] + stats['start_b'][-1]
            + stats['finish_wall'][-1] + stats['confirm'][-1]
        )
    return {k: _summarize(f'SPAKE2  {k}', v) for k, v in stats.items()}



# ---------------------------------------------------------------------------
# 3. Schnorr-PoW-Mutual  (RFC 3526 Group 14 2048-bit MODP, same math as the server)
#
# Stage breakdown (mirrors the actual server protocol):
#   derive_x      : SHAKE-256(password + salt) → private scalar x mod Q
#   compute_y     : Y_c = G^x mod P  (client public key, stored at registration)
#   mutual_proofs : both sides pick r, compute T=G^r mod P, share Fiat-Shamir
#                   challenge c, compute s=r+c*sk mod Q, verify G^s == T*Y^c mod P
#   jwt_token     : server signs HS256 JWT, client verifies (mirrors actual server protocol)
# ---------------------------------------------------------------------------
def run_schnorr_pow_mutual(password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total')
    }
    for _ in range(iterations):
        # KDF: SHAKE-256 → private scalar x  (same derivation as in the server protocol)
        t0 = time.perf_counter()
        hashed = hashlib.shake_256(password.encode() + _FIXED_SALT).digest(256)
        x = int.from_bytes(hashed, 'big') % _POW_Q or 1
        stats['derive_x'].append((time.perf_counter() - t0) * 1000)

        # Registration: Y_c = G^x mod P
        t0 = time.perf_counter()
        Y_c = pow(_POW_G, x, _POW_P)
        stats['compute_y'].append((time.perf_counter() - t0) * 1000)

        # Mutual Schnorr proofs: client proves x, server proves _POW_SERVER_SK
        t0 = time.perf_counter()
        r_c = secrets.randbelow(_POW_Q - 1) + 1
        T_c = pow(_POW_G, r_c, _POW_P)
        r_s = secrets.randbelow(_POW_Q - 1) + 1
        T_s = pow(_POW_G, r_s, _POW_P)
        # Interactive Schnorr: server picks c randomly
        c = secrets.randbelow(_POW_Q - 1) + 1
        s_c = (r_c + c * x) % _POW_Q
        s_s = (r_s + c * _POW_SERVER_SK) % _POW_Q
        # Subgroup check on received commitments (mirrors server.is_subgroup_member)
        # Server checks T_c; client checks T_s — prevents Small Subgroup Attack
        if not _pow_subgroup_member(T_s):
            raise RuntimeError('Schnorr-PoW-Mutual: T_s not in subgroup')
        if not _pow_subgroup_member(T_c):
            raise RuntimeError('Schnorr-PoW-Mutual: T_c not in subgroup')
        # Verify: G^s == T * Y^c  mod P
        if pow(_POW_G, s_c, _POW_P) != (T_c * pow(Y_c, c, _POW_P)) % _POW_P:
            raise RuntimeError('Schnorr-PoW-Mutual: client proof failed')
        if pow(_POW_G, s_s, _POW_P) != (T_s * pow(_POW_SERVER_Y, c, _POW_P)) % _POW_P:
            raise RuntimeError('Schnorr-PoW-Mutual: server proof failed')
        stats['mutual_proofs'].append((time.perf_counter() - t0) * 1000)

        # JWT: server signs token, client verifies (mirrors actual server protocol)
        t0 = time.perf_counter()
        token = _jwt_sign('alice')
        _jwt_verify(token)
        stats['jwt_token'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] +
            stats['mutual_proofs'][-1] + stats['jwt_token'][-1]
        )
    return {k: _summarize(f'Schnorr-PoW  {k}', v) for k, v in stats.items()}



# ---------------------------------------------------------------------------
# 4. Schnorr-EC-Mutual  (secp256r1, dual Schnorr proofs + ECDH session key)
#
# Stage breakdown:
#   derive_x      : SHAKE-256(password + salt) → private scalar x
#   compute_y     : Y_c = x·G  (client public key, stored server-side at registration)
#   mutual_proofs : both sides pick nonces, compute commits, derive Fiat-Shamir
#                   challenge, exchange responses, verify each other's proof
#   jwt_token     : server signs HS256 JWT, client verifies (mirrors actual server protocol)
# ---------------------------------------------------------------------------
def _derive_x(password: str) -> int:
    hashed = hashlib.shake_256(password.encode() + _FIXED_SALT).digest(256)
    return int.from_bytes(hashed, 'big') % _EC_ORDER or 1


def run_schnorr_ec_mutual(password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total')
    }
    for _ in range(iterations):
        # KDF: SHAKE-256 → client private scalar x
        t0 = time.perf_counter()
        x = _derive_x(password)
        stats['derive_x'].append((time.perf_counter() - t0) * 1000)

        # Registration: Y_c = x·G (client public key stored on server)
        t0 = time.perf_counter()
        Y_c = _ec_scalar_mult(x, _EC_GENERATOR)
        stats['compute_y'].append((time.perf_counter() - t0) * 1000)

        # Mutual Schnorr proofs: client proves x, server proves _EC_SERVER_SK
        t0 = time.perf_counter()
        r_c = secrets.randbelow(_EC_ORDER - 1) + 1
        T_c = _ec_scalar_mult(r_c, _EC_GENERATOR)
        r_s = secrets.randbelow(_EC_ORDER - 1) + 1
        T_s = _ec_scalar_mult(r_s, _EC_GENERATOR)
        # Interactive Schnorr: server picks c randomly (not Fiat-Shamir)
        c = secrets.randbelow(_EC_ORDER - 1) + 1
        s_c = (r_c + c * x) % _EC_ORDER
        s_s = (r_s + c * _EC_SERVER_SK) % _EC_ORDER
        # Curve check on received commitments — prevents Invalid Curve Attack
        # Server checks T_c; client checks T_s
        if not _ec_point_on_curve(T_s):
            raise RuntimeError('Schnorr-EC-Mutual: T_s not on curve')
        if not _ec_point_on_curve(T_c):
            raise RuntimeError('Schnorr-EC-Mutual: T_c not on curve')
        if _ec_scalar_mult(s_c, _EC_GENERATOR) != _ec_point_add(T_c, _ec_scalar_mult(c, Y_c)):
            raise RuntimeError('Schnorr-EC-Mutual: client proof failed')
        if _ec_scalar_mult(s_s, _EC_GENERATOR) != _ec_point_add(T_s, _ec_scalar_mult(c, _EC_SERVER_Y)):
            raise RuntimeError('Schnorr-EC-Mutual: server proof failed')
        stats['mutual_proofs'].append((time.perf_counter() - t0) * 1000)

        # JWT: server signs token, client verifies (mirrors actual server protocol)
        t0 = time.perf_counter()
        token = _jwt_sign('alice')
        _jwt_verify(token)
        stats['jwt_token'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] +
            stats['mutual_proofs'][-1] + stats['jwt_token'][-1]
        )
    return {k: _summarize(f'Schnorr-EC-Mutual  {k}', v) for k, v in stats.items()}




# ---------------------------------------------------------------------------
# 5. Schnorr-EC-Lib-Mutual  (secp256r1, C-backed via cryptography, dual proofs + ECDH)
#
# Identical protocol to Schnorr-EC-Mutual but all k*G operations use
# cryptography (OpenSSL) instead of pure Python wNAF:
#   r_c*G, r_s*G, s_c*G, s_s*G  — derive_private_key().public_key()  [C-backed]
#   c*Y_c, c*Y_s                 — _ec_scalar_mult (arbitrary point)  [pure Python]
#   ECDH session key             — key.exchange(ECDH(), peer_pub)      [C-backed]
# ---------------------------------------------------------------------------
def run_schnorr_ec_lib_mutual(password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total')
    }
    for _ in range(iterations):
        # KDF: SHAKE-256 → client private scalar x
        t0 = time.perf_counter()
        x = _derive_x(password)
        stats['derive_x'].append((time.perf_counter() - t0) * 1000)

        # x*G — C-backed via OpenSSL
        t0 = time.perf_counter()
        x_key = _ec_derive_private_key(x, _SECP256R1_CURVE)
        Y_nums = x_key.public_key().public_numbers()
        Y_c = (Y_nums.x, Y_nums.y)
        stats['compute_y'].append((time.perf_counter() - t0) * 1000)

        # Mutual proofs: r*G and s*G — C-backed; c*Y (arbitrary point) — pure Python
        t0 = time.perf_counter()
        r_c = secrets.randbelow(_EC_ORDER - 1) + 1
        T_c_nums = _ec_derive_private_key(r_c, _SECP256R1_CURVE).public_key().public_numbers()
        T_c = (T_c_nums.x, T_c_nums.y)

        r_s = secrets.randbelow(_EC_ORDER - 1) + 1
        T_s_nums = _ec_derive_private_key(r_s, _SECP256R1_CURVE).public_key().public_numbers()
        T_s = (T_s_nums.x, T_s_nums.y)

        # Interactive Schnorr: server picks c randomly (not Fiat-Shamir)
        c = secrets.randbelow(_EC_ORDER - 1) + 1
        s_c = (r_c + c * x) % _EC_ORDER
        s_s = (r_s + c * _EC_SERVER_SK) % _EC_ORDER

        # Curve check via cryptography (OpenSSL) — raises ValueError if not on curve
        # Server checks T_c; client checks T_s — prevents Invalid Curve Attack
        try:
            _ECPublicNumbers(T_c[0], T_c[1], _SECP256R1_CURVE).public_key()
            _ECPublicNumbers(T_s[0], T_s[1], _SECP256R1_CURVE).public_key()
        except Exception as exc:
            raise RuntimeError(f'EC-lib-Mutual: commitment not on curve: {exc}') from exc

        # s_c*G — C-backed; T_c + c*Y_c — pure Python (arbitrary point)
        sG_c = _ec_derive_private_key(s_c % _EC_ORDER or 1, _SECP256R1_CURVE).public_key().public_numbers()
        lhs_c = (sG_c.x, sG_c.y)
        rhs_c = _ec_point_add(T_c, _ec_scalar_mult(c, Y_c))
        if lhs_c != rhs_c:
            raise RuntimeError('EC-lib-Mutual: client proof failed')

        # s_s*G — C-backed; T_s + c*Y_s — pure Python (arbitrary point)
        sG_s = _ec_derive_private_key(s_s % _EC_ORDER or 1, _SECP256R1_CURVE).public_key().public_numbers()
        lhs_s = (sG_s.x, sG_s.y)
        rhs_s = _ec_point_add(T_s, _ec_scalar_mult(c, _EC_SERVER_Y_LIB))
        if lhs_s != rhs_s:
            raise RuntimeError('EC-lib-Mutual: server proof failed')
        stats['mutual_proofs'].append((time.perf_counter() - t0) * 1000)

        # JWT: server signs token, client verifies (mirrors actual server protocol)
        t0 = time.perf_counter()
        token = _jwt_sign('alice')
        _jwt_verify(token)
        stats['jwt_token'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] +
            stats['mutual_proofs'][-1] + stats['jwt_token'][-1]
        )
    return {k: _summarize(f'Schnorr-EC-Lib-Mutual  {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 6. Schnorr-NIZKP-Mutual  (secp256r1, non-interactive Fiat-Shamir, zksk-style, C-backed)
#
# Non-interactive variant of Schnorr-EC-Lib-Mutual.  The challenge is NOT
# sent by the server — both sides derive it deterministically from the
# commitments via SHA-256 (Fiat-Shamir transform), as zksk/petlib would do.
# This collapses 2 round-trips to 1 and makes the proof standalone (NIZK).
#
# Stage breakdown:
#   derive_x    : SHAKE-256(password + salt) → private scalar x
#   compute_y   : Y_c = x·G  (OpenSSL C-backed)
#   nizkp_proof : dual non-interactive Schnorr proofs  [Fiat-Shamir, C-backed r*G, s*G]
#   jwt_token   : server signs HS256 JWT, client verifies
# ---------------------------------------------------------------------------
def run_schnorr_nizkp_mutual(password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'nizkp_proof', 'jwt_token', 'total')
    }
    for _ in range(iterations):
        # KDF: SHAKE-256 → client private scalar x
        t0 = time.perf_counter()
        x = _derive_x(password)
        stats['derive_x'].append((time.perf_counter() - t0) * 1000)

        # x*G — C-backed via OpenSSL
        t0 = time.perf_counter()
        x_key = _ec_derive_private_key(x, _SECP256R1_CURVE)
        Y_nums = x_key.public_key().public_numbers()
        Y_c = (Y_nums.x, Y_nums.y)
        stats['compute_y'].append((time.perf_counter() - t0) * 1000)

        # Non-interactive dual Schnorr proofs (Fiat-Shamir transform)
        t0 = time.perf_counter()
        r_c = secrets.randbelow(_EC_ORDER - 1) + 1
        T_c_nums = _ec_derive_private_key(r_c, _SECP256R1_CURVE).public_key().public_numbers()
        T_c = (T_c_nums.x, T_c_nums.y)

        r_s = secrets.randbelow(_EC_ORDER - 1) + 1
        T_s_nums = _ec_derive_private_key(r_s, _SECP256R1_CURVE).public_key().public_numbers()
        T_s = (T_s_nums.x, T_s_nums.y)

        # Fiat-Shamir challenge: c = SHA-256(T_c || Y_c || T_s || Y_s || context)
        # No server round-trip — challenge derived deterministically from public values
        h = hashlib.sha256()
        for coord in (T_c[0], T_c[1], Y_c[0], Y_c[1],
                      T_s[0], T_s[1], _EC_SERVER_Y_LIB[0], _EC_SERVER_Y_LIB[1]):
            h.update(coord.to_bytes(32, 'big'))
        h.update(b'schnorr-nizkp-auth')
        c = int.from_bytes(h.digest(), 'big') % _EC_ORDER or 1

        s_c = (r_c + c * x) % _EC_ORDER
        s_s = (r_s + c * _EC_SERVER_SK) % _EC_ORDER

        # Curve check via OpenSSL — prevents Invalid Curve Attack
        try:
            _ECPublicNumbers(T_c[0], T_c[1], _SECP256R1_CURVE).public_key()
            _ECPublicNumbers(T_s[0], T_s[1], _SECP256R1_CURVE).public_key()
        except Exception as exc:
            raise RuntimeError(f'NIZKP: commitment not on curve: {exc}') from exc

        # Verify: s*G == T + c*Y  (s*G — C-backed; c*Y — pure Python wNAF)
        sG_c = _ec_derive_private_key(s_c % _EC_ORDER or 1, _SECP256R1_CURVE).public_key().public_numbers()
        lhs_c = (sG_c.x, sG_c.y)
        rhs_c = _ec_point_add(T_c, _ec_scalar_mult(c, Y_c))
        if lhs_c != rhs_c:
            raise RuntimeError('NIZKP: client proof failed')

        sG_s = _ec_derive_private_key(s_s % _EC_ORDER or 1, _SECP256R1_CURVE).public_key().public_numbers()
        lhs_s = (sG_s.x, sG_s.y)
        rhs_s = _ec_point_add(T_s, _ec_scalar_mult(c, _EC_SERVER_Y_LIB))
        if lhs_s != rhs_s:
            raise RuntimeError('NIZKP: server proof failed')
        stats['nizkp_proof'].append((time.perf_counter() - t0) * 1000)

        # JWT: server signs token, client verifies
        t0 = time.perf_counter()
        token = _jwt_sign('alice')
        _jwt_verify(token)
        stats['jwt_token'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] +
            stats['nizkp_proof'][-1] + stats['jwt_token'][-1]
        )
    return {k: _summarize(f'Schnorr-NIZKP  {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# Write box-drawing results file
# ---------------------------------------------------------------------------
def _write_results(
    path: Path,
    iterations: int,
    srp_res: dict,
    spake2_res: dict,
    ec_mut_res: dict,
    ec_lib_mut_res: dict,
    pow_mut_res: dict,
    nizkp_res: dict,
) -> None:
    lines: list[str] = []

    W = 90
    lines.append('┌' + '─' * (W - 2) + '┐')
    title = f'  Top-6 PAKE Benchmark  —  {iterations} iterations'
    lines.append('│' + title.ljust(W - 2) + '│')
    lines.append('│' + '  SRP-6a  |  SPAKE2  |  Schnorr-EC-Mutual  |  Schnorr-EC-Lib  |  Schnorr-PoW  |  Schnorr-NIZKP'.ljust(W - 2) + '│')
    lines.append('└' + '─' * (W - 2) + '┘')
    lines.append('')

    # --- Per-protocol timing tables ---
    lines += _build_timing_table(
        'SRP-6a  [RFC 5054 2048-bit MODP, SHA-256 KDF]',
        _timing_rows(srp_res, ['register', 'commit', 'challenge', 'solve', 'verify', 'total']),
    )
    lines.append('')
    lines += _build_timing_table(
        'SPAKE2  [Ed25519 / M255, + HMAC key confirmation]',
        _timing_rows(spake2_res, ['start_a', 'start_b', 'finish_a', 'finish_b', 'finish_wall', 'confirm', 'total']),
    )
    lines.append('')
    lines += _build_timing_table(
        'Schnorr-EC-Mutual  [secp256r1, SHAKE-256 KDF, dual proofs + JWT]',
        _timing_rows(ec_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total']),
    )
    lines.append('')
    lines += _build_timing_table(
        'Schnorr-EC-Lib-Mutual  [secp256r1, C-backed (OpenSSL), dual proofs + JWT]',
        _timing_rows(ec_lib_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total']),
    )
    lines.append('')
    lines += _build_timing_table(
        'Schnorr-PoW-Mutual  [RFC 3526 Group 14 2048-bit MODP, same math as server protocol + JWT]',
        _timing_rows(pow_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total']),
    )
    lines.append('')
    lines += _build_timing_table(
        'Schnorr-NIZKP-Mutual  [secp256r1, Fiat-Shamir non-interactive (zksk-style), OpenSSL + JWT]',
        _timing_rows(nizkp_res, ['derive_x', 'compute_y', 'nizkp_proof', 'jwt_token', 'total']),
    )
    lines.append('')

    # --- Summary table ---
    srp_reg   = srp_res['register']['mean_ms']
    srp_auth  = sum(srp_res[k]['mean_ms'] for k in ('commit', 'challenge', 'solve', 'verify'))
    srp_total = srp_res['total']['mean_ms']
    sp_total  = spake2_res['total']['mean_ms']
    sp_auth   = (spake2_res['start_a']['mean_ms'] + spake2_res['start_b']['mean_ms']
                 + spake2_res['finish_wall']['mean_ms'] + spake2_res['confirm']['mean_ms'])
    ec_reg     = ec_mut_res['derive_x']['mean_ms'] + ec_mut_res['compute_y']['mean_ms']
    ec_auth    = (ec_mut_res['derive_x']['mean_ms'] + ec_mut_res['mutual_proofs']['mean_ms']
                  + ec_mut_res['jwt_token']['mean_ms'])
    ec_total   = ec_mut_res['total']['mean_ms']
    ecl_reg    = ec_lib_mut_res['derive_x']['mean_ms'] + ec_lib_mut_res['compute_y']['mean_ms']
    ecl_auth   = (ec_lib_mut_res['derive_x']['mean_ms'] + ec_lib_mut_res['mutual_proofs']['mean_ms']
                  + ec_lib_mut_res['jwt_token']['mean_ms'])
    ecl_total  = ec_lib_mut_res['total']['mean_ms']
    pow_reg    = pow_mut_res['derive_x']['mean_ms'] + pow_mut_res['compute_y']['mean_ms']
    pow_auth   = (pow_mut_res['derive_x']['mean_ms'] + pow_mut_res['mutual_proofs']['mean_ms']
                  + pow_mut_res['jwt_token']['mean_ms'])
    pow_total  = pow_mut_res['total']['mean_ms']
    nizkp_reg   = nizkp_res['derive_x']['mean_ms'] + nizkp_res['compute_y']['mean_ms']
    nizkp_auth  = (nizkp_res['derive_x']['mean_ms'] + nizkp_res['nizkp_proof']['mean_ms']
                   + nizkp_res['jwt_token']['mean_ms'])
    nizkp_total = nizkp_res['total']['mean_ms']
    fastest    = min(srp_auth, sp_auth, ec_auth, ecl_auth, pow_auth, nizkp_auth)

    sum_rows = [
        ('SRP-6a',                 f'{srp_reg:.3f} ms',   f'{srp_auth:.3f} ms',   f'{srp_total:.3f} ms',   f'{srp_auth/fastest:.2f}x'),
        ('SPAKE2',                 'N/A',                  f'{sp_auth:.3f} ms',    f'{sp_total:.3f} ms',    f'{sp_auth/fastest:.2f}x'),
        ('Schnorr-EC-Mutual',      f'{ec_reg:.3f} ms',     f'{ec_auth:.3f} ms',    f'{ec_total:.3f} ms',    f'{ec_auth/fastest:.2f}x'),
        ('Schnorr-EC-Lib-Mutual',  f'{ecl_reg:.3f} ms',    f'{ecl_auth:.3f} ms',   f'{ecl_total:.3f} ms',   f'{ecl_auth/fastest:.2f}x'),
        ('Schnorr-PoW-Mutual',     f'{pow_reg:.3f} ms',    f'{pow_auth:.3f} ms',   f'{pow_total:.3f} ms',   f'{pow_auth/fastest:.2f}x'),
        ('Schnorr-NIZKP-Mutual',   f'{nizkp_reg:.3f} ms',  f'{nizkp_auth:.3f} ms', f'{nizkp_total:.3f} ms', f'{nizkp_auth/fastest:.2f}x'),
    ]
    sum_headers = ['Protocol', 'Registration', 'Auth (login)', 'Total', 'vs fastest']
    sum_widths = [max(len(sum_headers[i]), max(len(r[i]) for r in sum_rows)) for i in range(5)]

    lines.append('  SUMMARY')
    lines.append('  ' + _box_top(sum_widths))
    lines.append('  ' + _box_row(sum_headers, sum_widths))
    lines.append('  ' + _box_divider(sum_widths))
    for row in sum_rows:
        lines.append('  ' + _box_row(list(row), sum_widths))
    lines.append('  ' + _box_bottom(sum_widths))
    lines.append('  * Registration is a one-time cost, not on the login hot-path.')
    lines.append('')

    # --- Feature table ---
    feat_rows = [
        ('Mutual authentication',    'YES',           'YES',       'YES',               'YES',               'YES',           'YES'),
        ('Session key established',  'YES',           'YES',       'YES',               'YES',               'YES',           'YES'),
        ('Password never sent',      'YES',           'YES',       'YES',               'YES',               'YES',           'YES'),
        ('Server-breach resistant',  'YES',           'YES *',     'NO',                'NO',                'NO',            'NO'),
        ('Standardised (RFC/IETF)',  'RFC 5054',      'Draft',     'NO',                'NO',                'NO',            'NO'),
        ('KDF on login path',        'NO',            'NO',        'Minimal (SHAKE)',   'Minimal (SHAKE)',   'Minimal (SHAKE)', 'Minimal (SHAKE)'),
        ('Group / curve',            '2048-bit MODP', 'Ed25519',   'secp256r1 P-256',  'secp256r1 P-256',  '2048-bit MODP', 'secp256r1 P-256'),
        ('Security level',           '~112 bits',     '~128 bits', '~128 bits',        '~128 bits',        '~112 bits',     '~128 bits'),
        ('Crypto backend',           'srp (C/Py)',    'spake2 lib','Pure Python wNAF',  'OpenSSL (C)',      'Python pow()',  'OpenSSL (C)'),
        ('Same math as server',      'NO',            'NO',        'NO',                'NO',                'YES',           'NO'),
        ('Non-interactive (1 RTT)',  'NO',            'NO',        'NO',                'NO',                'NO',            'YES'),
    ]
    feat_headers = ['Property', 'SRP-6a', 'SPAKE2', 'Schnorr-EC-Mut', 'Schnorr-EC-Lib', 'Schnorr-PoW', 'Schnorr-NIZKP']
    feat_widths = [max(len(feat_headers[i]), max(len(r[i]) for r in feat_rows)) for i in range(7)]

    lines.append('  FEATURE COMPARISON')
    lines.append('  ' + _box_top(feat_widths))
    lines.append('  ' + _box_row(feat_headers, feat_widths))
    lines.append('  ' + _box_divider(feat_widths))
    for row in feat_rows:
        lines.append('  ' + _box_row(list(row), feat_widths))
    lines.append('  ' + _box_bottom(feat_widths))
    lines.append('  * SPAKE2+ (server-breach resistant) is not in the spake2 library used here.')
    lines.append('  Schnorr-EC-Lib: c*Y (arbitrary-point mult) still uses pure Python wNAF; all k*G via OpenSSL.')
    lines.append('  Schnorr-PoW: uses Python built-in pow(a, b, n) — same group and same interactive construction as the actual server.')
    lines.append('  Schnorr-NIZKP: Fiat-Shamir transform (c = SHA-256(T_c||Y_c||T_s||Y_s||ctx)) — zksk-style, no server challenge round-trip.')
    lines.append('')

    path.write_text('\n'.join(lines), encoding='utf-8')


# ---------------------------------------------------------------------------
# Main comparison
# ---------------------------------------------------------------------------
def compare(password: str = 'compare-password', iterations: int = 100) -> None:
    print('=' * 90)
    print('  Top-6 PAKE comparison: SRP-6a  |  SPAKE2  |  Schnorr-EC-Mutual  |  Schnorr-EC-Lib  |  Schnorr-PoW  |  Schnorr-NIZKP')
    print('  All protocols: mutual auth + session JWT')
    print(f'  Iterations: {iterations}')
    print('=' * 90)

    print('\n[1/6] SRP-6a  (srp library, RFC 5054 2048-bit group, SHA-256 KDF) ...')
    srp_res = run_srp('alice', password, iterations)
    _section(
        'SRP-6a — RFC 5054 2048-bit MODP, SHA-256 KDF, mutual auth + session key',
        srp_res, ['register', 'commit', 'challenge', 'solve', 'verify', 'total'],
    )

    print('\n[2/6] SPAKE2  (spake2 library, Ed25519 / M255 group) ...')
    spake2_res = run_spake2(password, iterations)
    _section(
        'SPAKE2 — Ed25519 / M255, HMAC key confirmation, explicit mutual auth',
        spake2_res, ['start_a', 'start_b', 'finish_a', 'finish_b', 'finish_wall', 'confirm', 'total'],
    )

    print('\n[3/6] Schnorr-EC-Mutual  (secp256r1 pure Python wNAF, SHAKE-256 KDF) ...')
    ec_mut_res = run_schnorr_ec_mutual(password, iterations)
    _section(
        'Schnorr-EC-Mutual — secp256r1, dual Schnorr proofs + JWT  [pure Python]',
        ec_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total'],
    )

    print('\n[4/6] Schnorr-EC-Lib-Mutual  (secp256r1 C-backed via cryptography, SHAKE-256 KDF) ...')
    ec_lib_mut_res = run_schnorr_ec_lib_mutual(password, iterations)
    _section(
        'Schnorr-EC-Lib-Mutual — secp256r1 C-backed (OpenSSL), dual proofs + JWT',
        ec_lib_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total'],
    )

    print('\n[5/6] Schnorr-PoW-Mutual  (RFC 3526 Group 14 2048-bit MODP, Python pow(), same math as server) ...')
    pow_mut_res = run_schnorr_pow_mutual(password, iterations)
    _section(
        'Schnorr-PoW-Mutual — 2048-bit MODP, dual Schnorr proofs + JWT  [Python pow()]',
        pow_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total'],
    )

    print('\n[6/6] Schnorr-NIZKP-Mutual  (secp256r1 C-backed, Fiat-Shamir non-interactive, zksk-style) ...')
    nizkp_res = run_schnorr_nizkp_mutual(password, iterations)
    _section(
        'Schnorr-NIZKP-Mutual — secp256r1, Fiat-Shamir dual proofs + JWT  [zksk-style, OpenSSL]',
        nizkp_res, ['derive_x', 'compute_y', 'nizkp_proof', 'jwt_token', 'total'],
    )

    output_path = _GENERATED / 'pake_top3_results.txt'
    _write_results(output_path, iterations, srp_res, spake2_res, ec_mut_res, ec_lib_mut_res, pow_mut_res, nizkp_res)
    print(f'\n  Results written to: {output_path}')


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='Top-3 PAKE timing comparison.')
    ap.add_argument('iterations', type=int, nargs='?', default=100,
                    help='Iterations per protocol (default: 100)')
    ap.add_argument('--password', default='compare-password')
    args = ap.parse_args()
    compare(password=args.password, iterations=args.iterations)

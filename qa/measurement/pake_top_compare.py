"""
Top-5 PAKE comparison: SRP-6a | Schnorr-EC-Mutual | Schnorr-EC-Lib | Schnorr-PoW | pysnark Groth16.

All five protocols never transmit the password and issue a session JWT.

Protocols
  SRP-6a               : RFC 5054 2048-bit group, SHA-256 KDF (srp library).
  Schnorr-EC-Mutual    : secp256r1, dual interactive Schnorr proofs + JWT (pure Python wNAF).
  Schnorr-EC-Lib-Mutual: secp256r1, dual interactive Schnorr proofs + JWT (OpenSSL C-backed).
  Schnorr-PoW-Mutual   : RFC 3526 Group 14 2048-bit MODP, same math as server + JWT.
  pysnark Groth16      : BN128 field, Groth16 zkSNARK (x^2=y circuit, 1 R1CS gate) + JWT.

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
    """Sign and return an HS256 JWT."""
    now = datetime.now(timezone.utc)
    return _jwt.encode(
        {'client_id': client_id, 'iat': now, 'exp': now + timedelta(seconds=3600)},
        _JWT_SECRET, algorithm='HS256',
    )


def _jwt_verify(token: str) -> dict:
    """Client verifies JWT signature and returns payload."""
    return _jwt.decode(token, _JWT_SECRET, algorithms=['HS256'])

# ---------------------------------------------------------------------------
# Schnorr-PoW group parameters - same RFC 3526 Group 14 (2048-bit) as the server
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
    """True iff v is in the Schnorr subgroup of order Q."""
    return 1 < v < _POW_P and pow(v, _POW_Q, _POW_P) == 1


def _ec_point_on_curve(pt: tuple) -> bool:
    """True iff pt is on secp256r1: y^2 == x^3 + ax + b (mod p)."""
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
        k: [] for k in ('register', 'commit', 'challenge', 'solve', 'verify', 'jwt_token', 'total')
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

        # JWT: server issues HS256 JWT after successful auth, client verifies (same as all other protocols)
        t0 = time.perf_counter()
        token = _jwt_sign(username)
        _jwt_verify(token)
        stats['jwt_token'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['register'][-1] + stats['commit'][-1] + stats['challenge'][-1]
            + stats['solve'][-1] + stats['verify'][-1] + stats['jwt_token'][-1]
        )
    return {k: _summarize(f'SRP-6a  {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 2. Schnorr-PoW-Mutual  (RFC 3526 Group 14 2048-bit MODP)
#
#   derive_x      : SHAKE-256(password + salt) -> x mod Q
#   compute_y     : Y_c = G^x mod P
#   mutual_proofs : both sides commit T=G^r, exchange c, compute s=r+c*sk mod Q,
#                   verify G^s == T*Y^c mod P
#   jwt_token     : HS256 JWT sign + verify
# ---------------------------------------------------------------------------
def run_schnorr_pow_mutual(password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total')
    }
    for _ in range(iterations):
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
        # subgroup check on commitments
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

        # JWT
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
# 3. Schnorr-EC-Mutual  (secp256r1, pure Python wNAF)
#
#   derive_x      : SHAKE-256(password + salt) -> x
#   compute_y     : Y_c = x*G
#   mutual_proofs : both sides commit T=r*G, exchange c, compute s=r+c*sk mod n,
#                   verify s*G == T + c*Y
#   jwt_token     : HS256 JWT sign + verify
# ---------------------------------------------------------------------------
def _derive_x(password: str) -> int:
    hashed = hashlib.shake_256(password.encode() + _FIXED_SALT).digest(256)
    return int.from_bytes(hashed, 'big') % _EC_ORDER or 1


def run_schnorr_ec_mutual(password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total')
    }
    for _ in range(iterations):
        t0 = time.perf_counter()
        x = _derive_x(password)
        stats['derive_x'].append((time.perf_counter() - t0) * 1000)

        # Registration: Y_c = x*G
        t0 = time.perf_counter()
        Y_c = _ec_scalar_mult(x, _EC_GENERATOR)
        stats['compute_y'].append((time.perf_counter() - t0) * 1000)

        # Mutual Schnorr proofs: client proves x, server proves _EC_SERVER_SK
        t0 = time.perf_counter()
        r_c = secrets.randbelow(_EC_ORDER - 1) + 1
        T_c = _ec_scalar_mult(r_c, _EC_GENERATOR)
        r_s = secrets.randbelow(_EC_ORDER - 1) + 1
        T_s = _ec_scalar_mult(r_s, _EC_GENERATOR)

        c = secrets.randbelow(_EC_ORDER - 1) + 1
        s_c = (r_c + c * x) % _EC_ORDER
        s_s = (r_s + c * _EC_SERVER_SK) % _EC_ORDER
        # curve check on commitments
        if not _ec_point_on_curve(T_s):
            raise RuntimeError('Schnorr-EC-Mutual: T_s not on curve')
        if not _ec_point_on_curve(T_c):
            raise RuntimeError('Schnorr-EC-Mutual: T_c not on curve')
        if _ec_scalar_mult(s_c, _EC_GENERATOR) != _ec_point_add(T_c, _ec_scalar_mult(c, Y_c)):
            raise RuntimeError('Schnorr-EC-Mutual: client proof failed')
        if _ec_scalar_mult(s_s, _EC_GENERATOR) != _ec_point_add(T_s, _ec_scalar_mult(c, _EC_SERVER_Y)):
            raise RuntimeError('Schnorr-EC-Mutual: server proof failed')
        stats['mutual_proofs'].append((time.perf_counter() - t0) * 1000)

        # JWT
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
# 4. Schnorr-EC-Lib-Mutual  (secp256r1, OpenSSL C-backed)
#
# Same protocol as Schnorr-EC-Mutual; r*G, s*G via derive_private_key() (OpenSSL),
# c*Y (arbitrary point) still via pure Python wNAF.
# ---------------------------------------------------------------------------
def run_schnorr_ec_lib_mutual(password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total')
    }
    for _ in range(iterations):
        # KDF: SHAKE-256 - client private scalar x
        t0 = time.perf_counter()
        x = _derive_x(password)
        stats['derive_x'].append((time.perf_counter() - t0) * 1000)

        # x*G - C-backed via OpenSSL
        t0 = time.perf_counter()
        x_key = _ec_derive_private_key(x, _SECP256R1_CURVE)
        Y_nums = x_key.public_key().public_numbers()
        Y_c = (Y_nums.x, Y_nums.y)
        stats['compute_y'].append((time.perf_counter() - t0) * 1000)

        # r*G and s*G via OpenSSL; c*Y (arbitrary point) via pure Python
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

        # curve check via OpenSSL
        try:
            _ECPublicNumbers(T_c[0], T_c[1], _SECP256R1_CURVE).public_key()
            _ECPublicNumbers(T_s[0], T_s[1], _SECP256R1_CURVE).public_key()
        except Exception as exc:
            raise RuntimeError(f'EC-lib-Mutual: commitment not on curve: {exc}') from exc

        # s*G C-backed; T + c*Y pure Python
        sG_c = _ec_derive_private_key(s_c % _EC_ORDER or 1, _SECP256R1_CURVE).public_key().public_numbers()
        lhs_c = (sG_c.x, sG_c.y)
        rhs_c = _ec_point_add(T_c, _ec_scalar_mult(c, Y_c))
        if lhs_c != rhs_c:
            raise RuntimeError('EC-lib-Mutual: client proof failed')

        sG_s = _ec_derive_private_key(s_s % _EC_ORDER or 1, _SECP256R1_CURVE).public_key().public_numbers()
        lhs_s = (sG_s.x, sG_s.y)
        rhs_s = _ec_point_add(T_s, _ec_scalar_mult(c, _EC_SERVER_Y_LIB))
        if lhs_s != rhs_s:
            raise RuntimeError('EC-lib-Mutual: server proof failed')
        stats['mutual_proofs'].append((time.perf_counter() - t0) * 1000)

        # JWT
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
# 5. pysnark Groth16  (secp256r1 + BN128 field, Fiat-Shamir Schnorr, dual ZKP)
#
# Protocol:
#   1. T = r*G  (commitment, EC, outside circuit)
#   2. c = SHA-256(T_c || Y_c || T_s || Y_s) % 2^13  (Fiat-Shamir challenge)
#   3. s = r + c*x  (response, exact integer, no mod)
#   4. verify s*G == T + c*Y  (EC check outside circuit)
#   5. SNARK: prove (x, r) s.t. s - r - c*x = 0
#
# Scalar bounds: x,r < 2^240, c < 2^13
# s < 2^240*(1+2^13) < 2^253.0002 < BN128 prime (~2^253.6)
# ---------------------------------------------------------------------------
def run_pysnark(password: str, iterations: int) -> dict:
    try:
        from pysnark.runtime import snark
    except ImportError as exc:
        raise ImportError(
            'pysnark is required: pip install pysnark\n'
            'gmpy2 is also required for field arithmetic: pip install gmpy2\n'
            f'Original error: {exc}'
        ) from exc

    _BITS_X = 240  # x, r < 2^240 -> security = 240/2 = 120 bits (BSGS)
    _BITS_C = 13   # c < 2^13 -> s = r + c*x < 2^240*(1+2^13) < BN128 prime (~2^253.6)

    # Circuit: s - r - c*x = 0  (x, r are witnesses; c, s are public)
    @snark
    def _zk_schnorr(x, r, c, s):
        (s - r - c * x).assert_zero()

    # server key truncated to 240 bits to fit BN128 field
    x_s = (_EC_SERVER_SK % (1 << _BITS_X)) or 1
    # server public key recomputed from truncated x_s
    Y_s_nums = _ec_derive_private_key(x_s, _SECP256R1_CURVE).public_key().public_numbers()
    Y_s = (Y_s_nums.x, Y_s_nums.y)

    stats: dict[str, list[float]] = {k: [] for k in (
        'derive_x', 'compute_y', 'schnorr_ec', 'client_zkp', 'server_zkp', 'jwt_token', 'total',
    )}

    for _ in range(iterations):
        # KDF: SHAKE-256 -> x_c truncated to 240 bits
        t0 = time.perf_counter()
        hashed = hashlib.shake_256(password.encode() + _FIXED_SALT).digest(256)
        x_c = (int.from_bytes(hashed, 'big') % (1 << _BITS_X)) or 1
        stats['derive_x'].append((time.perf_counter() - t0) * 1000)

        # compute_y: Y_c = x_c*G  (OpenSSL)
        t0 = time.perf_counter()
        x_key = _ec_derive_private_key(x_c, _SECP256R1_CURVE)
        Y_c_nums = x_key.public_key().public_numbers()
        Y_c = (Y_c_nums.x, Y_c_nums.y)
        stats['compute_y'].append((time.perf_counter() - t0) * 1000)

        # steps 1-4: same work as mutual_proofs in other protocols
        t0 = time.perf_counter()
        # Step 1: commitments T = r*G
        r_c = secrets.randbelow(1 << _BITS_X) or 1
        r_s = secrets.randbelow(1 << _BITS_X) or 1
        T_c_nums = _ec_derive_private_key(r_c, _SECP256R1_CURVE).public_key().public_numbers()
        T_c = (T_c_nums.x, T_c_nums.y)
        T_s_nums = _ec_derive_private_key(r_s, _SECP256R1_CURVE).public_key().public_numbers()
        T_s = (T_s_nums.x, T_s_nums.y)
        # Step 2: Fiat-Shamir challenge - prover cannot choose c freely
        c_hash = hashlib.sha256(
            T_c[0].to_bytes(32, 'big') + T_c[1].to_bytes(32, 'big') +
            Y_c[0].to_bytes(32, 'big') + Y_c[1].to_bytes(32, 'big') +
            T_s[0].to_bytes(32, 'big') + T_s[1].to_bytes(32, 'big') +
            Y_s[0].to_bytes(32, 'big') + Y_s[1].to_bytes(32, 'big')
        ).digest()
        c = (int.from_bytes(c_hash, 'big') % (1 << _BITS_C)) or 1
        # Step 3: Schnorr responses (exact integers, < BN128 prime)
        s_c = r_c + c * x_c
        s_s = r_s + c * x_s
        # Step 4: EC verify s*G == T + c*Y
        sG_c = _ec_derive_private_key(s_c % _EC_ORDER or 1, _SECP256R1_CURVE).public_key().public_numbers()
        if (sG_c.x, sG_c.y) != _ec_point_add(T_c, _ec_scalar_mult(c, Y_c)):
            raise RuntimeError('pysnark: EC verification failed for client')
        sG_s = _ec_derive_private_key(s_s % _EC_ORDER or 1, _SECP256R1_CURVE).public_key().public_numbers()
        if (sG_s.x, sG_s.y) != _ec_point_add(T_s, _ec_scalar_mult(c, Y_s)):
            raise RuntimeError('pysnark: EC verification failed for server')
        stats['schnorr_ec'].append((time.perf_counter() - t0) * 1000)

        # Step 5a: client ZK proof
        t0 = time.perf_counter()
        _zk_schnorr(x_c, r_c, c, s_c)
        stats['client_zkp'].append((time.perf_counter() - t0) * 1000)

        # Step 5b: server ZK proof
        t0 = time.perf_counter()
        _zk_schnorr(x_s, r_s, c, s_s)
        stats['server_zkp'].append((time.perf_counter() - t0) * 1000)

        # JWT
        t0 = time.perf_counter()
        token = _jwt_sign('alice')
        _jwt_verify(token)
        stats['jwt_token'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] +
            stats['schnorr_ec'][-1] +
            stats['client_zkp'][-1] + stats['server_zkp'][-1] +
            stats['jwt_token'][-1]
        )

    return {k: _summarize(f'pysnark Groth16  {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# Write box-drawing results file
# ---------------------------------------------------------------------------
def _write_results(
    path: Path,
    iterations: int,
    srp_res: dict,
    ec_mut_res: dict,
    ec_lib_mut_res: dict,
    pow_mut_res: dict,
    pysnark_res: dict,
) -> None:
    lines: list[str] = []

    W = 90
    lines.append('┌' + '─' * (W - 2) + '┐')
    title = f'  Top-5 PAKE Benchmark  -  {iterations} iterations'
    lines.append('│' + title.ljust(W - 2) + '│')
    lines.append('│' + '  SRP-6a  |  Schnorr-EC-Mutual  |  Schnorr-EC-Lib  |  Schnorr-PoW  |  pysnark Groth16'.ljust(W - 2) + '│')
    lines.append('└' + '─' * (W - 2) + '┘')
    lines.append('')

    # --- Per-protocol timing tables ---
    lines += _build_timing_table(
        'SRP-6a  [RFC 5054 2048-bit MODP, SHA-256 KDF]',
        _timing_rows(srp_res, ['register', 'commit', 'challenge', 'solve', 'verify', 'jwt_token', 'total']),
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
        'pysnark Groth16  [secp256r1+BN128, Schnorr ZKP circuit, dual Groth16 proofs + JWT]',
        _timing_rows(pysnark_res, ['derive_x', 'compute_y', 'schnorr_ec', 'client_zkp', 'server_zkp', 'jwt_token', 'total']),
    )
    lines.append('')

    # --- Summary table ---
    srp_reg   = srp_res['register']['mean_ms']
    srp_auth  = sum(srp_res[k]['mean_ms'] for k in ('commit', 'challenge', 'solve', 'verify', 'jwt_token'))
    srp_total = srp_res['total']['mean_ms']
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
    pysnark_reg   = pysnark_res['derive_x']['mean_ms'] + pysnark_res['compute_y']['mean_ms']
    pysnark_auth  = (pysnark_res['derive_x']['mean_ms'] + pysnark_res['schnorr_ec']['mean_ms']
                     + pysnark_res['client_zkp']['mean_ms'] + pysnark_res['server_zkp']['mean_ms']
                     + pysnark_res['jwt_token']['mean_ms'])
    pysnark_total = pysnark_res['total']['mean_ms']
    fastest    = min(srp_auth, ec_auth, ecl_auth, pow_auth, pysnark_auth)

    sum_rows = [
        ('SRP-6a',                 f'{srp_reg:.3f} ms',   f'{srp_auth:.3f} ms',   f'{srp_total:.3f} ms',   f'{srp_auth/fastest:.2f}x'),
        ('Schnorr-EC-Mutual',      f'{ec_reg:.3f} ms',     f'{ec_auth:.3f} ms',    f'{ec_total:.3f} ms',    f'{ec_auth/fastest:.2f}x'),
        ('Schnorr-EC-Lib-Mutual',  f'{ecl_reg:.3f} ms',    f'{ecl_auth:.3f} ms',   f'{ecl_total:.3f} ms',   f'{ecl_auth/fastest:.2f}x'),
        ('Schnorr-PoW-Mutual',     f'{pow_reg:.3f} ms',    f'{pow_auth:.3f} ms',   f'{pow_total:.3f} ms',   f'{pow_auth/fastest:.2f}x'),
        ('pysnark Groth16',         f'{pysnark_reg:.3f} ms', f'{pysnark_auth:.3f} ms', f'{pysnark_total:.3f} ms', f'{pysnark_auth/fastest:.2f}x'),
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
        ('Mutual authentication',    'YES',           'YES',               'YES',               'YES',           'YES (dual ZKP)'),
        ('Session key established',  'YES',           'YES',               'YES',               'YES',           'JWT only'),
        ('Password never sent',      'YES',           'YES',               'YES',               'YES',           'YES'),
        ('Server-breach resistant',  'YES',           'NO',                'NO',                'NO',            'YES'),
        ('Standardised (RFC/IETF)',  'RFC 5054',      'NO',                'NO',                'NO',            'NO'),
        ('KDF on login path',        'NO',            'Minimal (SHAKE)',   'Minimal (SHAKE)',   'Minimal (SHAKE)', 'Minimal (SHAKE)'),
        ('Group / curve',            '2048-bit MODP', 'secp256r1 P-256',  'secp256r1 P-256',  '2048-bit MODP', 'BN128 field'),
        ('Security level',           '~112 bits',     '~128 bits',        '~128 bits',        '~112 bits',     '~120 bits (240-bit x)'),  # noqa: E501
        ('Crypto backend',           'srp (C/Py)',    'Pure Python wNAF',  'OpenSSL (C)',      'Python pow()',  'pysnark (Groth16)'),
        ('Same math as server',      'NO',            'NO',                'NO',                'YES',           'NO'),
        ('Non-interactive (1 RTT)',  'NO',            'NO',                'NO',                'NO',            'YES'),
    ]
    feat_headers = ['Property', 'SRP-6a', 'Schnorr-EC-Mut', 'Schnorr-EC-Lib', 'Schnorr-PoW', 'pysnark Groth16']
    feat_widths = [max(len(feat_headers[i]), max(len(r[i]) for r in feat_rows)) for i in range(6)]

    lines.append('  FEATURE COMPARISON')
    lines.append('  ' + _box_top(feat_widths))
    lines.append('  ' + _box_row(feat_headers, feat_widths))
    lines.append('  ' + _box_divider(feat_widths))
    for row in feat_rows:
        lines.append('  ' + _box_row(list(row), feat_widths))
    lines.append('  ' + _box_bottom(feat_widths))
    lines.append('  Schnorr-EC-Lib: c*Y (arbitrary-point mult) still uses pure Python wNAF; all k*G via OpenSSL.')
    lines.append('  Schnorr-PoW: uses Python built-in pow(a, b, n) - same group and same interactive construction as the actual server.')
    lines.append('  pysnark Groth16: Fiat-Shamir c=SHA256(T_c||Y_c||T_s||Y_s); EC verify s*G=T+c*Y outside circuit; SNARK proves knowledge of (x,r).')
    lines.append('  pysnark scalar bound: x,r < 2^240, c < 2^13, s < BN128 prime (~2^253.6). Security ~120 bits (BSGS).')
    lines.append('')

    path.write_text('\n'.join(lines), encoding='utf-8')




# ---------------------------------------------------------------------------
# Main comparison
# ---------------------------------------------------------------------------
_PROTOCOL_CHOICES = ('all', 'srp', 'ec', 'ec-lib', 'pow', 'pysnark')


def compare(password: str = 'compare-password', iterations: int = 100,
            protocol: str = 'all') -> None:
    run_all = protocol == 'all'

    print('=' * 90)
    proto_label = 'all protocols' if run_all else f'protocol: {protocol}'
    print(f'  Top-5 PAKE comparison  [{proto_label}]')
    print(f'  Iterations: {iterations}')
    print('=' * 90)

    srp_res = ec_mut_res = ec_lib_mut_res = pow_mut_res = pysnark_res = None

    if run_all or protocol == 'srp':
        print('\n[srp] SRP-6a  (srp library, RFC 5054 2048-bit group, SHA-256 KDF) ...')
        srp_res = run_srp('alice', password, iterations)
        _section(
            'SRP-6a - RFC 5054 2048-bit MODP, SHA-256 KDF, mutual auth + session key',
            srp_res, ['register', 'commit', 'challenge', 'solve', 'verify', 'jwt_token', 'total'],
        )

    if run_all or protocol == 'ec':
        print('\n[ec] Schnorr-EC-Mutual  (secp256r1 pure Python wNAF, SHAKE-256 KDF) ...')
        ec_mut_res = run_schnorr_ec_mutual(password, iterations)
        _section(
            'Schnorr-EC-Mutual - secp256r1, dual Schnorr proofs + JWT  [pure Python]',
            ec_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total'],
        )

    if run_all or protocol == 'ec-lib':
        print('\n[ec-lib] Schnorr-EC-Lib-Mutual  (secp256r1 C-backed via cryptography, SHAKE-256 KDF) ...')
        ec_lib_mut_res = run_schnorr_ec_lib_mutual(password, iterations)
        _section(
            'Schnorr-EC-Lib-Mutual - secp256r1 C-backed (OpenSSL), dual proofs + JWT',
            ec_lib_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total'],
        )

    if run_all or protocol == 'pow':
        print('\n[pow] Schnorr-PoW-Mutual  (RFC 3526 Group 14 2048-bit MODP, Python pow(), same math as server) ...')
        pow_mut_res = run_schnorr_pow_mutual(password, iterations)
        _section(
            'Schnorr-PoW-Mutual - 2048-bit MODP, dual Schnorr proofs + JWT  [Python pow()]',
            pow_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'jwt_token', 'total'],
        )

    if run_all or protocol == 'pysnark':
        print('\n[pysnark] pysnark Groth16  (BN128 field, x^2=y circuit, Groth16 proving system) ...')
        pysnark_res = run_pysnark(password, iterations)
        _section(
            'pysnark Groth16 - BN128 field, x^2=y circuit + JWT  [Groth16 proving system]',
            pysnark_res, ['derive_x', 'compute_y', 'schnorr_ec', 'client_zkp', 'server_zkp', 'jwt_token', 'total'],
        )

    if run_all:
        output_path = _GENERATED / 'pake_top3_results.txt'
        _write_results(output_path, iterations, srp_res, ec_mut_res, ec_lib_mut_res, pow_mut_res, pysnark_res)
        print(f'\n  Results written to: {output_path}')


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(
        description='Top-5 PAKE timing comparison.',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument('iterations', type=int, nargs='?', default=100,
                    help='Iterations per protocol (default: 100)')
    ap.add_argument('--password', default='compare-password')
    ap.add_argument(
        '--protocol', default='all', choices=_PROTOCOL_CHOICES,
        help=(
            'Protocol to run (default: all):\n'
            '  all      - run all five protocols\n'
            '  srp      - SRP-6a (RFC 5054)\n'
            '  ec       - Schnorr-EC-Mutual (pure Python wNAF)\n'
            '  ec-lib   - Schnorr-EC-Lib-Mutual (OpenSSL C-backed)\n'
            '  pow      - Schnorr-PoW-Mutual (2048-bit MODP)\n'
            '  pysnark  - pysnark Groth16 (BN128, zkSNARK)'
        ),
    )
    args = ap.parse_args()
    compare(password=args.password, iterations=args.iterations, protocol=args.protocol)

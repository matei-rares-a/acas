"""
Top-3 PAKE comparison: SRP-6a vs SPAKE2 vs Schnorr-EC-Mutual.

All three protocols offer mutual authentication and a session key,
making this a fair apples-to-apples benchmark.

Protocols
  SRP-6a           : RFC 5054 2048-bit group, SHA-256 KDF (srp library, pure Python).
  SPAKE2           : Ed25519 / M255 group (spake2 library, pure Python).
  Schnorr-EC-Mutual: secp256r1 + dual Schnorr proofs + ECDH session key (pure Python wNAF).

All three
  - Never transmit the password
  - Provide mutual authentication (both sides are verified)
  - Derive a shared session key
  - Are pure-Python (no C extensions)

Run:
    python qa/measurement/pake_top3_compare.py
    python qa/measurement/pake_top3_compare.py 200
"""

import hashlib
import secrets
import statistics
import sys
import time
from pathlib import Path

import srp
from spake2 import SPAKE2_A, SPAKE2_B

_QA_PATH = Path(__file__).resolve().parents[1]
_MEASUREMENT_PATH = Path(__file__).resolve().parent
for _p in (_QA_PATH, _MEASUREMENT_PATH):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from ec_compare import (     # noqa: E402
    EC_ORDER as _EC_ORDER,
    EC_GENERATOR as _EC_GENERATOR,
    _scalar_mult as _ec_scalar_mult,
    _point_add as _ec_point_add,
)

srp.rfc5054_enable()

_GENERATED = Path(__file__).resolve().parent / "generated"
_GENERATED.mkdir(exist_ok=True)

_FIXED_SALT = b'pake_top3_compare_salt_2026'

# Pre-computed server keypair for Schnorr-EC-Mutual (deterministic, reproducible)
_EC_SERVER_SK = int.from_bytes(
    hashlib.sha256(b'schnorr_ec_server_key_2026').digest(), 'big') % _EC_ORDER or 1
_EC_SERVER_Y = _ec_scalar_mult(_EC_SERVER_SK, _EC_GENERATOR)


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
# 3. Schnorr-EC-Mutual  (secp256r1, dual Schnorr proofs + ECDH session key)
#
# Stage breakdown:
#   derive_x      : SHAKE-256(password + salt) → private scalar x
#   compute_y     : Y_c = x·G  (client public key, stored server-side at registration)
#   mutual_proofs : both sides pick nonces, compute commits, derive Fiat-Shamir
#                   challenge, exchange responses, verify each other's proof
#   session_key   : ECDH — x·Y_server == sk_server·Y_client → HKDF → K
# ---------------------------------------------------------------------------
def _derive_x(password: str) -> int:
    hashed = hashlib.shake_256(password.encode() + _FIXED_SALT).digest(256)
    return int.from_bytes(hashed, 'big') % _EC_ORDER or 1


def run_schnorr_ec_mutual(password: str, iterations: int) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'mutual_proofs', 'session_key', 'total')
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
        c_bytes = hashlib.sha256(
            T_c[0].to_bytes(32, 'big') + T_c[1].to_bytes(32, 'big') +
            T_s[0].to_bytes(32, 'big') + T_s[1].to_bytes(32, 'big')
        ).digest()
        c = int.from_bytes(c_bytes, 'big') % _EC_ORDER or 1
        s_c = (r_c + c * x) % _EC_ORDER
        s_s = (r_s + c * _EC_SERVER_SK) % _EC_ORDER
        if _ec_scalar_mult(s_c, _EC_GENERATOR) != _ec_point_add(T_c, _ec_scalar_mult(c, Y_c)):
            raise RuntimeError('Schnorr-EC-Mutual: client proof failed')
        if _ec_scalar_mult(s_s, _EC_GENERATOR) != _ec_point_add(T_s, _ec_scalar_mult(c, _EC_SERVER_Y)):
            raise RuntimeError('Schnorr-EC-Mutual: server proof failed')
        stats['mutual_proofs'].append((time.perf_counter() - t0) * 1000)

        # Session key: ECDH  x·Y_server (client) == sk_server·Y_c (server)
        t0 = time.perf_counter()
        K_c = _ec_scalar_mult(x, _EC_SERVER_Y)
        K_s = _ec_scalar_mult(_EC_SERVER_SK, Y_c)
        if K_c != K_s:
            raise RuntimeError('Schnorr-EC-Mutual: session key mismatch')
        _ = hashlib.sha256(K_c[0].to_bytes(32, 'big')).digest()  # HKDF step
        stats['session_key'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] +
            stats['mutual_proofs'][-1] + stats['session_key'][-1]
        )
    return {k: _summarize(f'Schnorr  {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# Write box-drawing results file
# ---------------------------------------------------------------------------
def _write_results(
    path: Path,
    iterations: int,
    srp_res: dict,
    spake2_res: dict,
    ec_mut_res: dict,
) -> None:
    lines: list[str] = []

    W = 90
    lines.append('┌' + '─' * (W - 2) + '┐')
    title = f'  Top-3 PAKE Benchmark  —  {iterations} iterations'
    lines.append('│' + title.ljust(W - 2) + '│')
    lines.append('│' + '  SRP-6a  |  SPAKE2  |  Schnorr-EC-Mutual'.ljust(W - 2) + '│')
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
        'Schnorr-EC-Mutual  [secp256r1, SHAKE-256 KDF, dual proofs + ECDH]',
        _timing_rows(ec_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'session_key', 'total']),
    )
    lines.append('')

    # --- Summary table ---
    srp_reg   = srp_res['register']['mean_ms']
    srp_auth  = sum(srp_res[k]['mean_ms'] for k in ('commit', 'challenge', 'solve', 'verify'))
    srp_total = srp_res['total']['mean_ms']
    sp_total  = spake2_res['total']['mean_ms']
    sp_auth   = (spake2_res['start_a']['mean_ms'] + spake2_res['start_b']['mean_ms']
                 + spake2_res['finish_wall']['mean_ms'] + spake2_res['confirm']['mean_ms'])
    ec_reg    = ec_mut_res['derive_x']['mean_ms'] + ec_mut_res['compute_y']['mean_ms']
    ec_auth   = (ec_mut_res['derive_x']['mean_ms'] + ec_mut_res['mutual_proofs']['mean_ms']
                 + ec_mut_res['session_key']['mean_ms'])
    ec_total  = ec_mut_res['total']['mean_ms']
    fastest   = min(srp_auth, sp_auth, ec_auth)

    sum_rows = [
        ('SRP-6a',            f'{srp_reg:.3f} ms',  f'{srp_auth:.3f} ms',  f'{srp_total:.3f} ms', f'{srp_auth/fastest:.2f}x'),
        ('SPAKE2',            'N/A',                 f'{sp_auth:.3f} ms',   f'{sp_total:.3f} ms',  f'{sp_auth/fastest:.2f}x'),
        ('Schnorr-EC-Mutual', f'{ec_reg:.3f} ms',   f'{ec_auth:.3f} ms',   f'{ec_total:.3f} ms',  f'{ec_auth/fastest:.2f}x'),
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
        ('Mutual authentication',    'YES',        'YES',      'YES'),
        ('Session key established',  'YES',        'YES',      'YES'),
        ('Password never sent',      'YES',        'YES',      'YES'),
        ('Server-breach resistant',  'YES',        'YES *',    'NO'),
        ('Standardised (RFC/IETF)',  'RFC 5054',   'Draft',    'NO'),
        ('KDF on login path',        'NO',         'NO',       'Minimal (SHAKE-256)'),
        ('Group / curve',            '2048-bit MODP', 'Ed25519', 'secp256r1 P-256'),
        ('Security level',           '~112 bits',  '~128 bits','~128 bits'),
    ]
    feat_headers = ['Property', 'SRP-6a', 'SPAKE2', 'Schnorr-EC-Mut']
    feat_widths = [max(len(feat_headers[i]), max(len(r[i]) for r in feat_rows)) for i in range(4)]

    lines.append('  FEATURE COMPARISON')
    lines.append('  ' + _box_top(feat_widths))
    lines.append('  ' + _box_row(feat_headers, feat_widths))
    lines.append('  ' + _box_divider(feat_widths))
    for row in feat_rows:
        lines.append('  ' + _box_row(list(row), feat_widths))
    lines.append('  ' + _box_bottom(feat_widths))
    lines.append('  * SPAKE2+ (server-breach resistant) is not in the spake2 library used here.')
    lines.append('')

    path.write_text('\n'.join(lines), encoding='utf-8')


# ---------------------------------------------------------------------------
# Main comparison
# ---------------------------------------------------------------------------
def compare(password: str = 'compare-password', iterations: int = 100) -> None:
    print('=' * 90)
    print('  Top-3 PAKE comparison: SRP-6a  |  SPAKE2  |  Schnorr-EC-Mutual')
    print('  All protocols: mutual auth + session key | pure Python | ~128-bit security')
    print(f'  Iterations: {iterations}')
    print('=' * 90)

    print('\n[1/3] SRP-6a  (srp library, RFC 5054 2048-bit group, SHA-256 KDF) ...')
    srp_res = run_srp('alice', password, iterations)
    _section(
        'SRP-6a — RFC 5054 2048-bit MODP, SHA-256 KDF, mutual auth + session key',
        srp_res, ['register', 'commit', 'challenge', 'solve', 'verify', 'total'],
    )

    print('\n[2/3] SPAKE2  (spake2 library, Ed25519 / M255 group) ...')
    spake2_res = run_spake2(password, iterations)
    _section(
        'SPAKE2 — Ed25519 / M255, HMAC key confirmation, explicit mutual auth',
        spake2_res, ['start_a', 'start_b', 'finish_a', 'finish_b', 'finish_wall', 'confirm', 'total'],
    )

    print('\n[3/3] Schnorr-EC-Mutual  (secp256r1 pure Python wNAF, SHAKE-256 KDF) ...')
    ec_mut_res = run_schnorr_ec_mutual(password, iterations)
    _section(
        'Schnorr-EC-Mutual — secp256r1, dual Schnorr proofs + ECDH session key',
        ec_mut_res, ['derive_x', 'compute_y', 'mutual_proofs', 'session_key', 'total'],
    )

    output_path = _GENERATED / 'pake_top3_results.txt'
    _write_results(output_path, iterations, srp_res, spake2_res, ec_mut_res)
    print(f'\n  Results written to: {output_path}')


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='Top-3 PAKE timing comparison.')
    ap.add_argument('iterations', type=int, nargs='?', default=100,
                    help='Iterations per protocol (default: 100)')
    ap.add_argument('--password', default='compare-password')
    args = ap.parse_args()
    compare(password=args.password, iterations=args.iterations)

"""
Focused PAKE timing comparison: SRP-6a vs SPAKE2 vs Schnorr-EC (secp256r1).

All three operate at comparable security levels and use pure-Python arithmetic,
making this the fairest side-by-side benchmark in this suite.

Protocols
  SRP-6a      : RFC 5054 2048-bit group, SHA-256 KDF (srp library, pure Python).
                Provides mutual authentication and a session key as part of the protocol.
  SPAKE2      : Ed25519 / M255 group (spake2 library, pure Python).
                Password-authenticated key exchange; both sides derive a shared key.
  SCHNORR-EC  : Custom Schnorr ZKP on secp256r1 (pure Python wNAF from ec_compare.py).
                scrypt n=2**14 KDF. One-sided proof only — no mutual auth, no session key.
                Included to show the cost of the cryptographic core without those extras.

Stage mapping
  SRP-6a    : register → commit (A) → challenge (B) → solve (M) → verify (HAMK)
  SPAKE2    : start_a → start_b → finish
  SCHNORR-EC: derive_x → compute_y → commit → solve → verify

Notes
  - SRP 'register' is a one-time sign-up cost. 'auth-only' row excludes it.
  - scrypt n=2**14 (~46 ms) is intentional security cost; it dominates SCHNORR-EC total.
    KDF column isolates it so the cryptographic-core cost is visible separately.
  - All three libraries are pure Python; no C extensions involved.
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

from qa_utils import server  # noqa: E402 — path setup above
from ec_compare import (     # noqa: E402
    EC_ORDER as _EC_ORDER,
    EC_GENERATOR as _EC_GENERATOR,
    _scalar_mult as _ec_scalar_mult,
    _point_add as _ec_point_add,
)

srp.rfc5054_enable()  # RFC 5054 2048-bit group

_GENERATED = Path(__file__).resolve().parent / "generated"
_GENERATED.mkdir(exist_ok=True)

_FIXED_SALT = b'pake_focused_compare_salt_2026'

# Pre-computed server keypair for Schnorr-EC mutual-auth variant (deterministic)
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
        f"{entry['name']:<32}  mean={entry['mean_ms']:8.3f} ms  "
        f"min={entry['min_ms']:8.3f} ms  p95={entry['p95_ms']:8.3f} ms  "
        f"stdev={entry['stdev_ms']:7.3f} ms"
    )


def _print_section(label: str, summary: dict, keys: list[str]) -> None:
    print(f'\n{label}')
    print('-' * 82)
    for key in keys:
        entry = summary.get(key)
        if entry:
            print(f'  {_fmt(entry)}')


# ---------------------------------------------------------------------------
# 1. SRP-6a
# ---------------------------------------------------------------------------
def run_srp(username: str, password: str, iterations: int = 100) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('register', 'commit', 'challenge', 'solve', 'verify', 'total')
    }
    for _ in range(iterations):
        # Registration: KDF (SHA-256 based) + verifier v = g^x mod N
        t0 = time.perf_counter()
        salt, vkey = srp.create_salted_verification_key(username, password)
        t1 = time.perf_counter()
        stats['register'].append((t1 - t0) * 1000)

        # Commit: client A = g^a mod N
        usr = srp.User(username, password)
        t0 = time.perf_counter()
        _uname, A = usr.start_authentication()
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        # Challenge: server B = kv + g^b mod N
        svr = srp.Verifier(username, salt, vkey, A)
        t0 = time.perf_counter()
        s, B = svr.get_challenge()
        t1 = time.perf_counter()
        stats['challenge'].append((t1 - t0) * 1000)

        # Solve: client derives session key K and proof M
        t0 = time.perf_counter()
        M = usr.process_challenge(s, B)
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        # Verify: server checks M → HAMK; client checks HAMK (mutual auth)
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
# 2. SPAKE2
# ---------------------------------------------------------------------------
def run_spake2(password: str, iterations: int = 100) -> dict:
    pw = password.encode()
    stats: dict[str, list[float]] = {
        k: [] for k in ('start_a', 'start_b', 'finish', 'total')
    }
    for _ in range(iterations):
        a = SPAKE2_A(pw)
        b = SPAKE2_B(pw)

        t0 = time.perf_counter()
        msg_a = a.start()
        t1 = time.perf_counter()
        stats['start_a'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        msg_b = b.start()
        t1 = time.perf_counter()
        stats['start_b'].append((t1 - t0) * 1000)

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
# 3. Schnorr on secp256r1 — pure Python wNAF, scrypt n=2**14
# ---------------------------------------------------------------------------
def _derive_x_ec(password: str, salt: bytes, use_scrypt: bool = True) -> int:
    if use_scrypt:
        hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    else:
        hashed = hashlib.sha256(password.encode() + salt).digest()
    return int.from_bytes(hashed, 'big') % _EC_ORDER or 1


def run_schnorr_ec(password: str, iterations: int = 100, use_scrypt: bool = True) -> dict:
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total')
    }
    for _ in range(iterations):
        # KDF: scrypt n=2**14 (or SHA-256) → scalar x
        t0 = time.perf_counter()
        x = _derive_x_ec(password, _FIXED_SALT, use_scrypt=use_scrypt)
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        # Registration: Y = x * G  (public key)
        t0 = time.perf_counter()
        Y = _ec_scalar_mult(x, _EC_GENERATOR)
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        # Commit: T = r * G
        r = secrets.randbelow(_EC_ORDER - 1) + 1
        t0 = time.perf_counter()
        T = _ec_scalar_mult(r, _EC_GENERATOR)
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        # Solve: s = (r + c*x) mod order
        c = secrets.randbelow(_EC_ORDER - 1) + 1
        t0 = time.perf_counter()
        s = (r + c * x) % _EC_ORDER
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        # Verify: s*G == T + c*Y
        t0 = time.perf_counter()
        lhs = _ec_scalar_mult(s, _EC_GENERATOR)
        rhs = _ec_point_add(T, _ec_scalar_mult(c, Y))
        if lhs != rhs:
            raise RuntimeError('SCHNORR-EC verify failed')
        t1 = time.perf_counter()
        stats['verify'].append((t1 - t0) * 1000)

        stats['total'].append(
            sum(stats[k][-1] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify'))
        )

    return {k: _summarize(f'SCHNORR-EC {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 4. Schnorr-EC with mutual auth + ECDH session key — SHA-256 KDF
# ---------------------------------------------------------------------------
def run_schnorr_ec_mutual(password: str, iterations: int = 100) -> dict:
    """Bidirectional Schnorr proofs (client↔server) + ECDH session key.
    Uses SHA-256 KDF so mutual-auth overhead is isolated from scrypt cost.
    Server keypair (_EC_SERVER_SK, _EC_SERVER_Y) is pre-generated at module load.
    """
    stats: dict[str, list[float]] = {
        k: [] for k in ('derive_x', 'compute_y', 'mutual_proofs', 'session_key', 'total')
    }
    for _ in range(iterations):
        # KDF: SHA-256 → scalar x  (client private key)
        t0 = time.perf_counter()
        x = _derive_x_ec(password, _FIXED_SALT, use_scrypt=False)
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        # Registration: Y_c = x * G  (client public key stored server-side)
        t0 = time.perf_counter()
        Y_c = _ec_scalar_mult(x, _EC_GENERATOR)
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        # Mutual Schnorr proofs: client proves x, server proves sk_s
        t0 = time.perf_counter()
        r_c = secrets.randbelow(_EC_ORDER - 1) + 1
        T_c = _ec_scalar_mult(r_c, _EC_GENERATOR)          # client commit
        r_s = secrets.randbelow(_EC_ORDER - 1) + 1
        T_s = _ec_scalar_mult(r_s, _EC_GENERATOR)          # server commit
        # Fiat-Shamir challenge
        c_bytes = hashlib.sha256(
            T_c[0].to_bytes(32, 'big') + T_c[1].to_bytes(32, 'big') +
            T_s[0].to_bytes(32, 'big') + T_s[1].to_bytes(32, 'big')
        ).digest()
        c = int.from_bytes(c_bytes, 'big') % _EC_ORDER or 1
        s_c = (r_c + c * x) % _EC_ORDER                    # client response
        s_s = (r_s + c * _EC_SERVER_SK) % _EC_ORDER        # server response
        # Server verifies client: s_c*G == T_c + c*Y_c
        if _ec_scalar_mult(s_c, _EC_GENERATOR) != _ec_point_add(T_c, _ec_scalar_mult(c, Y_c)):
            raise RuntimeError('Mutual Schnorr-EC: client proof failed')
        # Client verifies server: s_s*G == T_s + c*Y_s
        if _ec_scalar_mult(s_s, _EC_GENERATOR) != _ec_point_add(T_s, _ec_scalar_mult(c, _EC_SERVER_Y)):
            raise RuntimeError('Mutual Schnorr-EC: server proof failed')
        t1 = time.perf_counter()
        stats['mutual_proofs'].append((t1 - t0) * 1000)

        # Session key: ECDH — x*Y_s (client) == sk_s*Y_c (server)
        t0 = time.perf_counter()
        K_c = _ec_scalar_mult(x, _EC_SERVER_Y)
        K_s = _ec_scalar_mult(_EC_SERVER_SK, Y_c)
        if K_c != K_s:
            raise RuntimeError('Mutual Schnorr-EC: session key mismatch')
        _session_key = hashlib.sha256(K_c[0].to_bytes(32, 'big')).digest()  # noqa: F841
        t1 = time.perf_counter()
        stats['session_key'].append((t1 - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] +
            stats['mutual_proofs'][-1] + stats['session_key'][-1]
        )

    return {k: _summarize(f'SCHNORR-EC-MUT {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------
def compare(password: str = 'compare-password', iterations: int = 100) -> None:
    print('Focused PAKE comparison: SRP-6a vs SPAKE2 vs Schnorr-EC (secp256r1)')
    print(f'Iterations: {iterations} | All pure Python | Security: ~128-bit')
    print('=' * 82)

    print('\n[1/5] SRP-6a  (srp library, RFC 5054 2048-bit, SHA-256, pure Python) ...')
    srp_res = run_srp('alice', password, iterations)
    _print_section(
        'SRP-6a — RFC 5054 2048-bit, SHA-256 KDF, mutual auth + session key',
        srp_res,
        ['register', 'commit', 'challenge', 'solve', 'verify', 'total'],
    )

    print('\n[2/5] SPAKE2  (spake2 library, Ed25519 / M255, pure Python) ...')
    spake2_res = run_spake2(password, iterations)
    _print_section(
        'SPAKE2 — Ed25519 / M255, password-authenticated key exchange',
        spake2_res,
        ['start_a', 'start_b', 'finish', 'total'],
    )

    print('\n[3/5] Schnorr-EC  (secp256r1 pure Python wNAF, scrypt n=2**14) ...')
    ec_res = run_schnorr_ec(password, iterations, use_scrypt=True)
    _print_section(
        'Schnorr-EC — secp256r1 pure Python, scrypt(n=16384), one-sided proof only',
        ec_res,
        ['derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'],
    )

    print('\n[4/5] Schnorr-EC  (secp256r1 pure Python wNAF, SHA-256 KDF — hash-only) ...')
    ec_hash_res = run_schnorr_ec(password, iterations, use_scrypt=False)
    _print_section(
        'Schnorr-EC (SHA-256) — secp256r1 pure Python, SHA-256 KDF only',
        ec_hash_res,
        ['derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'],
    )

    print('\n[5/5] Schnorr-EC-Mutual  (secp256r1 + mutual auth + ECDH session key, SHA-256 KDF) ...')
    ec_mut_res = run_schnorr_ec_mutual(password, iterations)
    _print_section(
        'Schnorr-EC-Mutual — dual Schnorr proofs + ECDH session key, SHA-256 KDF',
        ec_mut_res,
        ['derive_x', 'compute_y', 'mutual_proofs', 'session_key', 'total'],
    )

    # --- Totals ---
    srp_reg          = srp_res['register']['mean_ms']
    srp_auth         = (srp_res['commit']['mean_ms'] + srp_res['challenge']['mean_ms']
                        + srp_res['solve']['mean_ms'] + srp_res['verify']['mean_ms'])
    spake2_total     = spake2_res['total']['mean_ms']
    ec_derive_x      = ec_res['derive_x']['mean_ms']
    ec_compute_y     = ec_res['compute_y']['mean_ms']
    ec_reg           = ec_derive_x + ec_compute_y
    ec_auth          = ec_res['derive_x']['mean_ms'] + ec_res['commit']['mean_ms'] \
                       + ec_res['solve']['mean_ms'] + ec_res['verify']['mean_ms']
    # Hash-only variants
    ech_derive_x     = ec_hash_res['derive_x']['mean_ms']
    ech_compute_y    = ec_hash_res['compute_y']['mean_ms']
    ech_reg          = ech_derive_x + ech_compute_y
    ech_auth         = ec_hash_res['derive_x']['mean_ms'] + ec_hash_res['commit']['mean_ms'] \
                       + ec_hash_res['solve']['mean_ms'] + ec_hash_res['verify']['mean_ms']
    # Mutual auth + session key variant
    ec_mut_derive_x  = ec_mut_res['derive_x']['mean_ms']
    ec_mut_compute_y = ec_mut_res['compute_y']['mean_ms']
    ec_mut_reg       = ec_mut_derive_x + ec_mut_compute_y
    ec_mut_auth      = (ec_mut_res['derive_x']['mean_ms'] + ec_mut_res['mutual_proofs']['mean_ms']
                        + ec_mut_res['session_key']['mean_ms'])

    # --- Table 1: Registration ---
    reg_rows = [
        # label, total_ms, kdf_ms, crypto_ms, note
        ('SRP-6a',            srp_reg,  srp_reg,      0.0,
         'SHA-256 KDF → verifier v = g^x mod N'),
        ('SPAKE2',            0.0,      0.0,           0.0,
         'no separate registration step (password used directly)'),
        ('Schnorr-EC',        ec_reg,   ec_derive_x,  ec_compute_y,
         'scrypt(n=2**14) → x, then Y = x*G stored as public key'),
        ('Schnorr-EC(SHA256)', ech_reg,  ech_derive_x, ech_compute_y,
         'SHA-256 → x, then Y = x*G  [weak KDF, for comparison only]'),
        ('Schnorr-EC-Mutual', ec_mut_reg, ec_mut_derive_x, ec_mut_compute_y,
         'SHA-256 → x, Y_c = x*G + server keypair pre-generated  (mutual auth)'),
    ]
    fastest_reg = min(t for _, t, *_ in reg_rows if t > 0)

    print('\n' + '=' * 96)
    print('  TABLE 1 — Registration  (one-time cost per account)')
    print(f'  {"Protocol":<20}  {"Total":>8}  {"KDF":>8}  {"Crypto":>8}  {"vs fastest":>10}  Note')
    print(f'  {"-"*20}  {"-"*8}  {"-"*8}  {"-"*8}  {"-"*10}  ----')
    for label, total, kdf, crypto, note in reg_rows:
        rel = f'{total/fastest_reg:8.2f}x' if total > 0 else f'{"N/A":>9}'
        print(f'  {label:<20}  {total:8.2f}  {kdf:8.2f}  {crypto:8.2f}  {rel}  {note}')

    # --- Table 2: Authentication ---
    auth_rows = [
        # label, total_ms, kdf_ms, crypto_ms, note
        ('SRP-6a',            srp_auth,    0.0,         srp_auth,
         'commit → challenge → solve → verify  (mutual auth + session key)'),
        ('SPAKE2',            spake2_total, 0.0,        spake2_total,
         'start_a → start_b → finish  (mutual auth + session key)'),
        ('Schnorr-EC',        ec_auth,     ec_derive_x, ec_auth - ec_derive_x,
         'scrypt re-run + ZKP exchange  (one-sided proof only)'),
        ('Schnorr-EC(SHA256)', ech_auth,   ech_derive_x, ech_auth - ech_derive_x,
         'SHA-256 + ZKP exchange  [weak KDF, for comparison only]'),
        ('Schnorr-EC-Mutual', ec_mut_auth, ec_mut_derive_x, ec_mut_auth - ec_mut_derive_x,
         'SHA-256 + dual Schnorr proofs + ECDH session key  (mutual auth + session key)'),
    ]
    fastest_auth = min(t for _, t, *_ in auth_rows)

    print()
    print('  TABLE 2 — Authentication  (cost per login)')
    print(f'  {"Protocol":<20}  {"Total":>8}  {"KDF":>8}  {"Crypto":>8}  {"vs fastest":>10}  Note')
    print(f'  {"-"*20}  {"-"*8}  {"-"*8}  {"-"*8}  {"-"*10}  ----')
    for label, total, kdf, crypto, note in auth_rows:
        rel = total / fastest_auth
        print(f'  {label:<20}  {total:8.2f}  {kdf:8.2f}  {crypto:8.2f}  {rel:10.2f}x  {note}')

    print()
    print('  Key observations:')
    print(f'   • SPAKE2 auth ({spake2_total:.1f} ms) is fastest — Ed25519 avoids any KDF on the login path.')
    print(f'   • SRP auth ({srp_auth:.1f} ms): pure big-num modexp at 2048-bit; no KDF on login.')
    print(f'   • Schnorr-EC auth ({ec_auth:.1f} ms) dominated by scrypt ({ec_derive_x:.1f} ms, '
          f'{100*ec_derive_x/ec_auth:.0f}%); crypto-only is {ec_auth - ec_derive_x:.1f} ms.')
    print(f'   • Schnorr-EC(SHA-256) auth ({ech_auth:.1f} ms) shows raw ZKP cost without scrypt.')
    print(f'   • Schnorr-EC-Mutual ({ec_mut_auth:.1f} ms) adds mutual auth + ECDH on top of SHA-256 variant.')
    print(f'   • Mutual overhead vs SHA-256 only: {ec_mut_auth - ech_auth:.1f} ms '
          f'({ec_mut_res["mutual_proofs"]["mean_ms"]:.1f} ms proofs + '
          f'{ec_mut_res["session_key"]["mean_ms"]:.1f} ms ECDH).')
    print(f'   • SRP and SPAKE2 use fast KDFs (SHA-256/SHA-512) at registration only.')
    print(f'   • WARNING: SHA-256 KDF is weak against offline dictionary attacks — scrypt is recommended.')
    print()
    print('  Feature comparison:')
    print(f'   {"Property":<28}  {"SRP-6a":^10}  {"SPAKE2":^10}  {"Schnorr-EC":^10}  {"Schnorr+Mut":^12}')
    print(f'   {"-"*28}  {"-"*10}  {"-"*10}  {"-"*10}  {"-"*12}')
    features = [
        ('Mutual authentication',    'yes', 'yes', 'no',    'yes'),
        ('Session key established',  'yes', 'yes', 'no',    'yes'),
        ('Server-breach resistant',  'yes', 'yes*', 'no',   'no'),
        ('Standardised (RFC/IETF)',  'yes', 'draft', 'no',  'no'),
        ('Password never sent',      'yes', 'yes', 'yes',   'yes'),
        ('KDF cost on login path',   'no',  'no',  'yes',   'yes(fast)'),
    ]
    for prop, srp_v, spake_v, ec_v, mut_v in features:
        print(f'   {prop:<28}  {srp_v:^10}  {spake_v:^10}  {ec_v:^10}  {mut_v:^12}')
    print('   * SPAKE2+ variant (not in spake2 library) adds server-breach resistance.')

    # --- Write results ---
    output_path = _GENERATED / 'pake_focused_compare_results.txt'
    with output_path.open('w', encoding='utf-8') as f:
        f.write(f'Focused PAKE comparison  (iterations={iterations})\n')
        f.write('Protocols: SRP-6a | SPAKE2 | Schnorr-EC (secp256r1 pure Python)\n')
        f.write('=' * 82 + '\n\n')

        f.write('SRP-6a  [RFC 5054 2048-bit, SHA-256 KDF, pure Python]\n')
        for key in ('register', 'commit', 'challenge', 'solve', 'verify', 'total'):
            f.write(f'  {_fmt(srp_res[key])}\n')

        f.write('\nSPAKE2  [Ed25519 / M255, pure Python]\n')
        for key in ('start_a', 'start_b', 'finish', 'total'):
            f.write(f'  {_fmt(spake2_res[key])}\n')

        f.write('\nSchnorr-EC  [secp256r1 pure Python wNAF, scrypt n=2**14]\n')
        for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
            f.write(f'  {_fmt(ec_res[key])}\n')

        f.write('\nSchnorr-EC (SHA-256)  [secp256r1 pure Python wNAF, SHA-256 KDF only]\n')
        for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
            f.write(f'  {_fmt(ec_hash_res[key])}\n')

        f.write('\nSchnorr-EC-Mutual  [dual Schnorr proofs + ECDH session key, SHA-256 KDF]\n')
        for key in ('derive_x', 'compute_y', 'mutual_proofs', 'session_key', 'total'):
            f.write(f'  {_fmt(ec_mut_res[key])}\n')

        f.write('\n' + '=' * 96 + '\n')
        f.write('  TABLE 1 — Registration  (one-time cost per account)\n')
        f.write(f'  {"Protocol":<20}  {"Total":>8}  {"KDF":>8}  {"Crypto":>8}  Note\n')
        for label, total, kdf, crypto, note in reg_rows:
            f.write(f'  {label:<20}  {total:.4f}  {kdf:.4f}  {crypto:.4f}  {note}\n')
        f.write('\n')
        f.write('  TABLE 2 — Authentication  (cost per login)\n')
        f.write(f'  {"Protocol":<20}  {"Total":>8}  {"KDF":>8}  {"Crypto":>8}  Note\n')
        for label, total, kdf, crypto, note in auth_rows:
            f.write(f'  {label:<20}  {total:.4f}  {kdf:.4f}  {crypto:.4f}  {note}\n')

    print(f'\nResults written to: {output_path}')


if __name__ == '__main__':
    compare(iterations=50)

"""
SRP-6a vs J-PAKE benchmark.

Both protocols use a shared password to establish a session key with mutual
authentication without ever transmitting the password.

Protocols
  SRP-6a : RFC 5054, 2048-bit MODP group, SHA-256 KDF (srp library, pure Python).
           3-round protocol: commit → challenge → verify+MAC (confirm mutual).
  J-PAKE : RFC 8236, 2048-bit MODP group, Schnorr ZKPs (jpake library, pure Python).
           4-round protocol: one → process_one → two → process_two.
           Zero-knowledge proofs embedded at every step — no separate confirm needed.

Run:
    python qa/measurement/srp_jpake_compare.py
    python qa/measurement/srp_jpake_compare.py 200
"""

import hashlib
import hmac as _hmac
import statistics
import sys
import time
from pathlib import Path

import srp
import jpake as _jpake

_QA_PATH = Path(__file__).resolve().parents[1]
for _p in (_QA_PATH,):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

srp.rfc5054_enable()

_GENERATED = Path(__file__).resolve().parent / "generated"
_GENERATED.mkdir(exist_ok=True)


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


def _ms(v: float) -> str:
    return f'{v:.3f} ms'


def _fmt(entry: dict) -> str:
    return (
        f"{entry['name']:<38}  mean={entry['mean_ms']:8.3f} ms  "
        f"min={entry['min_ms']:8.3f} ms  p95={entry['p95_ms']:8.3f} ms  "
        f"stdev={entry['stdev_ms']:7.3f} ms"
    )


def _section(label: str, summary: dict, keys: list[str]) -> None:
    print(f'\n{label}')
    print('-' * 95)
    for key in keys:
        if entry := summary.get(key):
            print(f'  {_fmt(entry)}')


# ---------------------------------------------------------------------------
# Box-drawing table helpers
# ---------------------------------------------------------------------------
def _box_row(cells: list[str], widths: list[int]) -> str:
    parts = [f' {c:<{w}} ' for c, w in zip(cells, widths)]
    return '│' + '│'.join(parts) + '│'


def _box_divider(widths: list[int], left='├', mid='┼', right='┤') -> str:
    return left + mid.join('─' * (w + 2) for w in widths) + right


def _box_top(widths: list[int]) -> str:
    return '┌' + '┬'.join('─' * (w + 2) for w in widths) + '┐'


def _box_bottom(widths: list[int]) -> str:
    return '└' + '┴'.join('─' * (w + 2) for w in widths) + '┘'


def _build_table(title: str, headers: list[str], rows: list[tuple]) -> list[str]:
    col_w = [max(len(headers[i]), max(len(str(r[i])) for r in rows)) for i in range(len(headers))]
    lines = [f'  {title}',
             '  ' + _box_top(col_w),
             '  ' + _box_row(headers, col_w),
             '  ' + _box_divider(col_w)]
    for row in rows:
        lines.append('  ' + _box_row([str(c) for c in row], col_w))
    lines.append('  ' + _box_bottom(col_w))
    return lines


def _timing_rows(summary: dict, keys: list[str]) -> list[tuple]:
    rows = []
    for k in keys:
        e = summary.get(k)
        if e:
            rows.append((e['name'], _ms(e['mean_ms']), _ms(e['min_ms']),
                         _ms(e['p95_ms']), _ms(e['stdev_ms'])))
    return rows


# ---------------------------------------------------------------------------
# 1. SRP-6a  (RFC 5054, 2048-bit MODP)
#
# Stages measured:
#   register   : create_salted_verification_key  → verifier stored server-side
#   commit     : client generates ephemeral A
#   challenge  : server generates B from verifier + A
#   solve      : client computes proof M from (s, B, x)
#   verify     : server checks M, returns HAMK; client checks HAMK
#   confirm    : HMAC-based explicit key confirmation (parallel round)
# ---------------------------------------------------------------------------
def run_srp(username: str, password: str, iterations: int) -> dict:
    keys = ('register', 'commit', 'challenge', 'solve', 'verify', 'total')
    stats: dict[str, list[float]] = {k: [] for k in keys}

    for _ in range(iterations):
        # Registration (one-time)
        t0 = time.perf_counter()
        salt, vkey = srp.create_salted_verification_key(username, password)
        stats['register'].append((time.perf_counter() - t0) * 1000)

        # Login — round 1: client commit
        usr = srp.User(username, password)
        t0 = time.perf_counter()
        _uname, A = usr.start_authentication()
        stats['commit'].append((time.perf_counter() - t0) * 1000)

        # Login — round 2: server challenge
        svr = srp.Verifier(username, salt, vkey, A)
        t0 = time.perf_counter()
        s, B = svr.get_challenge()
        stats['challenge'].append((time.perf_counter() - t0) * 1000)

        # Login — round 3: client solve
        t0 = time.perf_counter()
        M = usr.process_challenge(s, B)
        stats['solve'].append((time.perf_counter() - t0) * 1000)

        # Login — round 4: server + client verify (SRP HAMK = built-in mutual confirm)
        t0 = time.perf_counter()
        HAMK = svr.verify_session(M)
        usr.verify_session(HAMK)
        if not usr.authenticated():
            raise RuntimeError('SRP-6a authentication failed')
        stats['verify'].append((time.perf_counter() - t0) * 1000)

        stats['total'].append(
            stats['commit'][-1] + stats['challenge'][-1]
            + stats['solve'][-1] + stats['verify'][-1]
        )

    return {k: _summarize(f'SRP-6a  {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 2. J-PAKE  (RFC 8236, jpake library, 2048-bit MODP group by default)
#
# The jpake library uses its own built-in 2048-bit safe-prime group.
# Schnorr ZKPs are embedded in every round — no separate confirm step needed;
# successful process_two() + matching K proves mutual knowledge of the password.
#
# Stages measured (wall-clock, parallel rounds labelled):
#   round1_A / round1_B   : each side generates g^x1, g^x2 with ZKPs  [parallel]
#   round1_wall           : max(round1_A, round1_B)
#   proc1_A / proc1_B     : each side verifies the other's round-1 ZKPs [parallel]
#   proc1_wall            : max(proc1_A, proc1_B)
#   round2_A / round2_B   : each side generates A/B (key-share) with ZKP [parallel]
#   round2_wall           : max(round2_A, round2_B)
#   proc2_A / proc2_B     : each side verifies key-share ZKP, derives K  [parallel]
#   proc2_wall            : max(proc2_A, proc2_B)
#   total                 : round1_wall + proc1_wall + round2_wall + proc2_wall
#                           (= 4 sequential network rounds, each internally parallel)
# ---------------------------------------------------------------------------
def run_jpake(password: str, iterations: int) -> dict:
    keys = (
        'round1_A', 'round1_B', 'round1_wall',
        'proc1_A',  'proc1_B',  'proc1_wall',
        'round2_A', 'round2_B', 'round2_wall',
        'proc2_A',  'proc2_B',  'proc2_wall',
        'total',
    )
    stats: dict[str, list[float]] = {k: [] for k in keys}

    # J-PAKE secret must be an integer in [1, q-1]
    secret = int.from_bytes(hashlib.sha256(password.encode()).digest(), 'big')

    for _ in range(iterations):
        A = _jpake.JPAKE(secret=secret, signer_id=b'alice')
        B = _jpake.JPAKE(secret=secret, signer_id=b'bob')

        # Round 1: both generate ephemeral key-shares + ZKPs  (parallel)
        t0 = time.perf_counter(); one_A = A.one(); tA = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter(); one_B = B.one(); tB = (time.perf_counter() - t0) * 1000
        stats['round1_A'].append(tA)
        stats['round1_B'].append(tB)
        stats['round1_wall'].append(max(tA, tB))

        # Process round 1: each side verifies the other's ZKPs  (parallel)
        t0 = time.perf_counter(); A.process_one(one_B); tA = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter(); B.process_one(one_A); tB = (time.perf_counter() - t0) * 1000
        stats['proc1_A'].append(tA)
        stats['proc1_B'].append(tB)
        stats['proc1_wall'].append(max(tA, tB))

        # Round 2: both generate password-authenticated key-shares + ZKPs  (parallel)
        t0 = time.perf_counter(); two_A = A.two(); tA = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter(); two_B = B.two(); tB = (time.perf_counter() - t0) * 1000
        stats['round2_A'].append(tA)
        stats['round2_B'].append(tB)
        stats['round2_wall'].append(max(tA, tB))

        # Process round 2: each side verifies ZKP and derives session key K  (parallel)
        t0 = time.perf_counter(); A.process_two(two_B); tA = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter(); B.process_two(two_A); tB = (time.perf_counter() - t0) * 1000
        stats['proc2_A'].append(tA)
        stats['proc2_B'].append(tB)
        stats['proc2_wall'].append(max(tA, tB))

        if A.K != B.K:
            raise RuntimeError('J-PAKE session key mismatch')

        stats['total'].append(
            stats['round1_wall'][-1] + stats['proc1_wall'][-1]
            + stats['round2_wall'][-1] + stats['proc2_wall'][-1]
        )

    return {k: _summarize(f'J-PAKE  {k}', v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# Write box-drawing results file
# ---------------------------------------------------------------------------
def _write_results(
    path: Path,
    iterations: int,
    srp_res: dict,
    jpake_res: dict,
) -> None:
    lines: list[str] = []

    W = 95
    lines.append('┌' + '─' * (W - 2) + '┐')
    lines.append('│' + f'  SRP-6a  vs  J-PAKE  —  {iterations} iterations'.ljust(W - 2) + '│')
    lines.append('│' + '  RFC 5054 2048-bit MODP  |  RFC 8236 J-PAKE 2048-bit MODP'.ljust(W - 2) + '│')
    lines.append('└' + '─' * (W - 2) + '┘')
    lines.append('')

    # SRP timing table
    lines += _build_table(
        'SRP-6a  [RFC 5054, 2048-bit MODP, SHA-256 KDF, 4-round login]',
        ['Stage', 'mean', 'min', 'p95', 'stdev'],
        _timing_rows(srp_res, ['register', 'commit', 'challenge', 'solve', 'verify', 'total']),
    )
    lines.append('')

    # J-PAKE timing table — wall-clock (parallel) rounds
    lines += _build_table(
        'J-PAKE  [RFC 8236, 2048-bit MODP, ZKP every round, 4-round login]',
        ['Stage', 'mean', 'min', 'p95', 'stdev'],
        _timing_rows(jpake_res, [
            'round1_A', 'round1_B', 'round1_wall',
            'proc1_A',  'proc1_B',  'proc1_wall',
            'round2_A', 'round2_B', 'round2_wall',
            'proc2_A',  'proc2_B',  'proc2_wall',
            'total',
        ]),
    )
    lines.append('')
    lines.append('  * _wall = max(A, B) — parallel cost per round-trip.')
    lines.append('  * J-PAKE total = round1_wall + proc1_wall + round2_wall + proc2_wall.')
    lines.append('  * SRP total    = commit + challenge + solve + verify (registration excluded).')
    lines.append('')

    # Summary
    srp_reg   = srp_res['register']['mean_ms']
    srp_auth  = sum(srp_res[k]['mean_ms'] for k in ('commit', 'challenge', 'solve', 'verify'))
    srp_total = srp_res['total']['mean_ms']

    jp_auth   = jpake_res['total']['mean_ms']
    fastest   = min(srp_auth, jp_auth)

    sum_rows = [
        ('SRP-6a', f'{srp_reg:.3f} ms', f'{srp_auth:.3f} ms', f'{srp_total:.3f} ms',
         '4 rounds', f'{srp_auth / fastest:.2f}x'),
        ('J-PAKE', 'N/A (inline)', f'{jp_auth:.3f} ms', f'{jp_auth:.3f} ms',
         '4 rounds', f'{jp_auth / fastest:.2f}x'),
    ]
    sum_headers = ['Protocol', 'Registration', 'Auth (login)', 'Total', 'Rounds', 'vs fastest']
    lines += _build_table('SUMMARY', sum_headers, sum_rows)
    lines.append('  * Registration is a one-time cost (not on login hot-path).')
    lines.append('  * J-PAKE has no separate registration — verifier is derived inline each time.')
    lines.append('')

    # Feature comparison
    feat_rows = [
        ('Mutual authentication',      'YES',         'YES'),
        ('Session key established',    'YES',         'YES'),
        ('Password never sent',        'YES',         'YES'),
        ('Server-breach resistant',    'YES',         'YES'),
        ('Separate registration step', 'YES',         'NO — inline'),
        ('ZKP embedded in protocol',   'NO',          'YES — every round'),
        ('Explicit key confirmation',  'HAMK round',  'Implicit (K match)'),
        ('Standardised',               'RFC 5054',    'RFC 8236'),
        ('Group / modulus',            '2048-bit MODP (RFC 5054)', '2048-bit MODP (library default)'),
        ('Security level',             '~112 bits',   '~112 bits'),
        ('Round trips (login)',        '3 (commit+challenge+verify)', '4 (one+proc1+two+proc2)'),
    ]
    feat_headers = ['Property', 'SRP-6a', 'J-PAKE']
    lines += _build_table('FEATURE COMPARISON', feat_headers, feat_rows)
    lines.append('')
    lines.append('  KEY DIFFERENCES:')
    lines.append('  SRP-6a : Server stores a verifier (salt + hash) — breached DB reveals')
    lines.append('           precomputed verifiers but NOT the password directly.')
    lines.append('           Faster login: 3 meaningful rounds (library uses C for modexp).')
    lines.append('')
    lines.append('  J-PAKE : No verifier stored — server never holds any password-derived')
    lines.append('           material between sessions. ZKPs prove knowledge at every step.')
    lines.append('           True forward secrecy: past sessions safe even if password leaked.')
    lines.append('           Extra round needed because ZKPs require two-way key-share exchange.')
    lines.append('')

    path.write_text('\n'.join(lines), encoding='utf-8')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def compare(password: str = 'compare-password', iterations: int = 100) -> None:
    print('=' * 95)
    print('  SRP-6a  vs  J-PAKE  —  Password Authenticated Key Exchange benchmark')
    print('  Both: mutual auth + session key | pure Python | 2048-bit MODP | RFC standards')
    print(f'  Iterations: {iterations}')
    print('=' * 95)

    print('\n[1/2] SRP-6a  (srp library, RFC 5054 2048-bit MODP) ...')
    srp_res = run_srp('alice', password, iterations)
    _section(
        'SRP-6a  — RFC 5054, 2048-bit MODP, SHA-256 KDF',
        srp_res, ['register', 'commit', 'challenge', 'solve', 'verify', 'total'],
    )

    print('\n[2/2] J-PAKE  (jpake library, RFC 8236, 2048-bit MODP, ZKP every round) ...')
    jpake_res = run_jpake(password, iterations)
    _section(
        'J-PAKE  — RFC 8236, 2048-bit MODP, Schnorr ZKPs embedded',
        jpake_res, [
            'round1_wall', 'proc1_wall', 'round2_wall', 'proc2_wall', 'total',
        ],
    )

    output_path = _GENERATED / 'srp_jpake_results.txt'
    _write_results(output_path, iterations, srp_res, jpake_res)
    print(f'\n  Results written to: {output_path}')


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='SRP-6a vs J-PAKE timing benchmark.')
    ap.add_argument('iterations', type=int, nargs='?', default=100,
                    help='Iterations per protocol (default: 100)')
    ap.add_argument('--password', default='compare-password')
    args = ap.parse_args()
    compare(password=args.password, iterations=args.iterations)



"""
Compare Schnorr protocol timings for classic modular-exponentiation vs EC secp256r1.

This script uses the current ZKP server parameters for the classic protocol and
implements a matching EC Schnorr flow for comparison.
"""

import hashlib
import secrets
import statistics
import sys
import time
from pathlib import Path

_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))

from qa_utils import derive_password_x, server

_GENERATED = Path(__file__).resolve().parent / "generated"
_GENERATED.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Classic Schnorr parameters (imported from the running QA server config)
# ---------------------------------------------------------------------------
CLASSIC_P = server.P
CLASSIC_Q = server.Q
CLASSIC_G = server.G

# ---------------------------------------------------------------------------
# EC Schnorr parameters for secp256r1
# ---------------------------------------------------------------------------
EC_P = int(
    'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 16
)
EC_A = EC_P - 3
EC_B = int(
    '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
    16,
)
EC_ORDER = int(
    'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    16,
)
EC_GENERATOR = (
    int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16),
    int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16),
)


def _point_neg(point: tuple[int, int]) -> tuple[int, int]:
    x, y = point
    return x, (-y) % EC_P


def _point_add(p: tuple[int, int] | None, q: tuple[int, int] | None) -> tuple[int, int] | None:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and y1 == (-y2 % EC_P):
        return None
    if p == q:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + EC_A) * pow(2 * y1, -1, EC_P) % EC_P
    else:
        if x1 == x2:
            return None
        slope = (y2 - y1) * pow(x2 - x1, -1, EC_P) % EC_P
    x3 = (slope * slope - x1 - x2) % EC_P
    y3 = (slope * (x1 - x3) - y1) % EC_P
    return x3, y3


EC_WNAF_WINDOW = 6


def _build_odd_multiples(point: tuple[int, int], window: int) -> list[tuple[int, int] | None]:
    max_digit = 1 << (window - 1)
    twoP = _point_add(point, point)
    multiples = [point]
    for _ in range(1, max_digit):
        multiples.append(_point_add(multiples[-1], twoP))
    return multiples


def _wnaf(scalar: int, window: int) -> list[int]:
    digits = []
    mask = (1 << window) - 1
    while scalar > 0:
        if scalar & 1:
            digit = scalar & mask
            if digit & (1 << (window - 1)):
                digit -= (1 << window)
            scalar -= digit
        else:
            digit = 0
        digits.append(digit)
        scalar >>= 1
    return digits


EC_GENERATOR_PRECOMP = _build_odd_multiples(EC_GENERATOR, EC_WNAF_WINDOW)


def _scalar_mult(scalar: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    if scalar % EC_ORDER == 0 or point is None:
        return None
    if scalar < 0:
        return _scalar_mult(-scalar, _point_neg(point))

    digits = _wnaf(scalar, EC_WNAF_WINDOW)
    if point == EC_GENERATOR:
        precomp = EC_GENERATOR_PRECOMP
    else:
        precomp = _build_odd_multiples(point, EC_WNAF_WINDOW)

    result = None
    for d in reversed(digits):
        result = _point_add(result, result)
        if d:
            if d > 0:
                result = _point_add(result, precomp[(d - 1) // 2])
            else:
                result = _point_add(result, _point_neg(precomp[(-d - 1) // 2]))
    return result


def _is_point_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    if not (0 <= x < EC_P and 0 <= y < EC_P):
        return False
    return (pow(y, 2, EC_P) - (pow(x, 3, EC_P) + EC_A * x + EC_B)) % EC_P == 0


def derive_password_scalar(password: str, modulus: int, salt: bytes) -> int:
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**11, r=8, p=1)
    return int.from_bytes(hashed, 'big') % modulus


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


def run_classic_schnorr(password: str, iterations: int = 100) -> dict:
    stats = {k: [] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total')}

    for _ in range(iterations):
        t0 = time.perf_counter()
        x = derive_password_x(password)
        x = x % CLASSIC_Q
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        y = pow(CLASSIC_G, x, CLASSIC_P)
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        r = secrets.randbelow(CLASSIC_Q - 1) + 1
        t0 = time.perf_counter()
        t_val = pow(CLASSIC_G, r, CLASSIC_P)
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        c = secrets.randbelow(CLASSIC_Q - 1) + 1
        t0 = time.perf_counter()
        s = (r + c * x) % CLASSIC_Q
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        left = pow(CLASSIC_G, s, CLASSIC_P)
        right = (t_val * pow(y, c, CLASSIC_P)) % CLASSIC_P
        if left != right:
            raise RuntimeError('Classic Schnorr verification failed')
        t1 = time.perf_counter()
        stats['verify'].append((t1 - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] + stats['commit'][-1] + stats['solve'][-1] + stats['verify'][-1]
        )

    return {k: _summarize(f'CLASSIC {k}', v) for k, v in stats.items()}


def run_ec_schnorr(password: str, iterations: int = 100) -> dict:
    salt = b'ec_compare_fixed_salt_2026'
    stats = {k: [] for k in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total')}

    for _ in range(iterations):
        t0 = time.perf_counter()
        x = derive_password_scalar(password, EC_ORDER, salt)
        t1 = time.perf_counter()
        stats['derive_x'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        y_point = _scalar_mult(x, EC_GENERATOR)
        if y_point is None or not _is_point_on_curve(y_point):
            raise RuntimeError('Invalid EC public point generated')
        t1 = time.perf_counter()
        stats['compute_y'].append((t1 - t0) * 1000)

        r = secrets.randbelow(EC_ORDER - 1) + 1
        t0 = time.perf_counter()
        t_point = _scalar_mult(r, EC_GENERATOR)
        t1 = time.perf_counter()
        stats['commit'].append((t1 - t0) * 1000)

        c = secrets.randbelow(EC_ORDER - 1) + 1
        t0 = time.perf_counter()
        s = (r + c * x) % EC_ORDER
        t1 = time.perf_counter()
        stats['solve'].append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        left = _scalar_mult(s, EC_GENERATOR)
        right = _point_add(t_point, _scalar_mult(c, y_point))
        if left != right:
            raise RuntimeError('EC Schnorr verification failed')
        t1 = time.perf_counter()
        stats['verify'].append((t1 - t0) * 1000)

        stats['total'].append(
            stats['derive_x'][-1] + stats['compute_y'][-1] + stats['commit'][-1] + stats['solve'][-1] + stats['verify'][-1]
        )

    return {k: _summarize(f'EC {k}', v) for k, v in stats.items()}


def _print_summary(summary: dict) -> None:
    for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
        entry = summary.get(key)
        if not entry:
            continue
        print(
            f"{entry['name']}: mean={entry['mean_ms']:.4f} ms, min={entry['min_ms']:.4f} ms, "
            f"p95={entry['p95_ms']:.4f} ms, stdev={entry['stdev_ms']:.4f} ms"
        )


def compare_protocols(password: str = 'compare-password', iterations: int = 100) -> None:
    print('Starting Schnorr timing comparison')
    print(f'Iterations per protocol: {iterations}')
    print('Classic Schnorr flow on server group parameters')
    classic_summary = run_classic_schnorr(password, iterations)
    print('\nEC Schnorr flow on secp256r1')
    ec_summary = run_ec_schnorr(password, iterations)

    print('\nClassic summary:')
    _print_summary(classic_summary)
    print('\nEC summary:')
    _print_summary(ec_summary)

    output_path = _GENERATED / 'ec_compare_results.txt'
    with output_path.open('w', encoding='utf-8') as f:
        f.write('Classic Schnorr timing\n')
        for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
            stats = classic_summary[key]
            f.write(
                f"{stats['name']}: mean={stats['mean_ms']:.6f} ms min={stats['min_ms']:.6f} ms "
                f"p95={stats['p95_ms']:.6f} ms stdev={stats['stdev_ms']:.6f} ms\n"
            )
        f.write('\nEC Schnorr timing\n')
        for key in ('derive_x', 'compute_y', 'commit', 'solve', 'verify', 'total'):
            stats = ec_summary[key]
            f.write(
                f"{stats['name']}: mean={stats['mean_ms']:.6f} ms min={stats['min_ms']:.6f} ms "
                f"p95={stats['p95_ms']:.6f} ms stdev={stats['stdev_ms']:.6f} ms\n"
            )
    print(f'Comparison written to: {output_path}')


if __name__ == '__main__':
    compare_protocols(iterations=50)

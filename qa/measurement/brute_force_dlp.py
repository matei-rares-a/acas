"""
brute_force_dlp.py — Discrete Logarithm Brute-Force
=========================================================
    Given (g, p, y = g^x mod p), recover x.

Strategy:
  Iterate x_try = 1, 2, 3, … computing g^x_try mod p incrementally
  Total tries are reported when each stage ends.

Escalation:
  Start with tiny safe primes where brute-force succeeds in milliseconds.
  Bit-size ladder: 8 -> 12 -> 16 -> 20 -> 24 -> 28 -> 32 -> 64 -> 128 bits,
  then the actual 1024-bit protocol prime as the final stage.
  All stage threads run in parallel.
  Safe-prime search uses sympy.isprime (deterministic).

"""

import hashlib
import threading
import time

from sympy import isprime

PROTOCOL_P = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579
PROTOCOL_G = 4  

PASSWORD = "my_secure_password"

#timeout in seconds.
TIMEOUT_PER_STAGE_S = 600



def _is_safe_prime(p: int) -> bool:
    # sympy.isprime uses BPSW (miller-rabin base 2 + Lucas) 
    return p > 4 and isprime(p) and isprime((p - 1) // 2)


def _next_safe_prime(start: int) -> int:
    p = start | 1  # make odd
    while not _is_safe_prime(p):
        p += 2
    return p


def _safe_prime_of_bits(bits: int) -> int:
    return _next_safe_prime(1 << (bits - 1))


def _find_generator(p: int) -> int:
    q = (p - 1) // 2
    for h in range(2, p - 1):
        g = pow(h, 2, p)
        if g != 1 and pow(g, q, p) == 1:
            return g
    raise RuntimeError(f"No generator found for p={p}")


def _derive_x(password: str, q: int) -> int:
    raw = int(hashlib.sha256(password.encode()).hexdigest(), 16) % q
    return raw if raw != 0 else 1


def _brute_force_worker(
    p: int,
    g: int,
    y: int,
    stop_event: threading.Event,
    result_holder: list,
) -> None:
    q = (p - 1) // 2
    g_pow = 1  # tracks g^x_try mod p; starts at g^0 = 1

    for x_try in range(1, q + 1):
        if stop_event.is_set():
            result_holder.append((None, x_try))  # (no solution, tries done before timeout)
            return

        g_pow = g_pow * g % p  # incremental: g^x_try = g^(x_try-1) * g

        if g_pow == y:
            result_holder.append((x_try, x_try))  # (solution, tries)
            return

    result_holder.append((None, q))  # exhausted entire search space



def run_demo() -> None:
    bit_sizes = [8, 12, 16, 20, 24, 28, 32, 64, 128]
    stages: list[tuple[str, int]] = []
    for bits in bit_sizes:
        p = _safe_prime_of_bits(bits)
        stages.append((f"{p.bit_length():>4}-bit", p))
    stages.append(("1024-bit (full protocol)", PROTOCOL_P))

    print()
    print("=" * 72)
    print("  DISCRETE LOGARITHM BRUTE-FORCE DEMO")
    print(f"  Password  : {PASSWORD!r}")
    print(f"  Attack    : iterate x = 1, 2, 3, ... checking  g^x mod p == y")
    print(f"  Progress  : total tries printed when each stage ends")
    print(f"  Threads   : all stages run in parallel")
    print(f"  Timeout   : {TIMEOUT_PER_STAGE_S}s shared deadline (timeout => infeasible)")
    print("=" * 72)

    stage_params = []
    for label, p in stages:
        q = (p - 1) // 2
        g = PROTOCOL_G if p == PROTOCOL_P else _find_generator(p)
        x = _derive_x(PASSWORD, q)
        y = pow(g, x, p)
        stage_params.append((label, p, q, g, x, y))

    print()
    active = []
    deadline = time.perf_counter() + TIMEOUT_PER_STAGE_S
    for label, p, q, g, x, y in stage_params:
        print(f"  +-- Stage: {label}")
        print(f"  |   p              = {p}")
        print(f"  |   g              = {g}")
        print(f"  |   y = g^x mod p  = {y}")
        print(f"  |   search space   = 2^{q.bit_length() - 1}  ({q:,} candidates)")
        print(f"  |   x (hidden)     = {x}")
        print(f"  +-- thread launched...")
        print()

        stop_event = threading.Event()
        result: list = []
        t_start = time.perf_counter()
        worker = threading.Thread(
            target=_brute_force_worker,
            args=(p, g, y, stop_event, result),
            daemon=True,
        )
        worker.start()
        active.append((label, p, g, x, y, q, t_start, stop_event, result, worker))

    print("  [all threads running -- collecting results...]")

    for label, p, g, x, y, q, t_start, stop_event, result, worker in active:
        remaining = max(0.0, deadline - time.perf_counter())
        worker.join(timeout=remaining)
        elapsed = time.perf_counter() - t_start

        print()
        print(f"  +-- Result: {label}")
        if worker.is_alive():
            stop_event.set()
            worker.join()
            tries = result[0][1] if result else 0
            print(f"      [{tries:,} tries -- timeout]")
            print(f"  -> Timed out after {elapsed * 1000:.1f} ms -- attack INFEASIBLE at this key size")
        elif result and result[0][0] is not None:
            x_found, tries = result[0]
            print(f"      [FOUND]  x = {x_found} after {tries:,} tries")
            print(f"  -> Attack SUCCEEDED in {elapsed * 1000:.3f} ms  (x = {x_found})")
            assert pow(g, x_found, p) == y, "BUG: verification of recovered x failed"
            print(f"  -> Verified: g^{x_found} mod p == y  [OK]")
        else:
            tries = result[0][1] if result else q
            print(f"      [FAIL]   search space exhausted after {tries:,} tries")
            print(f"  -> Full search space exhausted in {elapsed * 1000:.1f} ms -- x not found")


if __name__ == "__main__":
    run_demo()


'''  RESULTS

========================================================================
  DISCRETE LOGARITHM BRUTE-FORCE DEMO
  Password  : 'my_secure_password'
  Attack    : iterate x = 1, 2, 3, ... checking  g^x mod p == y
  Progress  : total tries printed when each stage ends
  Threads   : all stages run in parallel
  Timeout   : 600s shared deadline (timeout => infeasible)
========================================================================

  +-- Stage:    8-bit
  |   p              = 167
  |   g              = 4
  |   y = g^x mod p  = 48
  |   search space   = 2^6  (83 candidates)
  |   x (hidden)     = 26
  +-- thread launched...

  +-- Stage:   12-bit
  |   p              = 2063
  |   g              = 4
  |   y = g^x mod p  = 26
  |   search space   = 2^10  (1,031 candidates)
  |   x (hidden)     = 732
  +-- thread launched...

  +-- Stage:   16-bit
  |   p              = 32843
  |   g              = 4
  |   y = g^x mod p  = 14397
  |   search space   = 2^14  (16,421 candidates)
  |   x (hidden)     = 2356
  +-- thread launched...

  +-- Stage:   20-bit
  |   p              = 524387
  |   g              = 4
  |   y = g^x mod p  = 40507
  |   search space   = 2^18  (262,193 candidates)
  |   x (hidden)     = 2030
  +-- thread launched...

  +-- Stage:   24-bit
  |   p              = 8389163
  |   g              = 4
  |   y = g^x mod p  = 4407115
  |   search space   = 2^22  (4,194,581 candidates)
  |   x (hidden)     = 2891456
  +-- thread launched...

  +-- Stage:   28-bit
  |   p              = 134217827
  |   g              = 4
  |   y = g^x mod p  = 5146273
  |   search space   = 2^26  (67,108,913 candidates)
  |   x (hidden)     = 27455126
  +-- thread launched...

  +-- Stage:   32-bit
  |   p              = 2147483783
  |   g              = 4
  |   y = g^x mod p  = 881022919
  |   search space   = 2^30  (1,073,741,891 candidates)
  |   x (hidden)     = 744702253
  +-- thread launched...

  +-- Stage:   64-bit
  |   p              = 9223372036854778487
  |   g              = 4
  |   y = g^x mod p  = 3464087343133895889
  |   search space   = 2^62  (4,611,686,018,427,389,243 candidates)
  |   x (hidden)     = 1827948190754515988
  +-- thread launched...

  +-- Stage:  128-bit
  |   p              = 170141183460469231731687303715884114527
  |   g              = 4
  |   y = g^x mod p  = 60082740345373702405019323213284824609
  |   search space   = 2^126  (85,070,591,730,234,615,865,843,651,857,942,057,263 candidates)
  |   x (hidden)     = 9881994812226668511110993739465901343
  +-- thread launched...

  +-- Stage: 1024-bit (full protocol)
  |   p              = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579
  |   g              = 4
  |   y = g^x mod p  = 1087536136178018218585071290015562864680880776077076055897284930600130139328163223639904615665223972943052626720994884642733739101265991658697569319050249
  |   search space   = 2^510  (5,865,861,267,377,994,189,791,249,452,158,515,792,757,215,606,440,255,186,590,157,825,404,802,651,205,246,797,805,369,973,607,163,526,545,395,821,432,417,696,103,035,133,292,605,081,190,406,106,770,320,789 candidates)
  |   x (hidden)     = 20174833012342822590570076519384538984394342031405456827960163003816080524383
  +-- thread launched...

  [all threads running -- collecting results...]

  +-- Result:    8-bit
      [FOUND]  x = 26 after 26 tries
  -> Attack SUCCEEDED in 1819.096 ms  (x = 26)
  -> Verified: g^26 mod p == y  [OK]

  +-- Result:   12-bit
      [FOUND]  x = 732 after 732 tries
  -> Attack SUCCEEDED in 2165.972 ms  (x = 732)
  -> Verified: g^732 mod p == y  [OK]

  +-- Result:   16-bit
      [FOUND]  x = 2356 after 2,356 tries
  -> Attack SUCCEEDED in 2414.727 ms  (x = 2356)
  -> Verified: g^2356 mod p == y  [OK]

  +-- Result:   20-bit
      [FOUND]  x = 2030 after 2,030 tries
  -> Attack SUCCEEDED in 2930.272 ms  (x = 2030)
  -> Verified: g^2030 mod p == y  [OK]

  +-- Result:   24-bit
      [FOUND]  x = 2891456 after 2,891,456 tries
  -> Attack SUCCEEDED in 3212.259 ms  (x = 2891456)
  -> Verified: g^2891456 mod p == y  [OK]

  +-- Result:   28-bit
      [FOUND]  x = 27455126 after 27,455,126 tries
  -> Attack SUCCEEDED in 6990.731 ms  (x = 27455126)
  -> Verified: g^27455126 mod p == y  [OK]

  +-- Result:   32-bit
      [FOUND]  x = 744702253 after 744,702,253 tries
  -> Attack SUCCEEDED in 282747.737 ms  (x = 744702253)
  -> Verified: g^744702253 mod p == y  [OK]

  +-- Result:   64-bit
      [1,444,529,212 tries -- timeout]
  -> Timed out after 599295.4 ms -- attack INFEASIBLE at this key size

  +-- Result:  128-bit
      [1,306,246,020 tries -- timeout]
  -> Timed out after 599161.3 ms -- attack INFEASIBLE at this key size

  +-- Result: 1024-bit (full protocol)
      [884,634,079 tries -- timeout]
  -> Timed out after 598805.6 ms -- attack INFEASIBLE at this key size

  
    CONCLUSION
  - For small primes, brute-force recovers x in milliseconds.
  - Each extra bit doubles the search space.
  - The 1024-bit protocol prime has a search space of ~2^511 --
    larger than the number of atoms in the observable universe.
  - No classical computer can solve DLP at this size.

'''
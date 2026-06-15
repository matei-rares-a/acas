import csv
import re as _re
import secrets as secrets_module
import sys
import time
import timeit
import statistics
from pathlib import Path
from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs

import pytest

_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))

from qa_utils import (
    server, derive_password_x, pkce_challenge,
    OAUTH_PKCE_CLIENT_ID, OAUTH_SIMPLE_CLIENT_ID, OAUTH_REDIRECT_URI,
    AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI,
    OAuthTestSuite,
)

_GENERATED = Path(__file__).resolve().parent / "generated"
_GENERATED.mkdir(exist_ok=True)

from measurement_utils import setup_isolated_test_user


# ---------------------------------------------------------------------------
# CSV persistence helpers
# ---------------------------------------------------------------------------

def _oauth_authorize(c, prefix, client_id_param, redirect_uri, username, password,
                     code_challenge=None, code_challenge_method=None, scope="openid profile"):
    """Execute GET+POST authorize flow and return (code, ok).
    Mirrors the RFC 6749 browser redirect pattern used by the server.
    """
    qs = {"response_type": "code", "client_id": client_id_param,
          "redirect_uri": redirect_uri, "scope": scope}
    if code_challenge:
        qs["code_challenge"] = code_challenge
        qs["code_challenge_method"] = code_challenge_method or "S256"
    get_resp = c.get(f"/{prefix}/authorize", query_string=qs)
    if get_resp.status_code != 200:
        return None, False
    html = get_resp.data.decode("utf-8")
    m = _re.search(r'name="auth_request_id"\s+value="([^"]+)"', html)
    auth_req_id = m.group(1) if m else ""
    post_resp = c.post(
        f"/{prefix}/authorize",
        data={"auth_request_id": auth_req_id, "username": username, "password": password},
        follow_redirects=False,
    )
    if post_resp.status_code != 302:
        return None, False
    loc = post_resp.headers.get("Location", "")
    codes = _parse_qs(_urlparse(loc).query).get("code")
    return (codes[0] if codes else None), bool(codes)





def save_benchmark_csv(
    results: dict,
    path: str = str(_GENERATED / "benchmark_results.csv"),
) -> None:
    """Persist _benchmark_latency() results to CSV for generate_charts()."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["operation", "mean_ms", "min_ms", "max_ms", "p95_ms", "stdev_ms"]
        )
        writer.writeheader()
        for op, v in results.items():
            writer.writerow({
                "operation": op,
                "mean_ms":   round(v["mean"],         6),
                "min_ms":    round(v["min"],           6),
                "max_ms":    round(v["max"],           6),
                "p95_ms":    round(v["p95"],           6),
                "stdev_ms":  round(v.get("stdev", 0), 6),
            })
    print(f"Saved: {out}")


def save_e2e_csv(
    results: dict,
    path: str = str(_GENERATED / "e2e_results.csv"),
) -> None:
    """Persist _benchmark_e2e_flows() results to CSV."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["operation", "mean_ms", "min_ms", "max_ms", "p95_ms"]
        )
        writer.writeheader()
        for op, v in results.items():
            writer.writerow({
                "operation": op,
                "mean_ms":   round(v["mean"], 6),
                "min_ms":    round(v["min"],  6),
                "max_ms":    round(v["max"],  6),
                "p95_ms":    round(v["p95"],  6),
            })
    print(f"Saved: {out}")


# ---------------------------------------------------------------------------
# Throughput sweep: RPS at increasing burst sizes
# ---------------------------------------------------------------------------

def run_throughput_sweep(
    burst_sizes: list = None,
    output_csv: str = str(_GENERATED / "throughput_results.csv"),
) -> None:
    """
    For each (burst_size, method) pair run burst_size sequential full
    authentication flows and compute RPS = burst_size / elapsed_seconds.

    Writes throughput_results.csv  (columns: users, method, rps) which is
    read by generate_charts() to produce the throughput comparison bar chart.
    """
    if burst_sizes is None:
        burst_sizes = [10, 25, 50, 100]

    password = "thrpt-bench-pass"
    client_id_base = "thrpt_bench_user"

    server.app.config["TESTING"] = True
    with server.app.test_client() as c:
        x = derive_password_x(password)
        y = pow(server.G, x, server.P)
        c.post("/register",              json={"client_id": client_id_base, "secret_y": str(y)})
        c.post("/oauth/pkce/register",   json={"client_id": client_id_base, "password": password})
        c.post("/oauth/simple/register", json={"client_id": client_id_base, "password": password})
        c.post("/authlib/register",      json={"client_id": client_id_base, "password": password})

        rows = []
        for burst in burst_sizes:
            print(f"  burst={burst}")

            # -- ZKP: KDF + commit + verify -----------------------------------------
            t0 = time.perf_counter()
            zkp_ok = 0
            for _ in range(burst):
                x_iter = derive_password_x(password)
                rand_r = secrets_module.randbelow(server.P - 2) + 1
                t_val = pow(server.G, rand_r, server.P)
                resp = c.post("/login/commit",
                              json={"client_id": client_id_base, "commitment_t": t_val})
                if resp.status_code != 200:
                    continue
                payload = resp.get_json()
                s = (rand_r + int(payload["challenge_c"]) * x_iter) % server.Q
                c.post("/login/verify",
                       headers={"X-Auth-Session": payload["session_id"]},
                       json={"solution_s": s})
                zkp_ok += 1
            elapsed = time.perf_counter() - t0
            rps = round(zkp_ok / elapsed, 4) if elapsed > 0 else 0
            rows.append({"users": burst, "method": "ZKP", "rps": rps})
            print(f"    ZKP          : {zkp_ok}/{burst} OK  {rps:.2f} RPS")

            # -- OAuth2 PKCE: GET authorize + POST authorize + token ----------
            t0 = time.perf_counter()
            pkce_ok = 0
            for _ in range(burst):
                code_verifier = secrets_module.token_urlsafe(48)
                challenge = pkce_challenge(code_verifier)
                code, ok = _oauth_authorize(
                    c, "oauth/pkce", OAUTH_PKCE_CLIENT_ID, OAUTH_REDIRECT_URI,
                    client_id_base, password,
                    code_challenge=challenge, code_challenge_method="S256",
                )
                if ok and code:
                    c.post("/oauth/pkce/token", json={
                        "grant_type": "authorization_code",
                        "code": code,
                        "client_id": OAUTH_PKCE_CLIENT_ID,
                        "redirect_uri": OAUTH_REDIRECT_URI,
                        "code_verifier": code_verifier,
                    })
                    pkce_ok += 1
            elapsed = time.perf_counter() - t0
            rps = round(pkce_ok / elapsed, 4) if elapsed > 0 else 0
            rows.append({"users": burst, "method": "OAuth2 PKCE", "rps": rps})
            print(f"    OAuth2 PKCE  : {pkce_ok}/{burst} OK  {rps:.2f} RPS")

            # -- OAuth2 Simple: GET authorize + POST authorize + token --------
            t0 = time.perf_counter()
            simple_ok = 0
            for _ in range(burst):
                code, ok = _oauth_authorize(
                    c, "oauth/simple", OAUTH_SIMPLE_CLIENT_ID, OAUTH_REDIRECT_URI,
                    client_id_base, password,
                )
                if ok and code:
                    c.post("/oauth/simple/token", json={
                        "grant_type": "authorization_code",
                        "code": code,
                        "client_id": OAUTH_SIMPLE_CLIENT_ID,
                        "redirect_uri": OAUTH_REDIRECT_URI,
                    })
                    simple_ok += 1
            elapsed = time.perf_counter() - t0
            rps = round(simple_ok / elapsed, 4) if elapsed > 0 else 0
            rows.append({"users": burst, "method": "OAuth2 Simple", "rps": rps})
            print(f"    OAuth2 Simple: {simple_ok}/{burst} OK  {rps:.2f} RPS")

            # -- Authlib PKCE: GET authorize + POST authorize + token  (3 calls, RFC 6749 §4.1)
            t0 = time.perf_counter()
            authlib_ok = 0
            for _ in range(burst):
                code_verifier = secrets_module.token_urlsafe(48)
                challenge = pkce_challenge(code_verifier)
                code, ok = _oauth_authorize(
                    c, "authlib/oauth", AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI,
                    client_id_base, password,
                    code_challenge=challenge, code_challenge_method="S256",
                )
                if ok and code:
                    c.post("/authlib/oauth/token", data={
                        "grant_type":    "authorization_code",
                        "client_id":     AUTHLIB_CLIENT_ID,
                        "redirect_uri":  AUTHLIB_REDIRECT_URI,
                        "code":          code,
                        "code_verifier": code_verifier,
                    })
                    authlib_ok += 1
            elapsed = time.perf_counter() - t0
            rps = round(authlib_ok / elapsed, 4) if elapsed > 0 else 0
            rows.append({"users": burst, "method": "Authlib PKCE", "rps": rps})
            print(f"    Authlib PKCE : {authlib_ok}/{burst} OK  {rps:.2f} RPS")

    out = Path(output_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["users", "method", "rps"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Saved: {out} ({len(rows)} rows)")

# ---------------------------------------------------------------------------
# Latency table: ZKP step-by-step (commit / verify / RTT) -- perf_counter_ns
# ---------------------------------------------------------------------------

def gen_latency_table_zkp_fun_only(iterations: int = 100) -> str:
    """
    Run 'iterations' complete ZKP authentication flows inside the Flask test
    client, record commit_ns and verify_ns separately, return a Markdown table
    string.  Only ZKP steps are timed here; for cross-protocol e2e comparison
    see _benchmark_e2e_flows.
    """
    password = "probe-password"
    client_id = "probe_latency_user"
    x, client = setup_isolated_test_user(client_id, password)
    commit_times: list[float] = []
    verify_times: list[float] = []
    rtt_times: list[float] = []

    for _ in range(iterations):
        server.sessions.clear()
        rand_r = secrets_module.randbelow(server.P - 2) + 1
        t = pow(server.G, rand_r, server.P)

        rtt_start = time.perf_counter_ns()

        t0 = time.perf_counter_ns()
        commit_resp = client.post(
            "/login/commit",
            json={"client_id": client_id, "commitment_t": t},
        )
        t1 = time.perf_counter_ns()
        commit_times.append((t1 - t0) / 1e6)

        payload = commit_resp.get_json()
        c = int(payload["challenge_c"])
        session_id = payload["session_id"]
        s = (rand_r + c * x) % server.Q

        t2 = time.perf_counter_ns()
        client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": s},
        )
        t3 = time.perf_counter_ns()
        verify_times.append((t3 - t2) / 1e6)
        rtt_times.append((t3 - rtt_start) / 1e6)

    def row(label: str, data: list[float]) -> str:
        return (
            f"| {label:<32} | {statistics.mean(data):>9.4f} "
            f"| {min(data):>9.4f} | {max(data):>9.4f} "
            f"| {statistics.stdev(data):>9.4f} |"
        )

    header = (
        f"| {'Etapa':<32} | {'Media (ms)':>9} | {'Min (ms)':>9}"
        f" | {'Max (ms)':>9} | {'StdDev':>9} |"
    )
    sep = "|" + "-" * 34 + "|" + ("-" * 11 + "|") * 4

    lines = [
        "## Tabel de Latenta - Flux ZKP Schnorr",
        f"Iteratii: {iterations}",
        "",
        header,
        sep,
        row("/login/commit (server side)", commit_times),
        row("/login/verify (server side)", verify_times),
        row("HTTP RTT: commit + verify (no client crypto)", rtt_times),
        "",
    ]
    save_benchmark_csv(
        {
            "/login/commit (server side)": {
                "mean": statistics.mean(commit_times), "min": min(commit_times),
                "max": max(commit_times),
                "p95": sorted(commit_times)[int(len(commit_times) * 0.95)],
                "stdev": statistics.stdev(commit_times),
            },
            "/login/verify (server side)": {
                "mean": statistics.mean(verify_times), "min": min(verify_times),
                "max": max(verify_times),
                "p95": sorted(verify_times)[int(len(verify_times) * 0.95)],
                "stdev": statistics.stdev(verify_times),
            },
            "HTTP RTT: commit + verify (no client crypto)": {
                "mean": statistics.mean(rtt_times), "min": min(rtt_times),
                "max": max(rtt_times),
                "p95": sorted(rtt_times)[int(len(rtt_times) * 0.95)],
                "stdev": statistics.stdev(rtt_times),
            },
        },
        path=str(_GENERATED / "zkp_steps_latency.csv"),
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Micro-benchmark: ZKP component latency vs Classic (timeit)
# ---------------------------------------------------------------------------

def _benchmark_latency(iterations=100):
    import hashlib
    P, Q, G = server.P, server.Q, server.G

    def _derive():
        x = derive_password_x("bench-password")
        return x

    def _commitment(x):
        r = secrets_module.randbelow(P - 2) + 1
        return r, pow(G, r, P)

    def _verify_math(t, y, c, s):
        left = pow(G, s, P)
        right = (t * pow(y, c, P)) % P
        return left == right

    def _oauth_pkce_hash():
        return pkce_challenge("bench-code-verifier")

    def _oauth_simple_hash():
        return hashlib.sha256(b"bench-password").hexdigest()

    results = {}

    derive_times = [timeit.timeit(_derive, number=1) * 1000 for _ in range(iterations)]
    results["derive_x = SHAKE-256(pw+salt) mod Q (ms)"] = {
        "mean":  statistics.mean(derive_times),
        "min":   min(derive_times),
        "max":   max(derive_times),
        "p95":   sorted(derive_times)[int(iterations * 0.95)],
        "stdev": statistics.stdev(derive_times),
    }

    x = _derive()
    compute_y_times = [timeit.timeit(lambda: pow(G, x, P), number=1) * 1000 for _ in range(iterations)]
    results["compute_y = g^x mod p (ms)"] = {
        "mean":  statistics.mean(compute_y_times),
        "min":   min(compute_y_times),
        "max":   max(compute_y_times),
        "p95":   sorted(compute_y_times)[int(iterations * 0.95)],
        "stdev": statistics.stdev(compute_y_times),
    }

    y = pow(G, x, P)
    commit_times = [timeit.timeit(lambda: _commitment(x), number=1) * 1000 for _ in range(iterations)]
    results["commitment_t = g^r mod p (ms)"] = {
        "mean": statistics.mean(commit_times),
        "min": min(commit_times),
        "max": max(commit_times),
        "p95": sorted(commit_times)[int(iterations * 0.95)],
        "stdev": statistics.stdev(commit_times),
    }

    r, t = _commitment(x)
    c = secrets_module.randbelow(Q - 1) + 1
    s = (r + c * x) % Q

    # Client-side solution: s = (r + c * x) mod Q  (computed after receiving challenge)
    solve_times = [timeit.timeit(lambda: (r + c * x) % Q, number=1) * 1000 for _ in range(iterations)]
    results["ZKP solve s = (r + c*x) mod Q (ms)"] = {
        "mean":  statistics.mean(solve_times),
        "min":   min(solve_times),
        "max":   max(solve_times),
        "p95":   sorted(solve_times)[int(iterations * 0.95)],
        "stdev": statistics.stdev(solve_times),
    }

    verify_times = [timeit.timeit(lambda: _verify_math(t, y, c, s), number=1) * 1000 for _ in range(iterations)]
    results["ZKP verify math (ms)"] = {
        "mean": statistics.mean(verify_times),
        "min": min(verify_times),
        "max": max(verify_times),
        "p95": sorted(verify_times)[int(iterations * 0.95)],
        "stdev": statistics.stdev(verify_times),
    }

    # Subgroup membership check: pow(v, Q, P) == 1
    # Called by server.is_subgroup_member() on every received commitment_t
    # and public key Y — prevents Small Subgroup Attack.
    # Exponent Q = (P-1)/2 is a ~2048-bit safe-prime order, so this is a
    # full large-exponent modular exponentiation, same cost class as g^r mod P.
    subgroup_times = [timeit.timeit(lambda: 1 < t < P and pow(t, Q, P) == 1, number=1) * 1000 for _ in range(iterations)]
    results["ZKP subgroup check pow(v,Q,P)==1 (ms)"] = {
        "mean":  statistics.mean(subgroup_times),
        "min":   min(subgroup_times),
        "max":   max(subgroup_times),
        "p95":   sorted(subgroup_times)[int(iterations * 0.95)],
        "stdev": statistics.stdev(subgroup_times),
    }

    oauth_pkce_times = [timeit.timeit(_oauth_pkce_hash, number=1) * 1000 for _ in range(iterations)]
    results["OAuth2 PKCE S256 challenge (ms)"] = {
        "mean": statistics.mean(oauth_pkce_times),
        "min": min(oauth_pkce_times),
        "max": max(oauth_pkce_times),
        "p95": sorted(oauth_pkce_times)[int(iterations * 0.95)],
        "stdev": statistics.stdev(oauth_pkce_times),
    }

    oauth_simple_times = [timeit.timeit(_oauth_simple_hash, number=1) * 1000 for _ in range(iterations)]
    results["OAuth2 Simple hash check (ms)"] = {
        "mean": statistics.mean(oauth_simple_times),
        "min": min(oauth_simple_times),
        "max": max(oauth_simple_times),
        "p95": sorted(oauth_simple_times)[int(iterations * 0.95)],
        "stdev": statistics.stdev(oauth_simple_times),
    }

    return results


# ---------------------------------------------------------------------------
# End-to-end protocol comparison: ZKP vs OAuth2, equal footing
# ---------------------------------------------------------------------------
# All protocols are timed from first per-authentication client action to last HTTP response.
# Derivation of long-term keys (derive_password_x / register) is excluded for all.
# Per-authentication ephemeral client crypto IS included in all timers:
#   ZKP         : KDF(password->x) + rand_r + g^r mod P  +  2 HTTP calls  + s = (r + c*x) mod Q
#   OAuth2 PKCE : code_verifier gen + S256 challenge    +  3 HTTP calls  (GET+POST authorize + token)
#   OAuth2 Simple:                                          3 HTTP calls  (GET+POST authorize + token)
#   Authlib PKCE: code_verifier gen + S256 challenge    +  2 HTTP calls  (POST authorize + token)

def _benchmark_e2e_flows(iterations=100):
    """Full end-to-end authentication latency including all client-side crypto."""
    import time as _time

    P, Q, G = server.P, server.Q, server.G
    password = "bench-e2e-pass"
    client_id = "bench_e2e_user"
    results = {}

    with server.app.test_client() as c:
        x = derive_password_x(password)
        y = pow(G, x, P)
        with server.app.app_context():
            server.db.session.add(server.User(client_id=client_id, secret_y=y.to_bytes(256, 'big')))
            server.db.session.commit()
        c.post("/oauth/pkce/register",   json={"client_id": client_id, "password": password})
        c.post("/oauth/simple/register", json={"client_id": client_id, "password": password})
        c.post("/authlib/register",      json={"client_id": client_id, "password": password})

        # -- ZKP: KDF + commit + verify ---------------------------------------
        # derive_password_x is included in every iteration: the client must
        # re-derive x from the password on each login to compute s = (r + c*x) mod Q.
        zkp_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            x = derive_password_x(password)
            rand_r = secrets_module.randbelow(P - 2) + 1
            commitment_t = pow(G, rand_r, P)
            commit_resp = c.post("/login/commit", json={"client_id": client_id, "commitment_t": commitment_t})
            if commit_resp.status_code != 200:
                continue
            payload = commit_resp.get_json()
            s = (rand_r + int(payload["challenge_c"]) * x) % Q
            c.post("/login/verify", headers={"X-Auth-Session": payload["session_id"]}, json={"solution_s": s})
            zkp_times.append((_time.perf_counter() - t0) * 1000)

        results["ZKP full flow (KDF + commit + verify) (ms)"] = {
            "mean": statistics.mean(zkp_times), "min": min(zkp_times),
            "max": max(zkp_times), "p95": sorted(zkp_times)[int(len(zkp_times) * 0.95)],
        }

        # -- OAuth2 PKCE: client crypto + GET authorize + POST authorize + token
        pkce_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            code_verifier = secrets_module.token_urlsafe(48)
            challenge = pkce_challenge(code_verifier)
            code, ok = _oauth_authorize(
                c, "oauth/pkce", OAUTH_PKCE_CLIENT_ID, OAUTH_REDIRECT_URI,
                client_id, password,
                code_challenge=challenge, code_challenge_method="S256",
            )
            if not (ok and code):
                continue
            c.post("/oauth/pkce/token", json={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": OAUTH_PKCE_CLIENT_ID,
                "redirect_uri": OAUTH_REDIRECT_URI,
                "code_verifier": code_verifier,
            })
            pkce_times.append((_time.perf_counter() - t0) * 1000)

        results["OAuth2 PKCE login (authorize + token) (ms)"] = {
            "mean": statistics.mean(pkce_times), "min": min(pkce_times),
            "max": max(pkce_times), "p95": sorted(pkce_times)[int(len(pkce_times) * 0.95)],
        }

        # -- OAuth2 Simple: GET authorize + POST authorize + token
        simple_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            code, ok = _oauth_authorize(
                c, "oauth/simple", OAUTH_SIMPLE_CLIENT_ID, OAUTH_REDIRECT_URI,
                client_id, password,
            )
            if not (ok and code):
                continue
            c.post("/oauth/simple/token", json={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": OAUTH_SIMPLE_CLIENT_ID,
                "redirect_uri": OAUTH_REDIRECT_URI,
            })
            simple_times.append((_time.perf_counter() - t0) * 1000)

        results["OAuth2 Simple login (authorize + token) (ms)"] = {
            "mean": statistics.mean(simple_times), "min": min(simple_times),
            "max": max(simple_times), "p95": sorted(simple_times)[int(len(simple_times) * 0.95)],
        }

        # -- Authlib PKCE: GET authorize + POST authorize + token  (3 calls, RFC 6749 §4.1)
        authlib_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            code_verifier = secrets_module.token_urlsafe(48)
            challenge = pkce_challenge(code_verifier)
            code, ok = _oauth_authorize(
                c, "authlib/oauth", AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI,
                client_id, password,
                code_challenge=challenge, code_challenge_method="S256",
            )
            if not (ok and code):
                continue
            c.post("/authlib/oauth/token", data={
                "grant_type":    "authorization_code",
                "client_id":     AUTHLIB_CLIENT_ID,
                "redirect_uri":  AUTHLIB_REDIRECT_URI,
                "code":          code,
                "code_verifier": code_verifier,
            })
            authlib_times.append((_time.perf_counter() - t0) * 1000)

        results["Authlib PKCE full flow (authorize + token) (ms)"] = {
            "mean": statistics.mean(authlib_times), "min": min(authlib_times),
            "max": max(authlib_times), "p95": sorted(authlib_times)[int(len(authlib_times) * 0.95)],
        }

    return results

class TestBenchmark(OAuthTestSuite):

    def test_benchmark_prints_latency_table(self, capsys):
        '''Testare benchmark micro-latenta operatii criptografice - afisare tabel rezultate'''
        """Test run benchmark loop, test print table, server math stay measurable."""
        data = _benchmark_latency(iterations=100)
        header = (
            f"| {'Operation':<40} | {'Mean (ms)':>10} | {'Min (ms)':>10}"
            f" | {'Max (ms)':>10} | {'P95 (ms)':>10} | {'StdDev':>8} | Unit |"
        )
        sep = "|" + "-" * 42 + "|" + ("-" * 12 + "|") * 4 + "-" * 10 + "|------|" 
        print()
        print(header)
        print(sep)
        for op, vals in data.items():
            print(
                f"| {op:<40} | {vals['mean']:>10.4f} | {vals['min']:>10.4f}"
                f" | {vals['max']:>10.4f} | {vals['p95']:>10.4f}"
                f" | {vals.get('stdev', 0):>8.4f} | ms   |"
            )
        save_benchmark_csv(data)
        output = capsys.readouterr().out
        sys.stdout.write(output)
        assert "Operation" in output
        assert "Mean (ms)" in output
        assert "StdDev" in output
        assert "commitment_t = g^r mod p (ms)" in output
        assert "ZKP solve s = (r + c*x) mod Q (ms)" in output
        assert all(v["mean"] >= 0 for v in data.values())

    def test_benchmark_e2e_protocol_comparison(self, capsys):
        '''Testare comparatie latentza e2e ZKP vs OAuth2 inclusiv crypto client'''
        """Compare ZKP vs OAuth2 e2e: full authentication latency including all client-side crypto."""
        data = _benchmark_e2e_flows(iterations=100)
        save_e2e_csv(data)
        header = (
            f"| {'Protocol Flow':<52} | {'Mean (ms)':>10} | {'Min (ms)':>10}"
            f" | {'Max (ms)':>10} | {'P95 (ms)':>10} |"
        )
        sep = "|" + "-" * 54 + "|" + ("-" * 12 + "|") * 4
        print()
        print("END-TO-END PROTOCOL COMPARISON  (full auth: client crypto + HTTP calls; ZKP=2, PKCE/Simple=3, Authlib=2)")
        print(header)
        print(sep)
        for op, vals in data.items():
            print(
                f"| {op:<52} | {vals['mean']:>10.4f} | {vals['min']:>10.4f}"
                f" | {vals['max']:>10.4f} | {vals['p95']:>10.4f} |"
            )
        output = capsys.readouterr().out
        sys.stdout.write(output)
        assert "ZKP full flow (KDF + commit + verify)" in output
        assert "OAuth2 PKCE login" in output
        assert "Authlib PKCE full flow" in output
        assert all(v["mean"] >= 0 for v in data.values())


# ---------------------------------------------------------------------------
# Entry point: run tests (with logs) then generate both CSVs
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", message=r".*request\.scope.*is deprecated")

    # if len(sys.argv) > 1 and sys.argv[1] == "--latency":
    print()
    print("STEP 1 -- latency table for zkp steps")
    print("=" * 70)
    print(gen_latency_table_zkp_fun_only(iterations=100))
    print("=" * 70)
    print()

    print("=" * 70)
    print("STEP 2 -- pytest tests")
    print("=" * 70)
    exit_code = pytest.main([
        __file__,
        "-v",
        "-s",
        "--log-cli-level=INFO",
        "--tb=short",
    ])

    print()
    print("=" * 70)
    print("STEP 3 -- throughput sweep (burst sizes: 10, 25, 50, 100)")
    print("=" * 70)
    run_throughput_sweep()

    sys.exit(exit_code)
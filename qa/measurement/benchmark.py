import secrets as secrets_module
import timeit
import statistics

import pytest

from qa_utils import (
    server, derive_password_x, pkce_challenge,
    OAUTH_PKCE_CLIENT_ID, OAUTH_SIMPLE_CLIENT_ID, OAUTH_REDIRECT_URI,
    AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI,
    OAuthTestSuite,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Prompt 2 – Micro-benchmark: ZKP component latency vs Classic (timeit)
# ---------------------------------------------------------------------------

def _benchmark_latency(iterations=100):
    import hashlib
    P, Q, G = server.P, server.Q, server.G

    def _derive():
        return derive_password_x("bench-password")

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
    results["derive_password_x (ms)"] = {
        "mean": statistics.mean(derive_times),
        "min": min(derive_times),
        "max": max(derive_times),
        "p95": sorted(derive_times)[int(iterations * 0.95)],
    }

    x = _derive()
    y = pow(G, x, P)
    commit_times = [timeit.timeit(lambda: _commitment(x), number=1) * 1000 for _ in range(iterations)]
    results["commitment_t = g^r mod p (ms)"] = {
        "mean": statistics.mean(commit_times),
        "min": min(commit_times),
        "max": max(commit_times),
        "p95": sorted(commit_times)[int(iterations * 0.95)],
    }

    r, t = _commitment(x)
    c = secrets_module.randbelow(Q - 1) + 1
    s = (r + c * x) % Q
    verify_times = [timeit.timeit(lambda: _verify_math(t, y, c, s), number=1) * 1000 for _ in range(iterations)]
    results["ZKP verify math (ms)"] = {
        "mean": statistics.mean(verify_times),
        "min": min(verify_times),
        "max": max(verify_times),
        "p95": sorted(verify_times)[int(iterations * 0.95)],
    }

    oauth_pkce_times = [timeit.timeit(_oauth_pkce_hash, number=1) * 1000 for _ in range(iterations)]
    results["OAuth2 PKCE S256 challenge (ms)"] = {
        "mean": statistics.mean(oauth_pkce_times),
        "min": min(oauth_pkce_times),
        "max": max(oauth_pkce_times),
        "p95": sorted(oauth_pkce_times)[int(iterations * 0.95)],
    }

    oauth_simple_times = [timeit.timeit(_oauth_simple_hash, number=1) * 1000 for _ in range(iterations)]
    results["OAuth2 Simple hash check (ms)"] = {
        "mean": statistics.mean(oauth_simple_times),
        "min": min(oauth_simple_times),
        "max": max(oauth_simple_times),
        "p95": sorted(oauth_simple_times)[int(iterations * 0.95)],
    }

    return results

class TestBenchmark(OAuthTestSuite):

    def test_benchmark_prints_latency_table(self, capsys):
        '''Testare benchmark micro-latenta operatii criptografice - afisare tabel rezultate'''
        """Test run benchmark loop, test print table, server math stay measurable."""
        data = _benchmark_latency(iterations=100)
        header = f"| {'Operation':<40} | {'Mean (ms)':>10} | {'Min (ms)':>10} | {'Max (ms)':>10} | {'P95 (ms)':>10} |"
        sep = "|" + "-" * 42 + "|" + ("-" * 12 + "|") * 4
        print()
        print(header)
        print(sep)
        for op, vals in data.items():
            print(
                f"| {op:<40} | {vals['mean']:>10.4f} | {vals['min']:>10.4f}"
                f" | {vals['max']:>10.4f} | {vals['p95']:>10.4f} |"
            )
        output = capsys.readouterr().out
        assert "Operation" in output
        assert "Mean (ms)" in output
        assert "derive_password_x (ms)" in output
        assert all(v["mean"] >= 0 for v in data.values())


    # ---------------------------------------------------------------------------
    # Prompt 2b – End-to-end protocol comparison: ZKP vs OAuth2, equal footing
    # ---------------------------------------------------------------------------
    # Both protocols complete exactly 2 HTTP round-trips per authentication.
    # The timer covers the FULL client-side authentication work:
    #   ZKP   : rand_r + g^r mod P + 2 HTTP calls + s = (r + c·x) mod Q
    #   OAuth2: code_verifier + SHA-256 PKCE challenge + 2 HTTP calls

def _benchmark_e2e_flows(iterations=50):
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
            server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
            server.db.session.commit()
        c.post("/oauth/pkce/register",   json={"client_id": client_id, "password": password})
        c.post("/oauth/simple/register", json={"client_id": client_id, "password": password})
        c.post("/authlib/register",      json={"client_id": client_id, "password": password})

        # ── ZKP: commit + verify ─────────────────────────────────────────────
        zkp_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            rand_r = secrets_module.randbelow(P - 2) + 1
            commitment_t = pow(G, rand_r, P)
            commit_resp = c.post("/login/commit", json={"client_id": client_id, "commitment_t": commitment_t})
            if commit_resp.status_code != 200:
                continue
            payload = commit_resp.get_json()
            s = (rand_r + int(payload["challenge_c"]) * x) % Q
            c.post("/login/verify", headers={"X-Auth-Session": payload["session_id"]}, json={"solution_s": s})
            zkp_times.append((_time.perf_counter() - t0) * 1000)

        results["ZKP full flow (commit + verify) (ms)"] = {
            "mean": statistics.mean(zkp_times), "min": min(zkp_times),
            "max": max(zkp_times), "p95": sorted(zkp_times)[int(len(zkp_times) * 0.95)],
        }

        # ── OAuth2 PKCE: authorize + token ────────────────────────────────────
        pkce_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            code_verifier = secrets_module.token_urlsafe(48)
            challenge = pkce_challenge(code_verifier)
            auth_resp = c.post(
                "/oauth/pkce/authorize",
                json={
                    "response_type": "code", "client_id": OAUTH_PKCE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI, "username": client_id,
                    "password": password, "scope": "openid profile",
                    "code_challenge": challenge, "code_challenge_method": "S256",
                    "response_mode": "json",
                },
            )
            if auth_resp.status_code != 200:
                continue
            c.post("/oauth/pkce/token", json={
                "grant_type": "authorization_code", "client_id": OAUTH_PKCE_CLIENT_ID,
                "redirect_uri": OAUTH_REDIRECT_URI, "code": auth_resp.get_json()["code"],
                "code_verifier": code_verifier,
            })
            pkce_times.append((_time.perf_counter() - t0) * 1000)

        results["OAuth2 PKCE full flow (authorize + token) (ms)"] = {
            "mean": statistics.mean(pkce_times), "min": min(pkce_times),
            "max": max(pkce_times), "p95": sorted(pkce_times)[int(len(pkce_times) * 0.95)],
        }

        # ── OAuth2 Simple: authorize + token ──────────────────────────────────
        simple_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            auth_resp = c.post(
                "/oauth/simple/authorize",
                json={
                    "response_type": "code", "client_id": OAUTH_SIMPLE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI, "username": client_id,
                    "password": password, "scope": "openid profile", "response_mode": "json",
                },
            )
            if auth_resp.status_code != 200:
                continue
            c.post("/oauth/simple/token", json={
                "grant_type": "authorization_code", "client_id": OAUTH_SIMPLE_CLIENT_ID,
                "redirect_uri": OAUTH_REDIRECT_URI, "code": auth_resp.get_json()["code"],
            })
            simple_times.append((_time.perf_counter() - t0) * 1000)

        results["OAuth2 Simple full flow (authorize + token) (ms)"] = {
            "mean": statistics.mean(simple_times), "min": min(simple_times),
            "max": max(simple_times), "p95": sorted(simple_times)[int(len(simple_times) * 0.95)],
        }

        # ── Authlib PKCE: authorize (form) + token (form) ─────────────────────
        # Authlib reads OAuth2 params from request.values (form-encoded), not JSON.
        authlib_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            code_verifier = secrets_module.token_urlsafe(48)
            challenge = pkce_challenge(code_verifier)
            auth_resp = c.post(
                "/authlib/oauth/authorize",
                data={
                    "response_type": "code", "client_id": AUTHLIB_CLIENT_ID,
                    "redirect_uri": AUTHLIB_REDIRECT_URI, "username": client_id,
                    "password": password, "scope": "openid profile",
                    "code_challenge": challenge, "code_challenge_method": "S256",
                },
            )
            if auth_resp.status_code != 200:
                continue
            c.post("/authlib/oauth/token", data={
                "grant_type": "authorization_code", "client_id": AUTHLIB_CLIENT_ID,
                "redirect_uri": AUTHLIB_REDIRECT_URI, "code": auth_resp.get_json()["code"],
                "code_verifier": code_verifier,
            })
            authlib_times.append((_time.perf_counter() - t0) * 1000)

        results["Authlib PKCE full flow (authorize + token) (ms)"] = {
            "mean": statistics.mean(authlib_times), "min": min(authlib_times),
            "max": max(authlib_times), "p95": sorted(authlib_times)[int(len(authlib_times) * 0.95)],
        }

    return results


    def test_benchmark_e2e_protocol_comparison(self, capsys):
        '''Testare comparatie latenta end-to-end ZKP vs OAuth2 inclusiv crypto client'''
        """Compare ZKP vs OAuth2 end-to-end: full authentication latency including all client-side crypto."""
        data = _benchmark_e2e_flows(iterations=50)
        header = (
            f"| {'Protocol Flow':<52} | {'Mean (ms)':>10} | {'Min (ms)':>10}"
            f" | {'Max (ms)':>10} | {'P95 (ms)':>10} |"
        )
        sep = "|" + "-" * 54 + "|" + ("-" * 12 + "|") * 4
        print()
        print("END-TO-END PROTOCOL COMPARISON  (full auth latency: client-side crypto + 2 HTTP calls each)")
        print(header)
        print(sep)
        for op, vals in data.items():
            print(
                f"| {op:<52} | {vals['mean']:>10.4f} | {vals['min']:>10.4f}"
                f" | {vals['max']:>10.4f} | {vals['p95']:>10.4f} |"
            )
        output = capsys.readouterr().out
        assert "ZKP full flow" in output
        assert "OAuth2 PKCE full flow" in output
        assert "Authlib PKCE full flow" in output
        assert all(v["mean"] >= 0 for v in data.values())


    # ---------------------------------------------------------------------------
    # Prompt 4 – Memory footprint: sessions dict under DoS-style commit flood
    # ---------------------------------------------------------------------------

    def test_sessions_dict_memory_footprint_under_commit_flood(self):
        '''Testare amprenta memorie dict sesiuni sub flood de commit-uri in loturi 100/500/1000 (simulare DoS stare)'''
        """Server receive 100 then 500 then 1000 commits from same user, each new commit evict previous session with 409 or 200, tracemalloc measure memory after each batch, server keep at most 1 active session after flood, final deep memory stay below 20x the 100-commit baseline."""
        import sys as _sys
        import tracemalloc

        P, G, Q = server.P, server.G, server.Q

        def _deep_sizeof(obj, seen=None):
            """Recursively sum sys.getsizeof over obj and all nested objects."""
            if seen is None:
                seen = set()
            oid = id(obj)
            if oid in seen:
                return 0
            seen.add(oid)
            size = _sys.getsizeof(obj)
            if isinstance(obj, dict):
                size += sum(_deep_sizeof(k, seen) + _deep_sizeof(v, seen) for k, v in obj.items())
            elif isinstance(obj, (list, tuple, set, frozenset)):
                size += sum(_deep_sizeof(i, seen) for i in obj)
            return size

        with server.app.test_client() as c:
            with server.app.app_context():
                x = derive_password_x("flood-pass")
                y = pow(G, x, P)
                server.db.session.add(server.User(client_id="flood_user", secret_y=str(y)))
                server.db.session.commit()

            sizes = {}
            for batch in (100, 500, 1000):
                server.sessions.clear()
                tracemalloc.start()

                for _ in range(batch):
                    rand_r = secrets_module.randbelow(P - 2) + 1
                    t = pow(G, rand_r, P)
                    resp = c.post("/login/commit", json={"client_id": "flood_user", "commitment_t": t})
                    assert resp.status_code in (200, 409)

                current_mem, peak_mem = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                deep_size = _deep_sizeof(server.sessions)
                sizes[batch] = {
                    "shallow_bytes": _sys.getsizeof(server.sessions),
                    "deep_bytes": deep_size,
                    "tracemalloc_current_kb": current_mem // 1024,
                    "tracemalloc_peak_kb": peak_mem // 1024,
                    "active_entries": len(server.sessions),
                }
                print(
                    f"After {batch:>5} commits: "
                    f"shallow={sizes[batch]['shallow_bytes']} B, "
                    f"deep={sizes[batch]['deep_bytes']} B, "
                    f"tracemalloc current={sizes[batch]['tracemalloc_current_kb']} KB "
                    f"peak={sizes[batch]['tracemalloc_peak_kb']} KB, "
                    f"active entries={sizes[batch]['active_entries']}"
                )

        assert len(server.sessions) <= 1
        assert sizes[1000]["deep_bytes"] < sizes[100]["deep_bytes"] * 20


    r"""
    Context inițial (de reamintit agentului)
    "Acționează ca un Security QA Automation Engineer. Scrie teste pentru urmatoarele prompturi"

    Prompt 2: Testarea de Latență (Micro-Benchmarking Client și Server)
    "Folosește benchmark-ul din testul test_benchmark_prints_latency_table (bazat pe librăria timeit)
    pentru a măsura latența componentelor individuale ale sistemului nostru ZKP vs. Clasic.
    Măsoară timpul de execuție pentru funcțiile de client: derivarea parolei și generarea angajamentului.
    Măsoară timpul de execuție pentru funcțiile de server ZKP: /login/commit și /login/verify.
    Rulează fiecare măsurătoare de 100 de ori și calculează Media, Minimul, Maximul și P95 în ms."

    Prompt 2b – End-to-end protocol comparison: ZKP vs OAuth2, equal footing
    Both protocols complete exactly 2 HTTP round-trips per authentication.
    Timer covers FULL client-side work: client crypto + 2 HTTP calls.

    Prompt 4: Testarea Amprentei de Memorie (Sesiuni Concurente)
    "Testează consumul de memorie al dicționarului sessions din serverul Flask.
    Injectează treptat 100, 500, 1000 cereri de POST /login/commit (fără /login/verify).
    Măsoară dimensiunea în memorie (RAM) a dicționarului sessions la fiecare pas.
    Validează că serverul nu poate fi doborât prin epuizarea memoriei (atac DoS pe resursa de memorie)."
    """

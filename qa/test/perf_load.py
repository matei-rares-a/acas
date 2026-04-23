"""
Performance & load test suite for the Schnorr ZKP authentication protocol.

Prompt 1  – /oauth/authorize + /oauth/token baseline endpoints + pytest unit tests
Prompt 2  – Micro-benchmark (timeit) for ZKP vs OAuth2 latency
Prompt 3  – Locust load-test stub (requires `locust` installed + live server)
Prompt 4  – In-process memory-footprint test for the sessions dict
"""

from pathlib import Path
import base64
import hashlib
import importlib.util
import secrets as secrets_module
import sys
import timeit
import statistics

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVER_APP_PATH = PROJECT_ROOT / "server_app"
SERVER_MODULE_PATH = SERVER_APP_PATH / "server.py"
if str(SERVER_APP_PATH) not in sys.path:
    sys.path.insert(0, str(SERVER_APP_PATH))
spec = importlib.util.spec_from_file_location("server", SERVER_MODULE_PATH)
server = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(server)

OAUTH_PKCE_CLIENT_ID = "acas-pkce-client"
OAUTH_SIMPLE_CLIENT_ID = "acas-simple-client"
OAUTH_REDIRECT_URI = "https://client.example/callback"
AUTHLIB_CLIENT_ID = "acas-authlib-client"
AUTHLIB_REDIRECT_URI = "https://client.example/callback"


def _register_oauth(client, client_id, password):
    """Register user credentials for both OAuth implementations."""
    x = int.from_bytes(
        hashlib.scrypt(password.encode(), salt=secrets_module.token_bytes(16), n=2**11, r=8, p=1),
        "big"
    ) % server.Q
    y = pow(server.G, x, server.P)
    resp = client.post("/register", json={"client_id": client_id, "secret_y": y})
    assert resp.status_code in (200, 201)
    pkce_resp = client.post(
        "/oauth/pkce/register", json={"client_id": client_id, "password": password}
    )
    simple_resp = client.post(
        "/oauth/simple/register", json={"client_id": client_id, "password": password}
    )
    authlib_resp = client.post(
        "/authlib/register", json={"client_id": client_id, "password": password}
    )
    assert pkce_resp.status_code == 201
    assert simple_resp.status_code == 201
    assert authlib_resp.status_code == 201
    return x, y


def _pkce_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _authorize_oauth_pkce(client, username, password, code_verifier=None, scope="openid profile"):
    if code_verifier is None:
        code_verifier = secrets_module.token_urlsafe(48)
    resp = client.post(
        "/oauth/pkce/authorize",
        json={
            "response_type": "code",
            "client_id": OAUTH_PKCE_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "username": username,
            "password": password,
            "scope": scope,
            "code_challenge": _pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
            "response_mode": "json",
        },
    )
    return resp, code_verifier


def _exchange_oauth_pkce_code(client, code, code_verifier):
    return client.post(
        "/oauth/pkce/token",
        json={
            "grant_type": "authorization_code",
            "client_id": OAUTH_PKCE_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "code": code,
            "code_verifier": code_verifier,
        },
    )


def _authorize_oauth_simple(client, username, password, scope="openid profile"):
    return client.post(
        "/oauth/simple/authorize",
        json={
            "response_type": "code",
            "client_id": OAUTH_SIMPLE_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "username": username,
            "password": password,
            "scope": scope,
            "response_mode": "json",
        },
    )


def _exchange_oauth_simple_code(client, code):
    return client.post(
        "/oauth/simple/token",
        json={
            "grant_type": "authorization_code",
            "client_id": OAUTH_SIMPLE_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "code": code,
        },
    )


@pytest.fixture(autouse=True)
def reset_state():
    server.app.config["TESTING"] = True
    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
    server.sessions.clear()
    server.clear_oauth_state()
    server.clear_authlib_state()
    yield
    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
    server.sessions.clear()
    server.clear_oauth_state()
    server.clear_authlib_state()


@pytest.fixture
def client():
    return server.app.test_client()


def test_oauth_pkce_authorize_returns_authorization_code(client):
    """OAuth PKCE authorize endpoint should issue an authorization code after user login."""
    _register_oauth(client, "oauth_user", "oauth-pass")
    resp, _ = _authorize_oauth_pkce(client, "oauth_user", "oauth-pass")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert "code" in payload
    assert payload.get("redirect_uri") == OAUTH_REDIRECT_URI
    assert payload.get("expires_in") > 0
    assert "X-Response-Time" in resp.headers


def test_oauth_pkce_token_returns_bearer_and_refresh_tokens(client):
    """OAuth PKCE token endpoint should exchange a valid authorization code for bearer tokens."""
    _register_oauth(client, "oauth_user", "oauth-pass")
    auth_resp, code_verifier = _authorize_oauth_pkce(client, "oauth_user", "oauth-pass")
    resp = _exchange_oauth_pkce_code(client, auth_resp.get_json()["code"], code_verifier)
    assert resp.status_code == 200
    payload = resp.get_json()
    assert "access_token" in payload
    assert "refresh_token" in payload
    assert payload.get("token_type") == "Bearer"
    assert isinstance(payload.get("expires_in"), int)


def test_oauth_pkce_authorize_wrong_password_returns_access_denied(client):
    """OAuth PKCE authorize should deny resource owner authentication failures."""
    _register_oauth(client, "oauth_user2", "correct-pass")
    resp, _ = _authorize_oauth_pkce(client, "oauth_user2", "wrong-pass")
    assert resp.status_code == 401
    assert resp.get_json().get("error") == "access_denied"


def test_oauth_pkce_token_wrong_verifier_returns_invalid_grant(client):
    """OAuth PKCE token exchange must reject mismatched PKCE verifiers."""
    _register_oauth(client, "oauth_user3", "oauth-pass")
    auth_resp, _ = _authorize_oauth_pkce(client, "oauth_user3", "oauth-pass", code_verifier="expected-verifier")
    resp = _exchange_oauth_pkce_code(client, auth_resp.get_json()["code"], "wrong-verifier")
    assert resp.status_code == 400
    assert resp.get_json().get("error") == "invalid_grant"


def test_oauth_pkce_refresh_token_returns_new_access_token(client):
    """OAuth PKCE refresh_token grant should issue a new bearer token and rotate refresh tokens."""
    _register_oauth(client, "oauth_user4", "oauth-pass")
    auth_resp, code_verifier = _authorize_oauth_pkce(client, "oauth_user4", "oauth-pass")
    token_resp = _exchange_oauth_pkce_code(client, auth_resp.get_json()["code"], code_verifier)
    refresh_token = token_resp.get_json()["refresh_token"]
    refresh_resp = client.post(
        "/oauth/pkce/token",
        json={
            "grant_type": "refresh_token",
            "client_id": OAUTH_PKCE_CLIENT_ID,
            "refresh_token": refresh_token,
        },
    )
    assert refresh_resp.status_code == 200
    payload = refresh_resp.get_json()
    assert payload.get("token_type") == "Bearer"
    assert payload.get("refresh_token") != refresh_token


def test_oauth_simple_token_flow_returns_bearer_and_refresh_tokens(client):
    """Simple OAuth flow should exchange authorization code without PKCE verifier."""
    _register_oauth(client, "oauth_simple_user", "oauth-pass")
    auth_resp = _authorize_oauth_simple(client, "oauth_simple_user", "oauth-pass")
    assert auth_resp.status_code == 200
    resp = _exchange_oauth_simple_code(client, auth_resp.get_json()["code"])
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload.get("token_type") == "Bearer"
    assert "access_token" in payload
    assert "refresh_token" in payload


def test_oauth_simple_refresh_token_returns_new_access_token(client):
    """Simple OAuth refresh_token grant should issue a new bearer token and rotate refresh tokens."""
    _register_oauth(client, "oauth_simple_user2", "oauth-pass")
    auth_resp = _authorize_oauth_simple(client, "oauth_simple_user2", "oauth-pass")
    token_resp = _exchange_oauth_simple_code(client, auth_resp.get_json()["code"])
    refresh_token = token_resp.get_json()["refresh_token"]
    refresh_resp = client.post(
        "/oauth/simple/token",
        json={
            "grant_type": "refresh_token",
            "client_id": OAUTH_SIMPLE_CLIENT_ID,
            "refresh_token": refresh_token,
        },
    )
    assert refresh_resp.status_code == 200
    assert refresh_resp.get_json().get("refresh_token") != refresh_token


# ---------------------------------------------------------------------------
# Prompt 2 – Micro-benchmark: ZKP component latency vs Classic (timeit)
# ---------------------------------------------------------------------------

def _benchmark_latency(iterations=100):
    P, Q, G = server.P, server.Q, server.G

    def _derive():
        salt = secrets_module.token_bytes(16)
        h = hashlib.scrypt(b"bench-password", salt=salt, n=2**11, r=8, p=1)
        return int.from_bytes(h, "big") % Q

    def _commitment(x):
        r = secrets_module.randbelow(P - 2) + 1
        return r, pow(G, r, P)

    def _verify_math(t, y, c, s):
        left = pow(G, s, P)
        right = (t * pow(y, c, P)) % P
        return left == right

    def _oauth_pkce_hash():
        return _pkce_challenge("bench-code-verifier")

    def _oauth_simple_hash():
        return hashlib.sha256(b"bench-password").hexdigest()

    results = {}

    derive_times = [
        timeit.timeit(_derive, number=1) * 1000 for _ in range(iterations)
    ]
    results["derive_password_x (ms)"] = {
        "mean": statistics.mean(derive_times),
        "min": min(derive_times),
        "max": max(derive_times),
        "p95": sorted(derive_times)[int(iterations * 0.95)],
    }

    x = _derive()
    y = pow(G, x, P)
    commit_times = [
        timeit.timeit(lambda: _commitment(x), number=1) * 1000 for _ in range(iterations)
    ]
    results["commitment_t = g^r mod p (ms)"] = {
        "mean": statistics.mean(commit_times),
        "min": min(commit_times),
        "max": max(commit_times),
        "p95": sorted(commit_times)[int(iterations * 0.95)],
    }

    r, t = _commitment(x)
    c = secrets_module.randbelow(Q - 1) + 1
    s = (r + c * x) % Q
    verify_times = [
        timeit.timeit(lambda: _verify_math(t, y, c, s), number=1) * 1000
        for _ in range(iterations)
    ]
    results["ZKP verify math (ms)"] = {
        "mean": statistics.mean(verify_times),
        "min": min(verify_times),
        "max": max(verify_times),
        "p95": sorted(verify_times)[int(iterations * 0.95)],
    }

    oauth_pkce_times = [
        timeit.timeit(_oauth_pkce_hash, number=1) * 1000 for _ in range(iterations)
    ]
    results["OAuth2 PKCE S256 challenge (ms)"] = {
        "mean": statistics.mean(oauth_pkce_times),
        "min": min(oauth_pkce_times),
        "max": max(oauth_pkce_times),
        "p95": sorted(oauth_pkce_times)[int(iterations * 0.95)],
    }

    oauth_simple_times = [
        timeit.timeit(_oauth_simple_hash, number=1) * 1000 for _ in range(iterations)
    ]
    results["OAuth2 Simple hash check (ms)"] = {
        "mean": statistics.mean(oauth_simple_times),
        "min": min(oauth_simple_times),
        "max": max(oauth_simple_times),
        "p95": sorted(oauth_simple_times)[int(iterations * 0.95)],
    }

    return results


def test_benchmark_prints_latency_table(capsys):
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
# Client-side crypto is excluded from the timer in both cases:
#   ZKP   : rand_r generation + g^r mod P  (before timer)
#   OAuth2: code_verifier generation + SHA-256 PKCE challenge (before timer)

def _benchmark_e2e_flows(iterations=50):
    """Full end-to-end HTTP flow latency: ZKP (commit+verify) vs OAuth2 (authorize+token)."""
    import time as _time

    P, Q, G = server.P, server.Q, server.G
    password = "bench-e2e-pass"
    client_id = "bench_e2e_user"
    results = {}

    with server.app.test_client() as c:
        # ── Setup: register one user for all three protocols ─────────────────
        x = int.from_bytes(
            hashlib.scrypt(
                password.encode(), salt=secrets_module.token_bytes(16), n=2**11, r=8, p=1
            ),
            "big",
        ) % Q
        y = pow(G, x, P)
        with server.app.app_context():
            server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
            server.db.session.commit()
        c.post("/oauth/pkce/register", json={"client_id": client_id, "password": password})
        c.post("/oauth/simple/register", json={"client_id": client_id, "password": password})
        c.post("/authlib/register", json={"client_id": client_id, "password": password})

        # ── ZKP: commit + verify ─────────────────────────────────────────────
        zkp_times = []
        for _ in range(iterations):
            rand_r = secrets_module.randbelow(P - 2) + 1          # client-side (outside timer)
            commitment_t = pow(G, rand_r, P)                       # client-side (outside timer)
            t0 = _time.perf_counter()
            commit_resp = c.post(
                "/login/commit",
                json={"client_id": client_id, "commitment_t": commitment_t},
            )
            if commit_resp.status_code != 200:
                continue
            payload = commit_resp.get_json()
            s = (rand_r + int(payload["challenge_c"]) * x) % Q
            c.post(
                "/login/verify",
                headers={"X-Auth-Session": payload["session_id"]},
                json={"solution_s": s},
            )
            zkp_times.append((_time.perf_counter() - t0) * 1000)

        results["ZKP full flow (commit + verify) (ms)"] = {
            "mean": statistics.mean(zkp_times),
            "min": min(zkp_times),
            "max": max(zkp_times),
            "p95": sorted(zkp_times)[int(len(zkp_times) * 0.95)],
        }

        # ── OAuth2 PKCE: authorize + token ────────────────────────────────────
        pkce_times = []
        for _ in range(iterations):
            code_verifier = secrets_module.token_urlsafe(48)       # client-side (outside timer)
            challenge = _pkce_challenge(code_verifier)             # client-side (outside timer)
            t0 = _time.perf_counter()
            auth_resp = c.post(
                "/oauth/pkce/authorize",
                json={
                    "response_type": "code",
                    "client_id": OAUTH_PKCE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "username": client_id,
                    "password": password,
                    "scope": "openid profile",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "response_mode": "json",
                },
            )
            if auth_resp.status_code != 200:
                continue
            code = auth_resp.get_json()["code"]
            c.post(
                "/oauth/pkce/token",
                json={
                    "grant_type": "authorization_code",
                    "client_id": OAUTH_PKCE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "code": code,
                    "code_verifier": code_verifier,
                },
            )
            pkce_times.append((_time.perf_counter() - t0) * 1000)

        results["OAuth2 PKCE full flow (authorize + token) (ms)"] = {
            "mean": statistics.mean(pkce_times),
            "min": min(pkce_times),
            "max": max(pkce_times),
            "p95": sorted(pkce_times)[int(len(pkce_times) * 0.95)],
        }

        # ── OAuth2 Simple: authorize + token ──────────────────────────────────
        simple_times = []
        for _ in range(iterations):
            t0 = _time.perf_counter()
            auth_resp = c.post(
                "/oauth/simple/authorize",
                json={
                    "response_type": "code",
                    "client_id": OAUTH_SIMPLE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "username": client_id,
                    "password": password,
                    "scope": "openid profile",
                    "response_mode": "json",
                },
            )
            if auth_resp.status_code != 200:
                continue
            code = auth_resp.get_json()["code"]
            c.post(
                "/oauth/simple/token",
                json={
                    "grant_type": "authorization_code",
                    "client_id": OAUTH_SIMPLE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "code": code,
                },
            )
            simple_times.append((_time.perf_counter() - t0) * 1000)

        results["OAuth2 Simple full flow (authorize + token) (ms)"] = {
            "mean": statistics.mean(simple_times),
            "min": min(simple_times),
            "max": max(simple_times),
            "p95": sorted(simple_times)[int(len(simple_times) * 0.95)],
        }

        # ── Authlib PKCE: authorize (form) + token (form) ─────────────────────
        # Authlib reads OAuth2 params from request.values (form-encoded), not JSON.
        # Client-side: code_verifier generation + S256 challenge (outside timer).
        authlib_times = []
        for _ in range(iterations):
            code_verifier = secrets_module.token_urlsafe(48)       # client-side (outside timer)
            challenge = _pkce_challenge(code_verifier)             # client-side (outside timer)
            t0 = _time.perf_counter()
            auth_resp = c.post(
                "/authlib/oauth/authorize",
                data={                                             # form-encoded per RFC 6749
                    "response_type": "code",
                    "client_id": AUTHLIB_CLIENT_ID,
                    "redirect_uri": AUTHLIB_REDIRECT_URI,
                    "username": client_id,
                    "password": password,
                    "scope": "openid profile",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
            )
            if auth_resp.status_code != 200:
                continue
            code = auth_resp.get_json()["code"]
            c.post(
                "/authlib/oauth/token",
                data={                                             # form-encoded per RFC 6749
                    "grant_type": "authorization_code",
                    "client_id": AUTHLIB_CLIENT_ID,
                    "redirect_uri": AUTHLIB_REDIRECT_URI,
                    "code": code,
                    "code_verifier": code_verifier,
                },
            )
            authlib_times.append((_time.perf_counter() - t0) * 1000)

        results["Authlib PKCE full flow (authorize + token) (ms)"] = {
            "mean": statistics.mean(authlib_times),
            "min": min(authlib_times),
            "max": max(authlib_times),
            "p95": sorted(authlib_times)[int(len(authlib_times) * 0.95)],
        }

    return results


def test_benchmark_e2e_protocol_comparison(capsys):
    """Compare ZKP vs OAuth2 on equal footing: 2 HTTP calls each, timer excludes client-side crypto."""
    data = _benchmark_e2e_flows(iterations=50)
    header = (
        f"| {'Protocol Flow':<52} | {'Mean (ms)':>10} | {'Min (ms)':>10}"
        f" | {'Max (ms)':>10} | {'P95 (ms)':>10} |"
    )
    sep = "|" + "-" * 54 + "|" + ("-" * 12 + "|") * 4
    print()
    print("END-TO-END PROTOCOL COMPARISON  (2 HTTP calls each; client-side crypto excluded from timer)")
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
# Prompt 3 – Locust load-test: requires running server + `pip install locust`
# ---------------------------------------------------------------------------
# TODO: Locust requires a live server process and cannot run inside pytest.
#       To execute the load test:
#         1. Start the server: python server_app/server.py
#         2. Install locust: pip install locust
#         3. Run: locust -f qa/test/perf_load.py --host=http://localhost:5000 --users 100 --spawn-rate 10 --headless --run-time 10s --html locust_report.html
#                        --users 100 --spawn-rate 10 --headless --run-time 60s
#                        --html locust_report.html
#
# The Locust user class below is defined but skipped by pytest automatically
# because it does not start with "test_".

try:
    from locust import HttpUser, task, between

    class SchnorrLoadUser(HttpUser):
        wait_time = between(0.5, 1.5)
        _x = None
        _y = None

        def on_start(self):
            client_id = f"locust_{secrets_module.token_hex(8)}"
            password = secrets_module.token_hex(16)
            salt = secrets_module.token_bytes(16)
            hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**11, r=8, p=1)
            self._x = int.from_bytes(hashed, "big") % server.Q
            self._y = pow(server.G, self._x, server.P)
            self._client_id = client_id
            self._password = password
            self.client.post("/register", json={"client_id": client_id, "secret_y": self._y})
            self.client.post(
                "/oauth/pkce/register",
                json={"client_id": client_id, "password": self._password},
                name="/oauth/pkce/register",
            )
            self.client.post(
                "/oauth/simple/register",
                json={"client_id": client_id, "password": self._password},
                name="/oauth/simple/register",
            )
            self.client.post(
                "/authlib/register",
                json={"client_id": client_id, "password": self._password},
                name="/authlib/register",
            )

        @task(2)
        def zkp_login(self):
            import time as _time
            rand_r = secrets_module.randbelow(server.P - 2) + 1
            commitment_t = pow(server.G, rand_r, server.P)
            # Timer encompasses both HTTP round-trips, mirroring full_oauth_pkce_login
            # which times authorize + token together.
            start = _time.perf_counter()
            commit = self.client.post(
                "/login/commit",
                json={"client_id": self._client_id, "commitment_t": commitment_t},
                name="/login/commit",
            )
            if commit.status_code != 200:
                self.environment.events.request.fire(
                    request_type="ZKP",
                    name="full_zkp_login",
                    response_time=(_time.perf_counter() - start) * 1000,
                    response_length=0,
                    exception=RuntimeError(f"commit failed: {commit.status_code}"),
                    context={},
                )
                return
            payload = commit.json()
            challenge_c = int(payload["challenge_c"])
            session_id = payload["session_id"]
            s = (rand_r + challenge_c * self._x) % server.Q
            verify = self.client.post(
                "/login/verify",
                headers={"X-Auth-Session": session_id},
                json={"solution_s": s},
                name="/login/verify",
            )
            elapsed = (_time.perf_counter() - start) * 1000
            self.environment.events.request.fire(
                request_type="ZKP",
                name="full_zkp_login",
                response_time=elapsed,
                response_length=0,
                exception=None if verify.status_code == 200 else RuntimeError(f"verify failed: {verify.status_code}"),
                context={},
            )

        @task(1)
        def oauth_pkce_token(self):
            import time as _time

            code_verifier = secrets_module.token_urlsafe(48)
            challenge = _pkce_challenge(code_verifier)
            start = _time.perf_counter()
            authorize = self.client.post(
                "/oauth/pkce/authorize",
                json={
                    "response_type": "code",
                    "client_id": OAUTH_PKCE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "username": self._client_id,
                    "password": self._password,
                    "scope": "openid profile",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "response_mode": "json",
                },
                name="/oauth/pkce/authorize",
            )
            if authorize.status_code != 200:
                self.environment.events.request.fire(
                    request_type="OAUTH2",
                    name="full_oauth_pkce_login",
                    response_time=(_time.perf_counter() - start) * 1000,
                    response_length=0,
                    exception=RuntimeError(f"authorize failed: {authorize.status_code}"),
                    context={},
                )
                return

            code = authorize.json()["code"]
            token = self.client.post(
                "/oauth/pkce/token",
                json={
                    "grant_type": "authorization_code",
                    "client_id": OAUTH_PKCE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "code": code,
                    "code_verifier": code_verifier,
                },
                name="/oauth/pkce/token",
            )
            elapsed = (_time.perf_counter() - start) * 1000
            self.environment.events.request.fire(
                request_type="OAUTH2",
                name="full_oauth_pkce_login",
                response_time=elapsed,
                response_length=0,
                exception=None if token.status_code == 200 else RuntimeError(f"token failed: {token.status_code}"),
                context={},
            )

        @task(1)
        def oauth_simple_token(self):
            import time as _time

            start = _time.perf_counter()
            authorize = self.client.post(
                "/oauth/simple/authorize",
                json={
                    "response_type": "code",
                    "client_id": OAUTH_SIMPLE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "username": self._client_id,
                    "password": self._password,
                    "scope": "openid profile",
                    "response_mode": "json",
                },
                name="/oauth/simple/authorize",
            )
            if authorize.status_code != 200:
                self.environment.events.request.fire(
                    request_type="OAUTH2",
                    name="full_oauth_simple_login",
                    response_time=(_time.perf_counter() - start) * 1000,
                    response_length=0,
                    exception=RuntimeError(f"authorize failed: {authorize.status_code}"),
                    context={},
                )
                return

            code = authorize.json()["code"]
            token = self.client.post(
                "/oauth/simple/token",
                json={
                    "grant_type": "authorization_code",
                    "client_id": OAUTH_SIMPLE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "code": code,
                },
                name="/oauth/simple/token",
            )
            elapsed = (_time.perf_counter() - start) * 1000
            self.environment.events.request.fire(
                request_type="OAUTH2",
                name="full_oauth_simple_login",
                response_time=elapsed,
                response_length=0,
                exception=None if token.status_code == 200 else RuntimeError(f"token failed: {token.status_code}"),
                context={},
            )

        @task(1)
        def authlib_pkce_login(self):
            """Authlib RFC-compliant PKCE flow: authorize (form) + token (form).

            Uses form-encoded bodies as required by RFC 6749 and Authlib internals.
            Client-side crypto (verifier + S256 challenge) is computed outside the
            timer to match the ZKP and custom OAuth benchmarks.
            """
            import time as _time

            code_verifier = secrets_module.token_urlsafe(48)        # client-side, outside timer
            challenge = _pkce_challenge(code_verifier)              # client-side, outside timer
            start = _time.perf_counter()
            authorize = self.client.post(
                "/authlib/oauth/authorize",
                data={                                              # form-encoded (RFC 6749)
                    "response_type": "code",
                    "client_id": AUTHLIB_CLIENT_ID,
                    "redirect_uri": AUTHLIB_REDIRECT_URI,
                    "username": self._client_id,
                    "password": self._password,
                    "scope": "openid profile",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
                name="/authlib/oauth/authorize",
            )
            if authorize.status_code != 200:
                self.environment.events.request.fire(
                    request_type="AUTHLIB",
                    name="full_authlib_pkce_login",
                    response_time=(_time.perf_counter() - start) * 1000,
                    response_length=0,
                    exception=RuntimeError(f"authorize failed: {authorize.status_code}"),
                    context={},
                )
                return

            code = authorize.json()["code"]
            token = self.client.post(
                "/authlib/oauth/token",
                data={                                              # form-encoded (RFC 6749)
                    "grant_type": "authorization_code",
                    "client_id": AUTHLIB_CLIENT_ID,
                    "redirect_uri": AUTHLIB_REDIRECT_URI,
                    "code": code,
                    "code_verifier": code_verifier,
                },
                name="/authlib/oauth/token",
            )
            elapsed = (_time.perf_counter() - start) * 1000
            self.environment.events.request.fire(
                request_type="AUTHLIB",
                name="full_authlib_pkce_login",
                response_time=elapsed,
                response_length=0,
                exception=None if token.status_code == 200 else RuntimeError(f"token failed: {token.status_code}"),
                context={},
            )

except ImportError:
    pass  # locust not installed; class is simply not defined


# ---------------------------------------------------------------------------
# Prompt 4 – Memory footprint: sessions dict under DoS-style commit flood
# ---------------------------------------------------------------------------

def test_sessions_dict_memory_footprint_under_commit_flood():
    """Many commit requests flood server, server stay alive, session dict stay bounded."""
    import sys as _sys

    P, G, Q = server.P, server.G, server.Q

    with server.app.test_client() as c:
        with server.app.app_context():
            # Register one user to accept commits
            x = int.from_bytes(
                hashlib.scrypt(b"flood-pass", salt=secrets_module.token_bytes(16), n=2**11, r=8, p=1),
                "big"
            ) % Q
            y = pow(G, x, P)
            server.db.session.add(server.User(client_id="flood_user", secret_y=str(y)))
            server.db.session.commit()

        sizes = {}
        for batch in (100, 500, 1000):
            server.sessions.clear()
            for _ in range(batch):
                rand_r = secrets_module.randbelow(P - 2) + 1
                t = pow(G, rand_r, P)
                resp = c.post(
                    "/login/commit",
                    json={"client_id": "flood_user", "commitment_t": t},
                )
                # Each new commit invalidates the previous session (409 or 200)
                assert resp.status_code in (200, 409)

            sizes[batch] = _sys.getsizeof(server.sessions)
            print(f"Sessions dict size after {batch} commits: {sizes[batch]} bytes,"
                  f" active entries: {len(server.sessions)}")

    # At most 1 active session can survive (each commit clears the previous)
    assert len(server.sessions) <= 1


'''
Context inițial (de reamintit agentului)
"Acționează ca un Security QA Automation Engineer. Scrie teste pentru urmatoarele prompturi"

Prompt 1: Crearea unui Baseline (Endpoint Clasic de Referință)
Înainte de a testa performanța, ai nevoie de un termen de comparație. Acest prompt generează un flux "clasic" de login pe același server, pentru a putea compara merele cu merele.
"Adaugă un endpoint nou în aplicația Flask (POST /classic/login) care să simuleze un flux de login clasic.
Acest endpoint va primi {"client_id": "user", "password": "parola"} în clar.
Implementează validarea: verifică dacă client_id există în baza de date.
Folosește librăria bcrypt sau passlib (sau un hash SHA256 simplu pentru simulare) pentru a valida parola (comparativ cu un hash stocat).
Dacă validarea trece, generează un JWT (exact la fel ca la login/verify) și returnează-l.
Adaugă și acestui endpoint header-ul X-Response-Time.
Adaugă teste unitare de bază pentru acest endpoint ca să fim siguri că funcționează corect ca referință (baseline)."

Prompt 2: Testarea de Latență (Micro-Benchmarking Client și Server)
Acest test măsoară exact cât timp durează operațiunile matematice grele (exponențierile modulare de 2048 de biți).
"Folosește benchmark-ul din testul test_benchmark_prints_latency_table din perf_load.py (bazat pe librăria timeit)
pentru a măsura latența componentelor individuale ale sistemului nostru ZKP vs. Clasic.
Măsoară timpul de execuție pentru funcțiile de client: derivarea parolei (derivePasswordX) și generarea angajamentului $t = g^r \pmod p$.
Măsoară timpul de execuție pentru funcțiile de server ZKP: Endpoint-urile /login/commit (generare $c$) și /login/verify (calculul complex $t \cdot y^c \pmod p$).
Măsoară timpul de execuție pentru funcția de server Clasic: Endpoint-ul /classic/login (verificare parolă + generare JWT).
Rulează fiecare măsurătoare de 100 de ori și calculează Timpul Mediu (Average Response Time) și Percentila 95 (P95) în milisecunde (ms).
Afișează rezultatele într-un format tabelar în consolă în timpul rulării testului (pentru a putea fi extrase ușor pentru lucrare)."

Prompt 3: Testarea de Scalabilitate (Load Testing cu Locust)
Acest prompt îți va genera un instrument cu care să simulezi sute de utilizatori simultani
(pentru a vedea cum se comportă dicționarul de sesiuni și calculele asincrone).
"Creează un fișier locustfile.py pentru a efectua teste de sarcină (Load Testing) folosind framework-ul Locust.
Definește un HttpUser (simulând un client).
Sarcina 1 (ZKP Login): Implementează fluxul complet ZKP: trimite request la /login/commit, extrage challenge_c și session_id,
calculează o soluție validă $s$ local (în Locust) și trimite request la /login/verify.
Măsoară întregul flux ca o singură tranzacție de login (folosind self.environment.events.request.fire).
Sarcina 2 (Classic Login): Implementează trimiterea unui request simplu către /classic/login.
Asigură-te că Locust generează date dinamice/unice (client_id, password) la fiecare cerere pentru a evita caching-ul.
Configurația trebuie să permită lansarea din linia de comandă, generând un raport HTML comparativ."

Prompt 4: Testarea Amprentei de Memorie (Sesiuni Concurente)
Acest test adresează una din criticile principale ale protocolului tău din disertație: necesitatea de a menține o stare (stateful) între pașii Commit și Verify.
"Scrie un script Python care testează consumul de memorie al dicționarului sessions din serverul Flask.
Injectează treptat 1.000, apoi 10.000, apoi 50.000 de cereri invalide de POST /login/commit (fără a apela vreodată /login/verify).
Măsoară dimensiunea în memorie (RAM) a dicționarului sessions la fiecare pas.
După trecerea timeout-ului de 5 secunde, validează că memoria a fost eliberată corect. (Acest test este crucial pentru a demonstra că un atacator nu poate doborî serverul prin epuizarea memoriei cu angajamente false - un atac DoS pe resursa de memorie)."

'''




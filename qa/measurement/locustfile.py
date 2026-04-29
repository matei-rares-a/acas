'''Testarea de Scalabilitate (Load Testing cu Locust) - simulare utilizatori simultani ZKP si OAuth2'''
"""HttpUser spawn with unique credentials on start, ZKP task do full commit+verify flow and fire single timed transaction, OAuth tasks do authorize+token flow, Locust collect stats and write HTML report on exit."""

# locustfile.py — Locust load-test scenarios for all four auth protocols.
# Run against a live server:
#   python server_app/server.py
#   locust -f qa/measurement/locustfile.py --host=http://localhost:5000 --users 100 --spawn-rate 10 --headless --run-time 60s --html qa/measurement/generated/locust_report.html
#

from pathlib import Path
import secrets as secrets_module
import sys
import time as _time

from locust import HttpUser, task, between

_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))
from qa_utils import (
    server,
    derive_password_x,
    pkce_challenge,
    OAUTH_PKCE_CLIENT_ID,
    OAUTH_SIMPLE_CLIENT_ID,
    OAUTH_REDIRECT_URI,
    AUTHLIB_CLIENT_ID,
    AUTHLIB_REDIRECT_URI,
)


class SchnorrLoadUser(HttpUser):
    wait_time = between(0.5, 1.5)
    _x = None
    _y = None

    def on_start(self):
        client_id = f"locust_{secrets_module.token_hex(8)}"
        password = secrets_module.token_hex(16)
        self._x, self._salt = derive_password_x(password)
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

    @task(1)
    def zkp_login(self):
        start = _time.perf_counter()
        rand_r = secrets_module.randbelow(server.P - 2) + 1          # client-side (inside timer)
        commitment_t = pow(server.G, rand_r, server.P)               # client-side (inside timer)
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
        x,_ = derive_password_x(self._password, self._salt)
        s = (rand_r + challenge_c * x) % server.Q
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
    def oauth_pkce_login(self):
        start = _time.perf_counter()
        code_verifier = secrets_module.token_urlsafe(48)              # client-side (inside timer)
        challenge = pkce_challenge(code_verifier)                    # client-side (inside timer)
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
    def oauth_simple_login(self):
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
        start = _time.perf_counter()
        code_verifier = secrets_module.token_urlsafe(48)              # client-side (inside timer)
        challenge = pkce_challenge(code_verifier)                    # client-side (inside timer)
        authorize = self.client.post(
            "/authlib/oauth/authorize",
            data={                                              # form-encoded per RFC 6749
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
            data={                                              # form-encoded per RFC 6749
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

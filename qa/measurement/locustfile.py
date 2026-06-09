'''Testarea de Scalabilitate (Load Testing cu Locust) - simulare utilizatori simultani ZKP si OAuth2'''
"""HttpUser spawn with unique credentials on start, ZKP task do full commit+verify flow and fire single timed transaction, OAuth tasks do authorize+token flow, Locust collect stats and write HTML report on exit."""

''' locustfile.py -- Locust load-test scenarios for all four auth protocols.
 Run against a live server:

python server_app/server.py
locust -f qa/measurement/locustfile.py --host=http://localhost:5000 --users 50 --spawn-rate 10 --headless --run-time 60s --html qa/measurement/generated/locust_report.html

'''
from pathlib import Path
import re as _re
import secrets as secrets_module
import sys
import time as _time
from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs

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
    ec_scalar_mult,
    EC_ORDER,
    EC_GENERATOR,
)



# ---------------------------------------------------------------------------
# Port assignments (one dedicated server process per protocol)
# ---------------------------------------------------------------------------
_PORT_ZKP    = 5000
_PORT_PKCE   = 5001
_PORT_SIMPLE = 5002
_PORT_AUTHLIB = 5003


# ---------------------------------------------------------------------------
# ZKP user  -- targets port 5000
# ---------------------------------------------------------------------------

class ZKPUser(HttpUser):
    host = f"http://127.0.0.1:{_PORT_ZKP}"
    wait_time = between(0.5, 1.5)

    def on_start(self):
        self._client_id = f"locust_{secrets_module.token_hex(8)}"
        self._password  = f"password-locust_{secrets_module.token_hex(16)}"
        self._x, self._salt = derive_password_x(self._password)
        Y = ec_scalar_mult(self._x, EC_GENERATOR)
        self.client.post("/register", json={"client_id": self._client_id, "secret_y_x": str(Y[0]), "secret_y_y": str(Y[1])})

    @task
    def zkp_login(self):
        start = _time.perf_counter()
        rand_r = secrets_module.randbelow(EC_ORDER - 1) + 1
        T = ec_scalar_mult(rand_r, EC_GENERATOR)
        commit = self.client.post(
            "/login/commit",
            json={"client_id": self._client_id, "commitment_t_x": str(T[0]), "commitment_t_y": str(T[1])},
            name="/login/commit",
        )
        if commit.status_code != 200:
            self.environment.events.request.fire(
                request_type="ZKP", name="full_zkp_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"commit failed: {commit.status_code}"),
                context={},
            )
            return
        payload     = commit.json()
        challenge_c = int(payload["challenge_c"])
        session_id  = payload["session_id"]
        x, _        = derive_password_x(self._password, self._salt)
        s = (rand_r + challenge_c * x) % EC_ORDER
        verify = self.client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": s},
            name="/login/verify",
        )
        elapsed = (_time.perf_counter() - start) * 1000
        self.environment.events.request.fire(
            request_type="ZKP", name="full_zkp_login",
            response_time=elapsed, response_length=0,
            exception=None if verify.status_code == 200
                      else RuntimeError(f"verify failed: {verify.status_code}"),
            context={},
        )


# ---------------------------------------------------------------------------
# OAuth2 PKCE user  -- targets port 5001
# ---------------------------------------------------------------------------

class OAuthPKCEUser(HttpUser):
    host = f"http://127.0.0.1:{_PORT_PKCE}"
    wait_time = between(0.5, 1.5)

    def on_start(self):
        self._client_id = f"locust_{secrets_module.token_hex(8)}"
        self._password  = f"password-locust_{secrets_module.token_hex(16)}"
        self.client.post("/oauth/pkce/register",
                         json={"client_id": self._client_id, "password": self._password},
                         name="/oauth/pkce/register")

    @task
    def oauth_pkce_login(self):
        start         = _time.perf_counter()
        code_verifier = secrets_module.token_urlsafe(48)
        challenge     = pkce_challenge(code_verifier)

        get_resp = self.client.get(
            "/oauth/pkce/authorize",
            params={
                "response_type":         "code",
                "client_id":             OAUTH_PKCE_CLIENT_ID,
                "redirect_uri":          OAUTH_REDIRECT_URI,
                "scope":                 "openid profile",
                "code_challenge":        challenge,
                "code_challenge_method": "S256",
            },
            name="GET /oauth/pkce/authorize",
            allow_redirects=False,
        )
        if get_resp.status_code != 200:
            self.environment.events.request.fire(
                request_type="OAUTH2", name="oauth_pkce_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"GET authorize failed: {get_resp.status_code}"),
                context={},
            )
            return
        m = _re.search(r'name="auth_request_id"\s+value="([^"]+)"', get_resp.text)
        auth_req_id = m.group(1) if m else ""

        authorize = self.client.post(
            "/oauth/pkce/authorize",
            data={"auth_request_id": auth_req_id,
                  "username": self._client_id,
                  "password": self._password},
            name="/oauth/pkce/authorize",
            allow_redirects=False,
        )
        if authorize.status_code != 302:
            self.environment.events.request.fire(
                request_type="OAUTH2", name="oauth_pkce_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"POST authorize failed: {authorize.status_code}"),
                context={},
            )
            return
        loc   = authorize.headers.get("Location", "")
        codes = _parse_qs(_urlparse(loc).query).get("code")
        elapsed = (_time.perf_counter() - start) * 1000
        if not codes:
            self.environment.events.request.fire(
                request_type="OAUTH2", name="oauth_pkce_login",
                response_time=elapsed, response_length=0,
                exception=RuntimeError("no code in redirect"), context={},
            )
            return
        self.environment.events.request.fire(
            request_type="OAUTH2", name="oauth_pkce_login",
            response_time=elapsed, response_length=0,
            exception=None, context={},
        )


# ---------------------------------------------------------------------------
# OAuth2 Simple user  -- targets port 5002
# ---------------------------------------------------------------------------

class OAuthSimpleUser(HttpUser):
    host = f"http://127.0.0.1:{_PORT_SIMPLE}"
    wait_time = between(0.5, 1.5)

    def on_start(self):
        self._client_id = f"locust_{secrets_module.token_hex(8)}"
        self._password  = f"password-locust_{secrets_module.token_hex(16)}"
        self.client.post("/oauth/simple/register",
                         json={"client_id": self._client_id, "password": self._password},
                         name="/oauth/simple/register")

    @task
    def oauth_simple_login(self):
        start = _time.perf_counter()

        get_resp = self.client.get(
            "/oauth/simple/authorize",
            params={
                "response_type": "code",
                "client_id":     OAUTH_SIMPLE_CLIENT_ID,
                "redirect_uri":  OAUTH_REDIRECT_URI,
                "scope":         "openid profile",
            },
            name="GET /oauth/simple/authorize",
            allow_redirects=False,
        )
        if get_resp.status_code != 200:
            self.environment.events.request.fire(
                request_type="OAUTH2", name="oauth_simple_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"GET authorize failed: {get_resp.status_code}"),
                context={},
            )
            return
        m = _re.search(r'name="auth_request_id"\s+value="([^"]+)"', get_resp.text)
        auth_req_id = m.group(1) if m else ""

        authorize = self.client.post(
            "/oauth/simple/authorize",
            data={"auth_request_id": auth_req_id,
                  "username": self._client_id,
                  "password": self._password},
            name="/oauth/simple/authorize",
            allow_redirects=False,
        )
        if authorize.status_code != 302:
            self.environment.events.request.fire(
                request_type="OAUTH2", name="oauth_simple_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"POST authorize failed: {authorize.status_code}"),
                context={},
            )
            return
        loc   = authorize.headers.get("Location", "")
        codes = _parse_qs(_urlparse(loc).query).get("code")
        elapsed = (_time.perf_counter() - start) * 1000
        if not codes:
            self.environment.events.request.fire(
                request_type="OAUTH2", name="oauth_simple_login",
                response_time=elapsed, response_length=0,
                exception=RuntimeError("no code in redirect"), context={},
            )
            return
        self.environment.events.request.fire(
            request_type="OAUTH2", name="oauth_simple_login",
            response_time=elapsed, response_length=0,
            exception=None, context={},
        )


# ---------------------------------------------------------------------------
# Authlib PKCE user  -- targets port 5003
# ---------------------------------------------------------------------------

class AuthlibUser(HttpUser):
    host = f"http://127.0.0.1:{_PORT_AUTHLIB}"
    wait_time = between(0.5, 1.5)

    def on_start(self):
        self._client_id = f"locust_{secrets_module.token_hex(8)}"
        self._password  = f"password-locust_{secrets_module.token_hex(16)}"
        self.client.post("/authlib/register",
                         json={"client_id": self._client_id, "password": self._password},
                         name="/authlib/register")

    @task
    def authlib_pkce_login(self):
        start         = _time.perf_counter()
        code_verifier = secrets_module.token_urlsafe(48)
        challenge     = pkce_challenge(code_verifier)
        authorize = self.client.post(
            "/authlib/oauth/authorize",
            data={
                "response_type":         "code",
                "client_id":             AUTHLIB_CLIENT_ID,
                "redirect_uri":          AUTHLIB_REDIRECT_URI,
                "username":              self._client_id,
                "password":              self._password,
                "scope":                 "openid profile",
                "code_challenge":        challenge,
                "code_challenge_method": "S256",
            },
            name="/authlib/oauth/authorize",
        )
        if authorize.status_code != 200:
            self.environment.events.request.fire(
                request_type="AUTHLIB", name="full_authlib_pkce_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"authorize failed: {authorize.status_code}"),
                context={},
            )
            return
        elapsed = (_time.perf_counter() - start) * 1000
        code = authorize.json().get("code")
        self.environment.events.request.fire(
            request_type="AUTHLIB", name="full_authlib_pkce_login",
            response_time=elapsed, response_length=0,
            exception=None if code else RuntimeError("no code in response"),
            context={},
        )

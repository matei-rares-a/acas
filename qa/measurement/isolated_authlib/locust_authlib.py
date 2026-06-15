"""Locust load test — Authlib PKCE only, port 5300 (izolat, fara competitie cu alte servere)."""
import re as _re
import secrets as _secrets
import sys
import time as _time
from pathlib import Path
from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs

from locust import HttpUser, task

_QA_PATH = Path(__file__).resolve().parents[2]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))

from qa_utils import AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI
from qa_utils import pkce_challenge

_PORT = 5300


class AuthlibUser(HttpUser):
    host = f"http://127.0.0.1:{_PORT}"

    def on_start(self):
        self._client_id = f"locust_{_secrets.token_hex(8)}"
        self._password  = f"pw-{_secrets.token_hex(16)}"
        self.client.post(
            "/authlib/register",
            json={"client_id": self._client_id, "password": self._password},
            name="/authlib/register",
        )

    @task
    def authlib_pkce_login(self):
        start         = _time.perf_counter()
        code_verifier = _secrets.token_urlsafe(48)
        challenge     = pkce_challenge(code_verifier)

        # 1) GET authorize — validate params, receive HTML form with auth_request_id
        get_resp = self.client.get(
            "/authlib/oauth/authorize",
            params={
                "response_type":         "code",
                "client_id":             AUTHLIB_CLIENT_ID,
                "redirect_uri":          AUTHLIB_REDIRECT_URI,
                "scope":                 "openid profile",
                "code_challenge":        challenge,
                "code_challenge_method": "S256",
            },
            name="GET /authlib/oauth/authorize",
            allow_redirects=False,
        )
        if get_resp.status_code != 200:
            self.environment.events.request.fire(
                request_type="AUTHLIB", name="full_authlib_pkce_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"GET authorize {get_resp.status_code}"),
                context={},
            )
            return

        m = _re.search(r'name="auth_request_id"\s+value="([^"]+)"', get_resp.text)
        auth_req_id = m.group(1) if m else ""

        # 2) POST credentials only (OAuth2 params sunt in pending store)
        authorize = self.client.post(
            "/authlib/oauth/authorize",
            data={
                "auth_request_id": auth_req_id,
                "username":        self._client_id,
                "password":        self._password,
            },
            name="POST /authlib/oauth/authorize",
            allow_redirects=False,
        )
        if authorize.status_code != 302:
            self.environment.events.request.fire(
                request_type="AUTHLIB", name="full_authlib_pkce_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"POST authorize {authorize.status_code}"),
                context={},
            )
            return

        loc   = authorize.headers.get("Location", "")
        codes = _parse_qs(_urlparse(loc).query).get("code")
        if not codes:
            self.environment.events.request.fire(
                request_type="AUTHLIB", name="full_authlib_pkce_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError("no code in redirect"),
                context={},
            )
            return

        # 3) POST token exchange
        token_resp = self.client.post(
            "/authlib/oauth/token",
            data={
                "grant_type":    "authorization_code",
                "code":          codes[0],
                "client_id":     AUTHLIB_CLIENT_ID,
                "redirect_uri":  AUTHLIB_REDIRECT_URI,
                "code_verifier": code_verifier,
            },
            name="POST /authlib/oauth/token",
        )

        elapsed = (_time.perf_counter() - start) * 1000
        self.environment.events.request.fire(
            request_type="AUTHLIB", name="full_authlib_pkce_login",
            response_time=elapsed,
            response_length=0,
            exception=None if token_resp.status_code == 200
                      else RuntimeError(f"token {token_resp.status_code}"),
            context={},
        )

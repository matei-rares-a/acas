import re as _re
import secrets as secrets_module
from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs

import pytest

from qa_utils import (
    server, pkce_challenge,
    OAUTH_PKCE_CLIENT_ID, OAUTH_SIMPLE_CLIENT_ID, OAUTH_REDIRECT_URI,
    AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI,
    OAuthTestSuite,
)


def _register_oauth(client, client_id, password):
    """Register user credentials for ZKP, PKCE, Simple and Authlib OAuth."""
    from qa_utils import derive_password_x
    x,_ = derive_password_x(password)
    y = pow(server.G, x, server.P)
    resp = client.post("/register", json={"client_id": client_id, "secret_y": y})
    assert resp.status_code in (200, 201)
    assert client.post("/oauth/pkce/register",   json={"client_id": client_id, "password": password}).status_code == 201
    assert client.post("/oauth/simple/register", json={"client_id": client_id, "password": password}).status_code == 201
    assert client.post("/authlib/register",      json={"client_id": client_id, "password": password}).status_code == 201
    return x, y


def _code_from_redirect(resp):
    """Parse the authorization code from a 302 Location header."""
    loc = resp.headers.get("Location", "")
    codes = _parse_qs(_urlparse(loc).query).get("code")
    return codes[0] if codes else None


def _authorize_oauth_pkce(client, username, password, code_verifier=None, scope="openid profile"):
    """Execute the RFC 6749 browser-style authorize flow for PKCE.
    Step 1: GET /oauth/pkce/authorize  -> HTML login form (auth_request_id hidden field).
    Step 2: POST /oauth/pkce/authorize (form) -> 302 redirect with code, or 4xx JSON on error.
    Returns (post_resp, code_verifier).
    """
    if code_verifier is None:
        code_verifier = secrets_module.token_urlsafe(48)

    get_resp = client.get(
        "/oauth/pkce/authorize",
        query_string={
            "response_type":         "code",
            "client_id":             OAUTH_PKCE_CLIENT_ID,
            "redirect_uri":          OAUTH_REDIRECT_URI,
            "scope":                 scope,
            "code_challenge":        pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        },
    )
    if get_resp.status_code != 200:
        return get_resp, code_verifier

    html = get_resp.data.decode("utf-8")
    m = _re.search(r'name="auth_request_id"\s+value="([^"]+)"', html)
    auth_request_id = m.group(1) if m else ""

    post_resp = client.post(
        "/oauth/pkce/authorize",
        data={"auth_request_id": auth_request_id, "username": username, "password": password},
        follow_redirects=False,
    )
    return post_resp, code_verifier


def _exchange_oauth_pkce_code(client, code, code_verifier):
    return client.post(
        "/oauth/pkce/token",
        json={
            "grant_type":    "authorization_code",
            "client_id":     OAUTH_PKCE_CLIENT_ID,
            "redirect_uri":  OAUTH_REDIRECT_URI,
            "code":          code,
            "code_verifier": code_verifier,
        },
    )


def _authorize_oauth_simple(client, username, password, scope="openid profile"):
    """Execute the RFC 6749 browser-style authorize flow for Simple OAuth.
    Step 1: GET /oauth/simple/authorize -> HTML login form.
    Step 2: POST /oauth/simple/authorize (form) -> 302 redirect with code, or 4xx JSON on error.
    Returns post_resp.
    """
    get_resp = client.get(
        "/oauth/simple/authorize",
        query_string={
            "response_type": "code",
            "client_id":     OAUTH_SIMPLE_CLIENT_ID,
            "redirect_uri":  OAUTH_REDIRECT_URI,
            "scope":         scope,
        },
    )
    if get_resp.status_code != 200:
        return get_resp

    html = get_resp.data.decode("utf-8")
    m = _re.search(r'name="auth_request_id"\s+value="([^"]+)"', html)
    auth_request_id = m.group(1) if m else ""

    return client.post(
        "/oauth/simple/authorize",
        data={"auth_request_id": auth_request_id, "username": username, "password": password},
        follow_redirects=False,
    )

def _exchange_oauth_simple_code(client, code):
    return client.post(
        "/oauth/simple/token",
        json={
            "grant_type":   "authorization_code",
            "client_id":    OAUTH_SIMPLE_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "code":         code,
        },
    )


class TestOAuthCases(OAuthTestSuite):

    def test_oauth_pkce_authorize_returns_authorization_code(self, client):
        '''Testare endpoint authorize OAuth PKCE - emitere cod de autorizare dupa autentificare'''
        """OAuth PKCE authorize endpoint should issue an authorization code after user login."""
        _register_oauth(client, "oauth_user", "oauth-pass")
        resp, _ = _authorize_oauth_pkce(client, "oauth_user", "oauth-pass")
        assert resp.status_code == 302
        code = _code_from_redirect(resp)
        assert code is not None
        assert OAUTH_REDIRECT_URI in resp.headers["Location"]


    def test_oauth_pkce_token_returns_bearer_and_refresh_tokens(self, client):
        '''Testare endpoint token OAuth PKCE - schimb cod de autorizare contra tokeni bearer'''
        """OAuth PKCE token endpoint should exchange a valid authorization code for bearer tokens."""
        _register_oauth(client, "oauth_user", "oauth-pass")
        auth_resp, code_verifier = _authorize_oauth_pkce(client, "oauth_user", "oauth-pass")
        assert auth_resp.status_code == 302
        resp = _exchange_oauth_pkce_code(client, _code_from_redirect(auth_resp), code_verifier)
        assert resp.status_code == 200
        payload = resp.get_json()
        assert "access_token" in payload
        assert "refresh_token" in payload
        assert payload.get("token_type") == "Bearer"
        assert isinstance(payload.get("expires_in"), int)


    def test_oauth_pkce_authorize_wrong_password_returns_access_denied(self, client):
        '''Testare respingere autentificare OAuth PKCE cu parola gresita'''
        """OAuth PKCE authorize should deny resource owner authentication failures."""
        _register_oauth(client, "oauth_user2", "correct-pass")
        resp, _ = _authorize_oauth_pkce(client, "oauth_user2", "wrong-pass")
        assert resp.status_code == 401
        assert resp.get_json().get("error") == "access_denied"


    def test_oauth_pkce_token_wrong_verifier_returns_invalid_grant(self, client):
        '''Testare respingere schimb token OAuth PKCE cu code_verifier nepotrivit'''
        """OAuth PKCE token exchange must reject mismatched PKCE verifiers."""
        _register_oauth(client, "oauth_user3", "oauth-pass")
        auth_resp, _ = _authorize_oauth_pkce(client, "oauth_user3", "oauth-pass", code_verifier="expected-verifier")
        assert auth_resp.status_code == 302
        resp = _exchange_oauth_pkce_code(client, _code_from_redirect(auth_resp), "wrong-verifier")
        assert resp.status_code == 400
        assert resp.get_json().get("error") == "invalid_grant"


    def test_oauth_pkce_refresh_token_returns_new_access_token(self, client):
        '''Testare refresh token OAuth PKCE - emitere token nou si rotatie refresh token'''
        """OAuth PKCE refresh_token grant should issue a new bearer token and rotate refresh tokens."""
        _register_oauth(client, "oauth_user4", "oauth-pass")
        auth_resp, code_verifier = _authorize_oauth_pkce(client, "oauth_user4", "oauth-pass")
        assert auth_resp.status_code == 302
        token_resp = _exchange_oauth_pkce_code(client, _code_from_redirect(auth_resp), code_verifier)
        refresh_token = token_resp.get_json()["refresh_token"]
        refresh_resp = client.post(
            "/oauth/pkce/token",
            json={
                "grant_type":    "refresh_token",
                "client_id":     OAUTH_PKCE_CLIENT_ID,
                "refresh_token": refresh_token,
            },
        )
        assert refresh_resp.status_code == 200
        payload = refresh_resp.get_json()
        assert payload.get("token_type") == "Bearer"
        assert payload.get("refresh_token") != refresh_token


    def test_oauth_simple_token_flow_returns_bearer_and_refresh_tokens(self, client):
        '''Testare flux simplu OAuth - schimb cod fara PKCE contra tokeni bearer'''
        """Simple OAuth flow should exchange authorization code without PKCE verifier."""
        _register_oauth(client, "oauth_simple_user", "oauth-pass")
        auth_resp = _authorize_oauth_simple(client, "oauth_simple_user", "oauth-pass")
        assert auth_resp.status_code == 302
        resp = _exchange_oauth_simple_code(client, _code_from_redirect(auth_resp))
        assert resp.status_code == 200
        payload = resp.get_json()
        assert payload.get("token_type") == "Bearer"
        assert "access_token" in payload
        assert "refresh_token" in payload


    def test_oauth_simple_refresh_token_returns_new_access_token(self, client):
        '''Testare refresh token OAuth simplu - emitere token nou si rotatie refresh token'''
        """Simple OAuth refresh_token grant should issue a new bearer token and rotate refresh tokens."""
        _register_oauth(client, "oauth_simple_user2", "oauth-pass")
        auth_resp = _authorize_oauth_simple(client, "oauth_simple_user2", "oauth-pass")
        assert auth_resp.status_code == 302
        token_resp = _exchange_oauth_simple_code(client, _code_from_redirect(auth_resp))
        refresh_token = token_resp.get_json()["refresh_token"]
        refresh_resp = client.post(
            "/oauth/simple/token",
            json={
                "grant_type":    "refresh_token",
                "client_id":     OAUTH_SIMPLE_CLIENT_ID,
                "refresh_token": refresh_token,
            },
        )
        assert refresh_resp.status_code == 200
        assert refresh_resp.get_json().get("refresh_token") != refresh_token


    # -- Backward-compat aliases  (/oauth/... -> pkce) -------------------------

    def test_oauth_compat_routes_behave_identically_to_pkce(self, client):
        '''Testare rute backward-compat /oauth/register|authorize|token - se comporta ca pkce'''
        """Compat aliases /oauth/register, /oauth/authorize, /oauth/token must behave
        identically to the explicit /oauth/pkce/... endpoints (they map to pkce internally)."""
        import secrets as _s
        code_verifier = _s.token_urlsafe(48)

        # ZKP registration must come first (OAuth register validates user exists)
        from qa_utils import derive_password_x
        x, _ = derive_password_x("compat-pass")
        y = pow(server.G, x, server.P)
        assert client.post("/register", json={"client_id": "compat_user", "secret_y": y}).status_code in (200, 201)

        # Register via compat alias
        assert client.post(
            "/oauth/register",
            json={"client_id": "compat_user", "password": "compat-pass"},
        ).status_code == 201

        # GET /oauth/authorize -> HTML form (compat -> pkce, PKCE S256 required)
        get_resp = client.get(
            "/oauth/authorize",
            query_string={
                "response_type":         "code",
                "client_id":             OAUTH_PKCE_CLIENT_ID,
                "redirect_uri":          OAUTH_REDIRECT_URI,
                "scope":                 "openid profile",
                "code_challenge":        pkce_challenge(code_verifier),
                "code_challenge_method": "S256",
            },
        )
        assert get_resp.status_code == 200
        html = get_resp.data.decode()
        m = _re.search(r'name="auth_request_id"\s+value="([^"]+)"', html)
        auth_request_id = m.group(1) if m else ""

        # POST /oauth/authorize with form credentials
        auth_resp = client.post(
            "/oauth/authorize",
            data={"auth_request_id": auth_request_id, "username": "compat_user", "password": "compat-pass"},
            follow_redirects=False,
        )
        assert auth_resp.status_code == 302
        code = _code_from_redirect(auth_resp)

        # Exchange code via compat alias
        token_resp = client.post(
            "/oauth/token",
            json={
                "grant_type":    "authorization_code",
                "client_id":     OAUTH_PKCE_CLIENT_ID,
                "redirect_uri":  OAUTH_REDIRECT_URI,
                "code":          code,
                "code_verifier": code_verifier,
            },
        )
        assert token_resp.status_code == 200
        payload = token_resp.get_json()
        assert payload.get("token_type") == "Bearer"
        assert "access_token"  in payload
        assert "refresh_token" in payload

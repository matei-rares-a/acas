import secrets as secrets_module

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
            "code_challenge": pkce_challenge(code_verifier),
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

class TestOAuthCases(OAuthTestSuite):

    def test_oauth_pkce_authorize_returns_authorization_code(self, client):
        '''Testare endpoint authorize OAuth PKCE - emitere cod de autorizare dupa autentificare'''
        """OAuth PKCE authorize endpoint should issue an authorization code after user login."""
        _register_oauth(client, "oauth_user", "oauth-pass")
        resp, _ = _authorize_oauth_pkce(client, "oauth_user", "oauth-pass")
        assert resp.status_code == 200
        payload = resp.get_json()
        assert "code" in payload
        assert payload.get("redirect_uri") == OAUTH_REDIRECT_URI
        assert payload.get("expires_in") > 0
        assert "X-Response-Time" in resp.headers


    def test_oauth_pkce_token_returns_bearer_and_refresh_tokens(self, client):
        '''Testare endpoint token OAuth PKCE - schimb cod de autorizare contra tokeni bearer'''
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
        resp = _exchange_oauth_pkce_code(client, auth_resp.get_json()["code"], "wrong-verifier")
        assert resp.status_code == 400
        assert resp.get_json().get("error") == "invalid_grant"


    def test_oauth_pkce_refresh_token_returns_new_access_token(self, client):
        '''Testare refresh token OAuth PKCE - emitere token nou si rotatie refresh token'''
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


    def test_oauth_simple_token_flow_returns_bearer_and_refresh_tokens(self, client):
        '''Testare flux simplu OAuth - schimb cod fara PKCE contra tokeni bearer'''
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


    def test_oauth_simple_refresh_token_returns_new_access_token(self, client):
        '''Testare refresh token OAuth simplu - emitere token nou si rotatie refresh token'''
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

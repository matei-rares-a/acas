"""
Authlib-backed OAuth 2.0 authorization server (RFC 6749 + RFC 7636 PKCE).

This module provides a reference-compliant OAuth2 implementation using the
Authlib library for comparison with ZKP-based auth.

Password verification uses SHA-256 (same as the custom OAuth implementations)
so that all three OAuth variants share an identical, negligible credential-check
cost.  This isolates the pure protocol overhead in benchmark comparisons.

Endpoints:
  POST /authlib/register
      Body (JSON): {"client_id": "...", "password": "..."}
      Stores an SHA-256 hex digest; user must already exist in the ZKP User table.

  POST /authlib/oauth/authorize
      Body (form-data): standard OAuth2 authorization-code + PKCE params
      plus  username=...  password=...  for resource-owner authentication.
      Returns JSON: {"code": "...", "redirect_uri": "...", "expires_in": 120}

  POST /authlib/oauth/token
      Body (form-data): standard authorization_code or refresh_token grant.
      Returns JSON with access_token (signed HS256 JWT), refresh_token, etc.

Note on request encoding
------------------------
Authlib's FlaskOAuth2Request reads parameters from request.values (query
string + form), NOT from JSON.  Therefore all calls to the authorize and
token endpoints must use application/x-www-form-urlencoded (the HTTP
standard for OAuth2), not application/json.  The benchmark and Locust tasks
use data=... (not json=...) accordingly.
"""

import os as _os
import secrets
import time
from datetime import datetime, timedelta, timezone

import hashlib
import jwt as pyjwt
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants, ClientMixin, AuthorizationCodeMixin, TokenMixin
from authlib.oauth2.rfc7636 import CodeChallenge
from flask import jsonify, request


# Allow HTTP during development/testing.  Set AUTHLIB_FORCE_HTTPS=1 in production.
_os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "1")

# ── Module-level state (cleared per test via clear_authlib_state) ────────────

_AUTHLIB_PASSWORDS: dict[str, str] = {}
_AUTHLIB_AUTH_CODES: dict[str, "_AuthCode"] = {}
_AUTHLIB_TOKENS: dict[str, "_Token"] = {}
_AUTHLIB_REFRESH_TOKENS: dict[str, "_Token"] = {}

AUTHLIB_CLIENT_ID = "acas-authlib-client"
AUTHLIB_REDIRECT_URI = "https://client.example/callback"
_AUTHLIB_SECRET: str = ""


def clear_authlib_state() -> None:
    for store in (_AUTHLIB_PASSWORDS, _AUTHLIB_AUTH_CODES,
                  _AUTHLIB_TOKENS, _AUTHLIB_REFRESH_TOKENS):
        store.clear()


# ── Authlib model mixins ──────────────────────────────────────────────────────

class _OAuthClient(ClientMixin):
    """Single hard-coded public client (PKCE, no client_secret)."""

    def get_client_id(self):
        return AUTHLIB_CLIENT_ID

    def get_default_redirect_uri(self):
        return AUTHLIB_REDIRECT_URI

    def get_allowed_scope(self, scope):
        allowed = {"openid", "profile", "read:data", "write:data"}
        requested = set(scope.split()) if scope else set()
        return " ".join(sorted(requested & allowed)) or "openid profile"

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in {AUTHLIB_REDIRECT_URI, "http://localhost:8000/callback"}

    def check_client_secret(self, client_secret):
        return True

    def check_token_endpoint_auth_method(self, method):
        return method in ("none", "client_secret_post", "client_secret_basic")

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == "token":
            return method == "none"
        return True

    def check_response_type(self, response_type):
        return response_type == "code"

    def check_grant_type(self, grant_type):
        return grant_type in ("authorization_code", "refresh_token")

    def has_client_secret(self):
        return False


_CLIENT = _OAuthClient()


class _AuthCode(AuthorizationCodeMixin):
    def __init__(self, code, client_id, redirect_uri, scope,
                 code_challenge, code_challenge_method, subject):
        self.code = code
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.subject = subject
        self._expires_at = time.time() + 120

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return int(time.time())

    def get_nonce(self):
        return None

    def is_expired(self):
        return time.time() > self._expires_at

    def get_code_challenge(self):
        return self.code_challenge

    def get_code_challenge_method(self):
        return self.code_challenge_method


class _Token(TokenMixin):
    def __init__(self, access_token, refresh_token, client_id,
                 scope, subject, issued_at, expires_in):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.scope = scope
        self.subject = subject
        self.issued_at = issued_at
        self.expires_in = expires_in

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + self.expires_in

    def is_expired(self):
        return time.time() > self.get_expires_at()

    def is_revoked(self):
        return False

    def check_client(self, client):
        return self.client_id == client.get_client_id()


# ── Grant implementations ────────────────────────────────────────────────────

class _ACPKCEGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    def save_authorization_code(self, code, request):
        user = request.user or ""
        auth_code = _AuthCode(
            code=code,
            client_id=request.client.get_client_id(),
            redirect_uri=request.payload.redirect_uri or AUTHLIB_REDIRECT_URI,
            scope=request.scope or "openid profile",
            code_challenge=request.payload.data.get("code_challenge", ""),
            code_challenge_method=request.payload.data.get("code_challenge_method", "S256"),
            subject=user,
        )
        _AUTHLIB_AUTH_CODES[code] = auth_code

    def query_authorization_code(self, code, client):
        auth_code = _AUTHLIB_AUTH_CODES.get(code)
        if auth_code and auth_code.client_id == client.get_client_id():
            return auth_code
        return None

    def delete_authorization_code(self, authorization_code):
        _AUTHLIB_AUTH_CODES.pop(authorization_code.code, None)

    def authenticate_user(self, authorization_code):
        return authorization_code.subject


class _RefreshTokenGrant(grants.RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    def authenticate_refresh_token(self, refresh_token):
        tok = _AUTHLIB_REFRESH_TOKENS.get(refresh_token)
        if tok and not tok.is_expired():
            return tok
        return None

    def authenticate_user(self, credential):
        return credential.subject

    def revoke_old_credential(self, credential):
        _AUTHLIB_REFRESH_TOKENS.pop(credential.refresh_token, None)
        _AUTHLIB_TOKENS.pop(credential.access_token, None)


# ── Token factory: issue a signed JWT so /data can validate it ───────────────

def _query_client(client_id):
    return _CLIENT if client_id == AUTHLIB_CLIENT_ID else None


def _save_token(token_data, oauth_request):
    """Build a signed JWT access_token and persist in memory."""
    subject = oauth_request.user or ""
    now = datetime.now(timezone.utc)
    expires_in = int(token_data.get("expires_in", 3600))
    jwt_str = pyjwt.encode(
        {
            "iss": "acas-authlib-server",
            "sub": subject,
            "client_id": subject,
            "scope": token_data.get("scope", ""),
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
        },
        _AUTHLIB_SECRET,
        algorithm="HS256",
    )
    refresh = secrets.token_urlsafe(48)
    tok = _Token(
        access_token=jwt_str,
        refresh_token=refresh,
        client_id=AUTHLIB_CLIENT_ID,
        scope=token_data.get("scope", ""),
        subject=subject,
        issued_at=int(now.timestamp()),
        expires_in=expires_in,
    )
    _AUTHLIB_TOKENS[jwt_str] = tok
    _AUTHLIB_REFRESH_TOKENS[refresh] = tok
    # Return a plain dict so Authlib serialises it as the token response body.
    return {
        "access_token": jwt_str,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": refresh,
        "scope": tok.scope,
    }


# ── Flask integration ────────────────────────────────────────────────────────

def init_authlib(app, secret: str) -> None:
    """Register Authlib OAuth2 endpoints on the Flask app instance."""
    global _AUTHLIB_SECRET
    _AUTHLIB_SECRET = secret

    authorization = AuthorizationServer(
        app=None,
        query_client=_query_client,
        save_token=_save_token,
    )
    authorization.init_app(app)
    authorization.register_grant(_ACPKCEGrant, [CodeChallenge(required=True)])
    authorization.register_grant(_RefreshTokenGrant)

    existing_routes = {rule.rule for rule in app.url_map.iter_rules()}

    # ── POST /authlib/register ───────────────────────────────────────────────
    if "/authlib/register" not in existing_routes:
        def authlib_register():
            data = request.get_json(silent=True) or {}
            client_id = data.get("client_id", "").strip()
            password = data.get("password", "")
            if not client_id or not password:
                return jsonify({"error": "missing client_id or password"}), 400
            from models import User as _User
            user = _User.query.filter_by(client_id=client_id).first()
            if not user:
                return jsonify({"error": "user not in ZKP store"}), 400
            _AUTHLIB_PASSWORDS[client_id] = hashlib.sha256(password.encode()).hexdigest()
            return jsonify({"status": "Authlib user registered"}), 201

        app.add_url_rule(
            "/authlib/register",
            endpoint="authlib_register",
            view_func=authlib_register,
            methods=["POST"],
        )

    # ── POST /authlib/oauth/authorize ────────────────────────────────────────
    # Authlib reads OAuth2 parameters from request.values (form + query string).
    # Resource-owner credentials (username/password) are also sent as form fields.
    # The view authenticates the user first, then calls Authlib to issue the code.
    if "/authlib/oauth/authorize" not in existing_routes:
        def authlib_authorize():
            # Resource-owner authentication from form fields
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            pw_hash = _AUTHLIB_PASSWORDS.get(username)
            if not pw_hash or not secrets.compare_digest(
                pw_hash, hashlib.sha256(password.encode()).hexdigest()
            ):
                return jsonify({
                    "error": "access_denied",
                    "error_description": "invalid credentials",
                }), 401

            # Hand control to Authlib; grant_user is the authenticated subject.
            # Build the OAuth2Request from the current Flask request, then
            # resolve the grant instance explicitly to avoid the DeprecationWarning
            # that fires when grant= is omitted (will become mandatory in v1.8).
            _oauth2_req = authorization.create_oauth2_request(None)
            grant = authorization.get_authorization_grant(_oauth2_req)
            resp = authorization.create_authorization_response(grant_user=username, grant=grant)

            # Authlib returns a redirect (302) with ?code=... in Location.
            # Convert to JSON for test/benchmark clients that expect JSON.
            if resp.status_code in (302, 303):
                from urllib.parse import urlparse, parse_qs
                loc = resp.headers.get("Location", "")
                qs = parse_qs(urlparse(loc).query)
                code = qs.get("code", [None])[0]
                if not code:
                    return jsonify({"error": "authorization_failed"}), 500
                return jsonify({
                    "code": code,
                    "redirect_uri": request.form.get("redirect_uri", AUTHLIB_REDIRECT_URI),
                    "expires_in": 120,
                }), 200
            # Authlib may return 200 with a JSON body for response_mode=json
            return resp

        app.add_url_rule(
            "/authlib/oauth/authorize",
            endpoint="authlib_authorize",
            view_func=authlib_authorize,
            methods=["POST"],
        )

    # ── POST /authlib/oauth/token ────────────────────────────────────────────
    # Standard token endpoint; Authlib reads form fields directly.
    if "/authlib/oauth/token" not in existing_routes:
        def authlib_token():
            return authorization.create_token_response()

        app.add_url_rule(
            "/authlib/oauth/token",
            endpoint="authlib_token",
            view_func=authlib_token,
            methods=["POST"],
        )

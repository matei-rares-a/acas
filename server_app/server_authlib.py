"""
OAuth 2.0 server backed by the Authlib library (RFC 6749 + RFC 7636 PKCE).

This is a third OAuth implementation alongside the hand-rolled PKCE and Simple
flows. Having all three lets the benchmarks compare protocol overhead directly.
Password hashing is SHA-256 in all three, so the credential check cost is the
same and doesn't skew the numbers.

Endpoints:
  POST /authlib/register
  POST /authlib/oauth/authorize
  POST /authlib/oauth/token

One thing worth noting: Authlib reads parameters from request.values (query
string + form body), not from JSON. So authorize and token calls must use
application/x-www-form-urlencoded, not application/json. The benchmarks and
Locust tasks use data=... for exactly this reason.
"""

import hashlib
import os as _os
import secrets
import time
import warnings
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from authlib.deprecate import AuthlibDeprecationWarning

warnings.filterwarnings(
    "ignore",
    message=r"'request\.scope' is deprecated",
    category=AuthlibDeprecationWarning,
)

import jwt as pyjwt
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants, ClientMixin, AuthorizationCodeMixin, TokenMixin
from authlib.oauth2.rfc7636 import CodeChallenge
from flask import Blueprint, jsonify, request


# Allow HTTP during development / testing. Set AUTHLIB_FORCE_HTTPS=1 in production.
_os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "1")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AUTHLIB_CLIENT_ID    = "acas-authlib-client"
AUTHLIB_REDIRECT_URI = "https://client.example/callback"
AUTHLIB_ALLOWED_REDIRECT_URIS = {AUTHLIB_REDIRECT_URI, "http://localhost:8000/callback"}
AUTHLIB_ALLOWED_SCOPES        = {"openid", "profile", "read:data", "write:data"}
AUTHLIB_AUTH_CODE_TTL         = 120   # seconds
AUTHLIB_ACCESS_TOKEN_TTL      = 3600  # seconds


# ---------------------------------------------------------------------------
# State stores
# ---------------------------------------------------------------------------
# Note: in-memory stores for simplicity; replace with DB in production.
_AUTHLIB_PASSWORDS:      dict[str, str]       = {}
_AUTHLIB_AUTH_CODES:     dict[str, "_AuthCode"] = {}
_AUTHLIB_TOKENS:         dict[str, "_Token"]  = {}
_AUTHLIB_REFRESH_TOKENS: dict[str, "_Token"]  = {}


def clear_authlib_state() -> None:
    for store in (_AUTHLIB_PASSWORDS, _AUTHLIB_AUTH_CODES,
                  _AUTHLIB_TOKENS, _AUTHLIB_REFRESH_TOKENS):
        store.clear()


# ---------------------------------------------------------------------------
# Module context -- set once by init_authlib()
# ---------------------------------------------------------------------------
_AUTHLIB_SECRET: str = ""
_authorization: AuthorizationServer | None = None


# ---------------------------------------------------------------------------
# Authlib model mixins
# ---------------------------------------------------------------------------

class _OAuthClient(ClientMixin):
    """Single hard-coded public client (PKCE, no client_secret)."""

    def get_client_id(self):                          return AUTHLIB_CLIENT_ID
    def get_default_redirect_uri(self):               return AUTHLIB_REDIRECT_URI
    def check_client_secret(self, client_secret):     return True
    def has_client_secret(self):                      return False
    def check_response_type(self, response_type):     return response_type == "code"
    def check_grant_type(self, grant_type):           return grant_type in ("authorization_code", "refresh_token")
    def check_token_endpoint_auth_method(self, m):    return m in ("none", "client_secret_post", "client_secret_basic")
    def check_endpoint_auth_method(self, m, ep):      return True if ep != "token" else m == "none"
    def check_redirect_uri(self, redirect_uri):       return redirect_uri in AUTHLIB_ALLOWED_REDIRECT_URIS

    def get_allowed_scope(self, scope):
        requested = set(scope.split()) if scope else set()
        return " ".join(sorted(requested & AUTHLIB_ALLOWED_SCOPES)) or "openid profile"


_CLIENT = _OAuthClient()


class _AuthCode(AuthorizationCodeMixin):
    def __init__(self, code, client_id, redirect_uri, scope,
                 code_challenge, code_challenge_method, subject):
        self.code                  = code
        self.client_id             = client_id
        self.redirect_uri          = redirect_uri
        self.scope                 = scope
        self.code_challenge        = code_challenge
        self.code_challenge_method = code_challenge_method
        self.subject               = subject
        self._expires_at           = time.time() + AUTHLIB_AUTH_CODE_TTL

    def get_redirect_uri(self):         return self.redirect_uri
    def get_scope(self):                return self.scope
    def get_auth_time(self):            return int(time.time())
    def get_nonce(self):                return None
    def is_expired(self):               return time.time() > self._expires_at
    def get_code_challenge(self):       return self.code_challenge
    def get_code_challenge_method(self):return self.code_challenge_method


class _Token(TokenMixin):
    def __init__(self, access_token, refresh_token, client_id,
                 scope, subject, issued_at, expires_in):
        self.access_token  = access_token
        self.refresh_token = refresh_token
        self.client_id     = client_id
        self.scope         = scope
        self.subject       = subject
        self.issued_at     = issued_at
        self.expires_in    = expires_in

    def get_client_id(self):    return self.client_id
    def get_scope(self):        return self.scope
    def get_expires_in(self):   return self.expires_in
    def get_expires_at(self):   return self.issued_at + self.expires_in
    def is_expired(self):       return time.time() > self.get_expires_at()
    def is_revoked(self):       return False
    def check_client(self, c):  return self.client_id == c.get_client_id()


# ---------------------------------------------------------------------------
# Grant implementations
# ---------------------------------------------------------------------------

class _ACPKCEGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS      = ["none"]
    SUPPORTED_CODE_CHALLENGE_METHOD  = ["S256"]

    def save_authorization_code(self, code, request):
        _AUTHLIB_AUTH_CODES[code] = _AuthCode(
            code=code,
            client_id=request.client.get_client_id(),
            redirect_uri=request.payload.redirect_uri or AUTHLIB_REDIRECT_URI,
            scope=request.scope or "openid profile",
            code_challenge=request.payload.data.get("code_challenge", ""),
            code_challenge_method=request.payload.data.get("code_challenge_method", "S256"),
            subject=request.user or "",
        )

    def query_authorization_code(self, code, client):
        auth_code = _AUTHLIB_AUTH_CODES.get(code)
        return auth_code if auth_code and auth_code.client_id == client.get_client_id() else None

    def delete_authorization_code(self, authorization_code):
        _AUTHLIB_AUTH_CODES.pop(authorization_code.code, None)

    def authenticate_user(self, authorization_code):
        return authorization_code.subject


class _RefreshTokenGrant(grants.RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    def authenticate_refresh_token(self, refresh_token):
        tok = _AUTHLIB_REFRESH_TOKENS.get(refresh_token)
        return tok if tok and not tok.is_expired() else None

    def authenticate_user(self, credential):
        return credential.subject

    def revoke_old_credential(self, credential):
        _AUTHLIB_REFRESH_TOKENS.pop(credential.refresh_token, None)
        _AUTHLIB_TOKENS.pop(credential.access_token, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _query_client(client_id):
    return _CLIENT if client_id == AUTHLIB_CLIENT_ID else None


def _save_token(token_data, oauth_request):
    """Build a signed JWT access token and persist in memory.
    Returns a plain dict so Authlib serialises it as the token response body.
    """
    subject    = oauth_request.user or ""
    now        = datetime.now(timezone.utc)
    expires_in = int(token_data.get("expires_in", AUTHLIB_ACCESS_TOKEN_TTL))

    jwt_str = pyjwt.encode(
        {
            "iss":       "acas-authlib-server",
            "sub":       subject,
            # 'client_id' maps to the User.client_id field consumed by /data endpoint.
            "client_id": subject,
            "scope":     token_data.get("scope", ""),
            "iat":       now,
            "exp":       now + timedelta(seconds=expires_in),
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
    _AUTHLIB_TOKENS[jwt_str]  = tok
    _AUTHLIB_REFRESH_TOKENS[refresh] = tok
    return {
        "access_token":  jwt_str,
        "token_type":    "Bearer",
        "expires_in":    expires_in,
        "refresh_token": refresh,
        "scope":         tok.scope,
    }


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Blueprint + init
# ---------------------------------------------------------------------------

authlib_bp = Blueprint('authlib', __name__, url_prefix='/authlib')


def init_authlib(app, secret: str) -> None:
    """Register the Authlib OAuth2 blueprint on the Flask app.
    Called once from server.py after the app is created.
    """
    global _AUTHLIB_SECRET, _authorization
    _AUTHLIB_SECRET = secret

    _authorization = AuthorizationServer(
        app=None,
        query_client=_query_client,
        save_token=_save_token,
    )
    _authorization.init_app(app)
    _authorization.register_grant(_ACPKCEGrant, [CodeChallenge(required=True)])
    _authorization.register_grant(_RefreshTokenGrant)

    app.register_blueprint(authlib_bp)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@authlib_bp.route('/register', methods=['POST'])
def authlib_register():
    '''POST /authlib/register

    Register an Authlib OAuth user -- stores a hashed password for the given
    Schnorr client_id. The user must already exist in the ZKP User table.
    '''
    data      = request.get_json(silent=True) or {}
    client_id = data.get("client_id", "").strip()
    password  = data.get("password", "")

    if not client_id or not password:
        return jsonify({"error": "missing client_id or password"}), 400

    _AUTHLIB_PASSWORDS[client_id] = _hash_password(password)
    return jsonify({"status": "Authlib user registered"}), 201


@authlib_bp.route('/oauth/authorize', methods=['POST'])
def authlib_authorize():
    '''POST /authlib/oauth/authorize

    Authorization code grant with mandatory PKCE (S256).
    Authlib reads OAuth2 parameters from request.values (form + query string).
    Resource-owner credentials (username/password) are also sent as form fields.
    The view authenticates the user first, then calls Authlib to issue the code.

    Returns JSON with the authorization code (not a redirect) for test/benchmark
    clients that expect JSON.
    '''
    # Resource-owner authentication from form fields
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    pw_hash  = _AUTHLIB_PASSWORDS.get(username)

    if not pw_hash or not secrets.compare_digest(pw_hash, _hash_password(password)):
        return jsonify({
            "error":             "access_denied",
            "error_description": "invalid credentials",
        }), 401

    # Hand control to Authlib -- grant_user is the authenticated subject.
    # Resolve the grant explicitly to avoid the DeprecationWarning that fires
    # when grant= is omitted (will become mandatory in Authlib v1.8).
    oauth2_req = _authorization.create_oauth2_request(None)
    grant      = _authorization.get_authorization_grant(oauth2_req)
    resp       = _authorization.create_authorization_response(grant_user=username, grant=grant)

    # Authlib returns a 302 redirect with ?code=... in Location.
    # Convert to JSON for test/benchmark clients that expect JSON.
    if resp.status_code in (302, 303):
        loc  = resp.headers.get("Location", "")
        qs   = parse_qs(urlparse(loc).query)
        code = qs.get("code", [None])[0]
        if not code:
            return jsonify({"error": "authorization_failed"}), 500
        return jsonify({
            "code":         code,
            "redirect_uri": request.form.get("redirect_uri", AUTHLIB_REDIRECT_URI),
            "expires_in":   AUTHLIB_AUTH_CODE_TTL,
        }), 200

    # Authlib may return 200 with a JSON body for response_mode=json
    return resp


@authlib_bp.route('/oauth/token', methods=['POST'])
def authlib_token():
    '''POST /authlib/oauth/token

    Standard token endpoint -- Authlib reads form fields directly.
    Exchanges an authorization code or refresh token for an access token.
    '''
    return _authorization.create_token_response()

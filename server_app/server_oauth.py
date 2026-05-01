import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from flask import Blueprint, jsonify, redirect, request


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OAUTH_ACCESS_TOKEN_TTL_SECONDS  = 3600
OAUTH_AUTH_CODE_TTL_SECONDS     = 120
OAUTH_REFRESH_TOKEN_TTL_SECONDS = 86400

OAUTH_IMPLEMENTATIONS = {
    "pkce":   {"client_id": "acas-pkce-client",   "requires_pkce": True},
    "simple": {"client_id": "acas-simple-client",  "requires_pkce": False},
}

REDIRECT_URIS  = {"https://client.example/callback", "http://localhost:8000/callback"}
ALLOWED_SCOPES = {"openid", "profile", "read:data", "write:data"}


# ---------------------------------------------------------------------------
# State stores  (one dict per implementation for deterministic comparison)
# ---------------------------------------------------------------------------
'''
Note: should be in a database
Simplicity: in-memory stores per implementation
'''
# Separate state stores make comparison deterministic between implementations.
OAUTH_PASSWORD_HASHES     = {"pkce": {}, "simple": {}}
OAUTH_AUTHORIZATION_CODES = {"pkce": {}, "simple": {}}
OAUTH_REFRESH_TOKENS      = {"pkce": {}, "simple": {}}


def clear_oauth_state():
    for store in (OAUTH_PASSWORD_HASHES, OAUTH_AUTHORIZATION_CODES, OAUTH_REFRESH_TOKENS):
        for impl in store:
            store[impl].clear()


# ---------------------------------------------------------------------------
# Module context — populated once by init_oauth()
# ---------------------------------------------------------------------------
'''
Note: these are set at startup and treated as read-only after that,
so no lock is needed.
'''
_db = _User = _AuthToken = _secret = None

# Two blueprints — one per implementation — give each its own visible URL prefix.
pkce_bp   = Blueprint('oauth_pkce',   __name__, url_prefix='/oauth/pkce')
simple_bp = Blueprint('oauth_simple', __name__, url_prefix='/oauth/simple')
# Backward-compat aliases: /oauth/register|authorize|token → pkce
compat_bp = Blueprint('oauth_compat', __name__, url_prefix='/oauth')


def init_oauth(app, db, User, AuthToken, secret):
    '''Register all OAuth blueprints on the Flask app.
    Called once from server.py after the app and DB are ready.
    '''
    global _db, _User, _AuthToken, _secret
    _db, _User, _AuthToken, _secret = db, User, AuthToken, secret
    app.register_blueprint(pkce_bp)
    app.register_blueprint(simple_bp)
    app.register_blueprint(compat_bp)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _oauth_error(error, description, status_code=400):
    return jsonify({"error": error, "error_description": description}), status_code


def _hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def _pkce_s256_challenge(code_verifier):
    '''Compute the S256 PKCE code challenge from a verifier string.'''
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _issue_access_token(subject, oauth_client_id, scope):
    import jwt
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "iss":       "acas-oauth-server",
            "aud":       "acas-resource-api",
            "sub":       subject,
            # 'client_id' maps to the User.client_id field consumed by /data endpoint.
            "client_id": subject,
            "azp":       oauth_client_id,
            "scope":     scope,
            "iat":       now,
            "nbf":       now,
            "exp":       now + timedelta(seconds=OAUTH_ACCESS_TOKEN_TTL_SECONDS),
        },
        _secret,
        algorithm="HS256",
    )


def _persist_access_token(subject, token_str):
    user = _User.query.filter_by(client_id=subject).first()
    if not user:
        return
    auth = _AuthToken.query.filter_by(user_id=user.id).first()
    if auth:
        auth.token = token_str
    else:
        _db.session.add(_AuthToken(user_id=user.id, token=token_str))
    _db.session.commit()


def _issue_refresh_token(impl, subject, oauth_client_id, scope):
    refresh_token = secrets.token_urlsafe(48)
    OAUTH_REFRESH_TOKENS[impl][refresh_token] = {
        "subject":         subject,
        "oauth_client_id": oauth_client_id,
        "scope":           scope,
        "expires_at":      time.time() + OAUTH_REFRESH_TOKEN_TTL_SECONDS,
    }
    return refresh_token


def _validate_client(client_id, redirect_uri, impl):
    impl_cfg = OAUTH_IMPLEMENTATIONS[impl]
    if client_id != impl_cfg["client_id"]:
        return _oauth_error("unauthorized_client", "unknown client_id", 400)
    if redirect_uri not in REDIRECT_URIS:
        return _oauth_error("invalid_request", "redirect_uri is not registered", 400)
    return None


def _validate_scope(scope_text):
    requested = set(scope_text.split()) if scope_text else {"openid", "profile"}
    if not requested.issubset(ALLOWED_SCOPES):
        return None
    return " ".join(sorted(requested))


# ---------------------------------------------------------------------------
# Shared route handlers  (called by both blueprints — DRY)
# ---------------------------------------------------------------------------

def _handle_register(impl):
    data      = request.get_json(silent=True) or {}
    client_id = data.get("client_id")
    password  = data.get("password")

    if not client_id or not password:
        return _oauth_error("invalid_request", "missing client_id or password", 400)
    if not _User.query.filter_by(client_id=client_id).first():
        return _oauth_error("invalid_grant", "user not registered", 400)

    OAUTH_PASSWORD_HASHES[impl][client_id] = _hash_password(password)
    return jsonify({"status": f"OAuth {impl} user registered"}), 201


def _handle_authorize(impl):
    data = request.get_json(silent=True) or {}

    response_type         = data.get("response_type", "code")
    client_id             = data.get("client_id")
    redirect_uri          = data.get("redirect_uri")
    username              = data.get("username")
    password              = data.get("password")
    state                 = data.get("state")
    code_challenge        = data.get("code_challenge")
    code_challenge_method = data.get("code_challenge_method", "S256")
    response_mode         = data.get("response_mode", "json")
    scope_text            = data.get("scope", "openid profile")

    if response_type != "code":
        return _oauth_error("unsupported_response_type", "only authorization code flow is supported", 400)
    if not client_id or not redirect_uri:
        return _oauth_error("invalid_request", "missing client_id or redirect_uri", 400)

    err = _validate_client(client_id, redirect_uri, impl)
    if err:
        return err

    # PKCE challenge validation (required for the "pkce" implementation)
    if OAUTH_IMPLEMENTATIONS[impl]["requires_pkce"]:
        if not code_challenge:
            return _oauth_error("invalid_request", "missing code_challenge for PKCE client", 400)
        if code_challenge_method != "S256":
            return _oauth_error("invalid_request", "only S256 code_challenge_method is supported", 400)

    if not username or not password:
        return _oauth_error("invalid_request", "missing username or password", 400)

    # Resource owner authentication
    user        = _User.query.filter_by(client_id=username).first()
    stored_hash = OAUTH_PASSWORD_HASHES[impl].get(username)
    if not user or stored_hash is None or not secrets.compare_digest(stored_hash, _hash_password(password)):
        return _oauth_error("access_denied", "resource owner authentication failed", 401)

    scope = _validate_scope(scope_text)
    if scope is None:
        return _oauth_error("invalid_scope", "requested scope is not allowed", 400)

    # Issue authorization code (single-use, short-lived)
    authorization_code = secrets.token_urlsafe(32)
    OAUTH_AUTHORIZATION_CODES[impl][authorization_code] = {
        "client_id":             client_id,
        "resource_owner":        username,
        "redirect_uri":          redirect_uri,
        "scope":                 scope,
        "code_challenge":        code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at":            time.time() + OAUTH_AUTH_CODE_TTL_SECONDS,
    }

    if response_mode == "redirect":
        query = {"code": authorization_code}
        if state:
            query["state"] = state
        return redirect(f"{redirect_uri}?{urlencode(query)}", code=302)

    return jsonify({
        "code":         authorization_code,
        "state":        state,
        "redirect_uri": redirect_uri,
        "expires_in":   OAUTH_AUTH_CODE_TTL_SECONDS,
        "scope":        scope,
    }), 200


def _handle_token(impl):
    data       = request.get_json(silent=True) or {}
    grant_type = data.get("grant_type")

    if grant_type not in {"authorization_code", "refresh_token"}:
        return _oauth_error("unsupported_grant_type", "grant_type must be authorization_code or refresh_token", 400)

    # ── Authorization code exchange ──────────────────────────────────────────
    if grant_type == "authorization_code":
        authorization_code = data.get("code")
        client_id          = data.get("client_id")
        redirect_uri       = data.get("redirect_uri")
        code_verifier      = data.get("code_verifier")

        if not authorization_code or not client_id or not redirect_uri:
            return _oauth_error("invalid_request", "missing code, client_id or redirect_uri", 400)

        err = _validate_client(client_id, redirect_uri, impl)
        if err:
            return err

        # Pop the code atomically — prevents replay
        code_record = OAUTH_AUTHORIZATION_CODES[impl].pop(authorization_code, None)
        if not code_record or code_record["expires_at"] < time.time():
            return _oauth_error("invalid_grant", "authorization code is invalid or expired", 400)
        if code_record["client_id"] != client_id or code_record["redirect_uri"] != redirect_uri:
            return _oauth_error("invalid_grant", "authorization code does not match client or redirect_uri", 400)

        # PKCE verifier check
        if OAUTH_IMPLEMENTATIONS[impl]["requires_pkce"]:
            if not code_verifier:
                return _oauth_error("invalid_request", "missing code_verifier", 400)
            if not secrets.compare_digest(_pkce_s256_challenge(code_verifier), code_record["code_challenge"]):
                return _oauth_error("invalid_grant", "code_verifier validation failed", 400)

        resource_owner = code_record["resource_owner"]
        scope          = code_record["scope"]

    # ── Refresh token exchange ────────────────────────────────────────────────
    else:
        refresh_token = data.get("refresh_token")
        client_id     = data.get("client_id")

        if not refresh_token or not client_id:
            return _oauth_error("invalid_request", "missing refresh_token or client_id", 400)

        # Pop the refresh token atomically — rotation prevents replay
        refresh_record = OAUTH_REFRESH_TOKENS[impl].pop(refresh_token, None)
        if not refresh_record or refresh_record["expires_at"] < time.time():
            return _oauth_error("invalid_grant", "refresh_token is invalid or expired", 400)
        if refresh_record["oauth_client_id"] != client_id:
            return _oauth_error("invalid_grant", "refresh_token does not belong to this client", 400)

        resource_owner = refresh_record["subject"]
        scope          = refresh_record["scope"]

    # ── Issue tokens ──────────────────────────────────────────────────────────
    token_str    = _issue_access_token(resource_owner, client_id, scope)
    next_refresh = _issue_refresh_token(impl, resource_owner, client_id, scope)
    _persist_access_token(resource_owner, token_str)

    response = jsonify({
        "access_token":  token_str,
        "token_type":    "Bearer",
        "expires_in":    OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        "refresh_token": next_refresh,
        "scope":         scope,
    })
    # RFC 6749 §5.1 — token responses must not be cached
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"]        = "no-cache"
    return response, 200


# ---------------------------------------------------------------------------
# PKCE endpoints   (POST /oauth/pkce/...)
# ---------------------------------------------------------------------------

@pkce_bp.route('/register', methods=['POST'])
def pkce_register():
    '''POST /oauth/pkce/register — register OAuth credentials for a PKCE client.
    Requires code_challenge (S256) on authorize; code_verifier on token exchange.
    '''
    return _handle_register("pkce")


@pkce_bp.route('/authorize', methods=['POST'])
def pkce_authorize():
    '''POST /oauth/pkce/authorize — authorization code grant with mandatory PKCE (S256).'''
    return _handle_authorize("pkce")


@pkce_bp.route('/token', methods=['POST'])
def pkce_token():
    '''POST /oauth/pkce/token — exchange authorization code (+ code_verifier) for tokens.'''
    return _handle_token("pkce")


# ---------------------------------------------------------------------------
# Simple / classic endpoints   (POST /oauth/simple/...)
# ---------------------------------------------------------------------------

@simple_bp.route('/register', methods=['POST'])
def simple_register():
    '''POST /oauth/simple/register — register OAuth credentials for a classic client.
    No PKCE required; standard authorization code grant only.
    '''
    return _handle_register("simple")


@simple_bp.route('/authorize', methods=['POST'])
def simple_authorize():
    '''POST /oauth/simple/authorize — authorization code grant without PKCE.'''
    return _handle_authorize("simple")


@simple_bp.route('/token', methods=['POST'])
def simple_token():
    '''POST /oauth/simple/token — exchange authorization code for tokens.'''
    return _handle_token("simple")


# ---------------------------------------------------------------------------
# Backward-compat aliases   (POST /oauth/... → pkce)
# ---------------------------------------------------------------------------

@compat_bp.route('/register', methods=['POST'])
def compat_register():
    return _handle_register("pkce")


@compat_bp.route('/authorize', methods=['POST'])
def compat_authorize():
    return _handle_authorize("pkce")


@compat_bp.route('/token', methods=['POST'])
def compat_token():
    return _handle_token("pkce")


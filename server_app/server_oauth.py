import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from flask import Blueprint, jsonify, make_response, redirect, request


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OAUTH_ACCESS_TOKEN_TTL_SECONDS  = 3600
OAUTH_AUTH_CODE_TTL_SECONDS     = 120
OAUTH_REFRESH_TOKEN_TTL_SECONDS = 86400

PKCE_CLIENT_ID   = "acas-pkce-client"
SIMPLE_CLIENT_ID = "acas-simple-client"

REDIRECT_URIS  = {
    "https://client.example/callback",
    "http://localhost:8000/callback",
    "http://localhost:8000/oauth-callback.html",
}
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
# Pending authorize requests: keyed by auth_request_id, stored between GET and POST /authorize.
OAUTH_PENDING_REQUESTS    = {"pkce": {}, "simple": {}}


def clear_oauth_state():
    for store in (OAUTH_PASSWORD_HASHES, OAUTH_AUTHORIZATION_CODES,
                  OAUTH_REFRESH_TOKENS, OAUTH_PENDING_REQUESTS):
        for impl in store:
            store[impl].clear()


# ---------------------------------------------------------------------------
# Module context -- populated once by init_oauth()
# ---------------------------------------------------------------------------
'''
Note: these are set at startup and treated as read-only after that,
so no lock is needed.
'''
_db = _User = _AuthToken = _secret = None

# Two blueprints -- one per implementation -- give each its own visible URL prefix.
pkce_bp   = Blueprint('oauth_pkce',   __name__, url_prefix='/oauth/pkce')
simple_bp = Blueprint('oauth_simple', __name__, url_prefix='/oauth/simple')
# Backward-compat aliases: /oauth/register|authorize|token -> pkce
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


def _validate_client(client_id, redirect_uri, expected_client_id):
    if client_id != expected_client_id:
        return _oauth_error("unauthorized_client", "unknown client_id", 400)
    if redirect_uri not in REDIRECT_URIS:
        return _oauth_error("invalid_request", "redirect_uri is not registered", 400)
    return None


def _validate_scope(scope_text):
    requested = set(scope_text.split()) if scope_text else {"openid", "profile"}
    if not requested.issubset(ALLOWED_SCOPES):
        return None
    return " ".join(sorted(requested))


def _html_login_form(action_url, auth_request_id, error=None):
    '''Return a minimal HTML login form with a hidden auth_request_id field.
    The browser submits username + password back to action_url via POST.
    '''
    error_html = f'<p style="color:red;margin:0 0 8px">{error}</p>' if error else ""
    return (
        '<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>'
        '<body style="font-family:sans-serif;max-width:320px;margin:60px auto">'
        f'<h2>Login</h2>{error_html}'
        f'<form method="post" action="{action_url}">'
        f'<input type="hidden" name="auth_request_id" value="{auth_request_id}">'
        '<label>Username<br><input type="text" name="username" autofocus style="width:100%"></label><br><br>'
        '<label>Password<br><input type="password" name="password" style="width:100%"></label><br><br>'
        '<button type="submit" style="width:100%">Login</button>'
        '</form></body></html>'
    )


# ---------------------------------------------------------------------------
# PKCE route handlers  (POST /oauth/pkce/...)
# ---------------------------------------------------------------------------

@pkce_bp.route('/register', methods=['POST'])
def pkce_register():
    '''POST /oauth/pkce/register -- register OAuth credentials for a PKCE client.
    Requires code_challenge (S256) on authorize; code_verifier on token exchange.
    '''
    data      = request.get_json(silent=True) or {}
    client_id = data.get("client_id")
    password  = data.get("password")

    if not client_id or not password:
        return _oauth_error("invalid_request", "missing client_id or password", 400)

    OAUTH_PASSWORD_HASHES["pkce"][client_id] = _hash_password(password)
    return jsonify({"status": "OAuth pkce user registered"}), 201


@pkce_bp.route('/authorize', methods=['GET'])
def pkce_authorize_get():
    '''GET /oauth/pkce/authorize -- validate client params, store pending request, return HTML login form.
    The browser initiates this with all OAuth params in the query string.
    The server stores the request and returns a login form; the user's credentials never pass through
    the client app -- they are submitted directly to the Authorization Server.
    '''
    response_type         = request.args.get("response_type", "code")
    client_id             = request.args.get("client_id")
    redirect_uri          = request.args.get("redirect_uri")
    state                 = request.args.get("state")
    code_challenge        = request.args.get("code_challenge")
    code_challenge_method = request.args.get("code_challenge_method", "S256")
    scope_text            = request.args.get("scope", "openid profile")

    if response_type != "code":
        return _oauth_error("unsupported_response_type", "only authorization code flow is supported", 400)
    if not client_id or not redirect_uri:
        return _oauth_error("invalid_request", "missing client_id or redirect_uri", 400)

    err = _validate_client(client_id, redirect_uri, PKCE_CLIENT_ID)
    if err:
        return err

    if not code_challenge:
        return _oauth_error("invalid_request", "missing code_challenge for PKCE client", 400)
    if code_challenge_method != "S256":
        return _oauth_error("invalid_request", "only S256 code_challenge_method is supported", 400)

    scope = _validate_scope(scope_text)
    if scope is None:
        return _oauth_error("invalid_scope", "requested scope is not allowed", 400)

    auth_request_id = secrets.token_urlsafe(32)
    OAUTH_PENDING_REQUESTS["pkce"][auth_request_id] = {
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "scope":                 scope,
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at":            time.time() + OAUTH_AUTH_CODE_TTL_SECONDS,
    }
    html = _html_login_form(request.path, auth_request_id)
    return make_response(html, 200, {"Content-Type": "text/html; charset=utf-8"})


@pkce_bp.route('/authorize', methods=['POST'])
def pkce_authorize():
    '''POST /oauth/pkce/authorize -- authenticate user from login form submission (RFC 6749 §4.1.2).
    Reads form-encoded fields: auth_request_id, username, password.
    On success: 302 redirect to redirect_uri?code=...&state=...
    On auth failure: 401 JSON (allows headless test clients to inspect the error).
    '''
    auth_request_id = request.form.get("auth_request_id", "")
    username        = request.form.get("username", "").strip()
    password        = request.form.get("password", "")

    pending = OAUTH_PENDING_REQUESTS["pkce"].pop(auth_request_id, None)
    if not pending or pending["expires_at"] < time.time():
        return _oauth_error("invalid_request", "authorization request not found or expired", 400)

    stored_hash = OAUTH_PASSWORD_HASHES["pkce"].get(username)
    if stored_hash is None or not secrets.compare_digest(stored_hash, _hash_password(password)):
        return _oauth_error("access_denied", "resource owner authentication failed", 401)

    authorization_code = secrets.token_urlsafe(32)
    OAUTH_AUTHORIZATION_CODES["pkce"][authorization_code] = {
        "client_id":             pending["client_id"],
        "resource_owner":        username,
        "redirect_uri":          pending["redirect_uri"],
        "scope":                 pending["scope"],
        "code_challenge":        pending["code_challenge"],
        "code_challenge_method": pending["code_challenge_method"],
        "expires_at":            time.time() + OAUTH_AUTH_CODE_TTL_SECONDS,
    }
    query = {"code": authorization_code}
    if pending["state"]:
        query["state"] = pending["state"]

    # API clients (Accept: application/json) receive the code directly in JSON
    # instead of a browser redirect -- keeps the fetch-based demo flow working.
    accept = request.headers.get("Accept", "")
    if "application/json" in accept:
        return jsonify({"code": authorization_code, "state": pending.get("state"), "redirect_uri": pending["redirect_uri"]}), 200

    return redirect(f"{pending['redirect_uri']}?{urlencode(query)}", code=302)


@pkce_bp.route('/token', methods=['POST'])
def pkce_token():
    '''POST /oauth/pkce/token -- exchange authorization code (+ code_verifier) for tokens.'''
    data       = request.get_json(silent=True) or {}
    grant_type = data.get("grant_type")

    if grant_type not in {"authorization_code", "refresh_token"}:
        return _oauth_error("unsupported_grant_type", "grant_type must be authorization_code or refresh_token", 400)

    if grant_type == "authorization_code":
        authorization_code = data.get("code")
        client_id          = data.get("client_id")
        redirect_uri       = data.get("redirect_uri")
        code_verifier      = data.get("code_verifier")

        if not authorization_code or not client_id or not redirect_uri:
            return _oauth_error("invalid_request", "missing code, client_id or redirect_uri", 400)

        err = _validate_client(client_id, redirect_uri, PKCE_CLIENT_ID)
        if err:
            return err

        code_record = OAUTH_AUTHORIZATION_CODES["pkce"].pop(authorization_code, None)
        if not code_record or code_record["expires_at"] < time.time():
            return _oauth_error("invalid_grant", "authorization code is invalid or expired", 400)
        if code_record["client_id"] != client_id or code_record["redirect_uri"] != redirect_uri:
            return _oauth_error("invalid_grant", "authorization code does not match client or redirect_uri", 400)

        if not code_verifier:
            return _oauth_error("invalid_request", "missing code_verifier", 400)
        if not secrets.compare_digest(_pkce_s256_challenge(code_verifier), code_record["code_challenge"]):
            return _oauth_error("invalid_grant", "code_verifier validation failed", 400)

        resource_owner = code_record["resource_owner"]
        scope          = code_record["scope"]

    else:
        refresh_token = data.get("refresh_token")
        client_id     = data.get("client_id")

        if not refresh_token or not client_id:
            return _oauth_error("invalid_request", "missing refresh_token or client_id", 400)

        refresh_record = OAUTH_REFRESH_TOKENS["pkce"].pop(refresh_token, None)
        if not refresh_record or refresh_record["expires_at"] < time.time():
            return _oauth_error("invalid_grant", "refresh_token is invalid or expired", 400)
        if refresh_record["oauth_client_id"] != client_id:
            return _oauth_error("invalid_grant", "refresh_token does not belong to this client", 400)

        resource_owner = refresh_record["subject"]
        scope          = refresh_record["scope"]

    token_str    = _issue_access_token(resource_owner, client_id, scope)
    next_refresh = _issue_refresh_token("pkce", resource_owner, client_id, scope)
    _persist_access_token(resource_owner, token_str)

    response = jsonify({
        "access_token":  token_str,
        "token_type":    "Bearer",
        "expires_in":    OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        "refresh_token": next_refresh,
        "scope":         scope,
    })
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"]        = "no-cache"
    return response, 200


# ---------------------------------------------------------------------------
# Simple / classic route handlers  (POST /oauth/simple/...)
# ---------------------------------------------------------------------------

@simple_bp.route('/register', methods=['POST'])
def simple_register():
    '''POST /oauth/simple/register -- register OAuth credentials for a classic client.
    No PKCE required; standard authorization code grant only.
    '''
    data      = request.get_json(silent=True) or {}
    client_id = data.get("client_id")
    password  = data.get("password")

    if not client_id or not password:
        return _oauth_error("invalid_request", "missing client_id or password", 400)

    OAUTH_PASSWORD_HASHES["simple"][client_id] = _hash_password(password)
    return jsonify({"status": "OAuth simple user registered"}), 201


@simple_bp.route('/authorize', methods=['GET'])
def simple_authorize_get():
    '''GET /oauth/simple/authorize -- validate client params, store pending request, return HTML login form.
    The browser initiates this with all OAuth params in the query string.
    '''
    response_type = request.args.get("response_type", "code")
    client_id     = request.args.get("client_id")
    redirect_uri  = request.args.get("redirect_uri")
    state         = request.args.get("state")
    scope_text    = request.args.get("scope", "openid profile")

    if response_type != "code":
        return _oauth_error("unsupported_response_type", "only authorization code flow is supported", 400)
    if not client_id or not redirect_uri:
        return _oauth_error("invalid_request", "missing client_id or redirect_uri", 400)

    err = _validate_client(client_id, redirect_uri, SIMPLE_CLIENT_ID)
    if err:
        return err

    scope = _validate_scope(scope_text)
    if scope is None:
        return _oauth_error("invalid_scope", "requested scope is not allowed", 400)

    auth_request_id = secrets.token_urlsafe(32)
    OAUTH_PENDING_REQUESTS["simple"][auth_request_id] = {
        "client_id":    client_id,
        "redirect_uri": redirect_uri,
        "scope":        scope,
        "state":        state,
        "expires_at":   time.time() + OAUTH_AUTH_CODE_TTL_SECONDS,
    }
    html = _html_login_form(request.path, auth_request_id)
    return make_response(html, 200, {"Content-Type": "text/html; charset=utf-8"})


@simple_bp.route('/authorize', methods=['POST'])
def simple_authorize():
    '''POST /oauth/simple/authorize -- authenticate user from login form submission (RFC 6749 §4.1.2).
    Reads form-encoded fields: auth_request_id, username, password.
    On success: 302 redirect to redirect_uri?code=...&state=...
    On auth failure: 401 JSON.
    '''
    auth_request_id = request.form.get("auth_request_id", "")
    username        = request.form.get("username", "").strip()
    password        = request.form.get("password", "")

    pending = OAUTH_PENDING_REQUESTS["simple"].pop(auth_request_id, None)
    if not pending or pending["expires_at"] < time.time():
        return _oauth_error("invalid_request", "authorization request not found or expired", 400)

    stored_hash = OAUTH_PASSWORD_HASHES["simple"].get(username)
    if stored_hash is None or not secrets.compare_digest(stored_hash, _hash_password(password)):
        return _oauth_error("access_denied", "resource owner authentication failed", 401)

    authorization_code = secrets.token_urlsafe(32)
    OAUTH_AUTHORIZATION_CODES["simple"][authorization_code] = {
        "client_id":      pending["client_id"],
        "resource_owner": username,
        "redirect_uri":   pending["redirect_uri"],
        "scope":          pending["scope"],
        "expires_at":     time.time() + OAUTH_AUTH_CODE_TTL_SECONDS,
    }
    query = {"code": authorization_code}
    if pending["state"]:
        query["state"] = pending["state"]
    return redirect(f"{pending['redirect_uri']}?{urlencode(query)}", code=302)


@simple_bp.route('/token', methods=['POST'])
def simple_token():
    '''POST /oauth/simple/token -- exchange authorization code for tokens.'''
    data       = request.get_json(silent=True) or {}
    grant_type = data.get("grant_type")

    if grant_type not in {"authorization_code", "refresh_token"}:
        return _oauth_error("unsupported_grant_type", "grant_type must be authorization_code or refresh_token", 400)

    if grant_type == "authorization_code":
        authorization_code = data.get("code")
        client_id          = data.get("client_id")
        redirect_uri       = data.get("redirect_uri")

        if not authorization_code or not client_id or not redirect_uri:
            return _oauth_error("invalid_request", "missing code, client_id or redirect_uri", 400)

        err = _validate_client(client_id, redirect_uri, SIMPLE_CLIENT_ID)
        if err:
            return err

        code_record = OAUTH_AUTHORIZATION_CODES["simple"].pop(authorization_code, None)
        if not code_record or code_record["expires_at"] < time.time():
            return _oauth_error("invalid_grant", "authorization code is invalid or expired", 400)
        if code_record["client_id"] != client_id or code_record["redirect_uri"] != redirect_uri:
            return _oauth_error("invalid_grant", "authorization code does not match client or redirect_uri", 400)

        resource_owner = code_record["resource_owner"]
        scope          = code_record["scope"]

    else:
        refresh_token = data.get("refresh_token")
        client_id     = data.get("client_id")

        if not refresh_token or not client_id:
            return _oauth_error("invalid_request", "missing refresh_token or client_id", 400)

        refresh_record = OAUTH_REFRESH_TOKENS["simple"].pop(refresh_token, None)
        if not refresh_record or refresh_record["expires_at"] < time.time():
            return _oauth_error("invalid_grant", "refresh_token is invalid or expired", 400)
        if refresh_record["oauth_client_id"] != client_id:
            return _oauth_error("invalid_grant", "refresh_token does not belong to this client", 400)

        resource_owner = refresh_record["subject"]
        scope          = refresh_record["scope"]

    token_str    = _issue_access_token(resource_owner, client_id, scope)
    next_refresh = _issue_refresh_token("simple", resource_owner, client_id, scope)
    _persist_access_token(resource_owner, token_str)

    response = jsonify({
        "access_token":  token_str,
        "token_type":    "Bearer",
        "expires_in":    OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        "refresh_token": next_refresh,
        "scope":         scope,
    })
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"]        = "no-cache"
    return response, 200


# ---------------------------------------------------------------------------
# Backward-compat aliases   (POST /oauth/... -> pkce)
# ---------------------------------------------------------------------------

@compat_bp.route('/register', methods=['POST'])
def compat_register():
    return pkce_register()


@compat_bp.route('/authorize', methods=['GET'])
def compat_authorize_get():
    return pkce_authorize_get()


@compat_bp.route('/authorize', methods=['POST'])
def compat_authorize():
    return pkce_authorize()


@compat_bp.route('/token', methods=['POST'])
def compat_token():
    return pkce_token()


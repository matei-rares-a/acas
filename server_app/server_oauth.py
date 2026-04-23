import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from flask import jsonify, redirect, request


OAUTH_ACCESS_TOKEN_TTL_SECONDS = 3600
OAUTH_AUTH_CODE_TTL_SECONDS = 120
OAUTH_REFRESH_TOKEN_TTL_SECONDS = 86400

OAUTH_IMPLEMENTATIONS = {
    "pkce": {
        "client_id": "acas-pkce-client",
        "requires_pkce": True,
    },
    "simple": {
        "client_id": "acas-simple-client",
        "requires_pkce": False,
    },
}

# Separate state stores make comparison deterministic between implementations.
OAUTH_PASSWORD_HASHES = {"pkce": {}, "simple": {}}
OAUTH_AUTHORIZATION_CODES = {"pkce": {}, "simple": {}}
OAUTH_REFRESH_TOKENS = {"pkce": {}, "simple": {}}

REDIRECT_URIS = {
    "https://client.example/callback",
    "http://localhost:8000/callback",
}
ALLOWED_SCOPES = {"openid", "profile", "read:data", "write:data"}


def clear_oauth_state():
    for store in (OAUTH_PASSWORD_HASHES, OAUTH_AUTHORIZATION_CODES, OAUTH_REFRESH_TOKENS):
        for impl in store:
            store[impl].clear()


def init_oauth(app, db, User, AuthToken, secret):
    existing_routes = {rule.rule for rule in app.url_map.iter_rules()}

    def _oauth_error(error, description, status_code=400):
        return jsonify({"error": error, "error_description": description}), status_code

    def _request_data():
        return request.get_json(silent=True) 

    def _hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def _pkce_s256_challenge(code_verifier):
        digest = hashlib.sha256(code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def _issue_access_token(subject, oauth_client_id, scope):
        now = datetime.now(timezone.utc)
        return __import__("jwt").encode(
            {
                "iss": "acas-oauth-server",
                "aud": "acas-resource-api",
                "sub": subject,
                # 'client_id' maps to the User.client_id field consumed by /data endpoint.
                "client_id": subject,
                "azp": oauth_client_id,
                "scope": scope,
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(seconds=OAUTH_ACCESS_TOKEN_TTL_SECONDS),
            },
            secret,
            algorithm="HS256",
        )

    def _persist_access_token(subject, token_str):
        user = User.query.filter_by(client_id=subject).first()
        if not user:
            return
        auth = AuthToken.query.filter_by(user_id=user.id).first()
        if auth:
            auth.token = token_str
        else:
            db.session.add(AuthToken(user_id=user.id, token=token_str))
        db.session.commit()

    def _issue_refresh_token(impl, subject, oauth_client_id, scope):
        refresh_token = secrets.token_urlsafe(48)
        OAUTH_REFRESH_TOKENS[impl][refresh_token] = {
            "subject": subject,
            "oauth_client_id": oauth_client_id,
            "scope": scope,
            "expires_at": time.time() + OAUTH_REFRESH_TOKEN_TTL_SECONDS,
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
        requested_scopes = set(scope_text.split()) if scope_text else {"openid", "profile"}
        if not requested_scopes.issubset(ALLOWED_SCOPES):
            return None
        return " ".join(sorted(requested_scopes))

    def make_register_view(impl):
        def register_view():
            data = _request_data()
            client_id = data.get("client_id")
            password = data.get("password")
            if not client_id or not password:
                return _oauth_error("invalid_request", "missing client_id or password", 400)

            user = User.query.filter_by(client_id=client_id).first()
            if not user:
                return _oauth_error("invalid_grant", "user not registered", 400)

            OAUTH_PASSWORD_HASHES[impl][client_id] = _hash_password(password)
            return jsonify({"status": f"OAuth {impl} user registered"}), 201

        return register_view

    def make_authorize_view(impl):
        def authorize_view():
            data = _request_data()
            response_type = data.get("response_type", "code")
            client_id = data.get("client_id")
            redirect_uri = data.get("redirect_uri")
            username = data.get("username")
            password = data.get("password")
            state = data.get("state")
            code_challenge = data.get("code_challenge")
            code_challenge_method = data.get("code_challenge_method", "S256")
            response_mode = data.get("response_mode", "json")

            if response_type != "code":
                return _oauth_error("unsupported_response_type", "only authorization code flow is supported", 400)
            if not client_id or not redirect_uri:
                return _oauth_error("invalid_request", "missing client_id or redirect_uri", 400)

            client_error = _validate_client(client_id, redirect_uri, impl)
            if client_error:
                return client_error

            if OAUTH_IMPLEMENTATIONS[impl]["requires_pkce"]:
                if not code_challenge:
                    return _oauth_error("invalid_request", "missing code_challenge for PKCE client", 400)
                if code_challenge_method != "S256":
                    return _oauth_error("invalid_request", "only S256 code_challenge_method is supported", 400)

            if not username or not password:
                return _oauth_error("invalid_request", "missing username or password", 400)

            user = User.query.filter_by(client_id=username).first()
            stored_hash = OAUTH_PASSWORD_HASHES[impl].get(username)
            if not user or stored_hash is None or not secrets.compare_digest(stored_hash, _hash_password(password)):
                return _oauth_error("access_denied", "resource owner authentication failed", 401)

            scope = _validate_scope(data.get("scope", "openid profile"))
            if scope is None:
                return _oauth_error("invalid_scope", "requested scope is not allowed", 400)

            authorization_code = secrets.token_urlsafe(32)
            OAUTH_AUTHORIZATION_CODES[impl][authorization_code] = {
                "client_id": client_id,
                "resource_owner": username,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "expires_at": time.time() + OAUTH_AUTH_CODE_TTL_SECONDS,
            }

            if response_mode == "redirect":
                query = {"code": authorization_code}
                if state:
                    query["state"] = state
                return redirect(f"{redirect_uri}?{urlencode(query)}", code=302)

            return (
                jsonify(
                    {
                        "code": authorization_code,
                        "state": state,
                        "redirect_uri": redirect_uri,
                        "expires_in": OAUTH_AUTH_CODE_TTL_SECONDS,
                        "scope": scope,
                    }
                ),
                200,
            )

        return authorize_view

    def make_token_view(impl):
        def token_view():
            data = _request_data()
            grant_type = data.get("grant_type")
            if grant_type not in {"authorization_code", "refresh_token"}:
                return _oauth_error("unsupported_grant_type", "grant_type must be authorization_code or refresh_token", 400)

            if grant_type == "authorization_code":
                authorization_code = data.get("code")
                client_id = data.get("client_id")
                redirect_uri = data.get("redirect_uri")
                code_verifier = data.get("code_verifier")
                if not authorization_code or not client_id or not redirect_uri:
                    return _oauth_error("invalid_request", "missing code, client_id or redirect_uri", 400)

                client_error = _validate_client(client_id, redirect_uri, impl)
                if client_error:
                    return client_error

                code_record = OAUTH_AUTHORIZATION_CODES[impl].pop(authorization_code, None)
                if not code_record or code_record["expires_at"] < time.time():
                    return _oauth_error("invalid_grant", "authorization code is invalid or expired", 400)
                if code_record["client_id"] != client_id or code_record["redirect_uri"] != redirect_uri:
                    return _oauth_error("invalid_grant", "authorization code does not match client or redirect_uri", 400)

                if OAUTH_IMPLEMENTATIONS[impl]["requires_pkce"]:
                    if not code_verifier:
                        return _oauth_error("invalid_request", "missing code_verifier", 400)
                    expected_challenge = _pkce_s256_challenge(code_verifier)
                    if not secrets.compare_digest(expected_challenge, code_record["code_challenge"]):
                        return _oauth_error("invalid_grant", "code_verifier validation failed", 400)

                resource_owner = code_record["resource_owner"]
                scope = code_record["scope"]
            else:
                refresh_token = data.get("refresh_token")
                client_id = data.get("client_id")
                if not refresh_token or not client_id:
                    return _oauth_error("invalid_request", "missing refresh_token or client_id", 400)

                refresh_record = OAUTH_REFRESH_TOKENS[impl].pop(refresh_token, None)
                if not refresh_record or refresh_record["expires_at"] < time.time():
                    return _oauth_error("invalid_grant", "refresh_token is invalid or expired", 400)
                if refresh_record["oauth_client_id"] != client_id:
                    return _oauth_error("invalid_grant", "refresh_token does not belong to this client", 400)

                resource_owner = refresh_record["subject"]
                scope = refresh_record["scope"]

            token_str = _issue_access_token(resource_owner, client_id, scope)
            next_refresh_token = _issue_refresh_token(impl, resource_owner, client_id, scope)
            _persist_access_token(resource_owner, token_str)
            response = jsonify(
                {
                    "access_token": token_str,
                    "token_type": "Bearer",
                    "expires_in": OAUTH_ACCESS_TOKEN_TTL_SECONDS,
                    "refresh_token": next_refresh_token,
                    "scope": scope,
                }
            )
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            return response, 200

        return token_view

    routes = [
        ("pkce", "/oauth/pkce/register", make_register_view("pkce"), ["POST"]),
        ("pkce", "/oauth/pkce/authorize", make_authorize_view("pkce"), ["POST"]),
        ("pkce", "/oauth/pkce/token", make_token_view("pkce"), ["POST"]),
        ("simple", "/oauth/simple/register", make_register_view("simple"), ["POST"]),
        ("simple", "/oauth/simple/authorize", make_authorize_view("simple"), ["POST"]),
        ("simple", "/oauth/simple/token", make_token_view("simple"), ["POST"]),
        # Backward-compat aliases now point to the PKCE implementation.
        ("pkce", "/oauth/register", make_register_view("pkce"), ["POST"]),
        ("pkce", "/oauth/authorize", make_authorize_view("pkce"), ["POST"]),
        ("pkce", "/oauth/token", make_token_view("pkce"), ["POST"]),
    ]

    for impl, path, view_func, methods in routes:
        if path in existing_routes:
            continue
        endpoint = f"oauth_{impl}_{path.strip('/').replace('/', '_')}"
        app.add_url_rule(path, endpoint=endpoint, view_func=view_func, methods=methods)

"""
Shared utilities for the Schnorr ZKP QA suite.

Exports:
    server          -- the loaded server module (Flask app, models, constants)
    derive_password_x(password_string) -> int
    register_user(client, client_id, password) -> (x, y)
    start_commit(client, client_id, rand_r=None) -> (rand_r, challenge_c, session_id)
    pkce_challenge(code_verifier) -> str
    OAUTH_PKCE_CLIENT_ID, OAUTH_SIMPLE_CLIENT_ID, OAUTH_REDIRECT_URI
    AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI
"""

import base64
import hashlib
import importlib.util
import secrets as secrets_module
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_APP_PATH = PROJECT_ROOT / "server_app"
SERVER_MODULE_PATH = SERVER_APP_PATH / "server.py"
if str(SERVER_APP_PATH) not in sys.path:
    sys.path.insert(0, str(SERVER_APP_PATH))
spec = importlib.util.spec_from_file_location("server", SERVER_MODULE_PATH)
server = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(server)


_KDF_SALT = b'acas-zkp-fixed-salt-2026'


def derive_password_x(password_string: str) -> int:
    """Derive private scalar x from a password. Uses SHAKE-256 (fast, 2048-bit output)."""
    hashed = hashlib.shake_256(password_string.encode() + _KDF_SALT).digest(256)
    return int.from_bytes(hashed, 'big') % server.Q or 1


def register_user(client, client_id: str, password: str):
    """Register a new user and return (x, y)."""
    x = derive_password_x(password)
    y = pow(server.G, x, server.P)
    resp = client.post("/register", json={"client_id": client_id, "secret_y": y})
    assert resp.status_code in (200, 201)
    return x, y


def start_commit(client, client_id: str, rand_r=None, t_override=None):
    """Post /login/commit and return (rand_r, challenge_c, session_id).

    t_override: use a specific commitment value instead of G^rand_r mod P.
    """
    if rand_r is None:
        rand_r = secrets_module.randbelow(server.P - 2) + 1
    commitment_t = t_override if t_override is not None else pow(server.G, rand_r, server.P)
    resp = client.post(
        "/login/commit", json={"client_id": client_id, "commitment_t": commitment_t}
    )
    assert resp.status_code == 200
    payload = resp.get_json()
    return rand_r, int(payload["challenge_c"]), payload["session_id"]


# ---------------------------------------------------------------------------
# OAuth2 shared constants
# ---------------------------------------------------------------------------

OAUTH_PKCE_CLIENT_ID = "acas-pkce-client"
OAUTH_SIMPLE_CLIENT_ID = "acas-simple-client"
OAUTH_REDIRECT_URI = "https://client.example/callback"
AUTHLIB_CLIENT_ID = "acas-authlib-client"
AUTHLIB_REDIRECT_URI = "https://client.example/callback"


def pkce_challenge(code_verifier: str) -> str:
    """Compute PKCE S256 code_challenge from a code_verifier."""
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Shared pytest base classes
# ---------------------------------------------------------------------------

import pytest  # noqa: E402  (import after heavy server load to avoid circular issues)


class BaseTestSuite:
    """Base class for ZKP test suites."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        server.app.config["TESTING"] = True
        server.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        with server.app.app_context():
            server.db.session.remove()
            server.db.drop_all()
            server.db.create_all()
        server.sessions.clear()
        yield
        with server.app.app_context():
            server.db.session.remove()
            server.db.drop_all()
            server.db.create_all()
        server.sessions.clear()

    @pytest.fixture
    def client(self):
        return server.app.test_client()


class OAuthTestSuite(BaseTestSuite):
    """Extended base class that also clears OAuth / Authlib state."""

    @pytest.fixture(autouse=True)
    def reset_state(self):
        server.app.config["TESTING"] = True
        server.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        with server.app.app_context():
            server.db.session.remove()
            server.db.drop_all()
            server.db.create_all()
        server.sessions.clear()
        server.clear_oauth_state()
        server.clear_authlib_state()
        yield
        with server.app.app_context():
            server.db.session.remove()
            server.db.drop_all()
            server.db.create_all()
        server.sessions.clear()
        server.clear_oauth_state()
        server.clear_authlib_state()


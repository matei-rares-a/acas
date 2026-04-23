from pathlib import Path
import base64
import hashlib
import importlib.util
import secrets
import sys

from locust import HttpUser, task, between

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVER_APP_PATH = PROJECT_ROOT / "server_app"
SERVER_MODULE_PATH = SERVER_APP_PATH / "server.py"
if str(SERVER_APP_PATH) not in sys.path:
    sys.path.insert(0, str(SERVER_APP_PATH))
spec = importlib.util.spec_from_file_location("server", SERVER_MODULE_PATH)
server = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(server)


class SchnorrComparisonUser(HttpUser):
    wait_time = between(0.5, 1.5)

    def on_start(self):
        self.client_id = f"locust_{secrets.token_hex(8)}"
        self.password = secrets.token_hex(16)
        salt = secrets.token_bytes(16)
        hashed = hashlib.scrypt(self.password.encode(), salt=salt, n=2**11, r=8, p=1)
        self.x = int.from_bytes(hashed, "big") % server.Q
        y = pow(server.G, self.x, server.P)

        self.client.post("/register", json={"client_id": self.client_id, "secret_y": y})
        self.client.post(
            "/oauth/pkce/register",
            json={"client_id": self.client_id, "password": self.password},
            name="/oauth/pkce/register",
        )
        self.client.post(
            "/oauth/simple/register",
            json={"client_id": self.client_id, "password": self.password},
            name="/oauth/simple/register",
        )

    @task(2)
    def test_schnorr_login(self):
        rand_r = secrets.randbelow(server.P - 2) + 1
        t = pow(server.G, rand_r, server.P)
        commit = self.client.post(
            "/login/commit",
            json={"client_id": self.client_id, "commitment_t": t},
            name="/login/commit",
        )
        if commit.status_code != 200:
            return
        payload = commit.json()
        c = int(payload["challenge_c"])
        sid = payload["session_id"]
        s = (rand_r + c * self.x) % server.Q
        self.client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid},
            json={"solution_s": s},
            name="/login/verify",
        )

    @task(1)
    def test_oauth_pkce_login(self):
        code_verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
        authorize = self.client.post(
            "/oauth/pkce/authorize",
            json={
                "response_type": "code",
                "client_id": "acas-pkce-client",
                "redirect_uri": "https://client.example/callback",
                "username": self.client_id,
                "password": self.password,
                "scope": "openid profile",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_mode": "json",
            },
            name="/oauth/pkce/authorize",
        )
        if authorize.status_code != 200:
            return
        code = authorize.json()["code"]
        self.client.post(
            "/oauth/pkce/token",
            json={
                "grant_type": "authorization_code",
                "client_id": "acas-pkce-client",
                "redirect_uri": "https://client.example/callback",
                "code": code,
                "code_verifier": code_verifier,
            },
            name="/oauth/pkce/token",
        )

    @task(1)
    def test_oauth_simple_login(self):
        authorize = self.client.post(
            "/oauth/simple/authorize",
            json={
                "response_type": "code",
                "client_id": "acas-simple-client",
                "redirect_uri": "https://client.example/callback",
                "username": self.client_id,
                "password": self.password,
                "scope": "openid profile",
                "response_mode": "json",
            },
            name="/oauth/simple/authorize",
        )
        if authorize.status_code != 200:
            return
        code = authorize.json()["code"]
        self.client.post(
            "/oauth/simple/token",
            json={
                "grant_type": "authorization_code",
                "client_id": "acas-simple-client",
                "redirect_uri": "https://client.example/callback",
                "code": code,
            },
            name="/oauth/simple/token",
        )

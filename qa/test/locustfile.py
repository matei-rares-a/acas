from pathlib import Path
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

        # Setup hash for /login/classic baseline path.
        with server.app.app_context():
            user = server.User.query.filter_by(client_id=self.client_id).first()
            if user:
                user._classic_hash = hashlib.sha256(self.password.encode()).hexdigest()
                server.db.session.commit()

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
    def test_classic_login(self):
        self.client.post(
            "/login/classic",
            json={"client_id": self.client_id, "password": self.password},
            name="/login/classic",
        )

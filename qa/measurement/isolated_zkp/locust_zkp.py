"""Locust load test — ZKP only, port 5200 (izolat, fara competitie cu alte servere)."""
import secrets as _secrets
import sys
import time as _time
from pathlib import Path

from locust import HttpUser, task

_QA_PATH = Path(__file__).resolve().parents[2]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))

from qa_utils import server, derive_password_x

_PORT = 5200


class ZKPUser(HttpUser):
    host = f"http://127.0.0.1:{_PORT}"

    def on_start(self):
        self._client_id = f"locust_{_secrets.token_hex(8)}"
        self._password  = f"pw-{_secrets.token_hex(16)}"
        self._x = derive_password_x(self._password)
        self._y = pow(server.G, self._x, server.P)
        self.client.post(
            "/register",
            json={"client_id": self._client_id, "secret_y": self._y},
            name="/register",
        )

    @task
    def zkp_login(self):
        start      = _time.perf_counter()
        rand_r     = _secrets.randbelow(server.P - 2) + 1
        commitment = pow(server.G, rand_r, server.P)

        commit = self.client.post(
            "/login/commit",
            json={"client_id": self._client_id, "commitment_t": commitment},
            name="/login/commit",
        )
        if commit.status_code != 200:
            self.environment.events.request.fire(
                request_type="ZKP", name="full_zkp_login",
                response_time=(_time.perf_counter() - start) * 1000,
                response_length=0,
                exception=RuntimeError(f"commit {commit.status_code}"),
                context={},
            )
            return

        payload     = commit.json()
        challenge_c = int(payload["challenge_c"])
        session_id  = payload["session_id"]
        s = (rand_r + challenge_c * self._x) % server.Q

        verify = self.client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": s},
            name="/login/verify",
        )

        elapsed = (_time.perf_counter() - start) * 1000
        self.environment.events.request.fire(
            request_type="ZKP", name="full_zkp_login",
            response_time=elapsed,
            response_length=0,
            exception=None if verify.status_code == 200
                      else RuntimeError(f"verify {verify.status_code}"),
            context={},
        )

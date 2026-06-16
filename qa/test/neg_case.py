import secrets as secrets_module
import time

import pytest

from qa_utils import server, derive_password_x, register_user, start_commit, BaseTestSuite

class TestNegativeCases(BaseTestSuite):

    def test_wrong_password_returns_401_and_clears_session(self, client):
        """Login with wrong password: verify step returns 401 and session is removed."""
        client_id = "client_test"
        correct_password = "correct-password"
        wrong_password = "wrong-password"

        register_user(client, client_id, correct_password)
        rand_r, challenge_c, session_id = start_commit(client, client_id)

        wrong_x = derive_password_x(wrong_password)
        wrong_solution_s = (rand_r + challenge_c * wrong_x) % server.Q

        verify_response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": wrong_solution_s},
        )

        assert verify_response.status_code == 401
        assert verify_response.get_json() == {"reason": "verification failed"}
        assert session_id not in server.sessions


    def test_reusing_consumed_session_returns_404(self, client):
        """Verify with an already-used session_id returns 404."""
        client_id = "replay_test"
        password = "replay-password"

        x, _ = register_user(client, client_id, password)
        rand_r, challenge_c, session_id = start_commit(client, client_id)
        solution_s = (rand_r + challenge_c * x) % server.Q

        first_verify = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": solution_s},
        )
        assert first_verify.status_code == 200

        replay_verify = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": solution_s},
        )
        assert replay_verify.status_code == 404
        assert replay_verify.get_json() == {"reason": "invalid session_id"}


    def test_verify_after_session_expiry_returns_401(self, client, monkeypatch):
        """Verify after SESSION_TTL has elapsed returns 401 and session is removed."""
        client_id = "timeout_test"
        password = "timeout-password"

        x, _ = register_user(client, client_id, password)
        rand_r, challenge_c, session_id = start_commit(client, client_id)
        solution_s = (rand_r + challenge_c * x) % server.Q

        real_time = time.time
        monkeypatch.setattr(server.time, "time", lambda: real_time() + server.SESSION_TTL + 1)

        verify_response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": solution_s},
        )

        assert verify_response.status_code == 401
        assert verify_response.get_json() == {"reason": "session expired"}
        assert session_id not in server.sessions


    def test_duplicate_commit_returns_409_and_clears_old_session(self, client):
        """Second commit for the same user while one is already pending returns 409."""
        client_id = "alice_test"
        password = "alice-password"
        register_user(client, client_id, password)

        _, _, session_id_1 = start_commit(client, client_id)

        time.sleep(0.1)

        second_commit = client.post(
            "/login/commit",
            json={
                "client_id": client_id,
                "commitment_t": pow(server.G, secrets_module.randbelow(server.P - 2) + 1, server.P),
            },
        )

        assert second_commit.status_code == 409
        assert second_commit.get_json().get("reason") == (
            "existing commitment found, start a new session"
        )
        assert session_id_1 not in server.sessions
        active_for_client = [s for s in server.sessions.values() if s["client_id"] == client_id]
        assert len(active_for_client) == 0  

    def test_register_with_existing_client_id_returns_409(self, client):
        """Registering a client_id that is already taken returns 409 and keeps original credentials."""
        client_id = "test_user"
        initial_password = "initial-password-version1"
        second_password = "second-password-version2"

        initial_password_x = derive_password_x(initial_password)
        second_password_x = derive_password_x(second_password)

        initial_secret_y = pow(server.G, initial_password_x, server.P)
        second_secret_y = pow(server.G, second_password_x, server.P)

        with server.app.app_context():
            server.db.session.add(
                server.User(client_id=client_id, secret_y=initial_secret_y.to_bytes(256, 'big'))
            )
            server.db.session.commit()

        response = client.post(
            "/register",
            json={"client_id": client_id, "secret_y": second_secret_y},
        )

        assert response.status_code == 409
        assert response.get_json() == {"reason": "already registered"}

        with server.app.app_context():
            users = server.User.query.filter_by(client_id=client_id).all()
            assert len(users) == 1
            assert users[0].secret_y == initial_secret_y.to_bytes(256, 'big')


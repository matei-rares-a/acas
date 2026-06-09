import secrets as secrets_module
import time

import pytest

from qa_utils import server, derive_password_x, register_user, start_commit, BaseTestSuite, ec_scalar_mult, ec_point_add, EC_ORDER, EC_GENERATOR


def _ec_encoded(Y: tuple) -> bytes:
    return Y[0].to_bytes(32, 'big') + Y[1].to_bytes(32, 'big')

class TestNegativeCases(BaseTestSuite):

    def test_wrong_password_proof_is_rejected_and_session_is_deleted(self, client):
        '''Testare verificare cu solutie folosind parola gresita si secret furat (stolen secret_y, adversary trying to login with wrong password)'''
        """Client send wrong proof, server reject login, server remove used session."""
        client_id = "client_test"
        correct_password = "correct-password"
        wrong_password = "wrong-password"

        register_user(client, client_id, correct_password)
        rand_r, challenge_c, session_id = start_commit(client, client_id)

        wrong_x, _ = derive_password_x(wrong_password)
        wrong_solution_s = (rand_r + challenge_c * wrong_x) % EC_ORDER

        verify_response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": wrong_solution_s},
        )

        assert verify_response.status_code == 401
        assert verify_response.get_json() == {"reason": "verification failed"}
        assert session_id not in server.sessions


    def test_replay_attack_reusing_verify_payload_is_rejected(self, client):
        '''Testare replay attack folosind aceeasi solutie si session_id (replay attack )'''
        """Client do valid verify once, client replay same data, server reject replay."""
        client_id = "replay_test"
        password = "replay-password"

        x, _ = register_user(client, client_id, password)
        rand_r, challenge_c, session_id = start_commit(client, client_id)
        solution_s = (rand_r + challenge_c * x) % EC_ORDER

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


    def test_verify_rejects_expired_session_and_cleans_up_state(self, client, monkeypatch):
        '''Testare expirare sesiune daca dureaza prea mult rezolvarea challenge-ului (DoS prevention)'''
        """Client wait too long then verify, server mark session expired and clean state."""
        client_id = "timeout_test"
        password = "timeout-password"

        x, _ = register_user(client, client_id, password)
        rand_r, challenge_c, session_id = start_commit(client, client_id)
        solution_s = (rand_r + challenge_c * x) % EC_ORDER

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


    def test_second_commit_same_user_returns_conflict_and_invalidates_old_session(self, client):
        '''Testare commit dublu pentru acelasi user, fara a finaliza prima sesiune (Hijacking / Overwrite prevention)'''
        """Client send second commit for same user, server return conflict and drop old session."""
        client_id = "alice_test"
        password = "alice-password"
        register_user(client, client_id, password)

        _, _, session_id_1 = start_commit(client, client_id)

        time.sleep(0.1)

        _rand_k = secrets_module.randbelow(EC_ORDER - 1) + 1
        _T = ec_scalar_mult(_rand_k, EC_GENERATOR)
        second_commit = client.post(
            "/login/commit",
            json={"client_id": client_id, "commitment_t_x": str(_T[0]), "commitment_t_y": str(_T[1])},
        )

        assert second_commit.status_code == 409
        assert second_commit.get_json().get("reason") == (
            "existing commitment found, start a new session"
        )
        assert session_id_1 not in server.sessions
        active_for_client = [s for s in server.sessions.values() if s["client_id"] == client_id]
        assert len(active_for_client) == 0  

    def test_register_rejects_duplicate_client_id_with_conflict(self, client):
        '''Testarea conflict la inregistrare duplicat'''
        """Client register once, server return 201, client register same client_id again, server return 409 and not duplicate user."""
        client_id = "test_user"
        initial_password = "initial-password-version1"
        second_password = "second-password-version2"

        initial_password_x,_ = derive_password_x(initial_password)
        second_password_x,_ = derive_password_x(second_password)
        initial_Y = ec_scalar_mult(initial_password_x, EC_GENERATOR)
        second_Y  = ec_scalar_mult(second_password_x, EC_GENERATOR)
        initial_encoded = _ec_encoded(initial_Y)

        with server.app.app_context():
            server.db.session.add(
                server.User(client_id=client_id, secret_y=initial_encoded)
            )
            server.db.session.commit()

        response = client.post(
            "/register",
            json={"client_id": client_id, "secret_y_x": str(second_Y[0]), "secret_y_y": str(second_Y[1])},
        )

        assert response.status_code == 409
        assert response.get_json() == {"reason": "already registered"}

        with server.app.app_context():
            users = server.User.query.filter_by(client_id=client_id).all()
            assert len(users) == 1
            assert users[0].secret_y == initial_encoded


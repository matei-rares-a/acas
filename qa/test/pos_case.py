from datetime import datetime, timedelta, timezone
import secrets as secrets_module

import jwt
import pytest

from qa_utils import server, derive_password_x, BaseTestSuite

class TestPositiveCases(BaseTestSuite):

    def test_register_creates_user_and_does_not_store_plain_password(self, client):
        '''Testarea înregistrării'''
        """Client send register data, server save public value, server doesn't keep plain password."""
        client_id = "test_user"
        raw_password = "my-secure-password-12345"
        password_x,_ = derive_password_x(raw_password)
        secret_y = pow(server.G, password_x, server.P)

        response = client.post(
            "/register",
            json={"client_id": client_id, "secret_y": secret_y},
        )

        assert response.status_code == 201
        assert response.get_json() == {"status": "Registered"}

        with server.app.app_context():
            user = server.User.query.filter_by(client_id=client_id).first()
            assert user is not None
            assert user.secret_y == str(secret_y)
            assert not hasattr(user, "password")
            serialized = f"{user.client_id}|{user.secret_y}"
            assert raw_password not in serialized


    def test_register_updates_existing_user_without_duplication(self, client):
        '''Testarea idempotenta inregistrare'''
        """Re-registering with a valid JWT updates credentials; no duplicate row is created."""
        client_id = "test_user_update"
        initial_password = "initial-password-version1"
        updated_password = "updated-password-version2"

        initial_x, _ = derive_password_x(initial_password)
        updated_x, _ = derive_password_x(updated_password)

        initial_y = pow(server.G, initial_x, server.P)
        updated_y = pow(server.G, updated_x, server.P)

        # 1. Register the user initially (unauthenticated — new user)
        r1 = client.post("/register", json={"client_id": client_id, "secret_y": initial_y})
        assert r1.status_code == 201
        assert r1.get_json() == {"status": "Registered"}

        # 2. Authenticate via ZKP to obtain a JWT
        rand_r = secrets_module.randbelow(server.P - 2) + 1
        t = pow(server.G, rand_r, server.P)

        commit_resp = client.post(
            "/login/commit",
            json={"client_id": client_id, "commitment_t": t},
        )
        assert commit_resp.status_code == 200
        commit_data = commit_resp.get_json()
        c = int(commit_data["challenge_c"])
        session_id = commit_data["session_id"]

        s = (rand_r + c * initial_x) % server.Q

        verify_resp = client.post(
            "/login/verify",
            json={"solution_s": s},
            headers={"X-Auth-Session": session_id},
        )
        assert verify_resp.status_code == 200, verify_resp.get_json()
        token = verify_resp.get_json()["token"]

        # 3. Use the JWT to update credentials (must send as Authorization: Bearer)
        r2 = client.post(
            "/register",
            json={"client_id": client_id, "secret_y": updated_y},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 200
        assert r2.get_json() == {"status": "Updated"}

        # 4. Verify exactly one row, with the new secret_y
        with server.app.app_context():
            users = server.User.query.filter_by(client_id=client_id).all()
            assert len(users) == 1
            assert users[0].secret_y == str(updated_y)


    def test_login_commit_then_verify_success_and_session_is_deleted(self, client):
        '''Testarea fluxului de autentificare '''
        """Client send commit then verify, server check proof, server give token, server delete session."""
        client_id = "test_login"
        raw_password = "test-password-secure"

        password_x,_ = derive_password_x(raw_password)
        secret_y = pow(server.G, password_x, server.P)

        with server.app.app_context():
            server.db.session.add(server.User(client_id=client_id, secret_y=str(secret_y)))
            server.db.session.commit()

        rand_r = secrets_module.randbelow(server.P - 2) + 1
        commitment_t = pow(server.G, rand_r, server.P)

        commit_response = client.post(
            "/login/commit",
            json={"client_id": client_id, "commitment_t": commitment_t},
        )

        assert commit_response.status_code == 200
        commit_payload = commit_response.get_json()
        assert "challenge_c" in commit_payload
        assert "session_id" in commit_payload

        challenge_c = int(commit_payload["challenge_c"])
        session_id = commit_payload["session_id"]

        solution_s = (rand_r + challenge_c * password_x) % server.Q

        verify_response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": solution_s},
        )

        assert verify_response.status_code == 200
        verify_payload = verify_response.get_json()
        assert "token" in verify_payload
        assert verify_payload["token"]
        assert session_id not in server.sessions


    def test_data_authorization_with_valid_and_invalid_tokens(self, client):
        '''Testarea consumare token'''
        """Client send valid token and get data, client send bad token and server deny."""
        from qa_utils import register_user, start_commit
        client_id = "test_user"
        raw_password = "data-endpoint-password"

        x, _ = register_user(client, client_id, raw_password)

        with server.app.app_context():
            user = server.User.query.filter_by(client_id=client_id).first()
            assert user is not None
            server.db.session.add(server.PersoData(user_id=user.id, message="hello"))
            server.db.session.commit()

        # Obtain a real EdDSA token via the ZKP flow
        rand_r, challenge_c, session_id = start_commit(client, client_id)
        solution_s = (rand_r + challenge_c * x) % server.Q
        verify_resp = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": solution_s},
        )
        assert verify_resp.status_code == 200
        valid_token = verify_resp.get_json()["token"]

        ok_response = client.get(
            "/data",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert ok_response.status_code == 200
        assert ok_response.get_json() == {"data": "hello"}

        missing_header_response = client.get("/data")
        assert missing_header_response.status_code == 401

        # Tampered / garbage token must be rejected
        tampered_token = valid_token[:-4] + "XXXX"
        tampered_response = client.get(
            "/data",
            headers={"Authorization": f"Bearer {tampered_token}"},
        )
        assert tampered_response.status_code == 401


    def test_two_users_authenticate_in_parallel_both_succeed(self, client):
        '''Testare autentificare paralela - doi utilizatori diferiti se autentifica simultan cu succes'''
        """Alice and Bob both commit so their sessions coexist, Alice verify with her correct s and get token, Bob verify with his correct s and get token, both receive 200."""
        # Register both users
        x_alice, _ = derive_password_x("alice-parallel-pass")
        y_alice = pow(server.G, x_alice, server.P)
        x_bob, _ = derive_password_x("bob-parallel-pass")
        y_bob = pow(server.G, x_bob, server.P)

        with server.app.app_context():
            server.db.session.add(server.User(client_id="parallel_alice", secret_y=str(y_alice)))
            server.db.session.add(server.User(client_id="parallel_bob", secret_y=str(y_bob)))
            server.db.session.commit()

        # Both commit — two sessions coexist simultaneously
        r_alice = secrets_module.randbelow(server.P - 2) + 1
        t_alice = pow(server.G, r_alice, server.P)
        resp_alice = client.post("/login/commit", json={"client_id": "parallel_alice", "commitment_t": t_alice})
        assert resp_alice.status_code == 200
        alice_payload = resp_alice.get_json()
        c_alice = int(alice_payload["challenge_c"])
        sid_alice = alice_payload["session_id"]

        r_bob = secrets_module.randbelow(server.P - 2) + 1
        t_bob = pow(server.G, r_bob, server.P)
        resp_bob = client.post("/login/commit", json={"client_id": "parallel_bob", "commitment_t": t_bob})
        assert resp_bob.status_code == 200
        bob_payload = resp_bob.get_json()
        c_bob = int(bob_payload["challenge_c"])
        sid_bob = bob_payload["session_id"]

        # Both sessions are alive at the same time
        assert sid_alice in server.sessions
        assert sid_bob in server.sessions

        # Alice verifies with her correct solution
        s_alice = (r_alice + c_alice * x_alice) % server.Q
        verify_alice = client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid_alice},
            json={"solution_s": s_alice},
        )
        assert verify_alice.status_code == 200
        assert "token" in verify_alice.get_json()

        # Bob verifies with his correct solution (session still intact)
        s_bob = (r_bob + c_bob * x_bob) % server.Q
        verify_bob = client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid_bob},
            json={"solution_s": s_bob},
        )
        assert verify_bob.status_code == 200
        assert "token" in verify_bob.get_json()


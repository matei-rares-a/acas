from datetime import datetime, timedelta, timezone
import hashlib
import secrets as secrets_module

import jwt
import pytest

from qa_utils import server, derive_password_x, BaseTestSuite

class TestPositiveCases(BaseTestSuite):

    def test_register_creates_user_and_does_not_store_plain_password(self, client):
        '''Testarea inregistrarii'''
        """Client send register data, server save public value, server doesn't keep plain password."""
        client_id = "test_user"
        raw_password = "my-secure-password-12345"
        password_x = derive_password_x(raw_password)
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
            assert user.secret_y == secret_y.to_bytes(256, 'big')
            assert not hasattr(user, "password")
            serialized = f"{user.client_id}|{user.secret_y.hex()}"
            assert raw_password not in serialized


    def test_register_does_not_store_hashed_password(self, client):
        '''Testarea ca baza de date nu stocheaza parola hashuita'''
        """Client send register data, server must not store any hash of the plain password."""
        client_id = "test_user_hash"
        raw_password = "my-secure-password-12345"
        password_x = derive_password_x(raw_password)
        secret_y = pow(server.G, password_x, server.P)

        response = client.post(
            "/register",
            json={"client_id": client_id, "secret_y": secret_y},
        )
        assert response.status_code == 201

        sha256_hex = hashlib.sha256(raw_password.encode()).hexdigest()
        sha512_hex = hashlib.sha512(raw_password.encode()).hexdigest()
        md5_hex    = hashlib.md5(raw_password.encode()).hexdigest()

        with server.app.app_context():
            user = server.User.query.filter_by(client_id=client_id).first()
            assert user is not None
            serialized = f"{user.client_id}|{user.secret_y.hex()}"
            assert sha256_hex not in serialized
            assert sha512_hex not in serialized
            assert md5_hex    not in serialized





    def test_login_commit_then_verify_success_and_session_is_deleted(self, client):
        '''Testarea fluxului de autentificare '''
        """Client send commit then verify, server check proof, server give token, server delete session."""
        client_id = "test_login"
        raw_password = "test-password-secure"

        password_x = derive_password_x(raw_password)
        secret_y = pow(server.G, password_x, server.P)

        with server.app.app_context():
            server.db.session.add(server.User(client_id=client_id, secret_y=secret_y.to_bytes(256, 'big')))
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
        client_id = "test_user"
        raw_password = "data-endpoint-password"

        password_x = derive_password_x(raw_password)
        secret_y = pow(server.G, password_x, server.P)

        register_response = client.post(
            "/register",
            json={"client_id": client_id, "secret_y": secret_y},
        )
        assert register_response.status_code == 201

        with server.app.app_context():
            user = server.User.query.filter_by(client_id=client_id).first()
            assert user is not None
            server.db.session.add(server.PersoData(user_id=user.id, message="hello"))
            server.db.session.commit()

        valid_token = jwt.encode({"client_id": client_id}, server.SECRET, algorithm="HS256")

        ok_response = client.get(
            "/data",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert ok_response.status_code == 200
        assert ok_response.get_json() == {"data": "hello"}

        missing_header_response = client.get("/data")
        assert missing_header_response.status_code == 401

        expired_token = jwt.encode(
            {
                "client_id": client_id,
                "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
            },
            server.SECRET,
            algorithm="HS256",
        )
        expired_response = client.get(
            "/data",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert expired_response.status_code == 401


    def test_two_users_authenticate_in_parallel_both_succeed(self, client):
        '''Testare autentificare paralela - doi utilizatori diferiti se autentifica simultan cu succes'''
        """Alice and Bob both commit so their sessions coexist, Alice verify with her correct s and get token, Bob verify with his correct s and get token, both receive 200."""
        # Register both users
        x_alice = derive_password_x("alice-parallel-pass")
        y_alice = pow(server.G, x_alice, server.P)
        x_bob = derive_password_x("bob-parallel-pass")
        y_bob = pow(server.G, x_bob, server.P)

        with server.app.app_context():
            server.db.session.add(server.User(client_id="parallel_alice", secret_y=y_alice.to_bytes(256, 'big')))
            server.db.session.add(server.User(client_id="parallel_bob", secret_y=y_bob.to_bytes(256, 'big')))
            server.db.session.commit()

        # Both commit -- two sessions coexist simultaneously
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


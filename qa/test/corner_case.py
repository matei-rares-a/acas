import concurrent.futures
import secrets as secrets_module

import pytest

from qa_utils import server, derive_password_x, BaseTestSuite, ec_scalar_mult, ec_point_add, EC_ORDER, EC_GENERATOR


def _ec_encoded(Y: tuple) -> bytes:
    return Y[0].to_bytes(32, 'big') + Y[1].to_bytes(32, 'big')


def register_and_commit(client, client_id, password):
    x, _ = derive_password_x(password)
    Y = ec_scalar_mult(x, EC_GENERATOR)
    resp = client.post("/register", json={"client_id": client_id, "secret_y_x": str(Y[0]), "secret_y_y": str(Y[1])})
    assert resp.status_code in (200, 201)
    rand_r = secrets_module.randbelow(EC_ORDER - 1) + 1
    T = ec_scalar_mult(rand_r, EC_GENERATOR)
    commit_resp = client.post(
        "/login/commit", json={"client_id": client_id, "commitment_t_x": str(T[0]), "commitment_t_y": str(T[1])}
    )
    assert commit_resp.status_code == 200
    payload = commit_resp.get_json()
    return x, rand_r, int(payload["challenge_c"]), payload["session_id"]

class TestCornerCases(BaseTestSuite):

    @pytest.mark.parametrize("bad_s", [-1, server.EC_ORDER, server.EC_ORDER + 1, server.EC_ORDER * 10])
    def test_verify_rejects_out_of_range_solution_s(self, client, bad_s):
        '''Testarea limitelor matematice ale soluiei_s (S<0 sau S>=Q trebuie respinse)'''
        """Client send out-of-range solution, server reject and clear session."""
        client_id = "boundary_s_user"
        x, rand_r, challenge_c, session_id = register_and_commit(client, client_id, "boundary-pass")

        response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": bad_s},
        )

        assert response.status_code == 422
        assert response.get_json() == {"reason": "invalid solution"}
        assert session_id not in server.sessions


    @pytest.mark.parametrize("xy_pair", [("0", "0"), ("1", "0"), ("-1", "0"), ("0", "-1")])
    def test_register_rejects_trivial_subgroup_values(self, client, xy_pair):
        '''Testarea atacului trivial zero/one pe register (secret_y nu este un punct valid pe curba)'''
        """Client send invalid EC point on register, server block value."""
        x_str, y_str = xy_pair
        response = client.post(
            "/register",
            json={"client_id": f"trivial_y_{x_str}_{y_str}", "secret_y_x": x_str, "secret_y_y": y_str},
        )
        assert response.status_code == 422
        assert response.get_json() == {"reason": "invalid public value"}


    @pytest.mark.parametrize("xy_pair", [("0", "0"), ("1", "0"), ("-1", "0"), ("0", "-1")])
    def test_commit_rejects_trivial_subgroup_values_and_no_orphan_session(self, client, xy_pair):
        '''Testarea atacului trivial zero/one pe commit (commitment_t nu este un punct valid)'''
        """Client send invalid EC commitment, server reject and leave no orphan session."""
        x, _ = derive_password_x("trivial-pass")
        Y = ec_scalar_mult(x, EC_GENERATOR)
        client.post("/register", json={"client_id": "trivial_commit_user", "secret_y_x": str(Y[0]), "secret_y_y": str(Y[1])})

        sessions_before = set(server.sessions.keys())
        x_str, y_str = xy_pair
        response = client.post(
            "/login/commit",
            json={"client_id": "trivial_commit_user", "commitment_t_x": x_str, "commitment_t_y": y_str},
        )

        assert response.status_code == 422
        assert response.get_json() == {"reason": "invalid commitment"}
        assert set(server.sessions.keys()) == sessions_before


    def test_concurrent_commits_produce_single_active_session(self, client):
        '''Testarea race condition la commit '''
        """Many client commits hit together, server avoid crash by dropping sessions and keep 1 """
        client_id = "race_user"
        x, _ = derive_password_x("race-pass")
        Y = ec_scalar_mult(x, EC_GENERATOR)
        with server.app.app_context():
            server.db.session.add(server.User(client_id=client_id, secret_y=_ec_encoded(Y)))
            server.db.session.commit()

        # Precompute all EC points before spawning threads so concurrent requests
        # arrive within COMMIT_RACE_WINDOW_S of each other
        n_workers = 10
        commitments = [
            (secrets_module.randbelow(EC_ORDER - 1) + 1,)
            for _ in range(n_workers)
        ]
        ts = [ec_scalar_mult(r, EC_GENERATOR) for r, in commitments]

        def do_commit(T):
            return client.post(
                "/login/commit", json={"client_id": client_id, "commitment_t_x": str(T[0]), "commitment_t_y": str(T[1])}
            ).status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
            statuses = list(pool.map(do_commit, ts))

        assert 500 not in statuses
        active = [s for s in server.sessions.values() if s["client_id"] == client_id]
        assert len(active) == 1


    @pytest.mark.parametrize("bad_y_value", ["12345.67", "1e20", "abc123", None, [], {}])
    def test_register_handles_malformed_secret_y_without_crash(self, client, bad_y_value):
        '''Testare tip de data pentru secret_y'''
        """Client send malformed secret_y types, server return 400/422 and not crash."""
        response = client.post(
            "/register",
            json={"client_id": "type_confusion_register_user", "secret_y": bad_y_value},
        )
        assert response.status_code in (400, 422)
        assert response.status_code != 500


    @pytest.mark.parametrize("bad_t_value", ["12345.67", "1e20", "abc123", None, [], {}])
    def test_commit_handles_malformed_commitment_t_without_crash(self, client, bad_t_value):
        '''Testare tip de data pentru commitment_t'''
        """Client send malformed commitment_t types, server return 400/422 and not crash."""
        x, _ = derive_password_x("type-commit-pass")
        Y = ec_scalar_mult(x, EC_GENERATOR)
        client.post("/register", json={"client_id": "type_confusion_commit_user", "secret_y_x": str(Y[0]), "secret_y_y": str(Y[1])})

        response = client.post(
            "/login/commit",
            json={"client_id": "type_confusion_commit_user", "commitment_t_x": bad_t_value, "commitment_t_y": bad_t_value},
        )
        assert response.status_code in (400, 422)
        assert response.status_code != 500


    @pytest.mark.parametrize("bad_s_value", ["12345.67", "1e20", "abc123", None])
    def test_verify_handles_malformed_solution_s_without_crash(self, client, bad_s_value):
        '''Testare tip de data pentru solution_s'''
        """Client send malformed solution types, server return error and not crash."""
        client_id = "type_confusion_user"
        x, _ = derive_password_x("type-pass")
        Y = ec_scalar_mult(x, EC_GENERATOR)
        client.post("/register", json={"client_id": client_id, "secret_y_x": str(Y[0]), "secret_y_y": str(Y[1])})
        rand_r = secrets_module.randbelow(EC_ORDER - 1) + 1
        T = ec_scalar_mult(rand_r, EC_GENERATOR)
        commit_resp = client.post(
            "/login/commit", json={"client_id": client_id, "commitment_t_x": str(T[0]), "commitment_t_y": str(T[1])}
        )
        session_id = commit_resp.get_json()["session_id"]

        response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": bad_s_value},
        )

        assert response.status_code in (400, 422)
        assert response.status_code != 500


    def test_verify_x_auth_session_header_edge_cases(self, client):
        '''Testare cazuri pt header'''
        """Client send weird session headers, server handle safely and keep stable behavior."""
        client_id = "header_edge_user"
        x, _ = derive_password_x("header-pass")
        Y = ec_scalar_mult(x, EC_GENERATOR)
        client.post("/register", json={"client_id": client_id, "secret_y_x": str(Y[0]), "secret_y_y": str(Y[1])})
        rand_r = secrets_module.randbelow(EC_ORDER - 1) + 1
        T = ec_scalar_mult(rand_r, EC_GENERATOR)
        commit_resp = client.post(
            "/login/commit", json={"client_id": client_id, "commitment_t_x": str(T[0]), "commitment_t_y": str(T[1])}
        )
        assert commit_resp.status_code == 200
        challenge_c = int(commit_resp.get_json()["challenge_c"])
        valid_s = (rand_r + challenge_c * x) % EC_ORDER

        r1 = client.post("/login/verify", json={"solution_s": valid_s})
        assert r1.status_code == 400
        assert r1.get_json() == {"reason": "missing session_id in X-Auth-Session header"}

        r2 = client.post(
            "/login/verify", headers={"X-Auth-Session": ""}, json={"solution_s": valid_s}
        )
        assert r2.status_code == 400

        r3 = client.post(
            "/login/verify", headers={"X-Auth-Session": "   "}, json={"solution_s": valid_s}
        )
        assert r3.status_code in (400, 404)

        long_id = "x" * 1001
        r4 = client.post(
            "/login/verify", headers={"X-Auth-Session": long_id}, json={"solution_s": valid_s}
        )
        assert r4.status_code in (400, 404)
        assert r4.status_code != 500

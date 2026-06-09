import concurrent.futures
import secrets as secrets_module

import pytest

from qa_utils import server, derive_password_x, BaseTestSuite
def register_and_commit(client, client_id, password):
    x = derive_password_x(password)
    y = pow(server.G, x, server.P)
    resp = client.post("/register", json={"client_id": client_id, "secret_y": y})
    assert resp.status_code in (200, 201)
    rand_r = secrets_module.randbelow(server.P - 2) + 1
    commitment_t = pow(server.G, rand_r, server.P)
    commit_resp = client.post(
        "/login/commit", json={"client_id": client_id, "commitment_t": commitment_t}
    )
    assert commit_resp.status_code == 200
    payload = commit_resp.get_json()
    return x, rand_r, int(payload["challenge_c"]), payload["session_id"]

class TestCornerCases(BaseTestSuite):

    @pytest.mark.parametrize("bad_s", [-1, server.Q, server.Q + 1, server.P * 10])
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


    @pytest.mark.parametrize("trivial_y", [0, 1, -1, server.P - 1])
    def test_register_rejects_trivial_subgroup_values(self, client, trivial_y):
        '''Testarea atacului trivial zero/one pe register (secret_y = 0, 1, -1, P-1)'''
        """Client send trivial subgroup value on register, server block value."""
        response = client.post(
            "/register",
            json={"client_id": f"trivial_y_{trivial_y}", "secret_y": trivial_y},
        )
        assert response.status_code == 422
        assert response.get_json() == {"reason": "invalid public value"}


    @pytest.mark.parametrize("trivial_t", [0, 1, -1, server.P - 1])
    def test_commit_rejects_trivial_subgroup_values_and_no_orphan_session(self, client, trivial_t):
        '''Testarea atacului trivial zero/one pe commit (commitment_t = 0, 1, -1, P-1)'''
        """Client send trivial commitment, server reject and leave no orphan session."""
        x = derive_password_x("trivial-pass")
        y = pow(server.G, x, server.P)
        client.post("/register", json={"client_id": "trivial_commit_user", "secret_y": y})

        sessions_before = set(server.sessions.keys())

        response = client.post(
            "/login/commit",
            json={"client_id": "trivial_commit_user", "commitment_t": trivial_t},
        )

        assert response.status_code == 422
        assert response.get_json() == {"reason": "invalid commitment"}
        assert set(server.sessions.keys()) == sessions_before


    def test_concurrent_commits_produce_single_active_session(self, client):
        '''Testarea race condition la commit '''
        """Many client commits hit together, server avoid crash by dropping sessions and keep 1 """
        client_id = "race_user"
        x = derive_password_x("race-pass")
        y = pow(server.G, x, server.P)
        with server.app.app_context():
            server.db.session.add(server.User(client_id=client_id, secret_y=y.to_bytes(256, 'big')))
            server.db.session.commit()

        def do_commit(_):
            rand_r = secrets_module.randbelow(server.P - 2) + 1
            t = pow(server.G, rand_r, server.P)
            return client.post(
                "/login/commit", json={"client_id": client_id, "commitment_t": t}
            ).status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            statuses = list(pool.map(do_commit, range(10)))

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
        x = derive_password_x("type-commit-pass")
        y = pow(server.G, x, server.P)
        client.post("/register", json={"client_id": "type_confusion_commit_user", "secret_y": y})

        response = client.post(
            "/login/commit",
            json={"client_id": "type_confusion_commit_user", "commitment_t": bad_t_value},
        )
        assert response.status_code in (400, 422)
        assert response.status_code != 500


    @pytest.mark.parametrize("bad_s_value", ["12345.67", "1e20", "abc123", None])
    def test_verify_handles_malformed_solution_s_without_crash(self, client, bad_s_value):
        '''Testare tip de data pentru solution_s'''
        """Client send malformed solution types, server return error and not crash."""
        client_id = "type_confusion_user"
        x = derive_password_x("type-pass")
        y = pow(server.G, x, server.P)
        client.post("/register", json={"client_id": client_id, "secret_y": y})
        rand_r = secrets_module.randbelow(server.P - 2) + 1
        t = pow(server.G, rand_r, server.P)
        commit_resp = client.post(
            "/login/commit", json={"client_id": client_id, "commitment_t": t}
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
        x = derive_password_x("header-pass")
        y = pow(server.G, x, server.P)
        client.post("/register", json={"client_id": client_id, "secret_y": y})
        rand_r = secrets_module.randbelow(server.P - 2) + 1
        t = pow(server.G, rand_r, server.P)
        commit_resp = client.post(
            "/login/commit", json={"client_id": client_id, "commitment_t": t}
        )
        assert commit_resp.status_code == 200
        challenge_c = int(commit_resp.get_json()["challenge_c"])
        valid_s = (rand_r + challenge_c * x) % server.Q

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

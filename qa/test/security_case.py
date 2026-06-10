"""
Attack taxonomy:
Commitment binding  - the prover must commit to t before seeing c
Solution forgery    - forging s without knowing the private key x
Session security    - cross-session and cross-credential attacks
Protocol properties - freshness, uniqueness, isolation
"""

import secrets as secrets_module

import pytest

from qa_utils import server, derive_password_x, register_user, start_commit, BaseTestSuite



class TestSecurityCases(BaseTestSuite):

    # =============================================================================
    # A. Commitment binding
    # =============================================================================

    def test_commitment_binding_simulator_s_fails_against_bound_t(self, client):
        """Simulator attack: prover commits t_real; attacker builds transcript (t_sim, c, s_forged)
        where t_sim = G^s * y^{-c}. G^s == t_sim*y^c self-verifies but fails against the bound t_real."""
        client_id = "binding_user"
        x, y = register_user(client, client_id, "binding-pass")

        # session is now bound to t_real
        r, challenge_c, session_id = start_commit(client, client_id)
        t_real = server.sessions[session_id]["t"]  # server-side binding

        # Attacker builds a simulator transcript: pick s_forged, derive t_sim
        s_forged = secrets_module.randbelow(server.Q - 1) + 1
        y_neg_c = pow(y, server.Q - challenge_c, server.P)   # y^{-c} = y^{Q-c} mod P
        t_sim = (pow(server.G, s_forged, server.P) * y_neg_c) % server.P

        # t_sim is a valid subgroup member - the transcript (t_sim, c, s_forged) verifies
        assert server.is_subgroup_member(t_sim), "t_sim must be a valid subgroup element"
        # ...but it differs from the committed t_real
        assert t_sim != t_real, "t_sim must differ from t_real (binding broken otherwise)"

        # Submitting s_forged to the session that holds t_real must fail
        response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": s_forged},
        )
        assert response.status_code == 401
        assert response.get_json() == {"reason": "verification failed"}


    def test_public_key_as_commitment_legitimate_user_can_authenticate(self, client):
        """t=y=G^x: correct s = x*(1+c) mod Q. Client commits t=y, computes s accordingly, server verifies and accepts."""
        client_id = "t_eq_y_legit"
        x, y = register_user(client, client_id, "t-eq-y-legit-pass")

        _, challenge_c, session_id = start_commit(client, client_id, t_override=y)
        # Correct response when t = y:  s = x * (1 + c) mod Q
        correct_s = (x * (1 + challenge_c)) % server.Q

        response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": correct_s},
        )
        assert response.status_code == 200


    # =============================================================================
    # B. Solution forgery without the private key
    # =============================================================================

    def test_bare_nonce_as_solution_fails(self, client):
        """s=r (no c*x term): G^r != G^r * y^c unless c*x == 0 mod Q. Server rejects."""
        client_id = "bare_nonce_user"
        register_user(client, client_id, "bare-nonce-pass")

        # Keep rand_r < Q so it passes the range check as a solution
        rand_r = secrets_module.randbelow(server.Q - 1) + 1
        _, _, session_id = start_commit(client, client_id, rand_r=rand_r)

        response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": rand_r},  # s = r, no c*x contribution
        )
        assert response.status_code == 401
        assert response.get_json() == {"reason": "verification failed"}


    def test_off_by_one_solution_fails(self, client):
        """s+/-1 forgery: G^(s+/-1) = G^s * G^(+/-1) != t * y^c since G^(+/-1) != 1 in the subgroup.
        Server rejects both s+1 and s-1."""
        client_id = "off_by_one_user"
        x, _ = register_user(client, client_id, "off-by-one-pass")

        # --- s + 1 ---
        rand_r1, c1, sid1 = start_commit(client, client_id)
        correct_s1 = (rand_r1 + c1 * x) % server.Q

        r1 = client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid1},
            json={"solution_s": (correct_s1 + 1) % server.Q},
        )
        assert r1.status_code == 401

        # --- s - 1 (new session; previous session was consumed by the failed verify) ---
        rand_r2, c2, sid2 = start_commit(client, client_id)
        correct_s2 = (rand_r2 + c2 * x) % server.Q

        r2 = client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid2},
            json={"solution_s": (correct_s2 - 1) % server.Q},
        )
        assert r2.status_code == 401


    def test_solution_s_zero_fails_no_crash(self, client):
        """s=0: G^0=1 != t*y^c for any valid t,y. Server returns 422 without crashing."""
        client_id = "s_zero_user"
        register_user(client, client_id, "s-zero-pass")

        _, _, session_id = start_commit(client, client_id)

        response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": 0},
        )
        assert response.status_code == 422, "s=0 must fail the ZKP check"


    # =============================================================================
    # C. Session security
    # =============================================================================

    def test_solution_from_consumed_session_fails_on_new_session(self, client):
        """Cross-session replay: s1 satisfies G^s1=t1*y^c1 but fails against (t2,c2) of a new session."""
        client_id = "cross_session_user"
        x, _ = register_user(client, client_id, "cross-session-pass")

        # --- First session: legitimate login ---
        rand_r1, c1, sid1 = start_commit(client, client_id)
        s1 = (rand_r1 + c1 * x) % server.Q

        first_verify = client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid1},
            json={"solution_s": s1},
        )
        assert first_verify.status_code == 200  # session_1 consumed

        # --- Second session: attacker replays s1 ---
        _, _, sid2 = start_commit(client, client_id)

        response = client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid2},
            json={"solution_s": s1},
        )
        assert response.status_code == 401
        assert response.get_json() == {"reason": "verification failed"}


    def test_session_id_brute_force_infeasible(self, client):
        """Session_id is 256-bit random (1/2^256 per guess). 500 random probes against a live session all miss."""
        register_user(client, "brute_target", "brute-pass")
        start_commit(client, "brute_target")  # ensures at least one real session exists

        hits = 0
        for _ in range(500):
            fake_sid = secrets_module.token_urlsafe(32)
            resp = client.post(
                "/login/verify",
                headers={"X-Auth-Session": fake_sid},
                json={"solution_s": 1},
            )
            if resp.status_code != 404:
                hits += 1

        assert hits == 0, f"{hits} random session IDs were incorrectly matched"


    # =============================================================================
    # D. Protocol properties
    # =============================================================================
    # Note: challenge_c and session_id uniqueness are covered at larger scale
    # (10 000 samples) by automated.py::test_challenge_and_session_id_uniqueness_over_10000_commits.

    def test_concurrent_users_sessions_are_isolated(self, client):
        """Session isolation: Alice's valid s fails on Bob's session (different t,c,y). Alice's own session still accepts the correct s."""
        x_alice, _ = register_user(client, "isolation_alice", "alice-iso-pass")
        x_bob,   _ = register_user(client, "isolation_bob",   "bob-iso-pass")

        # Both users commit; two independent sessions coexist in the dict
        rand_r_alice, c_alice, sid_alice = start_commit(client, "isolation_alice")
        _,_,sid_bob   = start_commit(client, "isolation_bob")
        s_alice = (rand_r_alice + c_alice * x_alice) % server.Q

        # Alice's valid solution applied to Bob's session must fail
        cross_attempt = client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid_bob},
            json={"solution_s": s_alice},
        )
        assert cross_attempt.status_code == 401

        # Alice's own session is unaffected and still verifies correctly
        alice_verify = client.post(
            "/login/verify",
            headers={"X-Auth-Session": sid_alice},
            json={"solution_s": s_alice},
        )
        assert alice_verify.status_code == 200

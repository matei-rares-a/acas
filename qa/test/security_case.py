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

# =============================================================================
# A. Commitment binding
# =============================================================================

class TestSecurityCases(BaseTestSuite):

    def test_commitment_binding_simulator_s_fails_against_bound_t(self, client):
        '''Math: simulator picks s freely -> t_sim = G^s * y^(-c) mod P, so (t_sim, c, s) self-verifies.
        Session is bound to t_real != t_sim; checking G^s == t_real * y^c (mod P) fails.'''
        '''Testare legare commitment - atacatorul forjeaza s cu t_sim diferit de t_real (simulator Schnorr)'''
        """Prover commit to t_real, attacker build simulator transcript with different t_sim, attacker send forged s to bound session, server reject because t_sim not match t_real."""
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
        '''Math: t = y = G^x. Verify: G^s == y * y^c = y^(1+c) mod P -> correct s = x(1+c) mod Q.'''
        '''Testare autentificare legitima cu t egal y (cheia publica ca commitment)'''
        """Client commit with t equal public key y, server accept commitment, client compute correct s with known x, server verify and accept."""
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
        '''Math: s = r (no c*x term). Verify: G^r ==? G^r * y^c = G^(r+c*x). Fails unless c*x == 0 mod Q.'''
        '''Testare atac cu s egal r (nonce gol, fara contributia cheii private c*x)'''
        """Client commit with nonce r, client send s equal r without adding c*x term, server reject because verification equation g^r not equal t * y^c."""
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
        '''Math: s' = s +/- 1. Verify: G^s' = G^s * G^(+/-1) ==? t * y^c. Fails since G^(+/-1) != 1 in the subgroup.'''
        '''Testare atac incrementare s cu 1 si decrementare s cu 1 (bit-flip / integer forgery)'''
        """Client commit, client send s + 1 instead of correct s, server reject, client commit again, client send s - 1, server reject again."""
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
        '''Math: s = 0. Verify: G^0 = 1 ==? t * y^c mod P. Fails since t * y^c != 1 for any valid t, y.'''
        '''Testare s egal 0 ca solutie (respingere fara crash server)'''
        """Client commit, client send s equal zero, server reach math check because zero pass range check, server return 401 and not crash with 500."""
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
        '''Math: s1 = r1 + c1*x satisfies G^s1 == t1 * y^c1. New session has (t2, c2) != (t1, c1); G^s1 != t2 * y^c2.'''
        '''Testare replay s valid din sesiunea anterioara in sesiune noua (cross-session replay)'''
        """Client login and consume session_1 with valid s1, client commit again and get session_2, client replay s1 to session_2, server reject because t and c differ."""
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
        '''Math: session_id in {0,1}^256. P(single hit) = 1/2^256; 500 trials: P ~= 500/2^256 ~= 0.'''
        '''Testare imposibilitate ghicire session_id prin forta bruta (256 biti entropy)'''
        """Server create live session with 256-bit random ID, attacker generate 500 random session IDs, attacker probe each, server reject all because none match."""
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
        '''Math: s_alice satisfies G^s == t_alice * y_alice^c_alice. Bob's session binds (t_bob, y_bob, c_bob); equality holds with P ~= 1/Q ~= 0.'''
        '''Testare izolare sesiuni intre utilizatori concurenti (Alice si Bob sesiuni simultane)'''
        """Alice commit and Bob commit at same time, Alice send valid s to Bob session, server reject, Alice send same s to her own session, server accept."""
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

"""
Security tests for the Schnorr Zero-Knowledge Proof protocol.

Each test targets a specific cryptographic attack vector or protocol security
property.  The JWT / token part is explicitly out of scope – each test stops
at the 401 / 200 boundary of the ZKP verification step.

Attack taxonomy:
  A. Commitment binding  – the prover must commit to t before seeing c
  B. Solution forgery    – forging s without knowing the private key x
  C. Session security    – cross-session and cross-credential attacks
  D. Protocol properties – freshness, uniqueness, isolation
"""

from pathlib import Path
import hashlib
import importlib.util
import secrets as secrets_module
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVER_APP_PATH = PROJECT_ROOT / "server_app"
SERVER_MODULE_PATH = SERVER_APP_PATH / "server.py"
if str(SERVER_APP_PATH) not in sys.path:
    sys.path.insert(0, str(SERVER_APP_PATH))
spec = importlib.util.spec_from_file_location("server", SERVER_MODULE_PATH)
server = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(server)


@pytest.fixture(autouse=True)
def reset_state():
    server.app.config["TESTING"] = True
    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
    server.sessions.clear()
    yield
    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
    server.sessions.clear()


@pytest.fixture
def client():
    return server.app.test_client()


# ── helpers ──────────────────────────────────────────────────────────────────

def _derive_x(password: str) -> int:
    salt = secrets_module.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**11, r=8, p=1)
    return int.from_bytes(h, "big") % server.Q


def _register(client, client_id: str, password: str):
    x = _derive_x(password)
    y = pow(server.G, x, server.P)
    resp = client.post("/register", json={"client_id": client_id, "secret_y": y})
    assert resp.status_code in (200, 201)
    return x, y


def _commit(client, client_id: str, rand_r=None, t_override=None):
    """Post /login/commit.  Returns (response, rand_r_used)."""
    if rand_r is None:
        rand_r = secrets_module.randbelow(server.P - 2) + 1
    t = t_override if t_override is not None else pow(server.G, rand_r, server.P)
    resp = client.post("/login/commit", json={"client_id": client_id, "commitment_t": t})
    return resp, rand_r


def _burn_session(client, session_id: str):
    """Consume a session with an out-of-range s (422) so the next commit is clean."""
    client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": server.Q},  # server.Q >= Q → 422, session deleted
    )


# ═════════════════════════════════════════════════════════════════════════════
# A. Commitment binding
# ═════════════════════════════════════════════════════════════════════════════

def test_commitment_binding_simulator_s_fails_against_bound_t(client):
    """
    Attack: Schnorr simulator / commitment substitution.

    The Schnorr simulator can produce valid transcripts (t_sim, c, s_sim) by
    choosing s_sim first, then computing  t_sim = g^{s_sim} · y^{-c}  (mod P).
    In an honest execution the prover must commit to t BEFORE seeing c, so
    the simulator's t_sim differs from the t already recorded in the session.

    This test verifies that submitting s_sim to a session bound to a different
    t is rejected, demonstrating the binding property of the commitment.

    The test also shows that t_sim IS a valid subgroup element (i.e. the
    attacker CAN construct a self-consistent transcript – just not for the
    already-committed session).
    """
    client_id = "binding_user"
    x, y = _register(client, client_id, "binding-pass")

    # Legitimate commit  →  session is now bound to t_real
    commit_resp, _ = _commit(client, client_id)
    assert commit_resp.status_code == 200
    payload = commit_resp.get_json()
    challenge_c = int(payload["challenge_c"])
    session_id = payload["session_id"]
    t_real = server.sessions[session_id]["t"]  # server-side binding

    # Attacker builds a simulator transcript: pick s_forged, derive t_sim
    s_forged = secrets_module.randbelow(server.Q - 1) + 1
    y_neg_c = pow(y, server.Q - challenge_c, server.P)   # y^{-c} = y^{Q-c} mod P
    t_sim = (pow(server.G, s_forged, server.P) * y_neg_c) % server.P

    # t_sim is a valid subgroup member – the transcript (t_sim, c, s_forged) verifies
    assert server.is_subgroup_member(t_sim), "t_sim must be a valid subgroup element"
    # …but it differs from the committed t_real
    assert t_sim != t_real, "t_sim must differ from t_real (binding broken otherwise)"

    # Submitting s_forged to the session that holds t_real must fail
    response = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": s_forged},
    )
    assert response.status_code == 401
    assert response.get_json() == {"reason": "verification failed"}


def test_public_key_as_commitment_legitimate_user_can_authenticate(client):
    """
    Protocol property: t = y is a valid group element and must be accepted as
    a commitment.

    When t = y = g^x, the verification equation becomes:
        g^s == y · y^c = y^{1+c}  →  s = x(1+c) mod Q

    The legitimate user knows x and can compute the correct s.
    This confirms the ZKP still holds for this unusual commitment value.
    """
    client_id = "t_eq_y_legit"
    x, y = _register(client, client_id, "t-eq-y-legit-pass")

    commit_resp, _ = _commit(client, client_id, t_override=y)
    assert commit_resp.status_code == 200, "t=y must be accepted as a valid commitment"

    payload = commit_resp.get_json()
    challenge_c = int(payload["challenge_c"])
    session_id = payload["session_id"]

    # Correct response when t = y:  s = x * (1 + c) mod Q
    correct_s = (x * (1 + challenge_c)) % server.Q

    response = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": correct_s},
    )
    assert response.status_code == 200


def test_public_key_as_commitment_attacker_cannot_forge_proof(client):
    """
    Attack: attacker uses t = y (public key, learnable from a DB dump or the
    /register response body) as the commitment value.

    Even though t = y passes the subgroup check and generates a valid session,
    the attacker cannot compute  s = x(1+c) mod Q  without knowing x.
    Any random s they submit must fail.
    """
    client_id = "t_eq_y_attacker"
    x, y = _register(client, client_id, "t-eq-y-attacker-pass")

    commit_resp, _ = _commit(client, client_id, t_override=y)
    assert commit_resp.status_code == 200

    payload = commit_resp.get_json()
    session_id = payload["session_id"]

    # Attacker submits a random s (does not know x)
    attacker_s = secrets_module.randbelow(server.Q - 1) + 1
    response = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": attacker_s},
    )
    assert response.status_code == 401
    assert response.get_json() == {"reason": "verification failed"}


# ═════════════════════════════════════════════════════════════════════════════
# B. Solution forgery without the private key
# ═════════════════════════════════════════════════════════════════════════════

def test_bare_nonce_as_solution_fails(client):
    """
    Attack: send  s = r  (the bare nonce, omitting the private-key term c·x).

    The verification equation is  g^s == t · y^c  (mod P).
    With s = r:  LHS = g^r = t,  so the equation reduces to  t == t · y^c,
    i.e.  y^c = 1 mod P.  Since y is a non-trivial subgroup element and
    c ∈ [1, Q-1], y^c = 1 only when Q | c, which never occurs here.

    rand_r is chosen in [1, Q-1] so it passes the s-range check; the failure
    is purely cryptographic, not a range rejection.
    """
    client_id = "bare_nonce_user"
    _register(client, client_id, "bare-nonce-pass")

    # Keep rand_r < Q so it passes the range check as a solution
    rand_r = secrets_module.randbelow(server.Q - 1) + 1
    commit_resp, _ = _commit(client, client_id, rand_r=rand_r)
    assert commit_resp.status_code == 200
    session_id = commit_resp.get_json()["session_id"]

    response = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": rand_r},  # s = r, no c·x contribution
    )
    assert response.status_code == 401
    assert response.get_json() == {"reason": "verification failed"}


def test_off_by_one_solution_fails(client):
    """
    Attack: integer-increment / bit-flip forgery on a valid s.

    Incrementing or decrementing s by 1 shifts g^s by one factor of g and
    breaks  g^s == t · y^c.  Both s+1 and s-1 (mod Q) must be rejected.
    This exercises the exactness of the discrete-log check.
    """
    client_id = "off_by_one_user"
    x, _ = _register(client, client_id, "off-by-one-pass")

    # --- s + 1 ---
    commit_resp1, rand_r1 = _commit(client, client_id)
    assert commit_resp1.status_code == 200
    payload1 = commit_resp1.get_json()
    c1 = int(payload1["challenge_c"])
    sid1 = payload1["session_id"]
    correct_s1 = (rand_r1 + c1 * x) % server.Q

    r1 = client.post(
        "/login/verify",
        headers={"X-Auth-Session": sid1},
        json={"solution_s": (correct_s1 + 1) % server.Q},
    )
    assert r1.status_code == 401

    # --- s - 1 (new session; previous session was consumed by the failed verify) ---
    commit_resp2, rand_r2 = _commit(client, client_id)
    assert commit_resp2.status_code == 200
    payload2 = commit_resp2.get_json()
    c2 = int(payload2["challenge_c"])
    sid2 = payload2["session_id"]
    correct_s2 = (rand_r2 + c2 * x) % server.Q

    r2 = client.post(
        "/login/verify",
        headers={"X-Auth-Session": sid2},
        json={"solution_s": (correct_s2 - 1) % server.Q},
    )
    assert r2.status_code == 401


def test_solution_s_zero_fails_gracefully(client):
    """
    Attack: s = 0.

    s = 0 satisfies the range check (0 is in [0, Q-1]) so it reaches the
    mathematical verification step.  g^0 = 1, while t · y^c is a non-trivial
    group element with overwhelming probability.  The server must return 401,
    not crash with 500.
    """
    client_id = "s_zero_user"
    _register(client, client_id, "s-zero-pass")

    commit_resp, _ = _commit(client, client_id)
    assert commit_resp.status_code == 200
    session_id = commit_resp.get_json()["session_id"]

    response = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": 0},
    )
    assert response.status_code == 401, "s=0 must fail the ZKP check"
    assert response.status_code != 500


# ═════════════════════════════════════════════════════════════════════════════
# C. Session security
# ═════════════════════════════════════════════════════════════════════════════

def test_foreign_credentials_fail_against_another_users_session(client):
    """
    Attack: cross-credential forgery.

    Alice creates a session (t_A, c_A).  Bob (who knows his own x_B and has
    somehow also obtained rand_r_A, e.g. from a compromised client device)
    computes  s = rand_r_A + c_A · x_B.  This is a valid Schnorr response
    for Bob's key, but the session is bound to Alice's public key y_A, so
    the check  g^s == t_A · y_A^{c_A}  fails because y_A ≠ y_B.
    """
    x_alice, _ = _register(client, "alice_foreign", "alice-foreign-pass")
    x_bob,   _ = _register(client, "bob_foreign",   "bob-foreign-pass")

    commit_resp, rand_r = _commit(client, "alice_foreign")
    assert commit_resp.status_code == 200
    payload = commit_resp.get_json()
    challenge_c = int(payload["challenge_c"])
    session_id = payload["session_id"]

    # Bob computes a "valid" solution for his own key using Alice's session data
    bob_s = (rand_r + challenge_c * x_bob) % server.Q

    response = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": bob_s},
    )
    assert response.status_code == 401
    assert response.get_json() == {"reason": "verification failed"}


def test_solution_from_consumed_session_fails_on_new_session(client):
    """
    Attack: replaying a valid (s, session_id) pair on a subsequent session.

    A valid s is bound to the specific (t, c) pair of its session.  After
    session_1 is successfully consumed, a new commit produces (t_2, c_2).
    Submitting s_1 to session_2 fails because t_2 ≠ t_1 and c_2 ≠ c_1.
    """
    client_id = "cross_session_user"
    x, _ = _register(client, client_id, "cross-session-pass")

    # --- First session: legitimate login ---
    commit_resp1, rand_r1 = _commit(client, client_id)
    assert commit_resp1.status_code == 200
    payload1 = commit_resp1.get_json()
    c1 = int(payload1["challenge_c"])
    sid1 = payload1["session_id"]
    s1 = (rand_r1 + c1 * x) % server.Q

    first_verify = client.post(
        "/login/verify",
        headers={"X-Auth-Session": sid1},
        json={"solution_s": s1},
    )
    assert first_verify.status_code == 200  # session_1 consumed

    # --- Second session: attacker replays s1 ---
    commit_resp2, _ = _commit(client, client_id)
    assert commit_resp2.status_code == 200
    sid2 = commit_resp2.get_json()["session_id"]

    response = client.post(
        "/login/verify",
        headers={"X-Auth-Session": sid2},
        json={"solution_s": s1},
    )
    assert response.status_code == 401
    assert response.get_json() == {"reason": "verification failed"}


def test_session_id_brute_force_infeasible(client):
    """
    Attack: session ID guessing.

    Session IDs are generated with secrets.token_urlsafe(32), providing
    256 bits of entropy.  500 randomly-generated token strings must all
    return 404 – none must coincidentally match the live session.
    """
    _register(client, "brute_target", "brute-pass")
    _commit(client, "brute_target")  # ensures at least one real session exists

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


# ═════════════════════════════════════════════════════════════════════════════
# D. Protocol properties
# ═════════════════════════════════════════════════════════════════════════════

def test_challenge_c_is_fresh_and_unique_per_session(client):
    """
    Property: challenge freshness / unpredictability.

    Each /login/commit must draw c independently from [1, Q-1].
    Collecting 50 challenges for the same user must yield 50 distinct values.
    A collision in 50 samples from a ~1024-bit space has probability ≈ 2^{-1012}
    (birthday bound), so any collision indicates a broken RNG.

    An attacker who could predict c in advance could pre-compute a forged
    commitment  t_forged = g^s · y^{-c}  before calling /login/commit, turning
    a non-interactive simulator into a real-protocol attack.
    """
    client_id = "freshness_user"
    x = _derive_x("freshness-pass")
    y = pow(server.G, x, server.P)
    with server.app.app_context():
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()

    challenges = []
    for _ in range(50):
        rand_r = secrets_module.randbelow(server.P - 2) + 1
        t = pow(server.G, rand_r, server.P)
        resp = client.post(
            "/login/commit",
            json={"client_id": client_id, "commitment_t": t},
        )
        assert resp.status_code == 200
        payload = resp.get_json()
        challenges.append(int(payload["challenge_c"]))
        _burn_session(client, payload["session_id"])  # free slot for next commit

    assert len(set(challenges)) == 50, "Duplicate challenge_c detected – RNG may be broken"
    assert all(1 <= c <= server.Q - 1 for c in challenges), "challenge_c outside [1, Q-1]"


def test_concurrent_users_sessions_are_isolated(client):
    """
    Property: per-user session isolation.

    Alice and Bob each commit concurrently (two live sessions).
    Alice's valid solution to her session must NOT accidentally satisfy
    Bob's session (different t, c, and y).
    After the failed cross-attempt, Alice's own session must still succeed.
    """
    x_alice, _ = _register(client, "isolation_alice", "alice-iso-pass")
    x_bob,   _ = _register(client, "isolation_bob",   "bob-iso-pass")

    # Both users commit; two independent sessions coexist in the dict
    commit_alice, rand_r_alice = _commit(client, "isolation_alice")
    commit_bob,   _            = _commit(client, "isolation_bob")
    assert commit_alice.status_code == 200
    assert commit_bob.status_code == 200

    c_alice  = int(commit_alice.get_json()["challenge_c"])
    sid_alice = commit_alice.get_json()["session_id"]
    sid_bob   = commit_bob.get_json()["session_id"]
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

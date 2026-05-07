from pathlib import Path
import secrets as secrets_module
import sys

import pytest

_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))
from qa_utils import server, derive_password_x, register_user, start_commit


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




# ---------------------------------------------------------------------------
# Data Breach simulation: stolen public key (secret_y) cannot log in
# ---------------------------------------------------------------------------

def test_stolen_public_key_cannot_authenticate(client):
    '''Testare atac cu cheia publica furata din baza de date (simulare data breach)'''
    """Attacker steal public value from DB, attacker try login, server reject fake proof."""
    client_id = "alice_test"
    password = "alices-secure-password"

    x, _ = register_user(client, client_id, password)
    rand_r, challenge_c, session_id = start_commit(client, client_id)

    # Attacker reads secret_y directly from the database
    with server.app.app_context():
        user = server.User.query.filter_by(client_id=client_id).first()
        stolen_y = int(user.secret_y)

    # Attacker computes solution_s using stolen y instead of private x
    # s = r + c * y mod Q  (wrong: y is public, not the private exponent)
    attacker_s = (rand_r + challenge_c * stolen_y) % server.Q

    response = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": attacker_s},
    )

    assert response.status_code == 401
    assert response.get_json() == {"reason": "verification failed"}


# ---------------------------------------------------------------------------
# RNG entropy: no collision in 10000 challenge_c and session_id values
# ---------------------------------------------------------------------------

def test_challenge_and_session_id_uniqueness_over_10000_commits(client):
    '''Testare unicitate challenge_c si session_id pe multe commit-uri (validare entropia RNG)'''
    """Client ask commit many times, server make unique challenge and unique session id."""
    client_id = "entropy_test_user"
    n=10000
    x, _ = derive_password_x("entropy-password")
    y = pow(server.G, x, server.P)
    with server.app.app_context():
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()

    challenges = []
    session_ids = []

    for _ in range(n):
        rand_r = secrets_module.randbelow(server.P - 2) + 1
        t = pow(server.G, rand_r, server.P)
        resp = client.post(
            "/login/commit",
            json={"client_id": client_id, "commitment_t": t},
        )
        assert resp.status_code == 200
        payload = resp.get_json()
        challenges.append(int(payload["challenge_c"]))
        session_ids.append(payload["session_id"])

        # Consume session with an invalid solution to keep the next commit independent.
        # Server should delete the session on invalid solution.
        verify = client.post(
            "/login/verify",
            headers={"X-Auth-Session": payload["session_id"]},
            json={"solution_s": server.Q},
        )
        assert verify.status_code == 422

    assert len(set(session_ids)) == n, "Session ID collision detected!"
    assert len(set(challenges)) == n, "challenge_c collision detected!"
    assert all(1 <= c <= server.P - 2 for c in challenges), "challenge_c out of range!"


# ---------------------------------------------------------------------------
# Prompt 4 - MitM Weak Parameter Injection: DLP brute-force then forge login
# ---------------------------------------------------------------------------

def test_mitm_weak_parameter_injection_allows_dlp_brute_force_and_login(client, monkeypatch):
    '''Testare atac MitM injectare parametri slabi P=23 - DLP brute-force si autentificare reusita cu x recuperat'''
    """Attacker MitM /parameters and replaces P/Q/G with a tiny group (P=23, Q=11, G=4).
    Victim registers using y computed under weak parameters.
    Attacker brute-forces the discrete logarithm trivially (at most P-1 iterations).
    Attacker completes a valid ZKP login as the victim using the recovered private key."""

    # Weak parameters injected by the MitM -- group of order 11 inside Z_23
    # Verification: 4^11 mod 23 = 1  (group order correct)
    P_weak = 23
    Q_weak = 11  # (P_weak - 1) // 2
    G_weak = 4   # generator of the unique subgroup of order 11

    monkeypatch.setattr(server, "P", P_weak)
    monkeypatch.setattr(server, "Q", Q_weak)
    monkeypatch.setattr(server, "G", G_weak)

    client_id = "mitm_victim"
    x_victim = 50                                      # victim's private key
    y_victim = pow(G_weak, x_victim, P_weak)          # = 8  (stored in DB)

    # Victim registers -- DB stores y computed under the (attacker-controlled) weak group
    resp = client.post("/register", json={"client_id": client_id, "secret_y": y_victim})
    assert resp.status_code == 201

    # Attacker brute-forces the discrete logarithm in at most P-2 steps
    x_recovered = next(
        (i for i in range(1, P_weak) if pow(G_weak, i, P_weak) == y_victim),
        None,
    )
    assert x_recovered is not None, "DLP brute-force found no solution"
    assert x_recovered == x_victim % Q_weak, f"Recovered x={x_recovered} != x_victim mod Q={x_victim % Q_weak}"

    # Attacker completes a fresh ZKP login using the recovered private key
    rand_r = secrets_module.randbelow(P_weak - 2) + 1
    t = pow(G_weak, rand_r, P_weak)

    commit_resp = client.post(
        "/login/commit",
        json={"client_id": client_id, "commitment_t": t},
    )
    assert commit_resp.status_code == 200
    payload = commit_resp.get_json()
    c = int(payload["challenge_c"])
    session_id = payload["session_id"]

    s = (rand_r + c * x_recovered) % Q_weak

    verify_resp = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": s},
    )
    assert verify_resp.status_code == 200, (
        "Attacker should successfully authenticate using brute-forced x in weak group"
    )
    assert "token" in verify_resp.get_json()


from pathlib import Path
import secrets as secrets_module
import sys

import pytest

_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))
from qa_utils import server, derive_password_x, register_user, start_commit, ec_scalar_mult, EC_ORDER, EC_GENERATOR


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

'''
python -m pytest qa/attack_simulation/automated.py -v
'''

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

    # Attacker reads secret_y directly from the database (EC: 64-byte = x_coord || y_coord)
    with server.app.app_context():
        user = server.User.query.filter_by(client_id=client_id).first()
        stolen_Y_x = int.from_bytes(user.secret_y[:32], 'big')

    # Attacker computes solution_s using stolen public x-coordinate instead of private x
    # s = r + c * Y_x mod EC_ORDER  (wrong: Y_x is public, not the private scalar)
    attacker_s = (rand_r + challenge_c * stolen_Y_x) % EC_ORDER

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
    n = 100
    x, _ = derive_password_x("entropy-password")
    Y = ec_scalar_mult(x, EC_GENERATOR)
    with server.app.app_context():
        server.db.session.add(server.User(
            client_id=client_id,
            secret_y=Y[0].to_bytes(32, 'big') + Y[1].to_bytes(32, 'big'),
        ))
        server.db.session.commit()

    challenges = []
    session_ids = []

    for _ in range(n):
        rand_r = secrets_module.randbelow(EC_ORDER - 1) + 1
        T = ec_scalar_mult(rand_r, EC_GENERATOR)
        resp = client.post(
            "/login/commit",
            json={"client_id": client_id, "commitment_t_x": str(T[0]), "commitment_t_y": str(T[1])},
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
            json={"solution_s": 0},
        )
        assert verify.status_code == 422

    assert len(set(session_ids)) == n, "Session ID collision detected!"
    assert len(set(challenges)) == n, "challenge_c collision detected!"
    assert all(1 <= c <= EC_ORDER - 1 for c in challenges), "challenge_c out of range!"


# ---------------------------------------------------------------------------
# MitM Weak Parameter Injection: DLP brute-force then force login
# ---------------------------------------------------------------------------

def test_mitm_weak_parameter_injection_fails_against_hardcoded_ec_curve(client):
    '''Testare atac MitM injectare parametri slabi esueaza - curba EC secp256r1 hardcodata respinge puncte invalide'''
    """With secp256r1 hardcoded in the server, an attacker cannot inject weak curve parameters.
    Any public key not on secp256r1 is rejected at /register with 422 'invalid public value',
    so the DLP brute-force attack is blocked before login is ever attempted."""

    # Attacker computes a point on a tiny fake group (P=23, G=4) -- NOT a secp256r1 point
    P_weak, G_weak = 23, 4
    x_victim = 50
    y_victim = pow(G_weak, x_victim, P_weak)  # small integer, NOT on secp256r1

    # Victim (or attacker) attempts to register a public key from the weak group
    resp = client.post("/register", json={
        "client_id": "mitm_victim",
        "secret_y_x": str(y_victim),
        "secret_y_y": str(y_victim),
    })
    # Server rejects because is_valid_ec_point fails for non-secp256r1 coordinates
    assert resp.status_code == 422
    assert resp.get_json() == {"reason": "invalid public value"}


def test_mitm_weak_parameters_fails_against_hardcoded_server(client):
    '''Testare atac MitM parametri slabi esueaza la inregistrare - server respinge y_weak care nu e membru subgrup'''
    """Server rejects y_weak at /register because is_subgroup_member checks y^Q == 1 mod P_big.
    y_weak = G^x mod P_weak does not satisfy that, so the attack is blocked before login."""
    P_weak, G_weak = 23, 4
    x_victim = 50
    y_weak = pow(G_weak, x_victim, P_weak)  # y_weak is a small integer, not on secp256r1

    # Server checks is_valid_ec_point(x, y); y_weak is not on secp256r1, so registration is rejected
    resp = client.post("/register", json={
        "client_id": "mitm_victim",
        "secret_y_x": str(y_weak),
        "secret_y_y": str(y_weak),
    })
    assert resp.status_code == 422
    assert resp.get_json() == {"reason": "invalid public value"}
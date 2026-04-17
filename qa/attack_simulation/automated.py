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


def derive_x(password: str) -> int:
    salt = secrets_module.token_bytes(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**11, r=8, p=1)
    return int.from_bytes(hashed, "big") % server.Q


def register(client, client_id: str, password: str):
    x = derive_x(password)
    y = pow(server.G, x, server.P)
    resp = client.post("/register", json={"client_id": client_id, "secret_y": y})
    assert resp.status_code in (200, 201)
    return x, y


def commit(client, client_id: str):
    rand_r = secrets_module.randbelow(server.P - 2) + 1
    t = pow(server.G, rand_r, server.P)
    resp = client.post(
        "/login/commit", json={"client_id": client_id, "commitment_t": t}
    )
    assert resp.status_code == 200
    payload = resp.get_json()
    return rand_r, int(payload["challenge_c"]), payload["session_id"]


# ---------------------------------------------------------------------------
# Prompt 1 – Data Breach simulation: stolen public key (secret_y) cannot log in
# ---------------------------------------------------------------------------

def test_stolen_public_key_cannot_authenticate(client):
    """Attacker steal public value from DB, attacker try login, server reject fake proof."""
    client_id = "alice_test"
    password = "alices-secure-password"

    x, _ = register(client, client_id, password)
    rand_r, challenge_c, session_id = commit(client, client_id)

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
# Prompt 2 – Replay Attack: session nonce is single-use
# ---------------------------------------------------------------------------

def test_replay_attack_on_verify_payload_rejected(client):
    """Attacker copy old verify request, server reject reused session data."""
    client_id = "replay_sim_user"
    password = "replay-sim-password"

    x, _ = register(client, client_id, password)
    rand_r, challenge_c, session_id = commit(client, client_id)
    solution_s = (rand_r + challenge_c * x) % server.Q

    # Legitimate login succeeds
    first = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": solution_s},
    )
    assert first.status_code == 200

    # Attacker replays the exact same request
    replay = client.post(
        "/login/verify",
        headers={"X-Auth-Session": session_id},
        json={"solution_s": solution_s},
    )
    assert replay.status_code == 404
    assert replay.get_json() == {"reason": "invalid session_id"}


# ---------------------------------------------------------------------------
# Prompt 3 – RNG entropy: no collision in 1000 challenge_c and session_id values
# ---------------------------------------------------------------------------

def test_challenge_and_session_id_uniqueness_over_1000_commits(client):
    """Client ask commit many times, server make unique challenge and unique session id."""
    client_id = "entropy_test_user"
    x = derive_x("entropy-password")
    y = pow(server.G, x, server.P)
    with server.app.app_context():
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()

    challenges = []
    session_ids = []

    for _ in range(1000):
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

    assert len(set(session_ids)) == 1000, "Session ID collision detected!"
    assert len(set(challenges)) == 1000, "challenge_c collision detected!"
    assert all(1 <= c <= server.Q - 1 for c in challenges), "challenge_c out of range!"


r'''
Context inițial pentru Agent
"Acționează ca un Penetration Tester / Security Researcher. Trebuie să validăm securitatea unui sistem de autentificare Zero-Knowledge Proof (Schnorr) implementat în Flask. Voi avea nevoie de teste automate (pytest) pentru simulările care pot rula în CI/CD. Pentru atacurile care necesită interceptarea fizică a rețelei sau interacțiune umană cu unelte externe (ex: Wireshark), nu scrie cod Python, ci generează un fișier SECURITY_AUDIT_MANUAL.md cu pașii exacți de reproducere, așteptările matematice și dovezile necesare."


Prompt 1: Simulare Data Breach (Server Compromise)
Acest test demonstrează că un atacator care obține un dump al bazei de date nu poate folosi datele pentru a se autentifica, rezolvând problema scurgerilor de parole.
"Scrie un test de securitate E2E care simulează compromiterea bazei de date.
Înregistrează un utilizator valid (alice_test) cu o parolă sigură, astfel încât secret_y să fie salvat în DB.
Simularea breșei: Extrage direct din baza de date valoarea secret_y a lui alice_test (așa cum ar face un hacker cu acces SQL).
Atacul: Încearcă să parcurgi fluxul de autentificare (POST /login/commit urmat de POST /login/verify),
dar în etapa de calculare a lui solution_s, folosește valoarea furată secret_y în loc de cheia privată $x$
(ex: calculează $s = r + c \cdot y \pmod q$).
Validează (assert) că serverul respinge acest răspuns cu 401 Unauthorized și mesajul verification failed,
demonstrând că furtul cheii publice nu compromite contul."


Prompt 2: Simulare Replay Attack strict pe sesiune
Aici testăm dacă atacatorul poate captura session_id și solution_s pentru a le refolosi.
"Scrie un test automat care simulează un Replay Attack asupra payload-ului de validare.
Execută un flux de login ZKP complet și valid pentru un utilizator (Commitment -> primire challenge -> calculare răspuns -> Verify).
Salvează exact header-ul X-Auth-Session și body-ul JSON {"solution_s": "..."} folosite la pasul de Verify.
Atacul: Execută imediat un nou request POST /login/verify folosind datele salvate la pasul 2.
Validează (assert) că request-ul malițios primește HTTP 404 cu invalid session_id. Dicționarul de sesiuni trebuie să împiedice orice refolosire a nonce-ului de sesiune."


Prompt 3: Testarea impredictibilității (Weak RNG & Session Fixation)
Un atacator ar putea încerca să ghicească challenge_c sau session_id dacă serverul folosește un generator de numere slabe.
"Scrie un test de securitate care validează entropia și unicitatea funcțiilor de generare
(secrets.randbelow și secrets.token_urlsafe) folosite în /login/commit.
Execută request-ul POST /login/commit de 1000 de ori consecutiv într-o buclă pentru același client_id.
Stochează toate valorile challenge_c și session_id primite.
Validează (assert) următoarele:
Lungimea listei de session_id-uri unice este exact 1000 (0 coliziuni, prevenind Session Fixation).
Lungimea listei de challenge_c unice este exact 1000 (0 coliziuni, prevenind Challenge Prediction).
Toate valorile challenge_c se încadrează strict în intervalul $[1, Q-1]$."
'''
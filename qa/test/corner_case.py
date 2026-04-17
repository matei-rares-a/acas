from pathlib import Path
import concurrent.futures
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


def derive_password_x(password_string):
    salt = secrets_module.token_bytes(16)
    hashed = hashlib.scrypt(password_string.encode(), salt=salt, n=2**11, r=8, p=1)
    return int.from_bytes(hashed, "big") % server.Q


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


# ---------------------------------------------------------------------------
# Prompt 1 – Boundary values on solution_s (s < 0 or s >= Q must be rejected)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_s", [-1, server.Q, server.Q + 1, server.P * 10])
def test_verify_rejects_out_of_range_solution_s(client, bad_s):
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
    # Session must be deleted to prevent reuse after malformed proofs.
    assert session_id not in server.sessions


# ---------------------------------------------------------------------------
# Prompt 2 – Trivial zero/one attack: values outside subgroup rejected
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("trivial_y", [0, 1, -1, server.P - 1])
def test_register_rejects_trivial_subgroup_values(client, trivial_y):
    """Client send trivial subgroup value on register, server block value."""
    response = client.post(
        "/register",
        json={"client_id": f"trivial_y_{trivial_y}", "secret_y": trivial_y},
    )
    assert response.status_code == 422
    assert response.get_json() == {"reason": "invalid public value"}


@pytest.mark.parametrize("trivial_t", [0, 1, -1, server.P - 1])
def test_commit_rejects_trivial_subgroup_values_and_no_orphan_session(client, trivial_t):
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


# ---------------------------------------------------------------------------
# Prompt 3 – Race condition: 10 simultaneous commits for the same client_id
# ---------------------------------------------------------------------------
def test_concurrent_commits_produce_single_active_session(client):
    """Many client commits hit together, server avoid crash and keep one active session."""
    client_id = "race_user"
    x = derive_password_x("race-pass")
    y = pow(server.G, x, server.P)
    with server.app.app_context():
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
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
    assert 409 in statuses
    active = [s for s in server.sessions.values() if s["client_id"] == client_id]
    assert len(active) == 1


# ---------------------------------------------------------------------------
# Prompt 4 – Type confusion: malformed solution_s values must not crash server
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_s_value", ["12345.67", "1e20", "abc123", None])
def test_verify_handles_malformed_solution_s_without_crash(client, bad_s_value):
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


# ---------------------------------------------------------------------------
# Prompt 5 – X-Auth-Session header edge cases
# ---------------------------------------------------------------------------
def test_verify_x_auth_session_header_edge_cases(client):
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

    # Missing header entirely
    r1 = client.post("/login/verify", json={"solution_s": valid_s})
    assert r1.status_code == 400
    assert r1.get_json() == {"reason": "missing session_id in X-Auth-Session header"}

    # Empty string header
    r2 = client.post(
        "/login/verify", headers={"X-Auth-Session": ""}, json={"solution_s": valid_s}
    )
    assert r2.status_code == 400

    # Whitespace-only header
    r3 = client.post(
        "/login/verify", headers={"X-Auth-Session": "   "}, json={"solution_s": valid_s}
    )
    assert r3.status_code in (400, 404)

    # Extremely long session_id (>1000 chars)
    long_id = "x" * 1001
    r4 = client.post(
        "/login/verify", headers={"X-Auth-Session": long_id}, json={"solution_s": valid_s}
    )
    assert r4.status_code in (400, 404)
    assert r4.status_code != 500


'''
Context inițial (de reamintit agentului)
"Acționează ca un Security QA Automation Engineer. Scrie teste de integrare avansate (corner cases/boundary tests) în Python cu pytest și Flask test_client pentru un sistem ZKP Schnorr. Concentrează-te pe endpoint-urile /register, /login/commit și /login/verify. Nu testa JWT-ul, ci strict matematica, limitele parametrilor și starea sesiunilor din memoria serverului."

Prompt 1: Testarea limitelor matematice ale soluției (Boundary Values pe $S$)
Codul tău validează if s < 0 or s >= Q:. Trebuie să ne asigurăm că extremele absolute sunt gestionate corect și nu produc crash-uri (ex: Overflow sau excepții de parsare).
"Scrie un test parametrizat (@pytest.mark.parametrize) care să testeze limitele valorii solution_s pe endpoint-ul POST /login/verify.
1. Formează o sesiune validă în prealabil (POST /login/commit) pentru a avea un session_id valid.
2. Testează următoarele valori extreme (corner cases) pentru solution_s:O valoare negativă: -1Limita superioară exactă: Q (adică (P - 1) // 2)O valoare peste limită: Q + 1O valoare extrem de mare: P * 10 (pentru a testa comportamentul memoriei/parserului la BigInt)
3. Validează (assert) că serverul respinge toate aceste cereri cu HTTP 422 Unprocessable Entity și motivul invalid solution.Asigură-te că testul verifică eliberarea dicționarului sessions chiar și după un solution_s formatat ciudat."


Prompt 2: "The Trivial Zero/One Attack" (Extremele pe Subgrup)
Un atacator ar putea trimite valori matematice banale ($0$ sau $1$) sperând să "anuleze" o ecuație de pe server (deoarece $1^X = 1$ și $0^X = 0$).
"Scrie un test criptografic de tip Corner Case pentru endpoint-urile de Setup și Commit, încercând atacul valorilor banale.
Încearcă să înregistrezi un utilizator (POST /register) trimițând secret_y cu valorile: 0, 1, -1 și P-1.
2. Validează că funcția is_subgroup_member blochează cu succes aceste valori, returnând 422 Unprocessable Entity.
3. Încearcă un request POST /login/commit trimițând commitment_t cu aceleași valori: 0, 1, -1, P-1.Validează (assert) că serverul returnează HTTP 422 pentru toate și NU creează o sesiune orfană în dicționarul din memorie pentru aceste intrări invalide."


Prompt 3: Race Conditions la Crearea Sesiunilor (Concurență asincronă)
Ce se întâmplă dacă un client are un bug de rețea sau un atacator rulează un script care dă "spam" pe butonul de login în aceeași milisecundă?
"Scrie un test de concurență (Race Condition) folosind concurrent.futures.ThreadPoolExecutor pentru a apela POST /login/commit simultan.
1. Creează un utilizator valid de test în baza de date.
2. Lansează 10 request-uri POST /login/commit PENTRU ACELAȘI client_id, rulând în thread-uri paralele (cât mai aproape de aceeași milisecundă).
3. Capturează toate răspunsurile HTTP.
4. Validează (assert) următoarele condiții stricte de stabilitate a stării:
Nu există erori de tip HTTP 500 (Server Crash).
Cel puțin un request a primit 409 Conflict (dovedind că serverul a curățat o sesiune concurentă).
- La finalul testului, în dicționarul sessions există exact o singură sesiune activă pentru acel client_id, prevenind memory leaks."


Prompt 4: Manipularea tipurilor de date (Type Confusion & Payload malformat)
Serverul așteaptă stringuri care pot fi convertite în numere întregi mari (BigInt). Ce se întâmplă dacă îi dăm formate ciudate?
"Scrie un test de validare a parserului de date (validate_int_field) pentru endpoint-ul POST /login/verify.
Creează un session_id valid prin POST /login/commit.
Trimite request-ul către /login/verify manipulând câmpul solution_s în următoarele moduri:
Ca string cu zecimale (Float): "12345.67"
Ca notație științifică: "1e20"
Ca string non-numeric: "abc123"
Null/None: null
Validează (assert) că aplicația nu dă crash cu ValueError sau TypeError (HTTP 500), ci tratează elegant eroarea returnând 422 (sau 400) conform comportamentului de fallback din funcția validate_int_field."

Prompt 5: Manipularea la limită a Header-ului de Sesiune
Sesiunea dintre Commit și Verify este legată doar de un header HTTP. Acesta poate fi manipulat de un proxy sau de un atacator.
"Scrie un test E2E care acoperă corner cases pentru header-ul X-Auth-Session folosit în etapa de verificare a protocolului Schnorr.
Realizează pasul POST /login/commit cu succes.
Apelează POST /login/verify dar cu următoarele scenarii pentru header-ul X-Auth-Session:
Omiterea totală a header-ului. (Assert: HTTP 400 "missing session_id")
Un header complet gol (Empty string).
Un header care conține doar spații albe ("   ").
Un session_id extrem de lung (peste 1000 caractere) pentru a verifica dacă dicționarul de sesiuni crapă la căutare.
Validează (assert) că serverul returnează erorile corecte (400 sau 404) și menține o stare stabilă (fără Internal Server Error)."

'''
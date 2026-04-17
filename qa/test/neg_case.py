from pathlib import Path
import hashlib
import importlib.util
import secrets as secrets_module
import sys
import time

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


def derive_password_x(password_string, salt=None):
	if salt is None:
		salt = secrets_module.token_bytes(16)
	password_hashed = hashlib.scrypt(
		password_string.encode(),
		salt=salt,
		n=2**11,
		r=8,
		p=1,
	)
	return int.from_bytes(password_hashed, "big") % server.Q


def register_user(client, client_id, password):
	x = derive_password_x(password)
	y = pow(server.G, x, server.P)
	response = client.post("/register", json={"client_id": client_id, "secret_y": y})
	assert response.status_code in (200, 201)
	return x, y


def start_commit(client, client_id, rand_r=None):
	if rand_r is None:
		rand_r = secrets_module.randbelow(server.P - 2) + 1
	commitment_t = pow(server.G, rand_r, server.P)
	commit_response = client.post(
		"/login/commit", json={"client_id": client_id, "commitment_t": commitment_t}
	)
	assert commit_response.status_code == 200
	payload = commit_response.get_json()
	return rand_r, int(payload["challenge_c"]), payload["session_id"]


def test_wrong_password_proof_is_rejected_and_session_is_deleted(client):
	"""Client send wrong proof, server reject login, server remove used session."""
	client_id = "hacker_test"
	correct_password = "correct-password"
	wrong_password = "wrong-password"

	register_user(client, client_id, correct_password)
	rand_r, challenge_c, session_id = start_commit(client, client_id)

	wrong_x = derive_password_x(wrong_password)
	wrong_solution_s = (rand_r + challenge_c * wrong_x) % server.Q

	verify_response = client.post(
		"/login/verify",
		headers={"X-Auth-Session": session_id},
		json={"solution_s": wrong_solution_s},
	)

	assert verify_response.status_code == 401
	assert verify_response.get_json() == {"reason": "verification failed"}
	assert session_id not in server.sessions


def test_replay_attack_reusing_verify_payload_is_rejected(client):
	"""Client do valid verify once, attacker replay same data, server reject replay."""
	client_id = "replay_test"
	password = "replay-password"

	x, _ = register_user(client, client_id, password)
	rand_r, challenge_c, session_id = start_commit(client, client_id)
	solution_s = (rand_r + challenge_c * x) % server.Q

	first_verify = client.post(
		"/login/verify",
		headers={"X-Auth-Session": session_id},
		json={"solution_s": solution_s},
	)
	assert first_verify.status_code == 200

	replay_verify = client.post(
		"/login/verify",
		headers={"X-Auth-Session": session_id},
		json={"solution_s": solution_s},
	)
	assert replay_verify.status_code == 404
	assert replay_verify.get_json() == {"reason": "invalid session_id"}


@pytest.mark.parametrize("malicious_t", [0, 1, -5, server.P + 10])
def test_commit_rejects_non_subgroup_values(client, malicious_t):
	"""Client send bad commitment value, server block value outside subgroup."""
	register_user(client, "subgroup_commit_user", "subgroup-pass")

	response = client.post(
		"/login/commit",
		json={"client_id": "subgroup_commit_user", "commitment_t": malicious_t},
	)

	assert response.status_code == 422
	assert response.get_json() == {"reason": "invalid commitment"}


@pytest.mark.parametrize("malicious_y", [0, 1, -5, server.P + 10])
def test_register_rejects_non_subgroup_values(client, malicious_y):
	"""Client send bad public value on register, server reject bad math input."""
	response = client.post(
		"/register",
		json={"client_id": f"subgroup_register_user_{malicious_y}", "secret_y": malicious_y},
	)

	assert response.status_code == 422
	assert response.get_json() == {"reason": "invalid public value"}


def test_verify_rejects_expired_session_and_cleans_up_state(client, monkeypatch):
	"""Client wait too long then verify, server mark session expired and clean state."""
	client_id = "timeout_test"
	password = "timeout-password"

	x, _ = register_user(client, client_id, password)
	rand_r, challenge_c, session_id = start_commit(client, client_id)
	solution_s = (rand_r + challenge_c * x) % server.Q

	real_time = time.time
	monkeypatch.setattr(server.time, "time", lambda: real_time() + 6)

	verify_response = client.post(
		"/login/verify",
		headers={"X-Auth-Session": session_id},
		json={"solution_s": solution_s},
	)

	assert verify_response.status_code == 300
	assert verify_response.get_json() == {"reason": "session expired"}
	assert session_id not in server.sessions


def test_second_commit_same_user_returns_conflict_and_invalidates_old_session(client):
	"""Client send second commit for same user, server return conflict and drop old session."""
	client_id = "alice_test"
	password = "alice-password"
	register_user(client, client_id, password)

	_, _, session_id_1 = start_commit(client, client_id)

	second_commit = client.post(
		"/login/commit",
		json={
			"client_id": client_id,
			"commitment_t": pow(server.G, secrets_module.randbelow(server.P - 2) + 1, server.P),
		},
	)

	assert second_commit.status_code == 409
	assert second_commit.get_json().get("reason") == (
		"existing commitment found, start a new session"
	)
	assert session_id_1 not in server.sessions
	active_for_client = [s for s in server.sessions.values() if s["client_id"] == client_id]
	assert len(active_for_client) <= 1
	


'''
Context inițial (de reamintit agentului)
"Acționează ca un Security QA Automation Engineer. Scrie teste pentru urmatoarele prompturi"

Prompt 1: Testarea validării matematice (Parolă/Dovadă greșită)
Acest test demonstrează că o persoană care ghicește sau greșește parola nu poate trece de ecuația $G^s == t \cdot y^c \pmod P$.
"Scrie un test de integrare E2E pentru fluxul de login ZKP care simulează introducerea unei parole greșite.
Înregistrează în baza de date de test utilizatorul hacker_test cu un secret_y valid calculat pe baza unei parole corecte.
Execută un request POST /login/commit valid și obține challenge_c și session_id.
Calculează solution_s folosind o valoare $x$ (parolă) greșită/diferită față de cea cu care a fost generat secret_y.
Trimite request-ul POST /login/verify cu acest solution_s invalid.
Validează (assert) că răspunsul HTTP are statusul 401 Unauthorized și corpul {"reason": "verification failed"}.
Asigură-te că sesiunea a fost distrusă (ștearsă din memorie) chiar și în caz de eșec."

Prompt 2: Simulare Replay Attack (Refolosirea soluției/sesiunii interceptate)
Acest test validează afirmația din disertație conform căreia "Traffic Sniffing" nu permite refolosirea mesajelor.
"Scrie un test de securitate care simulează un Replay Attack asupra endpoint-ului /login/verify.
Parcurge un flux complet și valid de autentificare ZKP pentru un utilizator de test (Commitment -> primire $c$ -> calculare $s$ valid).
Execută request-ul POST /login/verify cu soluția calculată și validează că returnează 200 OK (Autentificare reușită).
Imediat după, simulează un atacator care a interceptat traficul: execută exact același request POST /login/verify, cu același session_id și același solution_s.
Validează (assert) că al doilea request este respins cu 404 Not Found și mesajul {"reason": "invalid session_id"},
demonstrând că starea (nonce-ul de sesiune) este de unică folosință și previne replay-urile."
Prompt 3: Atacul Subgrupurilor (Subgroup Confinement Attack)
Aici demonstrezi de ce ai funcția is_subgroup_member în cod. E un test criptografic avansat care va impresiona comisia.
"Scrie un test de securitate care simulează trimiterea unor parametri criptografici malițioși (în afara subgrupului valid).
Creează un test parametrizat (folosind @pytest.mark.parametrize) care să testeze endpoint-ul POST /login/commit.
Folosește valori malițioase pentru commitment_t: 0, 1, o valoare negativă (-5), și o valoare mai mare decât P (P + 10).
Pentru fiecare valoare, trimite request-ul către /login/commit.
Validează (assert) că serverul respinge TOATE aceste cereri cu status 422 Unprocessable Entity și mesajul {"reason": "invalid commitment"}.
Scrie un sub-test identic pentru endpoint-ul POST /register care să trimită aceste valori malițioase în câmpul secret_y și validează că se returnează status 422 cu {"reason": "invalid public value"}."

Prompt 4: Expirarea ferestrei de timp (Session Timeout)
Protocolul nu lasă atacatorului timp infinit să încerce să spargă criptografia sau să facă brute-force pe challenge.
"Scrie un test de integrare care validează mecanismul de timeout al sesiunilor ZKP.
Execută POST /login/commit pentru un utilizator valid și obține session_id.
Folosește librăria freezegun sau fă un mock pe time.time() în Python pentru a simula trecerea a 6 secunde în sistem (deoarece pragul din cod este de 5 secunde).
Trimite request-ul POST /login/verify cu un solution_s matematic corect, asociat acelui session_id.
Validează (assert) că răspunsul serverului este status 300 Multiple Choices cu mesajul {"reason": "session expired"}.
Verifică în memoria serverului (dicționarul sessions) că sesiunea respectivă a fost ștearsă automat."

Prompt 5: Conflict de Sesiune (Hijacking / Overwrite prevention)
Ce se întâmplă dacă un atacator trimite un nou "commit" în timp ce tu ești deja în faza de rezolvare a challenge-ului?
"Scrie un test care validează protecția la concurența sesiunilor de login (prevenirea stării corupte).
Execută un POST /login/commit pentru utilizatorul alice_test. Sesiunea 1 este creată.
Simulează un comportament malițios sau o eroare de client: execută un al doilea request POST /login/commit PENTRU ACELAȘI client_id="alice_test", fără a finaliza prima sesiune.
Validează (assert) că serverul detectează conflictul și returnează status 409 Conflict cu mesajul {"reason": "existing commitment found, start a new session"}.
Validează că, drept măsură de securitate defensivă, Sesiunea 1 (cea veche) a fost invalidată/ștearsă din dicționarul sessions."
'''
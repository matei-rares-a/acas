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
	'''Testare verificare cu solutie folosind parola gresita (stolen secret_y, adversary trying to login with wrong password)'''
	"""Client send wrong proof, server reject login, server remove used session."""
	client_id = "client_test"
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
	'''Testare replay attack folosind aceeasi solutie si session_id (replay attack )'''
	"""Client do valid verify once, client replay same data, server reject replay."""
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


def test_verify_rejects_expired_session_and_cleans_up_state(client, monkeypatch):
	'''Testare expirare sesiune daca dureaza prea mult rezolvarea challenge-ului (DoS prevention)'''
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
	'''Testare commit dublu pentru acelasi user, fara a finaliza prima sesiune (Hijacking / Overwrite prevention)'''
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
	

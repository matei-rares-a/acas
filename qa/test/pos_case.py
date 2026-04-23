from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import hashlib
import secrets as secrets_module

import jwt
import pytest


# Load server module directly from file path for stable test imports.
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
	"""Derive password_x using scrypt KDF, matching calculations.py."""
	if salt is None:
		salt = secrets_module.token_bytes(16)

	password_hashed = hashlib.scrypt(
		password_string.encode(),
		salt=salt,
		n=2**11,
		r=8,
		p=1
	)
	password_x = int.from_bytes(password_hashed, 'big') % server.Q
	return password_x, salt


def test_register_creates_user_and_does_not_store_plain_password(client):
	'''Testarea înregistrării'''
	"""Client send register data, server save public value, server doesn't keep plain password."""
	client_id = "test_user"
	raw_password = "my-secure-password-12345"
	password_x, _ = derive_password_x(raw_password)
	secret_y = pow(server.G, password_x, server.P)

	response = client.post(
		"/register",
		json={"client_id": client_id, "secret_y": secret_y},
	)

	assert response.status_code == 201
	assert response.get_json() == {"status": "Registered"}

	with server.app.app_context():
		user = server.User.query.filter_by(client_id=client_id).first()
		assert user is not None
		assert user.secret_y == str(secret_y)
		assert not hasattr(user, "password")
		serialized = f"{user.client_id}|{user.secret_y}"
		assert raw_password not in serialized


def test_register_updates_existing_user_without_duplication(client):
	'''Testarea idempotenta inregistrare'''
	"""Client send same user again, server update value, server don't duplicate user."""
	client_id = "test_user"
	initial_password = "initial-password-version1"
	updated_password = "updated-password-version2"

	initial_password_x, _ = derive_password_x(initial_password)
	updated_password_x, _ = derive_password_x(updated_password)

	initial_secret_y = pow(server.G, initial_password_x, server.P)
	updated_secret_y = pow(server.G, updated_password_x, server.P)

	with server.app.app_context():
		server.db.session.add(
			server.User(client_id=client_id, secret_y=str(initial_secret_y))
		)
		server.db.session.commit()

	response = client.post(
		"/register",
		json={"client_id": client_id, "secret_y": updated_secret_y},
	)

	assert response.status_code == 200
	assert response.get_json() == {"status": "Updated"}

	with server.app.app_context():
		users = server.User.query.filter_by(client_id=client_id).all()
		assert len(users) == 1
		assert users[0].secret_y == str(updated_secret_y)


def test_login_commit_then_verify_success_and_session_is_deleted(client):
	'''Testarea fluxului de autentificare '''
	"""Client send commit then verify, server check proof, server give token, server delete session."""
	client_id = "test_login"
	raw_password = "test-password-secure"

	password_x, _ = derive_password_x(raw_password)
	secret_y = pow(server.G, password_x, server.P)

	with server.app.app_context():
		server.db.session.add(server.User(client_id=client_id, secret_y=str(secret_y)))
		server.db.session.commit()

	rand_r = secrets_module.randbelow(server.P - 2) + 1
	commitment_t = pow(server.G, rand_r, server.P)

	commit_response = client.post(
		"/login/commit",
		json={"client_id": client_id, "commitment_t": commitment_t},
	)

	assert commit_response.status_code == 200
	commit_payload = commit_response.get_json()
	assert "challenge_c" in commit_payload
	assert "session_id" in commit_payload

	challenge_c = int(commit_payload["challenge_c"])
	session_id = commit_payload["session_id"]

	solution_s = (rand_r + challenge_c * password_x) % server.Q

	verify_response = client.post(
		"/login/verify",
		headers={"X-Auth-Session": session_id},
		json={"solution_s": solution_s},
	)

	assert verify_response.status_code == 200
	verify_payload = verify_response.get_json()
	assert "token" in verify_payload
	assert verify_payload["token"]
	assert session_id not in server.sessions


def test_data_authorization_with_valid_and_invalid_tokens(client):
	'''Testarea consumare token'''
	"""Client send valid token and get data, client send bad token and server deny."""
	client_id = "test_user"
	raw_password = "data-endpoint-password"

	password_x, _ = derive_password_x(raw_password)
	secret_y = pow(server.G, password_x, server.P)

	register_response = client.post(
		"/register",
		json={"client_id": client_id, "secret_y": secret_y},
	)
	assert register_response.status_code in (200, 201)

	with server.app.app_context():
		user = server.User.query.filter_by(client_id=client_id).first()
		assert user is not None
		server.db.session.add(server.PersoData(user_id=user.id, message="hello"))
		server.db.session.commit()

	valid_token = jwt.encode({"client_id": client_id}, server.SECRET, algorithm="HS256")

	ok_response = client.get(
		"/data",
		headers={"Authorization": f"Bearer {valid_token}"},
	)
	assert ok_response.status_code == 200
	assert ok_response.get_json() == {"data": "hello"}

	missing_header_response = client.get("/data")
	assert missing_header_response.status_code == 401

	expired_token = jwt.encode(
		{
			"client_id": client_id,
			"exp": datetime.now(timezone.utc) - timedelta(minutes=1),
		},
		server.SECRET,
		algorithm="HS256",
	)
	expired_response = client.get(
		"/data",
		headers={"Authorization": f"Bearer {expired_token}"},
	)
	assert expired_response.status_code == 401
	




#START AI AGENTS IGNORE THIS LINE#
#TODO Pentru fiecare dintre aceste teste, adaugă în documentație log-urile din consola serverului Flask (unde se vede generarea request-urilor) alături de explicația pe care am conturat-o mai sus. Acest lucru arată comisiei că sistemul chiar a rulat și nu este doar o teorie.
#TODO Pentru testele de performanță, adaugă în documentație și graficele generate (ex: din benchmark.py sau raportul HTML din Locust) pentru a susține afirmațiile din disertație legate de performanță.
#END AI AGENTS IGNORE THIS LINE#
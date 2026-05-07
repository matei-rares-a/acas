"""Shared utilities for dissertation measurement scripts."""

from pathlib import Path
import sys

_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))

from qa_utils import server, derive_password_x

# Shared output directory -- all measurement scripts write here.
GENERATED = Path(__file__).resolve().parent / "generated"
GENERATED.mkdir(exist_ok=True)


def setup_isolated_test_user(client_id: str, password: str):
    """
    Reset the test DB, register one ZKP user, and return
    (x, flask_test_client) ready for latency/audit/chart probes.
    Each call wipes the database to guarantee a clean, isolated state.
    """
    server.app.config["TESTING"] = True
    x, _ = derive_password_x(password)
    y = pow(server.G, x, server.P)
    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()
    return x, server.app.test_client()

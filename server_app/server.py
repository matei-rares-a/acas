from flask import Flask, request, jsonify
from flask_cors import CORS
from extensions import db
from models import User, AuthToken, PersoData, OAuthCredential
from server_oauth import init_oauth, clear_oauth_state
from server_authlib import init_authlib, clear_authlib_state

import hashlib
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt

# ---------------------------------------------------------------------------
# Schnorr group parameters  (P = 2Q + 1 safe prime, G = 4)
# ---------------------------------------------------------------------------
# P = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579
# Q = (P - 1) // 2
# G = 4
# Note: hardcoded for simplicity; move constants to env vars in production.
P = int(
'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
'29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
'83655D23DCA3AD961C62F356208552BB9ED529077096966D'
'670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
'15728E5A8AACAA68FFFFFFFFFFFFFFFF',
16,
)
Q = (P - 1) // 2
G = 4

# Python's jwt gives warning if secret is shorter than 32
SECRET      = 'dev-only-server-secret-at-least-32-bytes-long'
SESSION_TTL = 10        # seconds -- commit -> verify window
# Second commit within 50 ms = race, first writer wins.
# Second commit after 50 ms = hijack attempt, both sessions invalidated.
COMMIT_RACE_WINDOW_S = 0.050   # 50 ms: two commits within this window = race
'''
Note: the server choses the auth scheme
Simplicity: support similar schemes Bearer (RFC 6750).
'''
SUPPORTED_AUTH_SCHEMES = {"bearer", "token", "jwt", "dpop"}

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
_db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'db')
os.makedirs(_db_path, exist_ok=True)
_default_db_uri = f"sqlite:///{os.path.join(_db_path, 'auth.db')}"
_db_uri = os.environ.get('ACAS_DB_URI', _default_db_uri)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# SQLite: busy timeout so concurrent writers retry instead of failing immediately.
# app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
#     "connect_args": {"timeout": 30},   # seconds to wait on a locked DB
# }


# # Enable WAL journal mode for better concurrent write throughput under Locust load.
# from sqlalchemy import event as _sa_event
# from sqlalchemy.engine import Engine as _Engine
# import sqlite3 as _sqlite3

# @_sa_event.listens_for(_Engine, "connect")
# def _set_sqlite_wal(dbapi_conn, _conn_record):
#     if isinstance(dbapi_conn, _sqlite3.Connection):
#         dbapi_conn.execute("PRAGMA journal_mode=WAL")
#         dbapi_conn.execute("PRAGMA synchronous=NORMAL")
        
CORS(app, resources={r"/*": {"origins": "*"}})
db.init_app(app)
with app.app_context():
    db.create_all()
    print("DB ready:", app.config['SQLALCHEMY_DATABASE_URI'])

# ---------------------------------------------------------------------------
# Request / response hooks
# ---------------------------------------------------------------------------
@app.before_request
def _before_request():
    if not request.path.startswith('/login') and not request.path.startswith('/register') and not request.path.startswith('/parameters') and not request.path.startswith('/health') and not request.path.startswith('/data'):
        pass
    request.start_time = time.time_ns()


_SECURITY_HEADERS = {
    # Prevents MIME-type sniffing; reduces XSS-style misinterpretation.
    'X-Content-Type-Options': 'nosniff',
    # Blocks iframe embedding; prevents clickjacking.
    'X-Frame-Options': 'DENY',
    # Restricts resource loading to same origin; prevents script injection and frame embedding.
    'Content-Security-Policy': "default-src 'self'; base-uri 'self'; frame-ancestors 'none'",
    # Turn off browser features we don't need.
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
    # Limits Referer leakage on cross-origin requests.
    'Referrer-Policy': 'strict-origin-when-cross-origin',
}

@app.after_request
def _after_request(response):
    if not request.path.startswith('/login') and not request.path.startswith('/register') and not request.path.startswith('/parameters') and not request.path.startswith('/health') and not request.path.startswith('/data'):
        return response
    response.headers['Request-ID'] = request.headers.get('Request-ID', str(uuid.uuid4()))
    response.headers['API-Version'] = 'S1.0'

    for header, value in _SECURITY_HEADERS.items():
        response.headers[header] = value

    if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Auth responses should never be cached by browsers or proxies.
    response.headers.setdefault('Cache-Control', 'private, no-store, no-cache, must-revalidate')
    # Always JSON.
    response.headers.setdefault('Content-Type', 'application/json; charset=utf-8')

    elapsed_ms = (time.time_ns() - request.start_time) / 1_000_000
    # Endpoint latency in milliseconds.
    response.headers['X-Response-Time'] = f"{elapsed_ms:.3f} ms"
    # Visible in browser DevTools Performance tab.
    response.headers['Server-Timing']   = f"app;dur={elapsed_ms:.3f}"

    if response.status_code == 401:
        response.headers['WWW-Authenticate'] = 'Bearer realm="Schnorr Authentication", charset="UTF-8"'

    return response


# Note: in-memory store; replace with DB for production.
class _SessionStore(dict):
    """dict with a built-in reverse index: client_id -> session_id.

    Each entry has the shape:
    {
        "<session_id>": {
            "client_id":  str,    # owner of the session
            "t":          int,    # commitment G^r mod P sent by the prover
            "c":          int,    # challenge derived from (session_id, client_id, t, binding)
            "binding":    bytes,  # channel-binding digest -- stored, never sent to client
            "raw_addr":   str,    # direct TCP peer address at commit time (for logging)
            "created_at": float,  # time.time() at commit -- used for SESSION_TTL expiry
        }
    }
    """
    def __init__(self):
        super().__init__()
        self._client_sessions: dict[str, str] = {}
        self._lock = threading.Lock()

    def __setitem__(self, session_id, value):
        super().__setitem__(session_id, value)
        self._client_sessions[value["client_id"]] = session_id

    def __delitem__(self, session_id):
        session = self.get(session_id)
        if session:
            self._client_sessions.pop(session["client_id"], None)
        super().__delitem__(session_id)

    def pop(self, session_id, *args):
        session = self.get(session_id)
        if session:
            self._client_sessions.pop(session["client_id"], None)
        return super().pop(session_id, *args)

    def clear(self):
        super().clear()
        self._client_sessions.clear()


sessions = _SessionStore()

# ---------------------------------------------------------------------------
# Session Binding -- simplified channel-binding concept (demo)
# ---------------------------------------------------------------------------

def _compute_session_binding(raw_addr: str, user_agent: str, session_id: str,
                             client_id: str, t: int) -> bytes:
    """Build a 128-byte (1024-bit) digest that ties this auth attempt to the
    exact TCP connection: peer address, User-Agent, session ID, client ID,
    and commitment. 1024 bits matches Q's bit-length so the challenge covers
    the full subgroup after reduction.

    We use remote_addr instead of X-Forwarded-For so a relayed request
    coming from a different IP won't match the stored binding.
    """
    data = f"{raw_addr}|{user_agent}|{session_id}|{client_id}|{t}".encode("utf-8")
    return hashlib.shake_256(data).digest(128)  # 128 bytes = 1024 bits


def _compute_challenge(binding: bytes) -> int:
    """
    c = int(binding) mod Q  -- challenge in Zq = [1, Q-1]

    Because the binding already ties together the peer address, User-Agent,
    session ID, client ID, and commitment t, the challenge is deterministic
    and replay-resistant, the randomness factor is session id.
    """
    # SHAKE-256 gives 128 bytes (1024 bits), same bit-length as Q, so
    # % Q is a real reduction and c is spread across the full subgroup.
    # `or 1` handles the negligible zero case.
    return (int.from_bytes(binding, "big") % Q) or 1




# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def validate_int_field(data: dict, key: str):
    """Return int(data[key]) or None if missing / not convertible."""
    try:
        return int(data[key])
    except (KeyError, TypeError, ValueError):
        return None


def is_subgroup_member(value: int) -> bool:
    """True iff value is a non-trivial element of the Schnorr subgroup of order Q.
    Prevents Small Subgroup attack -- rejects y or t outside the subgroup."""
    return 1 < value < P and pow(value, Q, P) == 1


def extract_access_token() -> str | None:
    """Return Bearer token from Authorization header, or None."""
    header = request.headers.get('Authorization', '').strip()
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() in SUPPORTED_AUTH_SCHEMES:
        return parts[1].strip() or None
    if len(parts) == 1:
        return parts[0] or None
    return None


def _parse_x_forwarded_for(header: str) -> str | None:
    """Return the first address from X-Forwarded-For or None if the header is missing."""
    if not header:
        return None
    first_addr = header.split(",", 1)[0].strip()
    return first_addr or None


def _get_peer() -> tuple[str, str]:
    """Return (remote_addr, user_agent) tuple for the current request."""
    remote_addr = _parse_x_forwarded_for(request.headers.get('X-Forwarded-For', ''))
    if not remote_addr:
        remote_addr = request.remote_addr or "127.0.0.1"

    return (
        remote_addr,
        request.headers.get("User-Agent", "").strip().lower(),
    )


def _issue_jwt(client_id: str) -> str:
    """Encode a signed HS256 JWT valid for 1 hour."""
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {'client_id': client_id, 'iat': now, 'exp': now + timedelta(seconds=3600)},
        SECRET, algorithm='HS256',
    )


def _save_token(user_id: int, token: str) -> None:
    """Persist JWT in AuthToken table (upsert)."""
    auth = AuthToken.query.filter_by(user_id=user_id).first()
    if auth:
        auth.token = token
    else:
        db.session.add(AuthToken(user_id=user_id, token=token))


def _upsert_perso(user_id: int, message: str) -> bool:
    """Update or create PersoData. Returns True if created."""
    perso = PersoData.query.filter_by(user_id=user_id).first()
    if perso:
        perso.message = message
        return False
    db.session.add(PersoData(user_id=user_id, message=message))
    return True

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/health')
def healthAPI():
    return jsonify({"health": "running"})


@app.route('/parameters')
def getParametersAPI():
    resp = jsonify({'P': str(P), 'G': str(G)})
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    resp.headers['ETag'] = 'W/"v1.0-schnorr"'
    return resp


@app.route('/register', methods=['POST'])
def registerAPI():
    '''POST /register: client sends client_id and secret_y=G^x; server stores it.
    No auth guard on this endpoint (simplicity; protect with shared secret in production).'''
    data = request.get_json() or {}
    client_id = data.get('client_id')
    secret = validate_int_field(data, 'secret_y')
    if not client_id or secret is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if User.query.filter_by(client_id=client_id).first():
        return jsonify({'reason': 'already registered'}), 409
    if not is_subgroup_member(secret):
        return jsonify({'reason': 'invalid public value'}), 422
    register_user_in_db(client_id, secret)
    return jsonify({'status': 'Registered'}), 201


def register_user_in_db(client_id: str, secret_y: int) -> None:
    """Insert user credentials. Caller must ensure user does not already exist."""
    db.session.add(User(client_id=client_id, secret_y=secret_y.to_bytes(256, 'big')))
    db.session.commit()


init_oauth(app, db, User, AuthToken, SECRET)
init_authlib(app, SECRET)

@app.route('/login/commit', methods=['POST'])
def commitAPI():
    '''POST /login/commit: client sends client_id and commitment_t; server returns challenge_c and session_id.'''
    data = request.get_json() or {}
    client_id = data.get('client_id')
    t = validate_int_field(data, 'commitment_t')

    if not client_id or t is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if not is_subgroup_member(t):
        return jsonify({'reason': 'invalid commitment'}), 422
    if not User.query.filter_by(client_id=client_id).first():
        return jsonify({'reason': 'user not registered'}), 404

    with sessions._lock:
        existing_sid = sessions._client_sessions.get(client_id)
        if existing_sid:
            age = time.time() - sessions[existing_sid]["created_at"]
            if age > COMMIT_RACE_WINDOW_S:   # hijack attempt -- drop old session
                del sessions[existing_sid]
            return jsonify({'reason': 'existing commitment found, start a new session'}), 409

        # Fresh session ID per commit, prevents session fixation.
        session_id = secrets.token_urlsafe(32)
        # Session binding: tie this authentication attempt to the exact
        # network connection (TCP peer address + User-Agent + session ID).
        # request.remote_addr is the direct peer -- not spoofable via headers.
        raw_addr, user_agent = _get_peer()
        binding = _compute_session_binding(raw_addr, user_agent, session_id, client_id, t)
        challenge_c = _compute_challenge(binding)

        sessions[session_id] = {
            "client_id":  client_id,
            "t":          t,
            "c":          challenge_c,
            "binding":    binding,       # stored; NOT sent to client
            "raw_addr":   raw_addr,      # original peer IP (for logging)
            "created_at": time.time(),
        }

    return jsonify({'challenge_c': str(challenge_c), 'session_id': session_id}), 200


@app.route('/login/verify', methods=['POST'])
def verifyAPI():
    '''POST /login/verify: client sends solution_s; server verifies G^s == t*y^c and issues JWT.'''
    data = request.get_json() or {}
    #session_id will be in X-Auth-Session: header
    session_id = (request.headers.get('X-Auth-Session') or '').strip()
    s = validate_int_field(data, 'solution_s')

    if not session_id:
        return jsonify({'reason': 'missing session_id in X-Auth-Session header'}), 400
    if session_id not in sessions:
        return jsonify({'reason': 'invalid session_id'}), 404

    sess = sessions[session_id]

    if sess['created_at'] < time.time() - SESSION_TTL:
        del sessions[session_id]
        return jsonify({'reason': 'session expired'}), 401
    if s is None or s <= 0 or s >= Q:
        del sessions[session_id]
        return jsonify({'reason': 'invalid solution'}), 422

    client_id = sess['client_id']
    raw_addr_now, ua_now = _get_peer()
    stored_binding = sess.get('binding')

    #NOTE: check for binding mismatch to prevent relay/MITM attack
    current_binding = _compute_session_binding(raw_addr_now, ua_now, session_id, client_id, sess['t'])
    if stored_binding and current_binding != stored_binding:
        original_ip = sess.get("raw_addr", "unknown")
        print(
            f"[verify] Binding mismatch: possible relay attack | "
            f"original_ip={original_ip!r} current_ip={raw_addr_now!r}"
        )
        del sessions[session_id]
        return jsonify({'reason': 'session binding mismatch'}), 401

    
    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        del sessions[session_id]
        return jsonify({'reason': 'user not found'}), 404

    y, t, c = int.from_bytes(user.secret_y, 'big'), sess['t'], sess['c']
    # left == right
    if pow(G, s, P) == (t * pow(y, c, P)) % P:
        token_str = _issue_jwt(client_id)
        _save_token(user.id, token_str)
        # Delete session right after use, a captured session_id can't be replayed.
        del sessions[session_id]
        db.session.commit()
        return jsonify({'token': token_str}), 200

    del sessions[session_id]
    return jsonify({'reason': 'verification failed'}), 401


@app.route('/data', methods=['GET', 'POST', 'PUT'])
def dataAcessApi():
    token = extract_access_token()
    if not token:
        return jsonify({'reason': 'missing token'}), 401
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'reason': 'token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'reason': 'invalid token'}), 401

    user = User.query.filter_by(client_id=payload.get('client_id')).first()
    if not user:
        return jsonify({'reason': 'user not found'}), 404

    if request.method == 'GET':
        perso = PersoData.query.filter_by(user_id=user.id).first()
        if not perso:
            return jsonify({'reason': 'no personal data found'}), 404
        return jsonify({'data': perso.message})

    data = request.get_json(silent=True) or {}
    message = data.get('data')
    if message is None:
        return jsonify({'reason': 'missing data'}), 400
    created = _upsert_perso(user.id, str(message) if not isinstance(message, str) else message)
    db.session.commit()
    return jsonify({'message': 'personal data updated'}), 201 if created else 200

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import warnings
    warnings.filterwarnings('ignore', message=r'.*request\.scope.*is deprecated')
    https = False
    host, port = '0.0.0.0', 5000
    scheme = 'https' if https else 'http'
    print(f'Schnorr Authentication Server -- {scheme}://localhost:{port}  PID={os.getpid()}')
    ssl_ctx = ('cert.pem', 'key.pem') if https and os.path.exists('cert.pem') else None
    app.run(host=host, port=port, ssl_context=ssl_ctx, debug=True)

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
# Schnorr parameters  (secp256r1 / NIST P-256)
# ---------------------------------------------------------------------------
'''
Note: constants and settings should be in env files
Simplicity: hardcoded constants and settings
'''
# secp256r1 curve constants
_EC_P      = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_EC_B      = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
EC_ORDER   = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_EC_GX     = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_EC_GY     = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
EC_GENERATOR = (_EC_GX, _EC_GY)


def _ec_modinv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _ec_point_add(P1, P2):
    """Add two secp256r1 points. None represents the point at infinity."""
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1; x2, y2 = P2
    p = _EC_P
    if x1 == x2:
        if y1 != y2: return None
        lam = (3 * x1 * x1 - 3) * _ec_modinv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * _ec_modinv(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _ec_scalar_mult(k: int, point: tuple) -> tuple | None:
    """Scalar multiplication k*point on secp256r1. Returns None for k=0."""
    if k == 0: return None
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_point_add(result, addend)
        addend = _ec_point_add(addend, addend)
        k >>= 1
    return result

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
    # Prevents browsers from guessing the response type. For an auth API returning JSON, that matters
    # because you do not want a browser treating a JSON response like script or HTML under odd conditions.
    # It reduces client-side misinterpretation and some XSS-style abuse paths.
    'X-Content-Type-Options': 'nosniff',
    # Stops your pages or responses from being embedded in an iframe.
    # In a browser-based login flow, that helps defend against clickjacking.
    'X-Frame-Options': 'DENY',
    # Limits where scripts and other resources can load from, prevents base URL manipulation,
    # and forbids framing. That matters because if malicious JavaScript runs in the client,
    # it can steal the JWT returned after successful Schnorr verification or tamper with
    # the proof flow before it reaches the server.
    'Content-Security-Policy': "default-src 'self'; base-uri 'self'; frame-ancestors 'none'",
    # Not needed for Schnorr correctness, but it is reasonable least-privilege hardening for a browser client.
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
    # Limits what the browser leaks in the Referer header when navigating away or making cross-origin
    # requests. That helps avoid exposing sensitive URL structure or workflow details.
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

    # No JWTs, challenge values, or personal data cached by browsers or proxies.
    response.headers.setdefault('Cache-Control', 'private, no-store, no-cache, must-revalidate')
    # Consistent type
    response.headers.setdefault('Content-Type', 'application/json; charset=utf-8')

    elapsed_ms = (time.time_ns() - request.start_time) / 1_000_000
    # Helps you measure slow endpoints
    response.headers['X-Response-Time'] = f"{elapsed_ms:.3f} ms"
    # Similar to X-Response-Time, but standardized for browser tooling. Good for performance debugging in the frontend.
    response.headers['Server-Timing']   = f"app;dur={elapsed_ms:.3f}"

    if response.status_code == 401:
        response.headers['WWW-Authenticate'] = 'Bearer realm="Schnorr Authentication", charset="UTF-8"'

    return response


'''
note: should be in database
simplicity: in memory commitments and challenges
'''
class _SessionStore(dict):
    """dict with a built-in reverse index: client_id -> session_id.

    Each entry has the shape:
    {
        "<session_id>": {
            "client_id":  str,    # owner of the session
            "t":          tuple,  # commitment T = r*G (EC point) sent by the prover
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
                             client_id: str, t: tuple) -> bytes:
    """Derive a 32-byte binding token from all authentication context:
    the direct TCP peer address, the User-Agent, the session ID, the
    client identity, and the commitment t.

    Using request.remote_addr (not X-Forwarded-For) ensures the binding
    reflects the actual network connection endpoint -- a relayed request
    arrives from a different IP and will not match.
    """
    tx, ty = t
    data = f"{raw_addr}|{user_agent}|{session_id}|{client_id}|{tx}|{ty}".encode("utf-8")
    return hashlib.sha256(data).digest()


def _compute_challenge(binding: bytes) -> int:
    """
    c = int(binding) mod EC_ORDER  -- challenge scalar in [1, EC_ORDER-1]

    The binding already commits to the peer address, User-Agent,
    session ID, client ID, and commitment t, so the challenge is
    fully determined by -- and bound to -- all of those inputs.
    """
    return (int.from_bytes(binding, "big") % EC_ORDER) or 1




# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def validate_int_field(data: dict, key: str):
    """Return int(data[key]) or None if missing / not convertible."""
    try:
        return int(data[key])
    except (KeyError, TypeError, ValueError):
        return None


def is_valid_ec_point(x: int, y: int) -> bool:
    """True iff (x, y) is a non-infinity point on secp256r1."""
    if not (isinstance(x, int) and isinstance(y, int)):
        return False
    if not (0 <= x < _EC_P and 0 <= y < _EC_P):
        return False
    # curve equation: y² = x³ - 3x + b  (mod p)
    lhs = (y * y) % _EC_P
    rhs = (pow(x, 3, _EC_P) - 3 * x + _EC_B) % _EC_P
    return lhs == rhs


def validate_ec_point_fields(data: dict, x_key: str, y_key: str):
    """Return (x, y) int tuple or None if any field is missing or non-integer."""
    try:
        x = int(data[x_key])
        y = int(data[y_key])
        return x, y
    except (KeyError, TypeError, ValueError):
        return None


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
    resp = jsonify({'curve': 'secp256r1', 'order': str(EC_ORDER)})
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    resp.headers['ETag'] = 'W/"v1.0-schnorr-ec"'
    return resp


@app.route('/register', methods=['POST'])
def registerAPI():
    '''
    User registration, client sends client_id and secret_y_x/secret_y_y (Y = x*G on secp256r1)
    computed from password, server saves it for later verification at login
    '''
    '''
    Note: the server should have the relation of client_id - secret_y,
         this endpoint can be secured with a shared secret or other methods
    Simplicity: no authentication for this endpoint, in a real implementation it should be protected
    '''
    data = request.get_json() or {}
    client_id = data.get('client_id')
    point = validate_ec_point_fields(data, 'secret_y_x', 'secret_y_y')
    if not client_id or point is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if not is_valid_ec_point(*point):
        return jsonify({'reason': 'invalid public value'}), 422
    is_new = register_user_in_db(client_id, point)
    if not is_new:
        return jsonify({'reason': 'already registered'}), 409
    return jsonify({'status': 'Registered'}), 201


def register_user_in_db(client_id: str, point: tuple) -> bool:
    """Insert user credentials (EC point Y = x*G). Returns True if newly created, False if exists."""
    user = User.query.filter_by(client_id=client_id).first()
    if user:
        return False
    x_coord, y_coord = point
    encoded = x_coord.to_bytes(32, 'big') + y_coord.to_bytes(32, 'big')
    db.session.add(User(client_id=client_id, secret_y=encoded))
    db.session.commit()
    return True


init_oauth(app, db, User, AuthToken, SECRET)
init_authlib(app, SECRET)

@app.route('/login/commit', methods=['POST'])
def commitAPI():
    '''
    Login commitment, client sends client_id and commitment t,
    server saves it and returns challenge c
    '''
    data = request.get_json() or {}
    client_id = data.get('client_id')
    t = validate_ec_point_fields(data, 'commitment_t_x', 'commitment_t_y')

    if not client_id or t is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if not is_valid_ec_point(*t):
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

        # Note: prevents Session Fixation -- CSPRNG guarantees unpredictable session_id.
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
    '''
    Login verification, client sends client_id and solution s,
    server verifies the proof using the saved commitment t and challenge c,
    if valid returns JWT token
    '''
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
    if s is None or s <= 0 or s >= EC_ORDER:
        del sessions[session_id]
        return jsonify({'reason': 'invalid solution'}), 422

    client_id = sess['client_id']
    raw_addr_now, ua_now = _get_peer()
    stored_binding = sess.get('binding')

    #NOTE: check for binding mismatch to prevent relay/mitm attack, if the peer address or user agent changed between requests
    current_binding = _compute_session_binding(raw_addr_now, ua_now, session_id, client_id, sess['t'])
    if stored_binding and current_binding != stored_binding:
        original_ip = sess.get("raw_addr", "unknown")
        print(
            f"[verify] Binding mismatch: possible relay attack | "
            f"original_ip={original_ip!r} current_ip={raw_addr_now!r}"
        )
        del sessions[session_id]
        return jsonify({'reason': 'session binding mismatch'}), 401

    #NOTE: extra check, in case of relay/mitm
    # if _compute_challenge(stored_binding or b'') != sess['c']:
    #     del sessions[session_id]
    #     return jsonify({'reason': 'challenge integrity check failed'}), 400

    
    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        del sessions[session_id]
        return jsonify({'reason': 'user not found'}), 404

    encoded = user.secret_y
    Y = (int.from_bytes(encoded[:32], 'big'), int.from_bytes(encoded[32:], 'big'))
    T, c = sess['t'], sess['c']
    # Verify Schnorr proof: s*G == T + c*Y
    if _ec_scalar_mult(s, EC_GENERATOR) == _ec_point_add(T, _ec_scalar_mult(c, Y)):
        token_str = _issue_jwt(client_id)
        _save_token(user.id, token_str)
        # Note: prevents Replay attack -- session deleted immediately after use
        # so a captured session_id cannot be reused.
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

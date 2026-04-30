from flask import Flask, request, jsonify
from flask_cors import CORS
from extensions import db
from models import User, AuthToken, PersoData
from server_oauth import init_oauth, clear_oauth_state
from server_authlib import init_authlib, clear_authlib_state

# ── crypto / session / auth / rate modules ──────────────────────────────────────
from schnorr_crypto import (
    P, Q, G,
    is_subgroup_member,
    compute_challenge,
    verify_proof,
    ips_match,
)
from session_store import (
    make_session_store,
    SESSION_TTL,
    COMMIT_RACE_WINDOW,
    SESSION_STATE_CHALLENGE_ISSUED,
    SESSION_STATE_CONSUMED,
)
from jwt_utils import jwt_encode, jwt_decode, jwks_payload
from rate_limiter import rate_check, is_over_fail_limit, record_fail

import hashlib
import os
import jwt
import secrets
import time
import uuid
from datetime import datetime, timezone

# Legacy HS256 secret retained only for any OAuth sub-modules that still use it.
SECRET = 'dev-only-server-secret-at-least-32-bytes-long'

# Convenience aliases kept for backward compatibility with test code that
# accesses server.P / server.Q / server.G directly.
# (Already re-exported via the schnorr_crypto import above.)

# ---------------------------------------------------------------------------
# Request context helpers
# ---------------------------------------------------------------------------
def _get_request_context() -> tuple[str, str]:
    """Return (client_ip, user_agent) normalised to lowercase, stripped.  §6"""
    ip = (
        request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        .split(",")[0]
        .strip()
    )
    ua = request.headers.get("User-Agent", "").strip().lower()
    return ip, ua


def _rl(key: str, endpoint: str) -> bool:
    """Rate-limit gate — bypassed in TESTING mode."""
    if app.config.get("TESTING"):
        return True
    return rate_check(key, endpoint)


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'db')
if not os.path.exists(db_path):
    os.makedirs(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(db_path, 'auth.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app,resources={r"/*": {"origins": "*"}},)
db.init_app(app)
with app.app_context():
    db.create_all()
    print("Tabelele au fost create cu succes în:", app.config['SQLALCHEMY_DATABASE_URI'])

@app.before_request
def before_request():
    request.start_time = time.time_ns()

# Security headers
@app.after_request
def add_rest_headers(response):
    # Request tracing
    request_id = request.headers.get('Request-ID', str(uuid.uuid4()))
    response.headers['Request-ID'] = request_id
    
    # Security headers
    #Prevents browsers from guessing the response type. For an auth API returning JSON, that matters because you do not want a browser treating a JSON response like script or HTML under odd conditions. It reduces client-side misinterpretation and some XSS-style abuse paths.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    #Stops your pages or responses from being embedded in an iframe. In a browser-based login flow, that helps defend against clickjacking.
    response.headers['X-Frame-Options'] = 'DENY'
    #it limits where scripts and other resources can load from, prevents base URL manipulation, and forbids framing. That matters because if malicious JavaScript runs in the client, it can steal the JWT returned after successful Schnorr verification or tamper with the proof flow before it reaches the server.
    response.headers['Content-Security-Policy'] = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    #not needed for Schnorr correctness, but it is reasonable least-privilege hardening for a browser client.
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    #Limits what the browser leaks in the Referer header when navigating away or making cross-origin requests. That helps avoid exposing sensitive URL structure or workflow details
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.is_secure or request.headers.get('X-Forwarded-Proto', 'http') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # API versioning
    response.headers['API-Version'] = 'S1.0'
    
    # Cache control (overridable per route)
    # No JWTs, challenge values, or personal data cached by browsers or proxies.
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate'
    
    # Performance metrics
    #It helps you measure slow endpoints
    response.headers['X-Response-Time'] = f"{(time.time_ns() - request.start_time) / 1000000:.6f} ms"
    #Similar to X-Response-Time, but standardized for browser tooling. Good for performance debugging in the frontend
    response.headers['Server-Timing'] = f"app;dur={(time.time_ns() - request.start_time) / 1000000:.6f} ms"
    
    # Content type
    #Consistent type
    if response.headers.get('Content-Type') is None:
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
    
    # Add WWW-Authenticate for 401 responses
    if response.status_code == 401:
        response.headers['WWW-Authenticate'] = 'Bearer realm="Schnorr Authentication", charset="UTF-8"'

    # Emit a Werkzeug-like access log line for in-process test_client requests.
    # if not app.config.get("TESTING"):
    #     remote_addr = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    #     timestamp = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    #     print(
    #         f'{remote_addr} - - [{timestamp}] "{request.method} {request.full_path.rstrip("?")} HTTP/1.1" {response.status_code} -'
    #     )
    
    return response


# ---------------------------------------------------------------------------
# Session store instance  (Redis if available, in-memory LRU otherwise)
# ---------------------------------------------------------------------------
sessions = make_session_store()

# Backward-compatible aliases for constants still referenced in route handlers
COMMIT_RACE_WINDOW_S = COMMIT_RACE_WINDOW

'''
Note: the servers choses the auth scheme
Simplicity: support similar schemes Bearer (RFC 6750).
'''
SUPPORTED_AUTH_SCHEMES = {"bearer", "token", "jwt", "dpop"}

def validate_int_field(data, key):
    value = data.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# Extract token from Authorization header, with optional body fallback
def extract_access_token(data=None):
    auth_header = request.headers.get('Authorization', '').strip()
    if auth_header:
        parts = auth_header.split(None, 1)
        if len(parts) == 2:
            scheme, token = parts[0].lower(), parts[1].strip()
            if scheme in SUPPORTED_AUTH_SCHEMES and token:
                return token
        elif len(parts) == 1 and parts[0]:
            # maybe raw token without scheme
            return parts[0]

    return None

@app.route('/health', methods=['GET'])
def healthAPI():
    return jsonify({"health":"running"})


@app.route('/get-parameters', methods=['GET'])
def getParametersAPI():
    """Endpoint to exchange global parameters P and G with the client"""
    response = jsonify({'P': str(P), 'G': str(G)})
    response.headers['Cache-Control'] = 'public, max-age=3600'
    response.headers['ETag'] = 'W/"v1.0-schnorr"'
    return response


@app.route('/jwks.json', methods=['GET'])
def jwksAPI():
    """RFC 7517 JWKS endpoint — public keys for JWT verification.  §4.5"""
    return jsonify(jwks_payload())

'''
Note: new users: unauthenticated.  Updates require a valid JWT (proof of ownership).  §3
'''
@app.route('/register', methods=['POST'])
def registerAPI():
    '''
    User registration.  New users: open.  Updates: require a valid JWT.
    '''
    client_ip, _ = _get_request_context()
    if not _rl(f"{client_ip}:register", "register"):   # §5 rate-limit
        return jsonify({'reason': 'too many requests'}), 429

    data = request.get_json() or {}
    client_id = data.get('client_id')
    secret = validate_int_field(data, 'secret_y')
    print(f"[register] client_id={client_id!r} ip={client_ip!r}")
    if not client_id or secret is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if not is_subgroup_member(secret):
        return jsonify({'reason': 'invalid public value'}), 422

    existing = User.query.filter_by(client_id=client_id).first()
    if existing:
        # §3 update requires proof of ownership — verify current JWT
        token = extract_access_token(data)
        if not token:
            return jsonify({'reason': 'authentication required to update credentials'}), 403
        try:
            payload = jwt_decode(token)
        except jwt.InvalidTokenError:
            return jsonify({'reason': 'invalid or expired token'}), 403
        if payload.get('client_id') != client_id:
            return jsonify({'reason': 'token does not match client_id'}), 403
        existing.secret_y = str(secret)
        db.session.commit()
        return jsonify({'status': 'Updated'}), 200

    # New user
    user = User(client_id=client_id, secret_y=str(secret))
    db.session.add(user)
    db.session.commit()
    return jsonify({'status': 'Registered'}), 201

def register_user_in_db(client_id, secret_y):
    """Internal helper used by OAuth sub-modules."""
    user = User.query.filter_by(client_id=client_id).first()
    if user:
        user.secret_y = str(secret_y)
        is_new = False
    else:
        user = User(client_id=client_id, secret_y=str(secret_y))
        db.session.add(user)
        is_new = True
    db.session.commit()
    return is_new


init_oauth(app, db, User, AuthToken, SECRET)
init_authlib(app, SECRET)

@app.route('/login/commit', methods=['POST'])
def commitAPI():
    '''
    Fiat–Shamir commit: client sends client_id + commitment t.
    Server generates a hash-bound challenge c and returns it.
    §1 §2 §3 §5 §9
    '''
    client_ip, user_agent = _get_request_context()

    if not _rl(f"{client_ip}:commit", "commit"):   # §5
        return jsonify({'reason': 'too many requests'}), 429

    data = request.get_json() or {}
    client_id = data.get('client_id')
    t = validate_int_field(data, 'commitment_t')
    if not client_id or t is None:
        return jsonify({'reason': 'missing parameters'}), 400

    # §9 subgroup check (1 < t < P, t^Q ≡ 1 mod P)
    if not is_subgroup_member(t):
        return jsonify({'reason': 'invalid commitment'}), 422

    # §9 commitment reuse guard
    if not sessions.check_and_record_t(client_id, t):
        print(f"[commit] suspicious: t reuse client_id={client_id!r} ip={client_ip!r}")
        return jsonify({'reason': 'commitment already used'}), 422

    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'reason': 'user not registered'}), 404

    # §2 atomic session creation (raises ValueError on race/hijack)
    try:
        session_id, challenge_c = sessions.create_session(
            client_id, t, client_ip, user_agent
        )
    except ValueError:
        return jsonify({'reason': 'existing commitment found, start a new session'}), 409

    return jsonify({'challenge_c': str(challenge_c), 'session_id': session_id}), 200


@app.route('/login/verify', methods=['POST'])
def verifyAPI():
    '''
    Verify ZKP proof.  Server recomputes c from stored context, checks proof,
    issues EdDSA JWT on success.  §1 §2 §3 §4 §5 §11
    '''
    client_ip, user_agent = _get_request_context()

    if not _rl(f"{client_ip}:verify", "verify"):   # §5
        return jsonify({'reason': 'too many requests'}), 429

    data = request.get_json() or {}
    session_id = request.headers.get('X-Auth-Session', '').strip()
    if not session_id or len(session_id) > 256:
        return jsonify({'reason': 'missing session_id in X-Auth-Session header'}), 400

    sess = sessions.get(session_id)
    if sess is None:
        return jsonify({'reason': 'invalid session_id'}), 404

    # §2.4 lifecycle: only challenge_issued sessions may verify
    if sess.get('state') != SESSION_STATE_CHALLENGE_ISSUED:
        del sessions[session_id]
        return jsonify({'reason': 'invalid session state'}), 400

    if sess['created_at'] < time.time() - SESSION_TTL:
        del sessions[session_id]
        return jsonify({'reason': 'session expired'}), 300

    # §3 context binding (IP tolerance via ips_match allows /24 subnet)
    if not ips_match(sess['ctx_ip'], client_ip) or sess['ctx_ua'] != user_agent:
        del sessions[session_id]
        return jsonify({'reason': 'request context mismatch'}), 401

    s = validate_int_field(data, 'solution_s')
    if s is None:
        del sessions[session_id]
        return jsonify({'reason': 'invalid solution'}), 422
    if s < 0 or s >= Q:
        del sessions[session_id]
        return jsonify({'reason': 'invalid solution'}), 422

    client_id = sess['client_id']

    # §5 early-exit if client already exceeded failure quota (read-only check)
    if is_over_fail_limit(client_id):
        del sessions[session_id]
        return jsonify({'reason': 'too many failed attempts'}), 429

    # §1 recompute Fiat–Shamir challenge; reject if session tampered
    c_expected = compute_challenge(
        session_id, client_id,
        sess['t'], sess['nonce'],
        sess['ctx_ip'], sess['ctx_ua'],
    )
    if c_expected != sess['c']:
        del sessions[session_id]
        return jsonify({'reason': 'challenge integrity check failed'}), 400

    # §10 proof replay protection
    if not sessions.check_and_record_proof(session_id, s):
        del sessions[session_id]
        return jsonify({'reason': 'proof already used'}), 400

    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        del sessions[session_id]
        return jsonify({'reason': 'user not found'}), 404

    y = int(user.secret_y)
    t = sess['t']
    c = sess['c']

    # §11 constant-time ZKP verification
    if verify_proof(s, t, y, c):
        sess['state'] = SESSION_STATE_CONSUMED
        # §4 EdDSA JWT with full claims + session binding
        sid_hash = hashlib.sha256(session_id.encode()).hexdigest()[:16]
        token_str = jwt_encode({'client_id': client_id, 'sid': sid_hash})
        auth = AuthToken.query.filter_by(user_id=user.id).first()
        if auth:
            auth.token = token_str
        else:
            db.session.add(AuthToken(user_id=user.id, token=token_str))
        del sessions[session_id]
        db.session.commit()
        return jsonify({'token': token_str}), 200
    else:
        record_fail(client_id)   # §5 record failure ONLY on actual bad proof
        del sessions[session_id]
        return jsonify({'reason': 'verification failed'}), 401


@app.route('/data', methods=['GET', 'POST', 'PUT'])
def dataAcessApi():
    data = request.get_json(silent=True) or {}
    token = extract_access_token(data)
    if not token:
        return jsonify({'reason': 'missing token'}), 401
    try:
        payload = jwt_decode(token)   # §4 full EdDSA + claim validation
        client_id = payload.get('client_id')
        user = User.query.filter_by(client_id=client_id).first()
        if not user:
            return jsonify({'reason': 'user not found'}), 404
        if request.method == 'GET':
            perso = PersoData.query.filter_by(user_id=user.id).first()
            if not perso:
                return jsonify({'reason': 'no personal data found'}), 404
            return jsonify({'data': perso.message})
        else:
            new_data = data.get('data')
            if new_data is None:
                return jsonify({'reason': 'missing data'}), 400
            if not isinstance(new_data, str):
                new_data = str(new_data)
            perso = PersoData.query.filter_by(user_id=user.id).first()
            was_created = False
            if perso:
                perso.message = new_data
            else:
                perso = PersoData(user_id=user.id, message=new_data)
                db.session.add(perso)
                was_created = True
            db.session.commit()
            return jsonify({'message': 'personal data updated'}), 201 if was_created else 200
    except jwt.ExpiredSignatureError:
        return jsonify({'reason': 'token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'reason': 'invalid token'}), 401
    

def create_self_signed_cert():
    """Create a self-signed certificate for HTTPS"""
    try:
        if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
            import subprocess
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                '-keyout', 'key.pem', '-out', 'cert.pem',
                '-days', '365', '-nodes',
                '-subj', '/CN=localhost'
            ], check=True)
            print('Created self-signed certificate')
    except Exception as e:
        print(f'Warning: Could not create certificate: {e}')
        print('Run without HTTPS or generate certificates manually:')
        print('openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"')


if __name__ == '__main__':
    import warnings
    warnings.filterwarnings("ignore", message=r".*request\.scope.*is deprecated")

    https=False

    print('Schnorr Authentication Server')
    print('\n')
    print('=' * 50)
    print(f'Starting Flask server on { 'https://localhost:5000' if https else 'http://localhost:5000'}')
    print(f'PID: {os.getpid()}')
    print('=' * 50)
    print('\n')

    #create_self_signed_cert()

    if https and os.path.exists('cert.pem') and os.path.exists('key.pem'):
        app.run(
            host='0.0.0.0',
            port=5000,
            ssl_context=('cert.pem', 'key.pem'),
            debug=True
        )
    else:
        # Fall back to HTTP
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True
        )

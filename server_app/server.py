from flask import Flask, request, jsonify
from flask_cors import CORS
from extensions import db
from models import User, AuthToken, PersoData
from server_oauth import init_oauth, clear_oauth_state
from server_authlib import init_authlib, clear_authlib_state
import secrets
import os
import jwt
import uuid
import time
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import dh

'''
Note: constants and settings should be in env files
Simplicity: hardcoded constants and settings
'''
P = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579
Q = (P - 1) // 2
G = 4

# Python's jwt gives warning if secret is shorter than 32
SECRET = 'dev-only-server-secret-at-least-32-bytes-long' 

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
    remote_addr = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    timestamp = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    print(
        f'{remote_addr} - - [{timestamp}] "{request.method} {request.full_path.rstrip("?")} HTTP/1.1" {response.status_code} -'
    )
    
    return response


'''
note: should be in database
simplicity: in memory commitments and challenges
'''
# commitments={}
#challenge_c_values={}
sessions = {}
SESSION_TTL = 5  # seconds; window between /login/commit and /login/verify
# {
#     'session_id': {
#         "client_id": '',
#         "t": t,
#         "c": challenge_c,
#         "created_at": time.time()
#     }
# }

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


# valid Schnorr group element in subgroup of order Q.
def is_subgroup_member(value):
    return 1 < value < P and pow(value, Q, P) == 1


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

'''
Note: the server should have the relation of client_id - secret_y,
     this endpoint can be secured with a shared secret or other methods
Simplicity: no authentication for this endpoint, in a real implementation it should be protected
'''
@app.route('/register', methods=['POST'])
def registerAPI():
    '''
    User registration, client sends client_id and secret_y (y = g^x mod p) computed from password,
    server saves it for later verification at login
    '''
    data = request.get_json() or {}
    client_id = data.get('client_id')
    secret = validate_int_field(data, 'secret_y')
    print(client_id, secret)
    if not client_id or secret is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if not is_subgroup_member(secret):
        return jsonify({'reason': 'invalid public value'}), 422

    is_new = register_user_in_db(client_id, secret)
    status = 'Registered' if is_new else 'Updated'
    return jsonify({'status': status}), 201 if is_new else 200

def register_user_in_db(client_id, secret_y):
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
    Login commitment, client sends client_id and commitment t, server saves it and returns challenge c
    '''
    data = request.get_json() or {}
    client_id = data.get('client_id')
    t = validate_int_field(data, 'commitment_t')
    if not client_id or t is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if not is_subgroup_member(t):
        return jsonify({'reason': 'invalid commitment'}), 422

    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'reason': 'user not registered'}), 404
    
    #if commitment already exists in inmemory dict -> delete it and return error -> a new session should be started
    for session_id, session in sessions.items():
        if session['client_id'] == client_id:
            del sessions[session_id]
            return jsonify({'reason': 'existing commitment found, start a new session'}), 409
    
    # create session, save commitment for verification
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "client_id": client_id,
        "t": t,
        "c": None, 
        "created_at": time.time()}

    challenge_c = secrets.randbelow(Q - 1) + 1
    sessions[session_id]["c"] = challenge_c
    return jsonify({'challenge_c': str(challenge_c), 'session_id': session_id}), 200


@app.route('/login/verify', methods=['POST'])
def verifyAPI():
    '''
    Login verification, client sends client_id and solution s,
    server verifies the proof using the saved commitment t and challenge c, if valid returns JWT token
    '''
    data = request.get_json() or {}
    #session_id will be in X-Auth-Session: header
    session_id = request.headers.get('X-Auth-Session')
    s = validate_int_field(data, 'solution_s')

    if not session_id:
        return jsonify({'reason': 'missing session_id in X-Auth-Session header'}), 400
    if session_id not in sessions:
        return jsonify({'reason': 'invalid session_id'}), 404
    if sessions[session_id]['created_at'] < time.time() - SESSION_TTL:
        del sessions[session_id]
        return jsonify({'reason': 'session expired'}), 300
    if s is None:
        del sessions[session_id]
        return jsonify({'reason': 'invalid solution'}), 422
    if s < 0 or s >= Q:
        del sessions[session_id]
        return jsonify({'reason': 'invalid solution'}), 422

    session = sessions[session_id]
    client_id = session['client_id']
    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'reason': 'user not found'}), 404
        
    y = int(user.secret_y)
    t = session['t']
    c = session['c']
    left = pow(G, s, P)
    right = (t * pow(y, c, P)) % P
    if left == right:
        # Issue JWT with expiry consistent with OAuth2 access token TTL (1 hour).
        now = datetime.now(timezone.utc)
        token_str = jwt.encode(
            {
                'client_id': client_id,
                'iat': now,
                'exp': now + timedelta(seconds=3600),
            },
            SECRET,
            algorithm='HS256',
        )
        auth = AuthToken.query.filter_by(user_id=user.id).first()
        if auth:
            auth.token = token_str
        else:
            auth = AuthToken(user_id=user.id, token=token_str)
            db.session.add(auth)
        del sessions[session_id]
        db.session.commit()
        return jsonify({'token': token_str}), 200
    else:
        del sessions[session_id]
        return jsonify({'reason': 'verification failed'}), 401


# @app.route('/forgetme', methods=['POST'])
# def forgetmeApi():
#     data = request.get_json(silent=True) or {}
#     client_id = data.get('client_id')
#     token = extract_access_token(data)
#     if not client_id:
#         return jsonify({'reason': 'missing client_id'}), 400
#     user = User.query.filter_by(client_id=client_id).first()
#     if not user:
#         return jsonify({'reason': 'user not found'}), 404
#     if token:
#         auth = AuthToken.query.filter_by(user_id=user.id, token=token).first()
#         if not auth:
#             return jsonify({'reason': 'invalid token'}), 401
#     # delete user cascades
#     AuthToken.query.filter_by(user_id=user.id).delete()
#     db.session.delete(user)
#     db.session.commit()
#     return jsonify({'message': 'User data deleted'})


@app.route('/data', methods=['GET', 'POST', 'PUT'])
def dataAcessApi():
    data = request.get_json(silent=True) or {}
    token = extract_access_token(data)
    if not token:
        return jsonify({'reason': 'missing token'}), 401
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
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
    https=False

    print('Schnorr Authentication Server')
    print('\n')
    print('=' * 50)
    print(f'Starting Flask server on { 'https://localhost:5000' if https else 'http://localhost:5000'}')
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

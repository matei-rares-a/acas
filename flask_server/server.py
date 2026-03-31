from flask import Flask, request, jsonify
from flask_cors import CORS
from extensions import db
from models import User, AuthToken, PersoData
import secrets
import os
import jwt
import uuid
import time

# public parameters for Schnorr protocol, using a 2048-bit safe prime
P = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579
Q = (P - 1) // 2
# generator of subgroup order Q (quadratic residue)
G = 4
SECRET = "server_secret"

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'db')
if not os.path.exists(db_path):
    os.makedirs(db_path)

app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(db_path, 'auth.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#todo everything should be in env vars, but for simplicity we keep it here for now
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
  )
db.init_app(app)

@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def add_rest_headers(response):
    """Add REST compliance and security headers to all responses"""
    # Request tracing
    request_id = request.headers.get('Request-ID', str(uuid.uuid4()))
    response.headers['Request-ID'] = request_id
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.is_secure or request.headers.get('X-Forwarded-Proto', 'http') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # API versioning
    response.headers['API-Version'] = '1.0'
    response.headers['Vary'] = 'Accept, Origin'
    
    # Cache control (overridable per route)
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate'
    
    # Performance metrics
    response.headers['X-Response-Time'] = f"{(time.time() - request.start_time):.3f}s"
    response.headers['Server-Timing'] = f"app;dur={(time.time() - request.start_time)*1000:.2f}"
    
    # Content type
    if response.headers.get('Content-Type') is None:
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
    
    # Add WWW-Authenticate for 401 responses
    if response.status_code == 401:
        response.headers['WWW-Authenticate'] = 'Bearer realm="Schnorr Authentication", charset="UTF-8"'
    
    return response




commitments={}
challenge_c_values={}

# Primary scheme: Bearer (RFC 6750). We also accept a few bearer-like schemes
# for interoperability with existing clients/tools.
# TODO: This multi-scheme authorization support must be extensively verified before production use.
SUPPORTED_AUTH_SCHEMES = {"bearer", "token", "jwt", "dpop"}


def validate_int_field(data, key):
    value = data.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_subgroup_member(value):
    # Valid Schnorr group element in subgroup of order Q.
    return 1 < value < P and pow(value, Q, P) == 1


def extract_access_token(data=None):
    """Extract token from Authorization header, with optional body fallback.

    Accepted header formats:
    - Authorization: Bearer <token>
    - Authorization: Token <token>
    - Authorization: JWT <token>
    - Authorization: DPoP <token>
    """
    auth_header = request.headers.get('Authorization', '').strip()
    if auth_header:
        parts = auth_header.split(None, 1)
        if len(parts) == 2:
            scheme, token = parts[0].lower(), parts[1].strip()
            if scheme in SUPPORTED_AUTH_SCHEMES and token:
                return token
        elif len(parts) == 1 and parts[0]:
            # Compatibility path for clients sending a raw token in Authorization.
            return parts[0]

    # Backward compatibility: accept token in JSON body.
    if data and data.get('token'):
        return data.get('token')

    return None


with app.app_context():
    db.create_all()
    print("Tabelele au fost create cu succes în:", app.config['SQLALCHEMY_DATABASE_URI'])


@app.route('/health', methods=['GET'])
def healthAPI():
    return jsonify({"health":"healthy"})


@app.route('/get-parameters', methods=['GET'])
def getParametersAPI():
    """Endpoint to exchange global parameters P and G with the client"""
    response = jsonify({'P': str(P), 'G': str(G)})
    response.headers['Cache-Control'] = 'public, max-age=3600'
    response.headers['ETag'] = 'W/"v1.0-schnorr"'
    return response


@app.route('/register', methods=['POST'])
def registerAPI():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    secret = validate_int_field(data, 'secret_y')
    print(client_id, secret)
    if not client_id or secret is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if not is_subgroup_member(secret):
        return jsonify({'reason': 'invalid public value'}), 422

    is_new = register_user_in_db(client_id, secret)
    return jsonify({'client_id': client_id}), 201 if is_new else 200

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

@app.route('/login/commit', methods=['POST'])
def commitAPI():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    t = validate_int_field(data, 'commitment_t')
    if not client_id or t is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if not is_subgroup_member(t):
        return jsonify({'reason': 'invalid commitment'}), 422

    # check user exists
    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'reason': 'user not registered'}), 404
    
    #if commitment already exists in inmemory dict, delete it and return error, because a new session should be started
    if client_id in commitments:
        del commitments[client_id]
        return jsonify({'reason': 'existing commitment found, start a new session'}), 409
    # save commitment in inmemory dict, because we need it for verification
    commitments[client_id] = t

    challenge_c = secrets.randbelow(Q - 1) + 1
    challenge_c_values[client_id] = challenge_c
    return jsonify({'challenge_c': str(challenge_c)})


@app.route('/login/verify', methods=['POST'])
def verifyAPI():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    s = validate_int_field(data, 'solution_s')
    if not client_id or s is None:
        return jsonify({'reason': 'missing parameters'}), 400
    if s < 0 or s >= Q:
        return jsonify({'reason': 'invalid solution'}), 422

    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'reason': 'user not found'}), 404
    
    if client_id not in commitments:
        return jsonify({'reason': 'no commitment'}), 409
    
    if client_id not in challenge_c_values:
        return jsonify({'reason': 'no challenge c'}), 409

    y = int(user.secret_y)
    t = commitments[client_id]
    c= challenge_c_values[client_id]
    left = pow(G, s, P)
    right = (t * pow(y, c, P)) % P
    if left == right:
        # generate or update token
        token_str = jwt.encode({'client_id': client_id}, SECRET, algorithm='HS256')
        auth = AuthToken.query.filter_by(user_id=user.id).first()
        if auth:
            auth.token = token_str
        else:
            auth = AuthToken(user_id=user.id, token=token_str)
            db.session.add(auth)
        del commitments[client_id]
        del challenge_c_values[client_id]
        db.session.commit()
        return jsonify({'token': token_str, 'client_id': client_id})
    else:
        return jsonify({'reason': 'verification failed'}), 401


@app.route('/forgetme', methods=['POST'])
def forgetmeApi():
    data = request.get_json(silent=True) or {}
    client_id = data.get('client_id')
    token = extract_access_token(data)
    if not client_id:
        return jsonify({'reason': 'missing client_id'}), 400
    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'reason': 'user not found'}), 404
    if token:
        auth = AuthToken.query.filter_by(user_id=user.id, token=token).first()
        if not auth:
            return jsonify({'reason': 'invalid token'}), 401
    # delete user cascades
    AuthToken.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User data deleted'})


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

    print('Schnorr Authentication Server')
    print('=' * 50)
    print('Starting Flask server on https://localhost:5000')
    print('=' * 50)

    # Try to create self-signed certificate
    create_self_signed_cert()

    # Run with HTTPS if certificates exist
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        app.run(
            host='0.0.0.0',
            port=5000,
            ssl_context=('cert.pem', 'key.pem'),
            debug=True
        )
    else:
        # Fall back to HTTP
        print('WARNING: Running without HTTPS. Certificates not found.')
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True
        )

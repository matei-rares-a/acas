from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import secrets
import os
import ssl
import jwt

# public parameters
P = 2089
G = 2
SECRET= "server_secret"

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, 'db', 'auth.db')}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(255), unique=True, nullable=False)
    secret_y = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


commitments={}
challenge_c_values={}

class AuthToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user = db.relationship('User', backref=db.backref('auth_token', uselist=False))

class PersoData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), unique=True, nullable=False)
    user = db.relationship('User', backref=db.backref('perso_data', uselist=False))


def init_db():
    if not os.path.exists('flask_server/db/auth.db'):
        db.create_all()
        print('Initialized SQLite database')


@app.route('/health', methods=['GET'])
def healthAPI():
    return jsonify({'status': 'healthy'})


@app.route('/register', methods=['POST'])
def registerAPI():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    secret = data.get('secret_y')
    if not client_id or secret is None:
        return jsonify({'status': 'failed', 'reason': 'missing parameters'}), 400

    status_msg = register_user_in_db(client_id, secret)
    return jsonify({'status': status_msg, 'client_id': client_id})

def register_user_in_db(client_id, secret_y):
    user = User.query.filter_by(client_id=client_id).first()
    if user:
        user.secret_y = str(secret_y)
        status_msg = 'updated'
    else:
        user = User(client_id=client_id, secret_y=str(secret_y))
        db.session.add(user)
        status_msg = 'registered'
    db.session.commit()
    return status_msg

@app.route('/login/commit', methods=['POST'])
def commitAPI():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    t = data.get('commitment_t')
    if not client_id or t is None:
        return jsonify({'status': 'failed', 'reason': 'missing parameters'}), 400

    # check user exists
    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'status': 'failed', 'reason': 'user not registered'}), 400
    
    #if commitment already exists in inmemory dict, delete it and return error, because a new session should be started
    if client_id in commitments:
        del commitments[client_id]
        return jsonify({'status': 'failed', 'reason': 'existing commitment found, start a new session'}), 400
    # save commitment in inmemory dict, because we need it for verification
    commitments[client_id] = t

    db.session.commit()
    challenge_c = secrets.randbelow(P - 2) + 1
    challenge_c_values[client_id] = challenge_c
    return jsonify({'status': 'committed', 'challenge_c': challenge_c})


@app.route('/login/verify', methods=['POST'])
def verifyAPI():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    s = data.get('solution_s')
    if not client_id or s is None:
        return jsonify({'status': 'failed', 'reason': 'missing parameters'}), 400

    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'status': 'failed', 'reason': 'user not found'}), 400
    
    if not commitments.get(client_id):
        return jsonify({'status': 'failed', 'reason': 'no commitment'}), 400
    
    if not challenge_c_values.get(client_id):
        return jsonify({'status': 'failed', 'reason': 'no challenge c'}), 400

    y = int(user.secret_y)
    t = int(commitments[client_id])
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
        db.session.commit()
        return jsonify({'status': 'authenticated', 'token': token_str, 'client_id': client_id})
    else:
        return jsonify({'status': 'failed', 'reason': 'verification failed'})


@app.route('/forgetme', methods=['POST'])
def forgetmeApi():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    token = data.get('token')
    if not client_id:
        return jsonify({'status': 'failed', 'reason': 'missing client_id'}), 400
    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'status': 'failed', 'reason': 'user not found'}), 400
    if token:
        auth = AuthToken.query.filter_by(user_id=user.id, token=token).first()
        if not auth:
            return jsonify({'status': 'failed', 'reason': 'invalid token'}), 400
    # delete user cascades
    AuthToken.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'forgotten', 'message': 'User data deleted'})


@app.route('/data', methods=['GET', 'POST', 'PUT'])
def dataAcessApi():
    data = request.get_json() or {}
    token = data.get('token')
    if not token:
        return jsonify({'status': 'failed', 'reason': 'missing token'}), 400
    try:
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
        client_id = payload.get('client_id')
        user = User.query.filter_by(client_id=client_id).first()
        if not user:
            return jsonify({'status': 'failed', 'reason': 'user not found'}), 400
        if request.method == 'GET':
            perso = PersoData.query.filter_by(user_id=user.id).first()
            if not perso:
                return jsonify({'status': 'failed', 'reason': 'no personal data found'}), 404
            return jsonify({'status': 'success', 'data': perso.message})
        else:
            new_data = str(data.get('data'))
            if new_data is None:
                return jsonify({'status': 'failed', 'reason': 'missing data'}), 400
            perso = PersoData.query.filter_by(user_id=user.id).first()
            if perso:
                perso.message = new_data
            else:
                perso = PersoData(user_id=user.id, message=new_data)
                db.session.add(perso)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'personal data updated'})
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'failed', 'reason': 'token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'status': 'failed', 'reason': 'invalid token'}), 401
    

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
    init_db()

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

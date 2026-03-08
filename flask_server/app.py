from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import secrets
import os

# public parameters
P = 2089
G = 2

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(255), unique=True, nullable=False)
    secret_y = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class Commitment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(255), unique=True, nullable=False)
    t = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class AuthToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user = db.relationship('User', backref=db.backref('auth_token', uselist=False))


def init_db():
    if not os.path.exists('flask_server/auth.db'):
        db.create_all()
        print('Initialized SQLite database')


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    secret = data.get('secret')
    if not client_id or secret is None:
        return jsonify({'status': 'failed', 'reason': 'missing parameters'}), 400

    user = User.query.filter_by(client_id=client_id).first()
    if user:
        user.secret_y = str(secret)
        status_msg = 'updated'
    else:
        user = User(client_id=client_id, secret_y=str(secret))
        db.session.add(user)
        status_msg = 'registered'
    db.session.commit()
    return jsonify({'status': status_msg, 'client_id': client_id})


@app.route('/commit', methods=['POST'])
def commit():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    t = data.get('t')
    if not client_id or t is None:
        return jsonify({'status': 'failed', 'reason': 'missing parameters'}), 400

    # check user exists
    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'status': 'failed', 'reason': 'user not registered'}), 400

    commitment = Commitment.query.filter_by(client_id=client_id).first()
    if commitment:
        commitment.t = str(t)
    else:
        commitment = Commitment(client_id=client_id, t=str(t))
        db.session.add(commitment)
    db.session.commit()
    c = secrets.randbelow(P - 2) + 1
    return jsonify({'status': 'committed', 'c': c})


@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json() or {}
    client_id = data.get('client_id')
    s = data.get('s')
    c = data.get('c')
    if not client_id or s is None or c is None:
        return jsonify({'status': 'failed', 'reason': 'missing parameters'}), 400

    user = User.query.filter_by(client_id=client_id).first()
    if not user:
        return jsonify({'status': 'failed', 'reason': 'user not found'}), 400
    commitment = Commitment.query.filter_by(client_id=client_id).first()
    if not commitment:
        return jsonify({'status': 'failed', 'reason': 'no commitment'}), 400

    y = int(user.secret_y)
    t = int(commitment.t)
    left = pow(G, s, P)
    right = (t * pow(y, c, P)) % P
    if left == right:
        # generate or update token
        token_str = secrets.token_hex(32)
        auth = AuthToken.query.filter_by(user_id=user.id).first()
        if auth:
            auth.token = token_str
        else:
            auth = AuthToken(user_id=user.id, token=token_str)
            db.session.add(auth)
        db.session.delete(commitment)
        db.session.commit()
        return jsonify({'status': 'authenticated', 'token': token_str, 'client_id': client_id})
    else:
        return jsonify({'status': 'failed', 'reason': 'verification failed'})


@app.route('/forgetme', methods=['POST'])
def forgetme():
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
    Commitment.query.filter_by(client_id=client_id).delete()
    AuthToken.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'forgotten', 'message': 'User data deleted'})


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

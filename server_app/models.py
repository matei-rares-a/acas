from extensions import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(255), unique=True, nullable=False)
    secret_y = db.Column(db.LargeBinary(256), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


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

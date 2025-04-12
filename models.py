from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=False, nullable=True)
    password = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=True)
    sms_mfa_completed = db.Column(db.Boolean, default=False)
    email_mfa_completed = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_mfa_completed = db.Column(db.Boolean, default=False)
    magic_link_completed = db.Column(db.Boolean, default=False)



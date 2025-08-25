from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import uuid
from sqlalchemy.dialects.postgresql import BYTEA

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    mfa_secret = db.Column(db.String(16), nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=False)
    approval_token = db.Column(db.String(36), unique=True, nullable=True)
    sponsor_email = db.Column(db.String(120), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    type = db.Column(db.String(50))

    __mapper_args__ = {
        'polymorphic_identity': 'user',
        'polymorphic_on': type
    }

    def set_password(self, password):
        #self.password_hash = password #will change it later on don't for know
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        #return self.password_hash == password #will change it later on don't for know
        return check_password_hash(self.password_hash, password)

class Employee(User):
    __tablename__ = 'employees'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    __mapper_args__ = {
        'polymorphic_identity': 'employee'
    }

class HR(User):
    __tablename__ = 'hrs'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    __mapper_args__ = {
        'polymorphic_identity': 'hr'
    }

class IT(User):
    __tablename__ = 'its'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    __mapper_args__ = {
        'polymorphic_identity': 'it'
    }

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    type = db.Column(db.String(20), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    mode = db.Column(db.String(20), nullable=True)  # Add this if needed
    reason = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class MFACode(db.Model):
    __tablename__ = 'mfa_codes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

class SponsorApproval(db.Model):
    __tablename__ = 'sponsor_approvals'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sponsor_email = db.Column(db.String(120), nullable=False)
    approved = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class WelcomeContent(db.Model):
    __tablename__ = 'welcome_content'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    encrypted_video_url = db.Column(BYTEA, nullable=False)  # Encrypted with pgcrypto

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    encrypted_content = db.Column(BYTEA, nullable=False)  # Encrypted with pgcrypto
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Policy(db.Model):
    __tablename__ = 'policies'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    version = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class SignedPolicy(db.Model):
    __tablename__ = 'signed_policies'
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_signed_content = db.Column(BYTEA, nullable=False)  # Encrypted PDF
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
import sys
import os
import re
import pytest
from flask import Flask, Blueprint, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime, timezone
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from decouple import config
import logging
import uuid
from freezegun import freeze_time
import base64
import boto3
from werkzeug.datastructures import FileStorage
from unittest.mock import patch

# Configure logging for tests
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create the test app factory
def create_test_app():
    test_app = Flask(__name__)
    test_app.config['TESTING'] = True
    test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    test_app.config['JWT_SECRET_KEY'] = 'test-jwt-secret-key'
    test_app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
    test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    test_app.config['SECRET_KEY'] = 'test-secret-key'
    test_app.config['BASE_URL'] = 'http://localhost'
    test_app.config['PGCRYPTO_KEY'] = 'test-pgcrypto-key'  # Mock for pgp_sym_encrypt
    
    # Initialize extensions
    db = SQLAlchemy()
    db.init_app(test_app)
    jwt = JWTManager(test_app)
    
    # Mock pgp_sym_encrypt for WelcomeContent
    def pgp_sym_encrypt(data, key):
        return f"encrypted:{data}"  # Simple mock for testing
    
    test_app.pgp_sym_encrypt = pgp_sym_encrypt
    
    # Define models to match production
    class User(db.Model):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(128), nullable=False)
        mfa_secret = db.Column(db.String(16), nullable=True)
        last_login = db.Column(db.DateTime, nullable=True)
        failed_attempts = db.Column(db.Integer, default=0)
        is_active = db.Column(db.Boolean, default=False)
        approval_token = db.Column(db.String(36), unique=True, nullable=True)
        sponsor_email = db.Column(db.String(120), nullable=True)
        type = db.Column(db.String(50))
        
        __mapper_args__ = {
            'polymorphic_identity': 'user',
            'polymorphic_on': type
        }
        
        def set_password(self, password):
            self.password_hash = generate_password_hash(password)
        
        def check_password(self, password):
            return check_password_hash(self.password_hash, password)
    
    class Employee(User):
        __tablename__ = 'employees'
        id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
        __mapper_args__ = {'polymorphic_identity': 'employee'}
    
    class HR(User):
        __tablename__ = 'hrs'
        id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
        __mapper_args__ = {'polymorphic_identity': 'hr'}
    
    class IT(User):
        __tablename__ = 'its'
        id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
        __mapper_args__ = {'polymorphic_identity': 'it'}
    
    class AuditLog(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
        type = db.Column(db.String(20), nullable=False)
        success = db.Column(db.Boolean, nullable=False)
        reason = db.Column(db.String(100), nullable=True)
        ip_address = db.Column(db.String(45), nullable=False)
        timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    class MFACode(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
        email = db.Column(db.String(120), nullable=True)
        code = db.Column(db.String(6), nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
    
    class SponsorApproval(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        sponsor_email = db.Column(db.String(120), nullable=False)
        approved = db.Column(db.Boolean, nullable=False)
        timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    class WelcomeContent(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        message = db.Column(db.String(200), nullable=False)
        encrypted_video_url = db.Column(db.Text, nullable=False)
    
    class Policy(db.Model):
        __tablename__ = 'policies'
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(100), nullable=False)
        content = db.Column(db.Text, nullable=False)
        version = db.Column(db.String(10), nullable=False)
        timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    class SignedPolicy(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=False)
        envelope_id = db.Column(db.String(50), nullable=False)
        timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    class Document(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        file_name = db.Column(db.String(100), nullable=False)
        file_type = db.Column(db.String(50), nullable=False)
        s3_key = db.Column(db.String(200), nullable=False)
        timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Store models in app for access
    test_app.User = User
    test_app.Employee = Employee
    test_app.HR = HR
    test_app.IT = IT
    test_app.AuditLog = AuditLog
    test_app.MFACode = MFACode
    test_app.SponsorApproval = SponsorApproval
    test_app.WelcomeContent = WelcomeContent
    test_app.Policy = Policy
    test_app.SignedPolicy = SignedPolicy
    test_app.Document = Document
    test_app.db = db
    
    def generate_mfa_code(length=6):
        return ''.join(random.choices(string.digits, k=length))
    
    def validate_password(password):
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        return True, "Password is valid"
    
    def send_mfa_email(email, code, context="login"):
        logger.info(f"Mock email sent to {email} with MFA code {code} for {context}")
        return True
    
    def send_sponsor_email(sponsor_email, token, username):
        logger.info(f"Mock sponsor email sent to {sponsor_email} for {username}")
        return True
    
    def send_confirmation_email(email, context="registration_confirmation"):
        logger.info(f"Mock confirmation email sent to {email}")
        return True
    
    # Define Blueprint for routes
    routes = Blueprint("routes", __name__)
    
    @routes.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        ip = request.remote_addr
        
        required_fields = ['username', 'email', 'password', 'password_confirmation', 'sponsor_email', 'role']
        if not all(key in data for key in required_fields):
            audit = test_app.AuditLog(type='register', user_id=None, success=False, reason='Missing required fields', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed registration attempt: missing fields from IP {ip}")
            return jsonify({"message": "Missing required fields"}), 400
        
        if data['password'] != data['password_confirmation']:
            audit = test_app.AuditLog(type='register', user_id=None, success=False, reason='Passwords do not match', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed registration attempt: passwords do not match from IP {ip}")
            return jsonify({"message": "Passwords do not match"}), 400
        
        if data['role'] not in ['employee', 'hr', 'it']:
            audit = test_app.AuditLog(type='register', user_id=None, success=False, reason='Invalid role', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed registration attempt: invalid role {data['role']} from IP {ip}")
            return jsonify({"message": "Invalid role"}), 400
        
        if test_app.User.query.filter_by(username=data['username']).first() or test_app.User.query.filter_by(email=data['email']).first():
            audit = test_app.AuditLog(type='register', user_id=None, success=False, reason='Username or email already exists', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed registration attempt: username {data['username']} or email {data['email']} already exists from IP {ip}")
            return jsonify({"message": "Username or email already exists"}), 400
        
        is_valid, reason = validate_password(data['password'])
        if not is_valid:
            audit = test_app.AuditLog(type='register', user_id=None, success=False, reason=reason, ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed registration attempt: weak password for {data['username']} from IP {ip}")
            return jsonify({"message": reason}), 400
        
        mfa_code = generate_mfa_code()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        mfa_entry = test_app.MFACode(email=data['email'], code=mfa_code, expires_at=expires_at)
        test_app.db.session.add(mfa_entry)
        
        audit = test_app.AuditLog(type='register', user_id=None, success=True, reason='MFA code sent', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        
        if not send_mfa_email(data['email'], mfa_code, context='registration'):
            return jsonify({"message": "Failed to send MFA code"}), 500
        
        return jsonify({"message": "MFA code sent to your email. Please verify."}), 200
    
    @routes.route('/verify_registration_mfa', methods=['POST'])
    def verify_registration_mfa():
        data = request.get_json()
        ip = request.remote_addr
        email = data.get('email')
        mfa_code = data.get('mfa_code')
        required_fields = ['username', 'email', 'password', 'sponsor_email', 'role']
        if not all(key in data for key in required_fields):
            return jsonify({"message": "Missing required data for verification"}), 400
        
        mfa_entry = test_app.MFACode.query.filter_by(email=email, code=mfa_code).filter(
            test_app.MFACode.expires_at > datetime.now(timezone.utc)
        ).first()
        
        if not mfa_entry:
            audit = test_app.AuditLog(type='mfa', user_id=None, success=False, reason='Invalid or expired MFA code', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed MFA verification for registration: invalid code for {email} from IP {ip}")
            return jsonify({"message": "Invalid or expired MFA code"}), 401
        
        user_class = {
            'employee': test_app.Employee,
            'hr': test_app.HR,
            'it': test_app.IT
        }.get(data['role'])
        
        user = user_class(
            username=data['username'],
            email=data['email'],
            sponsor_email=data['sponsor_email'],
            approval_token=str(uuid.uuid4()),
            is_active=False
        )
        user.set_password(data['password'])
        test_app.db.session.add(user)
        
        audit = test_app.AuditLog(type='mfa', user_id=user.id, success=True, reason='Pending user created, sponsor approval requested', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.delete(mfa_entry)
        test_app.db.session.commit()
        
        if not send_sponsor_email(user.sponsor_email, user.approval_token, user.username):
            audit = test_app.AuditLog(type='register', user_id=user.id, success=False, reason='Failed to send sponsor email', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "Failed to send sponsor approval request"}), 500
        
        return jsonify({"message": "Sponsor approval request sent. Awaiting approval."}), 200
    
    @routes.route('/sponsor_approve', methods=['POST'])
    def sponsor_approve():
        data = request.get_json()
        token = data.get('token')
        approve = data.get('approve', False)
        ip = request.remote_addr
        
        user = test_app.User.query.filter_by(approval_token=token).first()
        
        if not user:
            audit = test_app.AuditLog(type='sponsor', user_id=None, success=False, reason='Invalid or expired token', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed sponsor approval: invalid token from IP {ip}")
            return jsonify({"message": "Invalid or expired token"}), 404
        
        sponsor_approval = test_app.SponsorApproval(
            user_id=user.id,
            sponsor_email=user.sponsor_email,
            approved=approve
        )
        test_app.db.session.add(sponsor_approval)
        
        if not approve:
            audit = test_app.AuditLog(type='sponsor', user_id=user.id, success=False, reason='Sponsor rejected request', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.delete(user)
            test_app.db.session.commit()
            logger.info(f"Sponsor rejected registration for {user.username} from IP {ip}")
            return jsonify({"message": "Registration request rejected by sponsor"}), 200
        
        user.is_active = True
        user.approval_token = None
        audit = test_app.AuditLog(type='sponsor', user_id=user.id, success=True, reason='Sponsor approved', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        
        send_confirmation_email(user.email)
        
        return jsonify({"message": "User activated successfully"}), 201
    
    @routes.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        user = test_app.User.query.filter_by(username=data['username']).first()
        ip = request.remote_addr
        
        if not user:
            audit = test_app.AuditLog(type='login', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed login attempt: user {data.get('username')} not found from IP {ip}")
            return jsonify({"message": "Invalid username or password"}), 401
        
        if not user.is_active:
            audit = test_app.AuditLog(type='login', user_id=user.id, success=False, reason='Account not active', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed login attempt: account not active for {user.username} from IP {ip}")
            return jsonify({"message": "Account not active"}), 403
        
        if not user.check_password(data['password']):
            user.failed_attempts += 1
            audit = test_app.AuditLog(type='login', user_id=user.id, success=False, reason='Invalid password', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed login attempt: invalid password for {user.username} from IP {ip}")
            return jsonify({"message": "Invalid username or password"}), 401
        
        mfa_code = generate_mfa_code()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        mfa_entry = test_app.MFACode(user_id=user.id, code=mfa_code, expires_at=expires_at)
        test_app.db.session.add(mfa_entry)
        test_app.db.session.commit()
        
        if not send_mfa_email(user.email, mfa_code, context='login'):
            audit = test_app.AuditLog(type='login', user_id=user.id, success=False, reason='Failed to send MFA code', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "Failed to send MFA code"}), 500
        
        audit = test_app.AuditLog(type='login', user_id=user.id, success=True, reason='MFA code sent', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        
        return jsonify({"message": "MFA code sent to your email. Please verify."}), 200
    
    @routes.route('/verify_mfa', methods=['POST'])
    def verify_mfa():
        data = request.get_json()
        username = data.get('username')
        mfa_code = data.get('mfa_code')
        ip = request.remote_addr
        
        user = test_app.User.query.filter_by(username=username).first()
        if not user:
            audit = test_app.AuditLog(type='mfa', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed MFA verification: user {username} not found from IP {ip}")
            return jsonify({"message": "User not found"}), 404
        
        if not user.is_active:
            audit = test_app.AuditLog(type='mfa', user_id=user.id, success=False, reason='Account not active', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed MFA verification: account not active for {username} from IP {ip}")
            return jsonify({"message": "Account not active"}), 403
        
        mfa_entry = test_app.MFACode.query.filter_by(user_id=user.id, code=mfa_code).filter(
            test_app.MFACode.expires_at > datetime.now(timezone.utc)
        ).first()
        
        if not mfa_entry:
            audit = test_app.AuditLog(type='mfa', user_id=user.id, success=False, reason='Invalid or expired MFA code', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed MFA verification: invalid code for {username} from IP {ip}")
            return jsonify({"message": "Invalid or expired MFA code"}), 401
        
        access_token = create_access_token(identity=str(user.id))
        user.last_login = datetime.now(timezone.utc)
        user.failed_attempts = 0
        audit = test_app.AuditLog(type='mfa', user_id=user.id, success=True, reason='Login successful', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.delete(mfa_entry)
        test_app.db.session.commit()
        
        return jsonify({"access_token": access_token, "role": user.type}), 200
    
    @routes.route('/protected', methods=['GET'])
    @jwt_required()
    def protected():
        user_id = get_jwt_identity()
        logger.debug(f"Protected route accessed with user_id: {user_id}")
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            logger.error(f"User not found for id: {user_id}")
            audit = test_app.AuditLog(type='protected_access', user_id=None, success=False, reason='User not found', ip_address=request.remote_addr)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "User not found"}), 404
        if not user.is_active:
            logger.warning(f"Unauthorized access to protected route by {user.username} (inactive) from IP {request.remote_addr}")
            audit = test_app.AuditLog(type='protected_access', user_id=user.id, success=False, reason='Unauthorized or account not active', ip_address=request.remote_addr)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "Unauthorized or account not active"}), 403
        logger.info(f"Protected route accessed successfully by {user.username}")
        audit = test_app.AuditLog(type='protected_access', user_id=user.id, success=True, reason='Protected route accessed', ip_address=request.remote_addr)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        return jsonify({"message": f"Welcome {user.username}", "role": user.type}), 200
    
    @routes.route('/hr/users', methods=['GET'])
    @jwt_required()
    def hr_users():
        user_id = get_jwt_identity()
        ip = request.remote_addr
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            logger.error(f"User not found for id: {user_id}")
            audit = test_app.AuditLog(type='hr_access', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "User not found"}), 404
        if user.type != 'hr':
            logger.warning(f"Unauthorized access to HR route by {user.username} (role: {user.type}) from IP {ip}")
            audit = test_app.AuditLog(type='hr_access', user_id=user.id, success=False, reason='HR access required', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "HR access required"}), 403
        users = test_app.User.query.all()
        audit = test_app.AuditLog(type='hr_access', user_id=user.id, success=True, reason='Viewed user list', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"HR user {user.username} accessed user list from IP {ip}")
        return jsonify([{
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.type,
            "is_active": u.is_active,
            "sponsor_email": u.sponsor_email
        } for u in users]), 200
    
    @routes.route('/it/config', methods=['GET'])
    @jwt_required()
    def it_config():
        user_id = get_jwt_identity()
        ip = request.remote_addr
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            logger.error(f"User not found for id: {user_id}")
            audit = test_app.AuditLog(type='it_access', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "User not found"}), 404
        if user.type != 'it':
            logger.warning(f"Unauthorized access to IT route by {user.username} (role: {user.type}) from IP {ip}")
            audit = test_app.AuditLog(type='it_access', user_id=user.id, success=False, reason='IT access required', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "IT access required"}), 403
        config_data = {
            "system_version": "1.0.0",
            "mfa_enabled": True,
            "max_login_attempts": 5
        }
        audit = test_app.AuditLog(type='it_access', user_id=user.id, success=True, reason='Viewed system config', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"IT user {user.username} accessed system config from IP {ip}")
        return jsonify({"message": "System configuration retrieved", "config": config_data}), 200
    
    @routes.route('/hr/users/<int:user_id>/deactivate', methods=['POST'])
    @jwt_required()
    def deactivate_user(user_id):
        current_user_id = get_jwt_identity()
        ip = request.remote_addr
        current_user = test_app.db.session.get(test_app.User, int(current_user_id))
        
        if not current_user:
            audit = test_app.AuditLog(type='hr_access', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed deactivation attempt: user not found from IP {ip}")
            return jsonify({"message": "User not found"}), 404
        
        if current_user.type != 'hr':
            audit = test_app.AuditLog(type='hr_access', user_id=current_user.id, success=False, reason='HR access required', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Unauthorized deactivation attempt by {current_user.username} (role: {current_user.type}) from IP {ip}")
            return jsonify({"message": "HR access required"}), 403
        
        if current_user.id == user_id:
            audit = test_app.AuditLog(type='hr_access', user_id=current_user.id, success=False, reason='Cannot deactivate self', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed deactivation attempt: {current_user.username} tried to deactivate self from IP {ip}")
            return jsonify({"message": "Cannot deactivate self"}), 403
        
        user_to_deactivate = test_app.db.session.get(test_app.User, user_id)
        if not user_to_deactivate:
            audit = test_app.AuditLog(type='hr_access', user_id=current_user.id, success=False, reason='Target user not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed deactivation attempt: target user {user_id} not found from IP {ip}")
            return jsonify({"message": "Target user not found"}), 404
        
        if not user_to_deactivate.is_active:
            audit = test_app.AuditLog(type='hr_access', user_id=current_user.id, success=False, reason='User already deactivated', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Failed deactivation attempt: user {user_to_deactivate.username} already deactivated from IP {ip}")
            return jsonify({"message": "User already deactivated"}), 400
        
        user_to_deactivate.is_active = False
        audit = test_app.AuditLog(type='hr_access', user_id=current_user.id, success=True, reason=f'Deactivated user {user_to_deactivate.username}', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"User {user_to_deactivate.username} deactivated by {current_user.username} from IP {ip}")
        return jsonify({"message": f'User {user_to_deactivate.username} deactivated successfully'}), 200
    
    @routes.route('/pending_approvals', methods=['GET'])
    @jwt_required()
    def pending_approvals():
        user_id = get_jwt_identity()
        ip = request.remote_addr
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            logger.error(f"User not found for id: {user_id}")
            audit = test_app.AuditLog(type='hr_access', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "User not found"}), 404
        if user.type != 'hr':
            logger.warning(f"Unauthorized access to pending approvals by {user.username} (role: {user.type}) from IP {ip}")
            audit = test_app.AuditLog(type='hr_access', user_id=user.id, success=False, reason='HR access required', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            return jsonify({"message": "HR access required"}), 403
        pending_users = test_app.User.query.filter_by(sponsor_email=user.email, is_active=False).all()
        audit = test_app.AuditLog(type='hr_access', user_id=user.id, success=True, reason='Viewed pending approvals', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"HR user {user.username} accessed pending approvals from IP {ip}")
        return jsonify({
            "pending_approvals": [{
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.type,
                "approval_token": u.approval_token
            } for u in pending_users]
        }), 200
    
    @routes.route('/get_signing_url', methods=['POST'])
    @jwt_required()
    def get_signing_url():
        user_id = get_jwt_identity()
        ip = request.remote_addr
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            audit = test_app.AuditLog(type='signing_url', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.error(f"User not found for id: {user_id}")
            return jsonify({"message": "User not found"}), 404
        if not user.is_active:
            audit = test_app.AuditLog(type='signing_url', user_id=user.id, success=False, reason='Unauthorized or account not active', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Unauthorized access to signing_url by {user.username} (inactive) from IP {ip}")
            return jsonify({"message": "Unauthorized or account not active"}), 403
        data = request.get_json()
        envelope_id = data.get('envelope_id')
        if not envelope_id:
            audit = test_app.AuditLog(type='signing_url', user_id=user.id, success=False, reason='Missing envelope_id', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Missing envelope_id for user {user.username} from IP {ip}")
            return jsonify({"message": "Missing envelope_id"}), 400
        # Mock DocuSign response
        signing_url = "https://demo.docusign.net/restapi"
        audit = test_app.AuditLog(type='signing_url', user_id=user.id, success=True, reason='Signing URL generated', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"Signing URL generated for user {user.username} from IP {ip}")
        return jsonify({"signing_url": signing_url}), 200
    
    @routes.route('/onboarding/welcome', methods=['GET'])
    @jwt_required()
    def get_welcome():
        user_id = get_jwt_identity()
        ip = request.remote_addr
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            audit = test_app.AuditLog(type='onboarding_welcome', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.error(f"User not found for id: {user_id}")
            return jsonify({"message": "User not found"}), 404
        if not user.is_active:
            audit = test_app.AuditLog(type='onboarding_welcome', user_id=user.id, success=False, reason='Unauthorized or account not active', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Unauthorized access to onboarding/welcome by {user.username} (inactive) from IP {ip}")
            return jsonify({"message": "Unauthorized or account not active"}), 403
        welcome_content = test_app.WelcomeContent.query.first()
        if not welcome_content:
            audit = test_app.AuditLog(type='onboarding_welcome', user_id=user.id, success=False, reason='No welcome content found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"No welcome content available for user {user.username} from IP {ip}")
            return jsonify({"message": "No welcome content available"}), 404
        # Mock Zoom meeting link
        zoom_link = f"https://zoom.us/j/{random.randint(1000000000, 9999999999)}"
        audit = test_app.AuditLog(type='onboarding_welcome', user_id=user.id, success=True, reason='Welcome data fetched successfully', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"Welcome content accessed by {user.username} from IP {ip}")
        return jsonify({
            "message": welcome_content.message,
            "video_url": welcome_content.encrypted_video_url.replace("encrypted:", ""),
            "zoom": {"join_url": zoom_link}
        }), 200
    
    @routes.route('/policies', methods=['GET'])
    @jwt_required()
    def get_policies():
        user_id = get_jwt_identity()
        ip = request.remote_addr
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            audit = test_app.AuditLog(type='policies_fetch', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.error(f"User not found for id: {user_id}")
            return jsonify({"message": "User not found"}), 404
        if not user.is_active:
            audit = test_app.AuditLog(type='policies_fetch', user_id=user.id, success=False, reason='Unauthorized or account not active', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Unauthorized access to policies by {user.username} (inactive) from IP {ip}")
            return jsonify({"message": "Unauthorized or account not active"}), 403
        policies = test_app.Policy.query.all()
        audit = test_app.AuditLog(type='policies_fetch', user_id=user.id, success=True, reason='Policies fetched successfully', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"Policies fetched by {user.username} from IP {ip}")
        return jsonify([{
            "id": p.id,
            "title": p.title,
            "content": p.content,
            "version": p.version,
            "timestamp": p.timestamp.isoformat()
        } for p in policies]), 200
    
    @routes.route('/sign_policy', methods=['POST'])
    @jwt_required()
    def sign_policy():
        user_id = get_jwt_identity()
        ip = request.remote_addr
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            audit = test_app.AuditLog(type='policy_sign', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.error(f"User not found for id: {user_id}")
            return jsonify({"message": "User not found"}), 404
        if not user.is_active:
            audit = test_app.AuditLog(type='policy_sign', user_id=user.id, success=False, reason='Unauthorized or account not active', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Unauthorized policy signing attempt by {user.username} (inactive) from IP {ip}")
            return jsonify({"message": "Unauthorized or account not active"}), 403
        data = request.get_json()
        policy_id = data.get('policy_id')
        policy = test_app.db.session.get(test_app.Policy, policy_id)
        if not policy:
            audit = test_app.AuditLog(type='policy_sign', user_id=user.id, success=False, reason='Policy not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Policy {policy_id} not found for user {user.username} from IP {ip}")
            return jsonify({"message": "Policy not found"}), 404
        # Mock DocuSign envelope creation
        envelope_id = f"env_{random.randint(1000, 9999)}"
        signed_policy = test_app.SignedPolicy(
            user_id=user.id,
            policy_id=policy_id,
            envelope_id=envelope_id
        )
        test_app.db.session.add(signed_policy)
        audit = test_app.AuditLog(type='policy_sign', user_id=user.id, success=True, reason=f'Signed policy {policy.title} successfully', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"Policy {policy.title} signed by {user.username} from IP {ip}")
        return jsonify({"message": "Policy signing initiated", "envelope_id": envelope_id}), 200
    
    @routes.route('/upload', methods=['POST'])
    @jwt_required()
    def upload_file():
        user_id = get_jwt_identity()
        ip = request.remote_addr
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            audit = test_app.AuditLog(type='file_upload', user_id=None, success=False, reason='User not found', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.error(f"User not found for id: {user_id}")
            return jsonify({"message": "User not found"}), 404
        if not user.is_active:
            audit = test_app.AuditLog(type='file_upload', user_id=user.id, success=False, reason='Unauthorized or account not active', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Unauthorized file upload attempt by {user.username} (inactive) from IP {ip}")
            return jsonify({"message": "Unauthorized or account not active"}), 403
        if 'file' not in request.files:
            audit = test_app.AuditLog(type='file_upload', user_id=user.id, success=False, reason='No file provided', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"No file provided by {user.username} from IP {ip}")
            return jsonify({"message": "No file provided"}), 400
        file = request.files['file']
        if file.filename == '':
            audit = test_app.AuditLog(type='file_upload', user_id=user.id, success=False, reason='No file selected', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"No file selected by {user.username} from IP {ip}")
            return jsonify({"message": "No file selected"}), 400
        allowed_extensions = {'pdf', 'png'}
        if not '.' in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            audit = test_app.AuditLog(type='file_upload', user_id=user.id, success=False, reason='Invalid file type', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"Invalid file type {file.filename} by {user.username} from IP {ip}")
            return jsonify({"message": "Only PDF and PNG files are allowed"}), 400
        file_size = len(file.read())
        file.seek(0)  # Reset file pointer
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            audit = test_app.AuditLog(type='file_upload', user_id=user.id, success=False, reason='File too large', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.warning(f"File {file.filename} too large by {user.username} from IP {ip}")
            return jsonify({"message": "File must be less than 10MB"}), 400
        # Mock ClamAV scan
        with patch('subprocess.run') as mock_clamscan:
            mock_clamscan.return_value.stdout = 'Infected files: 0'
            # Simulate ClamAV scan
            result = mock_clamscan(['clamscan', '--no-summary'], capture_output=True, text=True)
            if 'Infected files: 0' not in result.stdout:
                audit = test_app.AuditLog(type='file_upload', user_id=user.id, success=False, reason='File scan failed', ip_address=ip)
                test_app.db.session.add(audit)
                test_app.db.session.commit()
                logger.warning(f"File scan failed for {file.filename} by {user.username} from IP {ip}")
                return jsonify({"message": "File scan failed"}), 400
        # Mock S3 upload
        s3_key = f"uploads/{user.id}/{file.filename}"
        try:
            s3 = boto3.client('s3')
            s3.upload_fileobj(file, 'test-bucket', s3_key)
        except Exception as e:
            audit = test_app.AuditLog(type='file_upload', user_id=user.id, success=False, reason='S3 upload failed', ip_address=ip)
            test_app.db.session.add(audit)
            test_app.db.session.commit()
            logger.error(f"S3 upload failed for {file.filename} by {user.username}: {str(e)}")
            return jsonify({"message": "S3 upload failed"}), 500
        document = test_app.Document(
            user_id=user.id,
            file_name=file.filename,
            file_type=file.mimetype,
            s3_key=s3_key
        )
        test_app.db.session.add(document)
        audit = test_app.AuditLog(type='file_upload', user_id=user.id, success=True, reason=f'File {file.filename} uploaded successfully', ip_address=ip)
        test_app.db.session.add(audit)
        test_app.db.session.commit()
        logger.info(f"File {file.filename} uploaded by {user.username} from IP {ip}")
        return jsonify({"message": "File uploaded successfully"}), 200
    
    # Register the Blueprint
    test_app.register_blueprint(routes)
    
    return test_app

@pytest.fixture
def app():
    app = create_test_app()
    with app.app_context():
        yield app
        app.db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def test_user(app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="testuser",
            email="testuser@example.com",
            sponsor_email="sponsor@example.com",
            approval_token=str(uuid.uuid4()),
            is_active=True
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        user_id = user.id
        yield user_id
        app.db.drop_all()
import sys
import os
import re
import pytest
from flask import Flask, Blueprint, jsonify
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
    
    # Initialize extensions
    db = SQLAlchemy()
    db.init_app(test_app)
    jwt = JWTManager(test_app)
    
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
    
    # Store models in app for access
    test_app.User = User
    test_app.Employee = Employee
    test_app.HR = HR
    test_app.IT = IT
    test_app.AuditLog = AuditLog
    test_app.MFACode = MFACode
    test_app.SponsorApproval = SponsorApproval
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
        from flask import request, jsonify
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
        from flask import request, jsonify
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
        from flask import request, jsonify
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
        from flask import request, jsonify
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
        from flask import request, jsonify
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
        from flask import jsonify
        user_id = get_jwt_identity()
        logger.debug(f"Protected route accessed with user_id: {user_id}")
        user = test_app.db.session.get(test_app.User, int(user_id))
        if not user:
            logger.error(f"User not found for id: {user_id}")
            return jsonify({"message": "User not found"}), 404
        logger.info(f"Protected route accessed successfully by {user.username}")
        return jsonify({"message": f"Welcome {user.username}", "role": user.type}), 200
    
    @routes.route('/hr/users', methods=['GET'])
    @jwt_required()
    def hr_users():
        from flask import request, jsonify
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
        from flask import request, jsonify
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
        from flask import request, jsonify
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
        from flask import request, jsonify
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

# Test User model password hashing and checking
def test_user_password(app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(username="testuser2", email="test2@example.com", sponsor_email="sponsor2@example.com")
        user.set_password("Test123!")
        assert user.check_password("Test123!") is True
        assert user.check_password("wrongpassword") is False
        app.db.drop_all()

# Test user inheritance
def test_user_inheritance(app):
    with app.app_context():
        app.db.create_all()
        employee = app.Employee(username="emp1", email="emp1@example.com", sponsor_email="sponsor@example.com")
        hr = app.HR(username="hr1", email="hr1@example.com", sponsor_email="sponsor@example.com")
        it = app.IT(username="it1", email="it1@example.com", sponsor_email="sponsor@example.com")
        employee.set_password("Test123!")
        hr.set_password("Test123!")
        it.set_password("Test123!")
        app.db.session.add_all([employee, hr, it])
        app.db.session.commit()
        
        assert employee.type == 'employee'
        assert hr.type == 'hr'
        assert it.type == 'it'
        assert isinstance(employee, app.User)
        assert isinstance(hr, app.User)
        assert isinstance(it, app.User)
        app.db.drop_all()

# Test registration with missing fields
def test_register_missing_fields(client, app):
    with app.app_context():
        app.db.create_all()
        response = client.post('/register', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'password_confirmation': 'Test123!'
        })
        assert response.status_code == 400
        assert response.json == {"message": "Missing required fields"}
        
        audit = app.AuditLog.query.filter_by(type='register', success=False, reason='Missing required fields').first()
        assert audit is not None
        assert audit.ip_address == '127.0.0.1'
        app.db.drop_all()

# Test registration with password mismatch
def test_register_password_mismatch(client, app):
    with app.app_context():
        app.db.create_all()
        response = client.post('/register', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'password_confirmation': 'Test1234!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee'
        })
        assert response.status_code == 400
        assert response.json == {"message": "Passwords do not match"}
        
        audit = app.AuditLog.query.filter_by(type='register', success=False, reason='Passwords do not match').first()
        assert audit is not None
        app.db.drop_all()

# Test registration with weak password
def test_register_weak_password(client, app):
    with app.app_context():
        app.db.create_all()
        response = client.post('/register', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'weak',
            'password_confirmation': 'weak',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee'
        })
        assert response.status_code == 400
        assert response.json == {"message": "Password must be at least 8 characters long"}
        
        audit = app.AuditLog.query.filter_by(type='register', success=False, reason='Password must be at least 8 characters long').first()
        assert audit is not None
        app.db.drop_all()

# Test registration with duplicate username
def test_register_duplicate_username(client, test_user, app):
    with app.app_context():
        user = app.db.session.get(app.User, test_user)
        response = client.post('/register', json={
            'username': user.username,
            'email': 'different@example.com',
            'password': 'Test123!',
            'password_confirmation': 'Test123!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee'
        })
        assert response.status_code == 400
        assert response.json == {"message": "Username or email already exists"}
        
        audit = app.AuditLog.query.filter_by(type='register', success=False, reason='Username or email already exists').first()
        assert audit is not None

# Test registration with valid data
def test_register_valid(client, app):
    with app.app_context():
        app.db.create_all()
        response = client.post('/register', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'password_confirmation': 'Test123!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee'
        })
        assert response.status_code == 200
        assert response.json == {"message": "MFA code sent to your email. Please verify."}
        
        mfa_entry = app.MFACode.query.filter_by(email='newuser@example.com').first()
        assert mfa_entry is not None
        assert len(mfa_entry.code) == 6
        audit = app.AuditLog.query.filter_by(type='register', success=True, reason='MFA code sent').first()
        assert audit is not None
        app.db.drop_all()

# Test registration MFA verification
def test_verify_registration_mfa_valid(client, app):
    with app.app_context():
        app.db.create_all()
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            email="newuser@example.com",
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_registration_mfa', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee',
            'mfa_code': mfa_code
        })
        assert response.status_code == 200
        assert response.json == {"message": "Sponsor approval request sent. Awaiting approval."}
        
        user = app.User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.is_active is False
        assert user.type == 'employee'
        assert user.sponsor_email == 'sponsor@example.com'
        assert user.approval_token is not None
        audit = app.AuditLog.query.filter_by(type='mfa', success=True, reason='Pending user created, sponsor approval requested').first()
        assert audit is not None
        mfa_entry = app.MFACode.query.filter_by(email='newuser@example.com', code=mfa_code).first()
        assert mfa_entry is None
        app.db.drop_all()

# Test registration MFA with invalid code
def test_verify_registration_mfa_invalid(client, app):
    with app.app_context():
        app.db.create_all()
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            email="newuser@example.com",
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_registration_mfa', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee',
            'mfa_code': 'wrongcode'
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid or expired MFA code"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Invalid or expired MFA code').first()
        assert audit is not None
        app.db.drop_all()

# Test registration MFA with expired code
def test_verify_registration_mfa_expired(client, app):
    with app.app_context():
        app.db.create_all()
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            email="newuser@example.com",
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_registration_mfa', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee',
            'mfa_code': mfa_code
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid or expired MFA code"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Invalid or expired MFA code').first()
        assert audit is not None
        app.db.drop_all()

# Test sponsor approval
def test_sponsor_approve_valid(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="newuser",
            email="newuser@example.com",
            sponsor_email="sponsor@example.com",
            approval_token=str(uuid.uuid4()),
            is_active=False
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        token = user.approval_token
    
        response = client.post('/sponsor_approve', json={
            'token': token,
            'approve': True
        })
        assert response.status_code == 201
        assert response.json == {"message": "User activated successfully"}
        
        user = app.User.query.filter_by(username='newuser').first()
        assert user.is_active is True
        assert user.approval_token is None
        sponsor_approval = app.SponsorApproval.query.filter_by(user_id=user.id, approved=True).first()
        assert sponsor_approval is not None
        audit = app.AuditLog.query.filter_by(type='sponsor', success=True, reason='Sponsor approved').first()
        assert audit is not None
        app.db.drop_all()

# Test sponsor rejection
def test_sponsor_reject_valid(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="newuser",
            email="newuser@example.com",
            sponsor_email="sponsor@example.com",
            approval_token=str(uuid.uuid4()),
            is_active=False
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        token = user.approval_token
    
        response = client.post('/sponsor_approve', json={
            'token': token,
            'approve': False
        })
        assert response.status_code == 200
        assert response.json == {"message": "Registration request rejected by sponsor"}
        
        user = app.User.query.filter_by(username='newuser').first()
        assert user is None
        sponsor_approval = app.SponsorApproval.query.filter_by(approved=False).first()
        assert sponsor_approval is not None
        audit = app.AuditLog.query.filter_by(type='sponsor', success=False, reason='Sponsor rejected request').first()
        assert audit is not None
        app.db.drop_all()

# Test sponsor approval with invalid token
def test_sponsor_approve_invalid_token(client, app):
    with app.app_context():
        app.db.create_all()
        response = client.post('/sponsor_approve', json={
            'token': str(uuid.uuid4()),
            'approve': True
        })
        assert response.status_code == 404
        assert response.json == {"message": "Invalid or expired token"}
        
        audit = app.AuditLog.query.filter_by(type='sponsor', success=False, reason='Invalid or expired token').first()
        assert audit is not None
        app.db.drop_all()

# Test login with valid credentials
def test_login_valid(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="testuser",
            email="testuser@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        user_id = user.id
    
        response = client.post('/login', json={
            'username': 'testuser',
            'password': 'Test123!'
        })
        assert response.status_code == 200
        assert response.json == {"message": "MFA code sent to your email. Please verify."}
        
        mfa_entry = app.MFACode.query.filter_by(user_id=user_id).first()
        assert mfa_entry is not None
        audit = app.AuditLog.query.filter_by(type='login', success=True, reason='MFA code sent').first()
        assert audit is not None
        app.db.drop_all()

# Test login with invalid password
def test_login_invalid_password(client, test_user, app):
    with app.app_context():
        user = app.db.session.get(app.User, test_user)
        response = client.post('/login', json={
            'username': user.username,
            'password': 'wrongpassword'
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid username or password"}
        
        user = app.db.session.get(app.User, test_user)
        assert user.failed_attempts == 1
        audit = app.AuditLog.query.filter_by(type='login', success=False, reason='Invalid password').first()
        assert audit is not None

# Test login with inactive account
def test_login_inactive_account(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="testuser",
            email="testuser@example.com",
            sponsor_email="sponsor@example.com",
            is_active=False
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
    
        response = client.post('/login', json={
            'username': 'testuser',
            'password': 'Test123!'
        })
        assert response.status_code == 403
        assert response.json == {"message": "Account not active"}
        
        audit = app.AuditLog.query.filter_by(type='login', success=False, reason='Account not active').first()
        assert audit is not None
        app.db.drop_all()

# Test login with non-existent user
def test_login_non_existent_user(client, app):
    with app.app_context():
        app.db.create_all()
        response = client.post('/login', json={
            'username': 'nonexistent',
            'password': 'Test123!'
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid username or password"}
        
        audit = app.AuditLog.query.filter_by(type='login', success=False, reason='User not found').first()
        assert audit is not None
        app.db.drop_all()

# Test MFA verification with valid code
def test_verify_mfa_valid(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="testuser",
            email="testuser@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        user_id = user.id
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=user_id,
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_mfa', json={
            'username': 'testuser',
            'mfa_code': mfa_code
        })
        assert response.status_code == 200
        assert 'access_token' in response.json
        assert response.json['role'] == 'employee'
        
        user = app.db.session.get(app.User, user_id)
        assert user.last_login is not None
        assert user.failed_attempts == 0
        audit = app.AuditLog.query.filter_by(type='mfa', success=True, reason='Login successful').first()
        assert audit is not None
        mfa_entry = app.MFACode.query.filter_by(user_id=user_id, code=mfa_code).first()
        assert mfa_entry is None
        app.db.drop_all()

# Test MFA verification with invalid code
def test_verify_mfa_invalid(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="testuser",
            email="testuser@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        user_id = user.id
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=user_id,
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_mfa', json={
            'username': 'testuser',
            'mfa_code': 'wrongcode'
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid or expired MFA code"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Invalid or expired MFA code').first()
        assert audit is not None
        app.db.drop_all()

# Test MFA verification with expired code
def test_verify_mfa_expired(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="testuser",
            email="testuser@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        user_id = user.id
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=user_id,
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_mfa', json={
            'username': 'testuser',
            'mfa_code': mfa_code
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid or expired MFA code"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Invalid or expired MFA code').first()
        assert audit is not None
        app.db.drop_all()

# Test MFA verification with inactive account
def test_verify_mfa_inactive_account(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="testuser",
            email="testuser@example.com",
            sponsor_email="sponsor@example.com",
            is_active=False
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
    
        response = client.post('/verify_mfa', json={
            'username': 'testuser',
            'mfa_code': '123456'
        })
        assert response.status_code == 403
        assert response.json == {"message": "Account not active"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Account not active').first()
        assert audit is not None
        app.db.drop_all()

# Test JWT token expiration
def test_jwt_token_expiration(app):
    with app.app_context():
        token = create_access_token(identity=str(1))
        assert app.config['JWT_ACCESS_TOKEN_EXPIRES'] == timedelta(minutes=30)

# Test JWT token expiration with protected route
def test_jwt_token_expiration_full(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="testuser",
            email="testuser@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        user_id = user.id
        token = create_access_token(identity=str(user_id))
    
        response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        assert response.json == {"message": "Welcome testuser", "role": "employee"}
    
        with freeze_time(datetime.now(timezone.utc) + timedelta(minutes=31)):
            response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
            assert response.status_code == 401
            assert response.json.get('msg') == 'Token has expired'
        app.db.drop_all()

# Test HR users route access
def test_hr_users_access(client, app):
    with app.app_context():
        app.db.create_all()
        hr_user = app.HR(
            username="hruser",
            email="hr@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        hr_user.set_password("Test123!")
        emp_user = app.Employee(
            username="empuser",
            email="emp@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        emp_user.set_password("Test123!")
        app.db.session.add_all([hr_user, emp_user])
        app.db.session.commit()
        hr_token = create_access_token(identity=str(hr_user.id))
        emp_token = create_access_token(identity=str(emp_user.id))
    
        response = client.get('/hr/users', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 200
        assert len(response.json) >= 2
        assert any(u['username'] == 'hruser' for u in response.json)
        assert any(u['username'] == 'empuser' for u in response.json)
        audit = app.AuditLog.query.filter_by(type='hr_access', success=True, reason='Viewed user list').first()
        assert audit is not None
    
        response = client.get('/hr/users', headers={'Authorization': f'Bearer {emp_token}'})
        assert response.status_code == 403
        assert response.json == {"message": "HR access required"}
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='HR access required').first()
        assert audit is not None
        app.db.drop_all()

# Test IT config route access
def test_it_config_access(client, app):
    with app.app_context():
        app.db.create_all()
        it_user = app.IT(
            username="ituser",
            email="it@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        it_user.set_password("Test123!")
        emp_user = app.Employee(
            username="empuser",
            email="emp@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        emp_user.set_password("Test123!")
        app.db.session.add_all([it_user, emp_user])
        app.db.session.commit()
        it_token = create_access_token(identity=str(it_user.id))
        emp_token = create_access_token(identity=str(emp_user.id))
    
        response = client.get('/it/config', headers={'Authorization': f'Bearer {it_token}'})
        assert response.status_code == 200
        assert response.json['message'] == "System configuration retrieved"
        assert response.json['config']['system_version'] == "1.0.0"
        audit = app.AuditLog.query.filter_by(type='it_access', success=True, reason='Viewed system config').first()
        assert audit is not None
    
        response = client.get('/it/config', headers={'Authorization': f'Bearer {emp_token}'})
        assert response.status_code == 403
        assert response.json == {"message": "IT access required"}
        audit = app.AuditLog.query.filter_by(type='it_access', success=False, reason='IT access required').first()
        assert audit is not None
        app.db.drop_all()

# Test initial admin creation
def test_initial_admin_creation(app, client):
    with app.app_context():
        # Create database tables
        app.db.create_all()
        # Ensure no users exist initially
        assert app.db.session.query(app.User).count() == 0
        # Manually create admin user (mimicking production setup script)
        admin = app.HR(
            username='admin',
            email='admin@example.com',
            sponsor_email='sponsor@example.com',
            is_active=True
        )
        admin.set_password('Admin123!')
        app.db.session.add(admin)
        audit = app.AuditLog(
            type='initial_setup',
            user_id=None,
            success=True,
            reason='Created initial HR user: admin',
            ip_address='127.0.0.1'
        )
        app.db.session.add(audit)
        app.db.session.commit()
        # Check if admin user was created
        admin = app.db.session.query(app.HR).filter_by(username='admin').first()
        assert admin is not None
        assert admin.email == 'admin@example.com'
        assert admin.is_active is True
        assert admin.check_password('Admin123!')
        audit = app.AuditLog.query.filter_by(type='initial_setup', success=True).first()
        assert audit is not None
        assert audit.reason == 'Created initial HR user: admin'
        app.db.drop_all()

# Test user deactivation
def test_deactivate_user(app, client):
    with app.app_context():
        app.db.create_all()
        hr_user = app.HR(
            username='hruser',
            email='hr@example.com',
            sponsor_email='sponsor@example.com',
            is_active=True
        )
        hr_user.set_password('Test123!')
        emp_user = app.Employee(
            username='empuser',
            email='emp@example.com',
            sponsor_email='sponsor@example.com',
            is_active=True
        )
        emp_user.set_password('Test123!')
        app.db.session.add_all([hr_user, emp_user])
        app.db.session.commit()
        hr_token = create_access_token(identity=str(hr_user.id))
        emp_token = create_access_token(identity=str(emp_user.id))
    
        response = client.post(f'/hr/users/{emp_user.id}/deactivate', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 200
        assert response.json['message'] == f'User {emp_user.username} deactivated successfully'
        emp_user = app.db.session.get(app.User, emp_user.id)
        assert emp_user.is_active is False
        audit = app.AuditLog.query.filter_by(type='hr_access', success=True, reason=f'Deactivated user {emp_user.username}').first()
        assert audit is not None
    
        response = client.post(f'/hr/users/{emp_user.id}/deactivate', headers={'Authorization': f'Bearer {emp_token}'})
        assert response.status_code == 403
        assert response.json['message'] == 'HR access required'
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='HR access required').first()
        assert audit is not None
    
        response = client.post(f'/hr/users/{hr_user.id}/deactivate', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 403
        assert response.json['message'] == 'Cannot deactivate self'
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='Cannot deactivate self').first()
        assert audit is not None
    
        response = client.post('/hr/users/999/deactivate', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 404
        assert response.json['message'] == 'Target user not found'
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='Target user not found').first()
        assert audit is not None
    
        response = client.post(f'/hr/users/{emp_user.id}/deactivate', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 400
        assert response.json['message'] == 'User already deactivated'
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='User already deactivated').first()
        assert audit is not None
        app.db.drop_all()

# Test pending approvals route access
def test_pending_approvals_access(client, app):
    with app.app_context():
        app.db.create_all()
        hr_user = app.HR(
            username="hruser",
            email="hr@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        hr_user.set_password("Test123!")
        pending_user = app.Employee(
            username="pendinguser",
            email="pending@example.com",
            sponsor_email="hr@example.com",
            approval_token=str(uuid.uuid4()),
            is_active=False
        )
        pending_user.set_password("Test123!")
        other_user = app.Employee(
            username="otheruser",
            email="other@example.com",
            sponsor_email="other.sponsor@example.com",
            is_active=False
        )
        other_user.set_password("Test123!")
        emp_user = app.Employee(
            username="empuser",
            email="emp@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        emp_user.set_password("Test123!")
        app.db.session.add_all([hr_user, pending_user, other_user, emp_user])
        app.db.session.commit()
        hr_token = create_access_token(identity=str(hr_user.id))
        emp_token = create_access_token(identity=str(emp_user.id))
    
        # Test HR user accessing pending approvals
        response = client.get('/pending_approvals', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 200
        assert response.json['pending_approvals'] is not None
        assert len(response.json['pending_approvals']) == 1
        assert response.json['pending_approvals'][0]['username'] == 'pendinguser'
        assert response.json['pending_approvals'][0]['email'] == 'pending@example.com'
        assert response.json['pending_approvals'][0]['role'] == 'employee'
        assert response.json['pending_approvals'][0]['approval_token'] == pending_user.approval_token
        audit = app.AuditLog.query.filter_by(type='hr_access', success=True, reason='Viewed pending approvals').first()
        assert audit is not None
        assert audit.user_id == hr_user.id
    
        # Test non-HR user accessing pending approvals
        response = client.get('/pending_approvals', headers={'Authorization': f'Bearer {emp_token}'})
        assert response.status_code == 403
        assert response.json == {"message": "HR access required"}
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='HR access required').first()
        assert audit is not None
        assert audit.user_id == emp_user.id
    
        # Test access with no token
        response = client.get('/pending_approvals')
        assert response.status_code == 401
        assert response.json.get('msg') == 'Missing Authorization Header'
    
        # Test access with invalid token
        response = client.get('/pending_approvals', headers={'Authorization': 'Bearer invalidtoken'})
        assert response.status_code == 422
        assert response.json.get('msg') == 'Not enough segments'
    
        # Test when no pending approvals exist for the HR user
        hr_user2 = app.HR(
            username="hruser2",
            email="hr2@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        hr_user2.set_password("Test123!")
        app.db.session.add(hr_user2)
        app.db.session.commit()
        hr_token2 = create_access_token(identity=str(hr_user2.id))
        response = client.get('/pending_approvals', headers={'Authorization': f'Bearer {hr_token2}'})
        assert response.status_code == 200
        assert response.json['pending_approvals'] == []
        audit = app.AuditLog.query.filter_by(type='hr_access', success=True, reason='Viewed pending approvals', user_id=hr_user2.id).first()
        assert audit is not None
    
        app.db.drop_all()
from flask import Blueprint, request, jsonify
from .models import User, LoginAudit, MFACode
from flask_jwt_extended import create_access_token
from datetime import datetime, timedelta, timezone
import random
import string
import smtplib
from email.mime.text import MIMEText
from decouple import config

# Define the Blueprint
routes = Blueprint("routes", __name__)

# Initialize db here to avoid circular import
from . import db

def generate_mfa_code(length=6):
    """Generate a random 6-digit MFA code."""
    return ''.join(random.choices(string.digits, k=length))

def send_mfa_email(email, code):
    """Send MFA code to the user's email."""
    smtp_server = config('SMTP_SERVER', default='smtp.gmail.com')
    smtp_port = config('SMTP_PORT', default=587, cast=int)
    smtp_username = config('SMTP_USERNAME')
    smtp_password = config('SMTP_PASSWORD')
    
    msg = MIMEText(f"Your MFA code is: {code}\nThis code will expire in 5 minutes.")
    msg['Subject'] = 'Your MFA Verification Code'
    msg['From'] = smtp_username
    msg['To'] = email
    
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

@routes.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists"}), 400

    user = User(
        username=data['username'],
        email=data['email']
    )
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@routes.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    ip = request.remote_addr

    if not user or not user.check_password(data['password']):
        # Log failed attempt
        audit = LoginAudit(user_id=user.id if user else None, success=False, ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        return jsonify({"message": "Invalid username or password"}), 401

    # Generate and store MFA code
    mfa_code = generate_mfa_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    mfa_entry = MFACode(user_id=user.id, code=mfa_code, expires_at=expires_at)
    db.session.add(mfa_entry)
    db.session.commit()

    # Send MFA code via email
    if not send_mfa_email(user.email, mfa_code):
        return jsonify({"message": "Failed to send MFA code"}), 500

    return jsonify({"message": "MFA code sent to your email. Please verify."}), 200

@routes.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    username = data.get('username')
    mfa_code = data.get('mfa_code')
    ip = request.remote_addr

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Find the latest unexpired MFA code
    mfa_entry = MFACode.query.filter_by(user_id=user.id, code=mfa_code).filter(
        MFACode.expires_at > datetime.now(timezone.utc)
    ).first()

    if not mfa_entry:
        audit = LoginAudit(user_id=user.id, success=False, ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        return jsonify({"message": "Invalid or expired MFA code"}), 401

    # Successful MFA verification
    access_token = create_access_token(identity=user.id)
    user.last_login = datetime.now(timezone.utc)
    user.failed_attempts = 0
    
    # Log successful login
    audit = LoginAudit(user_id=user.id, success=True, ip_address=ip)
    db.session.add(audit)
    
    # Delete used MFA code
    db.session.delete(mfa_entry)
    db.session.commit()

    return jsonify({"access_token": access_token}), 200
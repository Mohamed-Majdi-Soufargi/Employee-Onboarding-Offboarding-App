from flask import Blueprint, request, jsonify
from .models import User, AuditLog, MFACode, SponsorApproval, Employee, HR, IT, WelcomeContent, Document, Policy, SignedPolicy
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta, timezone
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from decouple import config
import logging
import re
import uuid
import jwt  # python-jwt for Zoom API
import requests
import boto3
from sqlalchemy import text
import magic  # python-magic for file type
import subprocess  # For ClamAV
from werkzeug.utils import secure_filename
from docusign_esign import ApiClient, EnvelopesApi, Document, Signer, SignHere, Tabs, Recipients, EnvelopeDefinition

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define the Blueprint
routes = Blueprint("routes", __name__, url_prefix='/api')

# Initialize db here to avoid circular import
from . import db

def generate_mfa_code(length=6):
    """Generate a random 6-digit MFA code."""
    return ''.join(random.choices(string.digits, k=length))

def validate_password(password):
    """Validate password strength."""
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
    """Send MFA code to the user's email with HTML and plain text versions."""
    smtp_server = config('SMTP_SERVER', default='smtp.gmail.com')
    smtp_port = config('SMTP_PORT', default=587, cast=int)
    smtp_username = config('SMTP_USERNAME')
    smtp_password = config('SMTP_PASSWORD')
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'Your MFA Verification Code for {context.capitalize()}'
    msg['From'] = smtp_username
    msg['To'] = email
    
    text = f"Your MFA code is: {code}\nThis code will expire in 5 minutes."
    html = f"""
    <html>
        <body>
            <h2>Your MFA Verification Code for {context.capitalize()}</h2>
            <p>Your verification code is: <strong>{code}</strong></p>
            <p>This code will expire in 5 minutes.</p>
            <p>If you did not request this code, please ignore this email.</p>
        </body>
    </html>
    """
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)
    
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        logger.info(f"Email sent successfully to {email} with MFA code {code} for {context}")
        return True
    except Exception as e:
        logger.error(f"Error sending email to {email} for {context}: {e}")
        return False

def send_sponsor_email(sponsor_email, token, username):
    """Send approval request to the sponsor."""
    smtp_server = config('SMTP_SERVER', default='smtp.gmail.com')
    smtp_port = config('SMTP_PORT', default=587, cast=int)
    smtp_username = config('SMTP_USERNAME')
    smtp_password = config('SMTP_PASSWORD')
    
    approval_url = f"{config('BASE_URL', default='http://127.0.0.1:5000')}/sponsor_approve?token={token}"
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Sponsor Approval Request'
    msg['From'] = smtp_username
    msg['To'] = sponsor_email
    
    text = f"""
    A new user ({username}) has requested registration and listed you as their sponsor.
    Please approve or reject the request using the following link:
    {approval_url}
    This link will expire in 24 hours.
    """
    html = f"""
    <html>
        <body>
            <h2>Sponsor Approval Request</h2>
            <p>A new user (<strong>{username}</strong>) has requested registration and listed you as their sponsor.</p>
            <p>Please approve or reject the request using the following link:</p>
            <p><a href="{approval_url}">Approve/Reject Request</a></p>
            <p>This link will expire in 24 hours.</p>
        </body>
    </html>
    """
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)
    
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        logger.info(f"Sponsor approval email sent to {sponsor_email} for user {username}")
        return True
    except Exception as e:
        logger.error(f"Error sending sponsor email to {sponsor_email}: {e}")
        return False

def send_confirmation_email(email, context="registration_confirmation"):
    """Send confirmation email after approval."""
    smtp_server = config('SMTP_SERVER', default='smtp.gmail.com')
    smtp_port = config('SMTP_PORT', default=587, cast=int)
    smtp_username = config('SMTP_USERNAME')
    smtp_password = config('SMTP_PASSWORD')
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Registration Approved'
    msg['From'] = smtp_username
    msg['To'] = email
    
    text = "Your registration has been approved. You can now log in."
    html = f"""
    <html>
        <body>
            <h2>Registration Approved</h2>
            <p>Your registration has been approved. You can now log in to the application.</p>
        </body>
    </html>
    """
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)
    
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        logger.info(f"Confirmation email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Error sending confirmation email to {email}: {e}")
        return False

@routes.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    return jsonify({"message": f"Welcome, {user.username}!", "username": user.username, "role": user.type}), 200

@routes.route('/hr/users', methods=['GET'])
@jwt_required()
def hr_users():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or user.type != 'hr':
        return jsonify({"message": "Unauthorized"}), 403
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.type,
        "is_active": u.is_active,
        "sponsor_email": u.sponsor_email
    } for u in users]), 200

@routes.route('/hr/users/<int:user_id>/deactivate', methods=['POST'])
@jwt_required()
def deactivate_user(user_id):
    user_id_auth = get_jwt_identity()
    user = User.query.get(user_id_auth)
    if not user or user.type != 'hr':
        return jsonify({"message": "Unauthorized"}), 403
    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({"message": "User not found"}), 404
    target_user.is_active = False
    db.session.commit()
    audit = AuditLog(
        type='deactivate',
        user_id=user_id,
        success=True,
        reason=f'User {target_user.username} deactivated by {user.username}',
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    logger.info(f"User {target_user.username} deactivated by {user.username}")
    return jsonify({"message": "User deactivated successfully"}), 200

@routes.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    ip = request.remote_addr
    
    # Validate input
    required_fields = ['username', 'email', 'password', 'password_confirmation', 'sponsor_email', 'role']
    if not all(key in data for key in required_fields):
        audit = AuditLog(type='register', user_id=None, success=False, reason='Missing required fields', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed registration attempt: missing fields from IP {ip}")
        return jsonify({"message": "Missing required fields"}), 400
    
    if data['password'] != data['password_confirmation']:
        audit = AuditLog(type='register', user_id=None, success=False, reason='Passwords do not match', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed registration attempt: passwords do not match from IP {ip}")
        return jsonify({"message": "Passwords do not match"}), 400
    
    # Validate role
    if data['role'] not in ['employee', 'hr', 'it']:
        audit = AuditLog(type='register', user_id=None, success=False, reason='Invalid role', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed registration attempt: invalid role {data['role']} from IP {ip}")
        return jsonify({"message": "Invalid role"}), 400
    
    # Check for existing username or email
    if User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first():
        audit = AuditLog(type='register', user_id=None, success=False, reason='Username or email already exists', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed registration attempt: username {data['username']} or email {data['email']} already exists from IP {ip}")
        return jsonify({"message": "Username or email already exists"}), 400
    
    # Validate password strength
    is_valid, reason = validate_password(data['password'])
    if not is_valid:
        audit = AuditLog(type='register', user_id=None, success=False, reason=reason, ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed registration attempt: weak password for {data['username']} from IP {ip}")
        return jsonify({"message": reason}), 400
    
    # Generate and store MFA code associated with email
    mfa_code = generate_mfa_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    mfa_entry = MFACode(email=data['email'], code=mfa_code, expires_at=expires_at)
    db.session.add(mfa_entry)
    
    # Log attempt
    audit = AuditLog(type='register', user_id=None, success=True, reason='MFA code sent', ip_address=ip)
    db.session.add(audit)
    db.session.commit()
    
    # Send MFA code
    if not send_mfa_email(data['email'], mfa_code, context='registration'):
        logger.error(f"Failed to send MFA code to {data['email']} for registration")
        return jsonify({"message": "Failed to send MFA code"}), 500
    
    logger.info(f"MFA code sent to {data['email']} for registration of {data['username']}")
    return jsonify({"message": "MFA code sent to your email. Please verify."}), 200

@routes.route('/verify_registration_mfa', methods=['POST'])
def verify_registration_mfa():
    data = request.get_json()
    ip = request.remote_addr
    email = data.get('email')
    mfa_code = data.get('mfa_code')
    # Assume other data (username, password_hash, sponsor_email, role) are sent again or stored temporarily; for simplicity, require them in payload
    # In production, use a temp session or token to store pre-MFA data
    required_fields = ['username', 'email', 'password', 'sponsor_email', 'role']
    if not all(key in data for key in required_fields):
        return jsonify({"message": "Missing required data for verification"}), 400
    
    # Find matching MFA code by email
    mfa_entry = MFACode.query.filter_by(email=email, code=mfa_code).filter(
        MFACode.expires_at > datetime.now(timezone.utc)
    ).first()
    
    if not mfa_entry:
        audit = AuditLog(type='mfa', user_id=None, success=False, reason='Invalid or expired MFA code', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed MFA verification for registration: invalid code for {email} from IP {ip}")
        return jsonify({"message": "Invalid or expired MFA code"}), 401
    
    # Create pending user based on role
    user_class = {
        'employee': Employee,
        'hr': HR,
        'it': IT
    }.get(data['role'])
    
    user = user_class(
        username=data['username'],
        email=data['email'],
        sponsor_email=data['sponsor_email'],
        approval_token=str(uuid.uuid4()),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        is_active=False
    )
    user.set_password(data['password'])
    db.session.add(user)
    
    # Log successful MFA
    audit = AuditLog(type='mfa', user_id=user.id, success=True, reason='Pending user created, sponsor approval requested', ip_address=ip)
    db.session.add(audit)
    db.session.delete(mfa_entry)
    db.session.commit()
    
    # Send sponsor approval request
    if not send_sponsor_email(user.sponsor_email, user.approval_token, user.username):
        audit = AuditLog(type='register', user_id=user.id, success=False, reason='Failed to send sponsor email', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.error(f"Failed to send sponsor email to {user.sponsor_email} for {user.username}")
        return jsonify({"message": "Failed to send sponsor approval request"}), 500
    
    logger.info(f"Successful MFA verification for registration of {email} from IP {ip}. Pending user created.")
    return jsonify({"message": "Sponsor approval request sent. Awaiting approval."}), 200

@routes.route('/sponsor_approve', methods=['GET', 'POST'])
def sponsor_approve():
    ip = request.remote_addr

    if request.method == 'GET':
        token = request.args.get('token')
        if not token:
            audit = AuditLog(type='sponsor', user_id=None, success=False, reason='Missing token', ip_address=ip)
            db.session.add(audit)
            db.session.commit()
            logger.warning(f"Failed sponsor approval: missing token from IP {ip}")
            return jsonify({"message": "Missing token"}), 400

        user = User.query.filter_by(approval_token=token).filter(
            User.expires_at > datetime.now(timezone.utc)
        ).first()
        if not user:
            audit = AuditLog(type='sponsor', user_id=None, success=False, reason='Invalid or expired token', ip_address=ip)
            db.session.add(audit)
            db.session.commit()
            logger.warning(f"Failed sponsor approval: invalid token from IP {ip}")
            return jsonify({"message": "Invalid or expired token"}), 404

        return jsonify({"message": "Valid token", "username": user.username}), 200

    elif request.method == 'POST':
        data = request.get_json()
        token = data.get('token')
        approve = data.get('approve', False)
        
        user = User.query.filter_by(approval_token=token).filter(
            User.expires_at > datetime.now(timezone.utc)
        ).first()
        
        if not user:
            audit = AuditLog(type='sponsor', user_id=None, success=False, reason='Invalid or expired token', ip_address=ip)
            db.session.add(audit)
            db.session.commit()
            logger.warning(f"Failed sponsor approval: invalid token from IP {ip}")
            return jsonify({"message": "Invalid or expired token"}), 404
        
        # Log sponsor action
        sponsor_approval = SponsorApproval(
            user_id=user.id,
            sponsor_email=user.sponsor_email,
            approved=approve
        )
        db.session.add(sponsor_approval)
        
        if not approve:
            audit = AuditLog(type='sponsor', user_id=user.id, success=False, reason='Sponsor rejected request', ip_address=ip)
            db.session.add(audit)
            # Delete pending user on rejection
            db.session.delete(user)
            db.session.commit()
            logger.info(f"Sponsor rejected registration for {user.username} from IP {ip}")
            return jsonify({"message": "Registration request rejected by sponsor"}), 200
        
        # Activate user
        user.is_active = True
        user.approval_token = None  # Clear token
        user.expires_at = None  # Clear expiration
        audit = AuditLog(type='sponsor', user_id=user.id, success=True, reason='Sponsor approved', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        
        # Send confirmation email to user
        send_confirmation_email(user.email)
        
        logger.info(f"User {user.username} activated after sponsor approval from IP {ip}")
        return jsonify({"message": "User activated successfully"}), 201

@routes.route('/pending_approvals', methods=['GET'])
@jwt_required()
def pending_approvals():
    ip = request.remote_addr
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        audit = AuditLog(type='pending_approvals', user_id=None, success=False, reason='User not found', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed to fetch pending approvals: user not found from IP {ip}")
        return jsonify({"message": "User not found"}), 404
    
    # For HR users, show all pending approvals
    # For other users, show only approvals where they are the sponsor
    if user.type == 'hr':
        pending_users = User.query.filter_by(is_active=False).filter(User.approval_token.isnot(None)).all()
    else:
        pending_users = User.query.filter_by(sponsor_email=user.email, is_active=False).filter(User.approval_token.isnot(None)).all()
    
    approvals = [{
        "id": pending_user.id,
        "username": pending_user.username,
        "email": pending_user.email,
        "role": pending_user.type,
        "approval_token": pending_user.approval_token,
        "sponsor_email": pending_user.sponsor_email
    } for pending_user in pending_users]
    
    logger.info(f"Fetched {len(approvals)} pending approvals for user {user.username} from IP {ip}")
    return jsonify({"pending_approvals": approvals}), 200
    
@routes.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    ip = request.remote_addr
    
    if not user:
        audit = AuditLog(type='login', user_id=None, success=False, reason='User not found', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed login attempt: user {data.get('username')} not found from IP {ip}")
        return jsonify({"message": "Invalid username or password"}), 401
    
    if not user.is_active:
        audit = AuditLog(type='login', user_id=user.id, success=False, reason='Account not active', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed login attempt: account not active for {user.username} from IP {ip}")
        return jsonify({"message": "Account not active"}), 403
    
    if not user.check_password(data['password']):
        user.failed_attempts += 1
        audit = AuditLog(type='login', user_id=user.id, success=False, reason='Invalid password', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed login attempt: invalid password for {user.username} from IP {ip}")
        return jsonify({"message": "Invalid username or password"}), 401
    
    mfa_code = generate_mfa_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    mfa_entry = MFACode(user_id=user.id, code=mfa_code, expires_at=expires_at)
    db.session.add(mfa_entry)
    db.session.commit()
    
    if not send_mfa_email(user.email, mfa_code, context='login'):
        audit = AuditLog(type='login', user_id=user.id, success=False, reason='Failed to send MFA code', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.error(f"Failed to send MFA code to {user.email} for {user.username}")
        return jsonify({"message": "Failed to send MFA code"}), 500
    
    audit = AuditLog(type='login', user_id=user.id, success=True, reason='MFA code sent', ip_address=ip)
    db.session.add(audit)
    db.session.commit()
    
    logger.info(f"MFA code sent to {user.email} for {user.username}")
    return jsonify({"message": "MFA code sent to your email. Please verify."}), 200

@routes.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    username = data.get('username')
    mfa_code = data.get('mfa_code')
    ip = request.remote_addr
    
    user = User.query.filter_by(username=username).first()
    if not user:
        audit = AuditLog(type='mfa', user_id=None, success=False, reason='User not found', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed MFA verification: user {username} not found from IP {ip}")
        return jsonify({"message": "User not found"}), 404
    
    if not user.is_active:
        audit = AuditLog(type='mfa', user_id=user.id, success=False, reason='Account not active', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed MFA verification: account not active for {username} from IP {ip}")
        return jsonify({"message": "Account not active"}), 403
    
    mfa_entry = MFACode.query.filter_by(user_id=user.id, code=mfa_code).filter(
        MFACode.expires_at > datetime.now(timezone.utc)
    ).first()
    
    if not mfa_entry:
        audit = AuditLog(type='mfa', user_id=user.id, success=False, reason='Invalid or expired MFA code', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed MFA verification: invalid code for {username} from IP {ip}")
        return jsonify({"message": "Invalid or expired MFA code"}), 401
    
    access_token = create_access_token(identity=str(user.id))
    user.last_login = datetime.now(timezone.utc)
    user.failed_attempts = 0
    audit = AuditLog(type='mfa', user_id=user.id, success=True, reason='Login successful', ip_address=ip)
    db.session.add(audit)
    db.session.delete(mfa_entry)
    db.session.commit()
    
    logger.info(f"Successful MFA verification for {username} from IP {ip}")
    return jsonify({"access_token": access_token, "role": user.type}), 200

# AWS S3 client (configure with your credentials in .env)
s3 = boto3.client(
    's3',
    aws_access_key_id=config('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=config('AWS_SECRET_ACCESS_KEY')
)

# Zoom API configuration
ZOOM_API_BASE = 'https://api.zoom.us/v2'

def create_zoom_meeting(access_token, topic='Virtual Team Introduction', start_time='2025-08-26T10:00:00Z'):
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    data = {
        'topic': topic,
        'type': 2,  # Scheduled meeting
        'start_time': start_time,
        'duration': 60,
        'settings': {'join_before_host': True}
    }
    response = requests.post(f'{ZOOM_API_BASE}/users/me/meetings', headers=headers, json=data)
    if response.status_code == 201:
        meeting = response.json()
        return {'join_url': meeting['join_url'], 'meeting_id': meeting['id']}
    else:
        logger.error(f"Failed to create Zoom meeting: {response.text}")
        raise Exception('Failed to create Zoom meeting')

# Helper to encrypt/decrypt with pgcrypto
def store_welcome_content(message, video_url):
    encrypted_url = db.session.execute(
        text("SELECT pgp_sym_encrypt(:url, :key)"),
        {'url': video_url, 'key': config('PGCRYPTO_KEY')}
    ).scalar()
    new_content = WelcomeContent(message=message, encrypted_video_url=encrypted_url)
    db.session.add(new_content)
    db.session.commit()
    return new_content.id

def get_welcome_content():
    result = db.session.execute(
        text("SELECT message, pgp_sym_decrypt(encrypted_video_url, :key) as video_url FROM welcome_content LIMIT 1"),
        {'key': config('PGCRYPTO_KEY')}
    ).fetchone()
    if not result:
        return None
    return {'message': result[0], 'video_url': result[1]}

@routes.route('/onboarding/welcome', methods=['GET'])
@jwt_required()
def get_welcome():
    ip = request.remote_addr
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        audit = AuditLog(
            type='onboarding_welcome',
            user_id=user_id,
            success=False,
            reason='Unauthorized or inactive user',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed to fetch welcome data for user_id {user_id} from IP {ip}")
        return jsonify({"message": "Unauthorized or account not active"}), 403

    welcome_data = get_welcome_content()
    if not welcome_data:
        audit = AuditLog(
            type='onboarding_welcome',
            user_id=user_id,
            success=False,
            reason='No welcome content found',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"No welcome content found for user_id {user_id} from IP {ip}")
        return jsonify({"message": "No welcome content available"}), 404

    # Zoom meeting creation (assume access_token fetched via OAuth; simplified here)
    try:
        zoom_access_token = config('ZOOM_ACCESS_TOKEN')  # Add to .env; implement OAuth in production
        zoom_details = create_zoom_meeting(zoom_access_token)
    except Exception as e:
        audit = AuditLog(
            type='onboarding_welcome',
            user_id=user_id,
            success=False,
            reason=f'Failed to create Zoom meeting: {str(e)}',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.error(f"Zoom meeting creation failed for user_id {user_id}: {str(e)}")
        return jsonify({"message": "Failed to create Zoom meeting"}), 500

    audit = AuditLog(
        type='onboarding_welcome',
        user_id=user_id,
        success=True,
        reason='Welcome data fetched successfully',
        ip_address=ip
    )
    db.session.add(audit)
    db.session.commit()
    logger.info(f"Welcome data fetched for {user.username} from IP {ip}")

    return jsonify({
        'message': welcome_data['message'],
        'video_url': welcome_data['video_url'],
        'zoom': zoom_details
    }), 200

def scan_for_malware(file_path):
    try:
        result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
        if 'Infected files: 0' not in result.stdout:
            raise Exception('Malware detected')
        return True
    except Exception as e:
        logger.error(f"Malware scan failed: {str(e)}")
        raise e

@routes.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    ip = request.remote_addr
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        audit = AuditLog(
            type='file_upload',
            user_id=user_id,
            success=False,
            reason='Unauthorized or inactive user',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed file upload for user_id {user_id} from IP {ip}: unauthorized")
        return jsonify({"message": "Unauthorized or account not active"}), 403

    if 'file' not in request.files:
        audit = AuditLog(type='file_upload', user_id=user_id, success=False, reason='No file provided', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed file upload for {user.username} from IP {ip}: no file")
        return jsonify({"message": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        audit = AuditLog(type='file_upload', user_id=user_id, success=False, reason='No file selected', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed file upload for {user.username} from IP {ip}: no file selected")
        return jsonify({"message": "No file selected"}), 400

    # Validate size and type
    file_content = file.read()
    if len(file_content) > 10 * 1024 * 1024:  # <10MB
        audit = AuditLog(type='file_upload', user_id=user_id, success=False, reason='File too large', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed file upload for {user.username} from IP {ip}: file too large")
        return jsonify({"message": "File must be less than 10MB"}), 400

    file.seek(0)  # Reset stream
    file_type = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    if file_type not in ['application/pdf', 'image/png']:
        audit = AuditLog(type='file_upload', user_id=user_id, success=False, reason='Invalid file type', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed file upload for {user.username} from IP {ip}: invalid file type {file_type}")
        return jsonify({"message": "Only PDF and PNG files are allowed"}), 400

    # Save file temporarily for scanning
    temp_path = f'/tmp/{secure_filename(file.filename)}'
    file.save(temp_path)
    try:
        scan_for_malware(temp_path)
    except Exception as e:
        audit = AuditLog(type='file_upload', user_id=user_id, success=False, reason=f'Malware scan failed: {str(e)}', ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.error(f"Malware scan failed for {user.username} from IP {ip}: {str(e)}")
        return jsonify({"message": "File failed malware scan"}), 400

    # Encrypt and store
    encrypted_content = db.session.execute(
        text("SELECT pgp_sym_encrypt(:content, :key)"),
        {'content': file_content, 'key': config('PGCRYPTO_KEY')}
    ).scalar()
    
    new_doc = Document(
        user_id=user_id,
        file_name=secure_filename(file.filename),
        file_type=file_type,
        encrypted_content=encrypted_content
    )
    db.session.add(new_doc)
    db.session.commit()

    # Clean up
    import os
    os.remove(temp_path)

    audit = AuditLog(
        type='file_upload',
        user_id=user_id,
        success=True,
        reason=f'File {file.filename} uploaded successfully',
        ip_address=ip
    )
    db.session.add(audit)
    db.session.commit()
    logger.info(f"File {file.filename} uploaded by {user.username} from IP {ip}")

    return jsonify({"message": "File uploaded successfully"}), 200

# DocuSign setup
def get_docusign_client():
    api_client = ApiClient()
    api_client.host = 'https://demo.docusign.net/restapi'  # Sandbox
    api_client.set_default_header('Authorization', f'Bearer {config("DOCUSIGN_ACCESS_TOKEN")}')
    return api_client

@routes.route('/policies', methods=['GET'])
@jwt_required()
def get_policies():
    ip = request.remote_addr
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        audit = AuditLog(
            type='policies_fetch',
            user_id=user_id,
            success=False,
            reason='Unauthorized or inactive user',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed to fetch policies for user_id {user_id} from IP {ip}: unauthorized")
        return jsonify({"message": "Unauthorized or account not active"}), 403

    policies = Policy.query.all()
    audit = AuditLog(
        type='policies_fetch',
        user_id=user_id,
        success=True,
        reason='Policies fetched successfully',
        ip_address=ip
    )
    db.session.add(audit)
    db.session.commit()
    logger.info(f"Policies fetched for {user.username} from IP {ip}")

    return jsonify([{
        'id': p.id,
        'title': p.title,
        'content': p.content,
        'version': p.version
    } for p in policies]), 200

@routes.route('/sign_policy', methods=['POST'])
@jwt_required()
def sign_policy():
    ip = request.remote_addr
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()
    policy_id = data.get('policy_id')
    
    if not user or not user.is_active:
        audit = AuditLog(
            type='policy_sign',
            user_id=user_id,
            success=False,
            reason='Unauthorized or inactive user',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed policy signing for user_id {user_id} from IP {ip}: unauthorized")
        return jsonify({"message": "Unauthorized or account not active"}), 403

    policy = Policy.query.get(policy_id)
    if not policy:
        audit = AuditLog(
            type='policy_sign',
            user_id=user_id,
            success=False,
            reason='Policy not found',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed policy signing for user_id {user_id} from IP {ip}: policy {policy_id} not found")
        return jsonify({"message": "Policy not found"}), 404

    # DocuSign envelope
    try:
        api_client = get_docusign_client()
        envelopes_api = EnvelopesApi(api_client)
        
        # Assume policy.content is base64-encoded PDF or generate PDF
        doc = Document(
            document_base64=policy.content.encode(),  # Adjust if content is text; use PDF generation if needed
            name=f'{policy.title}.pdf',
            file_extension='pdf',
            document_id='1'
        )
        signer = Signer(
            email=user.email,
            name=user.username,
            recipient_id='1',
            routing_order='1'
        )
        sign_here = SignHere(
            document_id='1',
            page_number='1',
            recipient_id='1',
            tab_label='SignHere',
            x_position='200',
            y_position='200'
        )
        tabs = Tabs(sign_here_tabs=[sign_here])
        signer.tabs = tabs
        recipients = Recipients(signers=[signer])
        envelope_definition = EnvelopeDefinition(
            email_subject=f'Please sign {policy.title}',
            documents=[doc],
            recipients=recipients,
            status='sent'
        )
        envelope_summary = envelopes_api.create_envelope(config('DOCUSIGN_ACCOUNT_ID'), envelope_definition=envelope_definition)
        
        # Store envelope ID for webhook/polling
        # For simplicity, assume signed PDF is returned via webhook; placeholder for encryption
        # In production, use webhook to capture signed_content
        signed_content = b'signed_pdf_bytes'  # Replace with actual signed content from webhook
        encrypted_signed = db.session.execute(
            text("SELECT pgp_sym_encrypt(:content, :key)"),
            {'content': signed_content, 'key': config('PGCRYPTO_KEY')}
        ).scalar()
        
        new_signed_policy = SignedPolicy(
            policy_id=policy_id,
            user_id=user_id,
            encrypted_signed_content=encrypted_signed
        )
        db.session.add(new_signed_policy)
        db.session.commit()

        audit = AuditLog(
            type='policy_sign',
            user_id=user_id,
            success=True,
            reason=f'Signed policy {policy.title} successfully',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.info(f"Policy {policy.title} signed by {user.username} from IP {ip}")

        return jsonify({"message": "Policy signing initiated", "envelope_id": envelope_summary.envelope_id}), 200
    except Exception as e:
        audit = AuditLog(
            type='policy_sign',
            user_id=user_id,
            success=False,
            reason=f'Failed to initiate signing: {str(e)}',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.error(f"Failed to sign policy {policy_id} for {user.username}: {str(e)}")
        return jsonify({"message": "Failed to initiate policy signing"}), 500

@routes.route('/get_signing_url', methods=['POST'])
@jwt_required()
def get_signing_url():
    ip = request.remote_addr
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()
    envelope_id = data.get('envelope_id')
    
    if not user or not user.is_active:
        audit = AuditLog(
            type='signing_url',
            user_id=user_id,
            success=False,
            reason='Unauthorized or inactive user',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Failed to fetch signing URL for user_id {user_id} from IP {ip}: unauthorized")
        return jsonify({"message": "Unauthorized or account not active"}), 403

    try:
        api_client = get_docusign_client()
        envelopes_api = EnvelopesApi(api_client)
        recipient_view = envelopes_api.create_recipient_view(
            config('DOCUSIGN_ACCOUNT_ID'),
            envelope_id,
            recipient_view_request={
                'user_name': user.username,
                'email': user.email,
                'recipient_id': '1',
                'return_url': config('BASE_URL') + '/dashboard'  # Redirect after signing
            }
        )
        audit = AuditLog(
            type='signing_url',
            user_id=user_id,
            success=True,
            reason='Signing URL generated',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.info(f"Signing URL generated for {user.username} from IP {ip}")
        return jsonify({"signing_url": recipient_view.url}), 200
    except Exception as e:
        audit = AuditLog(
            type='signing_url',
            user_id=user_id,
            success=False,
            reason=f'Failed to generate signing URL: {str(e)}',
            ip_address=ip
        )
        db.session.add(audit)
        db.session.commit()
        logger.error(f"Failed to generate signing URL for {user.username}: {str(e)}")
        return jsonify({"message": "Failed to generate signing URL"}), 500
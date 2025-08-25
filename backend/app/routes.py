from flask import Blueprint, request, jsonify
from .models import User, AuditLog, MFACode, SponsorApproval, Employee, HR, IT
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
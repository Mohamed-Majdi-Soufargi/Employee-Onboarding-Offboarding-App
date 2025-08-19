from flask import Blueprint, request, jsonify
from .models import User, LoginAudit, MFACode
from flask_jwt_extended import create_access_token
from datetime import datetime, timedelta, timezone
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from decouple import config
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define the Blueprint
routes = Blueprint("routes", __name__)

# Initialize db here to avoid circular import
from . import db

def generate_mfa_code(length=6):
    """Generate a random 6-digit MFA code."""
    return ''.join(random.choices(string.digits, k=length))

def send_mfa_email(email, code):
    """Send MFA code to the user's email with HTML and plain text versions."""
    smtp_server = config('SMTP_SERVER', default='smtp.gmail.com')
    smtp_port = config('SMTP_PORT', default=587, cast=int)
    smtp_username = config('SMTP_USERNAME')
    smtp_password = config('SMTP_PASSWORD')
    
    # Create a multipart email (HTML + plain text)
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Your MFA Verification Code'
    msg['From'] = smtp_username
    msg['To'] = email
    
    # Plain text version
    text = f"Your MFA code is: {code}\nThis code will expire in 5 minutes."
    part1 = MIMEText(text, 'plain')
    
    # HTML version
    html = f"""
    <html>
        <body>
            <h2>Your MFA Verification Code</h2>
            <p>Your verification code is: <strong>{code}</strong></p>
            <p>This code will expire in 5 minutes.</p>
            <p>If you did not request this code, please ignore this email.</p>
        </body>
    </html>
    """
    part2 = MIMEText(html, 'html')
    
    msg.attach(part1)
    msg.attach(part2)
    
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.set_debuglevel(1)  # Enable debug output for troubleshooting
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        logger.info(f"Email sent successfully to {email} with MFA code {code}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed for {smtp_username}: {e}")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error while sending email to {email}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email to {email}: {e}")
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
    logger.info(f"User {data['username']} registered successfully")
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
        logger.warning(f"Failed login attempt for username {data.get('username')} from IP {ip}")
        return jsonify({"message": "Invalid username or password"}), 401

    # Generate and store MFA code
    mfa_code = generate_mfa_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    mfa_entry = MFACode(user_id=user.id, code=mfa_code, expires_at=expires_at)
    db.session.add(mfa_entry)
    db.session.commit()

    # Send MFA code via email
    if not send_mfa_email(user.email, mfa_code):
        logger.error(f"Failed to send MFA code to {user.email} for user {user.username}")
        return jsonify({"message": "Failed to send MFA code"}), 500

    logger.info(f"MFA code sent to {user.email} for user {user.username}")
    return jsonify({"message": "MFA code sent to your email. Please verify."}), 200

@routes.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    username = data.get('username')
    mfa_code = data.get('mfa_code')
    ip = request.remote_addr

    user = User.query.filter_by(username=username).first()
    if not user:
        logger.warning(f"MFA verification attempt for non-existent username {username} from IP {ip}")
        return jsonify({"message": "User not found"}), 404

    # Find the latest unexpired MFA code
    mfa_entry = MFACode.query.filter_by(user_id=user.id, code=mfa_code).filter(
        MFACode.expires_at > datetime.now(timezone.utc)
    ).first()

    if not mfa_entry:
        audit = LoginAudit(user_id=user.id, success=False, ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        logger.warning(f"Invalid or expired MFA code for user {username} from IP {ip}")
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

    logger.info(f"Successful MFA verification for user {username} from IP {ip}")
    return jsonify({"access_token": access_token}), 200
from flask import request, jsonify
from .app import app, db
from .models import User, LoginAudit
from flask_jwt_extended import create_access_token
from datetime import datetime
import pyotp  # for MFA codes

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists"}), 400

    user = User(
        username=data['username'],
        email=data['email']
    )
    user.set_password(data['password'])
    # Optional: Generate MFA secret for user
    user.mfa_secret = pyotp.random_base32()
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    ip = request.remote_addr

    if not user or not user.check_password(data['password']):
        # log failed attempt
        audit = LoginAudit(user_id=user.id if user else None, success=False, ip_address=ip)
        db.session.add(audit)
        db.session.commit()
        return jsonify({"message": "Invalid username or password"}), 401

    # Optional: Check MFA if provided
    if user.mfa_secret:
        mfa_code = data.get('mfa_code')
        if not mfa_code or not pyotp.TOTP(user.mfa_secret).verify(mfa_code):
            audit = LoginAudit(user_id=user.id, success=False, ip_address=ip)
            db.session.add(audit)
            db.session.commit()
            return jsonify({"message": "MFA verification failed"}), 401

    # Successful login
    access_token = create_access_token(identity=user.id)
    user.last_login = datetime.utcnow()
    user.failed_attempts = 0
    db.session.commit()

    audit = LoginAudit(user_id=user.id, success=True, ip_address=ip)
    db.session.add(audit)
    db.session.commit()

    return jsonify({"access_token": access_token})

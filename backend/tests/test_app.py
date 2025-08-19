import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  # Add backend/ to path
import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash
from datetime import timedelta, datetime
from datetime import timezone
import random
import string

# Create the test app factory
def create_test_app():
    test_app = Flask(__name__)
    test_app.config['TESTING'] = True
    test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    test_app.config['JWT_SECRET_KEY'] = 'test-jwt-secret-key'
    test_app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
    test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    test_app.config['SECRET_KEY'] = 'test-secret-key'
    
    # Initialize extensions
    db = SQLAlchemy()
    db.init_app(test_app)
    jwt = JWTManager(test_app)
    
    # Define models within the test context to ensure they use the test db
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        mfa_secret = db.Column(db.String(32), nullable=True)
        last_login = db.Column(db.DateTime, nullable=True)
        failed_attempts = db.Column(db.Integer, default=0)
        
        def set_password(self, password):
            self.password_hash = generate_password_hash(password)
        
        def check_password(self, password):
            from werkzeug.security import check_password_hash
            return check_password_hash(self.password_hash, password)
    
    class LoginAudit(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Aligned with production
        timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
        ip_address = db.Column(db.String(45))
        success = db.Column(db.Boolean, nullable=False)
    
    class MFACode(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        code = db.Column(db.String(6), nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
    
    # Store models in app for access
    test_app.User = User
    test_app.LoginAudit = LoginAudit
    test_app.MFACode = MFACode
    test_app.db = db
    
    def generate_mfa_code(length=6):
        return ''.join(random.choices(string.digits, k=length))
    
    def send_mfa_email(email, code):
        return True  # Mock email sending for tests
    
    # Register routes
    @test_app.route('/register', methods=['POST'])
    def register():
        from flask import request, jsonify
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
    
    @test_app.route('/login', methods=['POST'])
    def login():
        from flask import request, jsonify
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        ip = request.remote_addr
        
        if not user or not user.check_password(data['password']):
            audit = LoginAudit(user_id=user.id if user else None, success=False, ip_address=ip)
            db.session.add(audit)
            db.session.commit()
            return jsonify({"message": "Invalid username or password"}), 401
        
        mfa_code = generate_mfa_code()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        mfa_entry = MFACode(user_id=user.id, code=mfa_code, expires_at=expires_at)
        db.session.add(mfa_entry)
        db.session.commit()
        
        if not send_mfa_email(user.email, mfa_code):
            return jsonify({"message": "Failed to send MFA code"}), 500
        
        return jsonify({"message": "MFA code sent to your email. Please verify."}), 200
    
    @test_app.route('/verify_mfa', methods=['POST'])
    def verify_mfa():
        from flask import request, jsonify
        from flask_jwt_extended import create_access_token
        data = request.get_json()
        username = data.get('username')
        mfa_code = data.get('mfa_code')
        ip = request.remote_addr
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        mfa_entry = MFACode.query.filter_by(user_id=user.id, code=mfa_code).filter(
            MFACode.expires_at > datetime.now(timezone.utc)
        ).first()
        
        if not mfa_entry:
            audit = LoginAudit(user_id=user.id, success=False, ip_address=ip)
            db.session.add(audit)
            db.session.commit()
            return jsonify({"message": "Invalid or expired MFA code"}), 401
        
        access_token = create_access_token(identity=user.id)
        user.last_login = datetime.now(timezone.utc)
        user.failed_attempts = 0
        audit = LoginAudit(user_id=user.id, success=True, ip_address=ip)
        db.session.add(audit)
        db.session.delete(mfa_entry)
        db.session.commit()
        
        return jsonify({"access_token": access_token}), 200
    
    return test_app

@pytest.fixture
def app():
    app = create_test_app()
    with app.app_context():
        app.db.create_all()
        yield app
        app.db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def test_user(app):
    with app.app_context():
        user = app.User(
            username="testuser",
            email="test@example.com",
            password_hash=generate_password_hash("testpassword")
        )
        app.db.session.add(user)
        app.db.session.commit()
        user_id = user.id
    return user_id  # Return user_id instead of the User object

# Test User model password hashing and checking
def test_user_password(app):
    with app.app_context():
        user = app.User(username="testuser", email="test@example.com")
        user.set_password("testpassword")
        assert user.check_password("testpassword") is True
        assert user.check_password("wrongpassword") is False

# Test user registration
def test_register(client, app):
    response = client.post('/register', json={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'newpassword'
    })
    assert response.status_code == 201
    assert response.json == {"message": "User registered successfully"}
    
    with app.app_context():
        user = app.User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'newuser@example.com'

# Test duplicate username registration
def test_register_duplicate_username(client, test_user, app):
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'different@example.com',
        'password': 'testpassword'
    })
    assert response.status_code == 400
    assert response.json == {"message": "Username already exists"}

# Test login with valid credentials
def test_login_valid(client, test_user, app):
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    assert response.json == {"message": "MFA code sent to your email. Please verify."}
    
    with app.app_context():
        mfa_entry = app.MFACode.query.filter_by(user_id=test_user).first()
        assert mfa_entry is not None
        assert len(mfa_entry.code) == 6

# Test login with invalid password
def test_login_invalid_password(client, test_user, app):
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert response.json == {"message": "Invalid username or password"}
    
    with app.app_context():
        audit = app.LoginAudit.query.filter_by(user_id=test_user, success=False).first()
        assert audit is not None

# Test MFA verification with valid code
def test_verify_mfa_valid(client, test_user, app):
    with app.app_context():
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=test_user,
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
    
    with app.app_context():
        audit = app.LoginAudit.query.filter_by(user_id=test_user, success=True).first()
        assert audit is not None
        mfa_entry = app.MFACode.query.filter_by(user_id=test_user, code=mfa_code).first()
        assert mfa_entry is None  # Code should be deleted after use

# Test MFA verification with invalid code
def test_verify_mfa_invalid(client, test_user, app):
    with app.app_context():
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=test_user,
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
    
    with app.app_context():
        audit = app.LoginAudit.query.filter_by(user_id=test_user, success=False).first()
        assert audit is not None

# Test MFA verification with expired code
def test_verify_mfa_expired(client, test_user, app):
    with app.app_context():
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=test_user,
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)  # Expired
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
    response = client.post('/verify_mfa', json={
        'username': 'testuser',
        'mfa_code': mfa_code
    })
    assert response.status_code == 401
    assert response.json == {"message": "Invalid or expired MFA code"}
    
    with app.app_context():
        audit = app.LoginAudit.query.filter_by(user_id=test_user, success=False).first()
        assert audit is not None
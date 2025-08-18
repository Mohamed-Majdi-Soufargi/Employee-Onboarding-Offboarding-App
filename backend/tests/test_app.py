import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  # Add backend/ to path
import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash
from datetime import timedelta, datetime
import pyotp

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
        mfa_secret = db.Column(db.String(32), nullable=False)
        last_login = db.Column(db.DateTime, nullable=True)
        failed_attempts = db.Column(db.Integer, default=0)
        
        def set_password(self, password):
            self.password_hash = generate_password_hash(password)
        
        def check_password(self, password):
            from werkzeug.security import check_password_hash
            return check_password_hash(self.password_hash, password)
    
    class LoginAudit(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)
        ip_address = db.Column(db.String(45))
        success = db.Column(db.Boolean, nullable=False)
    
    # Store models in app for access
    test_app.User = User
    test_app.LoginAudit = LoginAudit
    test_app.db = db
    
    # Register routes
    @test_app.route('/register', methods=['POST'])
    def register():
        from flask import request, jsonify
        data = request.get_json()
        
        # Check if username already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({"message": "Username already exists"}), 400
        
        # Create new user
        user = User(
            username=data['username'],
            email=data['email'],
            mfa_secret=pyotp.random_base32()
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({"message": "User registered successfully"}), 201
    
    @test_app.route('/login', methods=['POST'])
    def login():
        from flask import request, jsonify
        from flask_jwt_extended import create_access_token
        
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        mfa_code = data.get('mfa_code')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            if user:
                audit = LoginAudit(user_id=user.id, success=False)
                db.session.add(audit)
                db.session.commit()
            return jsonify({"message": "Invalid username or password"}), 401
        
        # Verify MFA
        if not mfa_code:
            return jsonify({"message": "MFA verification failed"}), 401
        
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(mfa_code):
            audit = LoginAudit(user_id=user.id, success=False)
            db.session.add(audit)
            db.session.commit()
            return jsonify({"message": "MFA verification failed"}), 401
        
        # Successful login
        user.last_login = datetime.utcnow()
        user.failed_attempts = 0
        audit = LoginAudit(user_id=user.id, success=True)
        db.session.add(audit)
        db.session.commit()
        
        access_token = create_access_token(identity=user.id)
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
    user = app.User(
        username="testuser",
        email="test@example.com",
        password_hash=generate_password_hash("testpassword"),
        mfa_secret=pyotp.random_base32()
    )
    return user

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
    
    # Verify user in database
    with app.app_context():
        user = app.User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'newuser@example.com'
        assert user.mfa_secret is not None

# Test duplicate username registration
def test_register_duplicate_username(client, test_user, app):
    with app.app_context():
        app.db.session.add(test_user)
        app.db.session.commit()
    
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'different@example.com',
        'password': 'testpassword'
    })
    assert response.status_code == 400
    assert response.json == {"message": "Username already exists"}

# Test login with valid credentials
def test_login_valid(client, test_user, app, mocker):
    with app.app_context():
        app.db.session.add(test_user)
        app.db.session.commit()
        user_id = test_user.id  # Get the ID while in app context
    
    # Mock pyotp.TOTP.verify to simulate valid MFA
    mocker.patch('pyotp.TOTP.verify', return_value=True)
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword',
        'mfa_code': '123456'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json
    
    # Verify login audit
    with app.app_context():
        audit = app.LoginAudit.query.filter_by(user_id=user_id, success=True).first()
        assert audit is not None

# Test login with invalid password
def test_login_invalid_password(client, test_user, app):
    with app.app_context():
        app.db.session.add(test_user)
        app.db.session.commit()
        user_id = test_user.id  # Get the ID while in app context
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'wrongpassword',
        'mfa_code': '123456'
    })
    assert response.status_code == 401
    assert response.json == {"message": "Invalid username or password"}
    
    # Verify login audit
    with app.app_context():
        audit = app.LoginAudit.query.filter_by(user_id=user_id, success=False).first()
        assert audit is not None

# Test login with invalid MFA code
def test_login_invalid_mfa(client, test_user, app, mocker):
    with app.app_context():
        app.db.session.add(test_user)
        app.db.session.commit()
        user_id = test_user.id  # Get the ID while in app context
    
    # Mock pyotp.TOTP.verify to simulate invalid MFA
    mocker.patch('pyotp.TOTP.verify', return_value=False)
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword',
        'mfa_code': 'invalidcode'
    })
    assert response.status_code == 401
    assert response.json == {"message": "MFA verification failed"}

# Test login without MFA code when MFA is enabled
def test_login_missing_mfa(client, test_user, app):
    with app.app_context():
        app.db.session.add(test_user)
        app.db.session.commit()
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 401
    assert response.json == {"message": "MFA verification failed"}
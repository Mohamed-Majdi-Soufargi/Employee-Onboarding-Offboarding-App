import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  # Add backend/ to path
import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from app.models import User, LoginAudit
import pyotp
from werkzeug.security import generate_password_hash
from datetime import timedelta

# Create a separate test database instance
test_db = SQLAlchemy()

# Fixture to set up the Flask test client and temporary database
@pytest.fixture
def client():
    # Create a new Flask app instance for testing
    test_app = Flask(__name__)
    test_app.config['TESTING'] = True
    test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory database for tests
    test_app.config['JWT_SECRET_KEY'] = 'test-jwt-secret-key'
    test_app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
    test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    test_app.config['SECRET_KEY'] = 'test-secret-key'
    
    # Initialize extensions with the test app
    test_db.init_app(test_app)
    jwt = JWTManager(test_app)
    
    # Import routes to register them
    with test_app.app_context():
        from app import routes  # Import the routes module to register routes
        # Create all tables
        test_db.create_all()
        
        # Yield the test client
        yield test_app.test_client()
        
        # Clean up after tests
        test_db.drop_all()

# Fixture to create a test user
@pytest.fixture
def test_user():
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=generate_password_hash("testpassword"),
        mfa_secret=pyotp.random_base32()
    )
    return user

# Helper fixture to get current app and db
@pytest.fixture
def app_and_db(client):
    from flask import current_app
    return current_app, test_db

# Test User model password hashing and checking
def test_user_password():
    user = User(username="testuser", email="test@example.com")
    user.set_password("testpassword")
    assert user.check_password("testpassword") is True
    assert user.check_password("wrongpassword") is False

# Test user registration
def test_register(client, app_and_db):
    app, db = app_and_db
    response = client.post('/register', json={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'newpassword'
    })
    assert response.status_code == 201
    assert response.json == {"message": "User registered successfully"}
    
    # Verify user in database
    with app.app_context():
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'newuser@example.com'
        assert user.mfa_secret is not None

# Test duplicate username registration
def test_register_duplicate_username(client, test_user, app_and_db):
    app, db = app_and_db
    with app.app_context():
        db.session.add(test_user)
        db.session.commit()
    
    response = client.post('/register', json={
        'username': 'testuser',
        'email': 'different@example.com',
        'password': 'testpassword'
    })
    assert response.status_code == 400
    assert response.json == {"message": "Username already exists"}

# Test login with valid credentials
def test_login_valid(client, test_user, app_and_db, mocker):
    app, db = app_and_db
    with app.app_context():
        db.session.add(test_user)
        db.session.commit()
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
        audit = LoginAudit.query.filter_by(user_id=user_id, success=True).first()
        assert audit is not None

# Test login with invalid password
def test_login_invalid_password(client, test_user, app_and_db):
    app, db = app_and_db
    with app.app_context():
        db.session.add(test_user)
        db.session.commit()
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
        audit = LoginAudit.query.filter_by(user_id=user_id, success=False).first()
        assert audit is not None

# Test login with invalid MFA code
def test_login_invalid_mfa(client, test_user, app_and_db, mocker):
    app, db = app_and_db
    with app.app_context():
        db.session.add(test_user)
        db.session.commit()
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
def test_login_missing_mfa(client, test_user, app_and_db):
    app, db = app_and_db
    with app.app_context():
        db.session.add(test_user)
        db.session.commit()
    
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 401
    assert response.json == {"message": "MFA verification failed"}
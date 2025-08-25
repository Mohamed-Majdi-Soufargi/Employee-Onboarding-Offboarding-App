import pytest
from .test_app import app, client, test_user

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
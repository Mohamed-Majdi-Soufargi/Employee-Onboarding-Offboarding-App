import pytest
from .test_app import app, client, test_user

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
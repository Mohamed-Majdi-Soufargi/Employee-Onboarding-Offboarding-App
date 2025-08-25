import pytest
from datetime import datetime, timedelta, timezone
from .test_app import app, client

# Test MFA verification with valid code
def test_verify_mfa_valid(client, app):
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
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=user_id,
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
        assert response.json['role'] == 'employee'
        
        user = app.db.session.get(app.User, user_id)
        assert user.last_login is not None
        assert user.failed_attempts == 0
        audit = app.AuditLog.query.filter_by(type='mfa', success=True, reason='Login successful').first()
        assert audit is not None
        mfa_entry = app.MFACode.query.filter_by(user_id=user_id, code=mfa_code).first()
        assert mfa_entry is None
        app.db.drop_all()

# Test MFA verification with invalid code
def test_verify_mfa_invalid(client, app):
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
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=user_id,
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
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Invalid or expired MFA code').first()
        assert audit is not None
        app.db.drop_all()

# Test MFA verification with expired code
def test_verify_mfa_expired(client, app):
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
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            user_id=user_id,
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_mfa', json={
            'username': 'testuser',
            'mfa_code': mfa_code
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid or expired MFA code"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Invalid or expired MFA code').first()
        assert audit is not None
        app.db.drop_all()

# Test MFA verification with inactive account
def test_verify_mfa_inactive_account(client, app):
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
    
        response = client.post('/verify_mfa', json={
            'username': 'testuser',
            'mfa_code': '123456'
        })
        assert response.status_code == 403
        assert response.json == {"message": "Account not active"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Account not active').first()
        assert audit is not None
        app.db.drop_all()
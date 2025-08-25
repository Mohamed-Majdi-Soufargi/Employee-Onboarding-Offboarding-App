import pytest
from datetime import datetime, timedelta, timezone
from .test_app import app, client

# Test registration MFA verification
def test_verify_registration_mfa_valid(client, app):
    with app.app_context():
        app.db.create_all()
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            email="newuser@example.com",
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_registration_mfa', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee',
            'mfa_code': mfa_code
        })
        assert response.status_code == 200
        assert response.json == {"message": "Sponsor approval request sent. Awaiting approval."}
        
        user = app.User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.is_active is False
        assert user.type == 'employee'
        assert user.sponsor_email == 'sponsor@example.com'
        assert user.approval_token is not None
        audit = app.AuditLog.query.filter_by(type='mfa', success=True, reason='Pending user created, sponsor approval requested').first()
        assert audit is not None
        mfa_entry = app.MFACode.query.filter_by(email='newuser@example.com', code=mfa_code).first()
        assert mfa_entry is None
        app.db.drop_all()

# Test registration MFA with invalid code
def test_verify_registration_mfa_invalid(client, app):
    with app.app_context():
        app.db.create_all()
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            email="newuser@example.com",
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_registration_mfa', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee',
            'mfa_code': 'wrongcode'
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid or expired MFA code"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Invalid or expired MFA code').first()
        assert audit is not None
        app.db.drop_all()

# Test registration MFA with expired code
def test_verify_registration_mfa_expired(client, app):
    with app.app_context():
        app.db.create_all()
        mfa_code = "123456"
        mfa_entry = app.MFACode(
            email="newuser@example.com",
            code=mfa_code,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        app.db.session.add(mfa_entry)
        app.db.session.commit()
    
        response = client.post('/verify_registration_mfa', json={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Test123!',
            'sponsor_email': 'sponsor@example.com',
            'role': 'employee',
            'mfa_code': mfa_code
        })
        assert response.status_code == 401
        assert response.json == {"message": "Invalid or expired MFA code"}
        
        audit = app.AuditLog.query.filter_by(type='mfa', success=False, reason='Invalid or expired MFA code').first()
        assert audit is not None
        app.db.drop_all()
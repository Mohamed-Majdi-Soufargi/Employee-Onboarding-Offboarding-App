import pytest
import uuid
from .test_app import app, client

# Test sponsor approval
def test_sponsor_approve_valid(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="newuser",
            email="newuser@example.com",
            sponsor_email="sponsor@example.com",
            approval_token=str(uuid.uuid4()),
            is_active=False
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        token = user.approval_token
    
        response = client.post('/sponsor_approve', json={
            'token': token,
            'approve': True
        })
        assert response.status_code == 201
        assert response.json == {"message": "User activated successfully"}
        
        user = app.User.query.filter_by(username='newuser').first()
        assert user.is_active is True
        assert user.approval_token is None
        sponsor_approval = app.SponsorApproval.query.filter_by(user_id=user.id, approved=True).first()
        assert sponsor_approval is not None
        audit = app.AuditLog.query.filter_by(type='sponsor', success=True, reason='Sponsor approved').first()
        assert audit is not None
        app.db.drop_all()

# Test sponsor rejection
def test_sponsor_reject_valid(client, app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(
            username="newuser",
            email="newuser@example.com",
            sponsor_email="sponsor@example.com",
            approval_token=str(uuid.uuid4()),
            is_active=False
        )
        user.set_password("Test123!")
        app.db.session.add(user)
        app.db.session.commit()
        token = user.approval_token
    
        response = client.post('/sponsor_approve', json={
            'token': token,
            'approve': False
        })
        assert response.status_code == 200
        assert response.json == {"message": "Registration request rejected by sponsor"}
        
        user = app.User.query.filter_by(username='newuser').first()
        assert user is None
        sponsor_approval = app.SponsorApproval.query.filter_by(approved=False).first()
        assert sponsor_approval is not None
        audit = app.AuditLog.query.filter_by(type='sponsor', success=False, reason='Sponsor rejected request').first()
        assert audit is not None
        app.db.drop_all()

# Test sponsor approval with invalid token
def test_sponsor_approve_invalid_token(client, app):
    with app.app_context():
        app.db.create_all()
        response = client.post('/sponsor_approve', json={
            'token': str(uuid.uuid4()),
            'approve': True
        })
        assert response.status_code == 404
        assert response.json == {"message": "Invalid or expired token"}
        
        audit = app.AuditLog.query.filter_by(type='sponsor', success=False, reason='Invalid or expired token').first()
        assert audit is not None
        app.db.drop_all()
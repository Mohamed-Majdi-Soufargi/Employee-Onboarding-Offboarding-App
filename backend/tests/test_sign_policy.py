import pytest
from flask_jwt_extended import create_access_token
from .test_app import app, client
import logging
import base64
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def test_sign_policy(client, app):
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
        token = create_access_token(identity=str(user_id))

        # Test with non-existent policy
        logger.debug("Testing /sign_policy with non-existent policy")
        response = client.post('/sign_policy', headers={'Authorization': f'Bearer {token}'}, json={'policy_id': 1})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}. Response: {response.get_data(as_text=True)}"
        assert response.json == {"message": "Policy not found"}
        audit = app.AuditLog.query.filter_by(type='policy_sign', success=False, reason='Policy not found').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Add a policy
        policy = app.Policy(
            title="Test Policy",
            content=base64.b64encode(b'%PDF-1.4 dummy content').decode('utf-8'),
            version="1.0",
            timestamp=datetime.now(timezone.utc)
        )
        app.db.session.add(policy)
        app.db.session.commit()
        policy_id = policy.id

        # Test successful policy signing
        logger.debug("Testing /sign_policy with valid policy")
        response = client.post('/sign_policy', headers={'Authorization': f'Bearer {token}'}, json={'policy_id': policy_id})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_data(as_text=True)}"
        assert response.json['message'] == "Policy signing initiated"
        assert 'envelope_id' in response.json
        signed_policy = app.SignedPolicy.query.filter_by(user_id=user_id, policy_id=policy_id).first()
        assert signed_policy is not None
        audit = app.AuditLog.query.filter_by(type='policy_sign', success=True, reason=f'Signed policy {policy.title} successfully').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Test with inactive user
        user.is_active = False
        app.db.session.commit()
        logger.debug("Testing /sign_policy with inactive user")
        response = client.post('/sign_policy', headers={'Authorization': f'Bearer {token}'}, json={'policy_id': policy_id})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 403
        assert response.json == {"message": "Unauthorized or account not active"}
        audit = app.AuditLog.query.filter_by(type='policy_sign', success=False, reason='Unauthorized or account not active').first()
        assert audit is not None
        assert audit.user_id == user_id

        app.db.drop_all()
import pytest
from flask_jwt_extended import create_access_token
from .test_app import app, client
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def test_get_policies(client, app):
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

        # Test with no policies
        logger.debug("Testing /policies with no policies")
        response = client.get('/policies', headers={'Authorization': f'Bearer {token}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_data(as_text=True)}"
        assert response.json == []
        audit = app.AuditLog.query.filter_by(type='policies_fetch', success=True, reason='Policies fetched successfully').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Add a policy
        policy = app.Policy(
            title="Test Policy",
            content="This is a test policy.",
            version="1.0",
            timestamp=datetime.now(timezone.utc)
        )
        app.db.session.add(policy)
        app.db.session.commit()

        # Test successful retrieval
        logger.debug("Testing /policies with one policy")
        response = client.get('/policies', headers={'Authorization': f'Bearer {token}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_data(as_text=True)}"
        assert len(response.json) == 1
        assert response.json[0]['title'] == "Test Policy"
        assert response.json[0]['content'] == "This is a test policy."
        assert response.json[0]['version'] == "1.0"
        audit = app.AuditLog.query.filter_by(type='policies_fetch', success=True, reason='Policies fetched successfully').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Test with inactive user
        user.is_active = False
        app.db.session.commit()
        logger.debug("Testing /policies with inactive user")
        response = client.get('/policies', headers={'Authorization': f'Bearer {token}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 403
        assert response.json == {"message": "Unauthorized or account not active"}
        audit = app.AuditLog.query.filter_by(type='policies_fetch', success=False, reason='Unauthorized or account not active').first()
        assert audit is not None
        assert audit.user_id == user_id

        app.db.drop_all()
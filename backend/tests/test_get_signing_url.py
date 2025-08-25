import pytest
from flask_jwt_extended import create_access_token
from .test_app import app, client
import logging

logger = logging.getLogger(__name__)

def test_get_signing_url(client, app):
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

        # Test successful signing URL generation
        logger.debug("Testing /get_signing_url with valid token")
        response = client.post('/get_signing_url', headers={'Authorization': f'Bearer {token}'}, json={'envelope_id': 'test-envelope-id'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_data(as_text=True)}"
        assert response.json == {"signing_url": "https://demo.docusign.net/restapi"}
        audit = app.AuditLog.query.filter_by(type='signing_url', success=True, reason='Signing URL generated').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Test with inactive user
        user.is_active = False
        app.db.session.commit()
        logger.debug("Testing /get_signing_url with inactive user")
        response = client.post('/get_signing_url', headers={'Authorization': f'Bearer {token}'}, json={'envelope_id': 'test-envelope-id'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 403
        assert response.json == {"message": "Unauthorized or account not active"}
        audit = app.AuditLog.query.filter_by(type='signing_url', success=False, reason='Unauthorized or account not active').first()
        assert audit is not None
        assert audit.user_id == user_id

        app.db.drop_all()
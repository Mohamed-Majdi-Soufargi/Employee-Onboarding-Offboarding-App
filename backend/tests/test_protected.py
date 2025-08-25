import pytest
from flask_jwt_extended import create_access_token
from .test_app import app, client
import logging

logger = logging.getLogger(__name__)

def test_protected(client, app):
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

        # Test successful access
        logger.debug("Testing /protected with valid token")
        response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_data(as_text=True)}"
        assert response.json == {
            "message": f"Welcome {user.username}",
            "role": user.type
        }
        audit = app.AuditLog.query.filter_by(type='protected_access', success=True, reason='Protected route accessed').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Test with inactive user
        user.is_active = False
        app.db.session.commit()
        logger.debug("Testing /protected with inactive user")
        response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 403
        assert response.json == {"message": "Unauthorized or account not active"}
        audit = app.AuditLog.query.filter_by(type='protected_access', success=False, reason='Unauthorized or account not active').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Test with invalid token
        logger.debug("Testing /protected with invalid token")
        response = client.get('/protected', headers={'Authorization': 'Bearer invalidtoken'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 422
        assert response.json.get('msg') == 'Not enough segments'

        # Test with non-existent user
        token_nonexistent = create_access_token(identity=str(9999))
        logger.debug("Testing /protected with non-existent user")
        response = client.get('/protected', headers={'Authorization': f'Bearer {token_nonexistent}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 404
        assert response.json == {"message": "User not found"}
        audit = app.AuditLog.query.filter_by(type='protected_access', success=False, reason='User not found').first()
        assert audit is not None
        assert audit.user_id is None

        app.db.drop_all()
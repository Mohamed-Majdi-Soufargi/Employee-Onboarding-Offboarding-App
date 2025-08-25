import pytest
from flask_jwt_extended import create_access_token
from .test_app import app, client
import logging

logger = logging.getLogger(__name__)

def test_get_welcome(client, app):
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

        # Test with no welcome content
        logger.debug("Testing /onboarding/welcome with no content")
        response = client.get('/onboarding/welcome', headers={'Authorization': f'Bearer {token}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}. Response: {response.get_data(as_text=True)}"
        assert response.json == {"message": "No welcome content available"}
        audit = app.AuditLog.query.filter_by(type='onboarding_welcome', success=False, reason='No welcome content found').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Add welcome content
        welcome_content = app.WelcomeContent(
            message="Welcome to the team!",
            encrypted_video_url=app.pgp_sym_encrypt("https://example.com/video", app.config['PGCRYPTO_KEY'])
        )
        app.db.session.add(welcome_content)
        app.db.session.commit()

        # Test successful retrieval
        logger.debug("Testing /onboarding/welcome with content")
        response = client.get('/onboarding/welcome', headers={'Authorization': f'Bearer {token}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_data(as_text=True)}"
        assert response.json['message'] == "Welcome to the team!"
        assert response.json['video_url'] == "https://example.com/video"
        assert response.json['zoom']['join_url'].startswith('https://zoom.us/j/')
        audit = app.AuditLog.query.filter_by(type='onboarding_welcome', success=True, reason='Welcome data fetched successfully').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Test with inactive user
        user.is_active = False
        app.db.session.commit()
        logger.debug("Testing /onboarding/welcome with inactive user")
        response = client.get('/onboarding/welcome', headers={'Authorization': f'Bearer {token}'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 403
        assert response.json == {"message": "Unauthorized or account not active"}
        audit = app.AuditLog.query.filter_by(type='onboarding_welcome', success=False, reason='Unauthorized or account not active').first()
        assert audit is not None
        assert audit.user_id == user_id

        # Test with invalid token
        logger.debug("Testing /onboarding/welcome with invalid token")
        response = client.get('/onboarding/welcome', headers={'Authorization': 'Bearer invalidtoken'})
        logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
        assert response.status_code == 422
        assert response.json.get('msg') == 'Not enough segments'

        app.db.drop_all()
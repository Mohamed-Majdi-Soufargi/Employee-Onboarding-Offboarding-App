import pytest
from datetime import datetime, timedelta, timezone
from flask_jwt_extended import create_access_token
from freezegun import freeze_time
from .test_app import app, client

# Test JWT token expiration
def test_jwt_token_expiration(app):
    with app.app_context():
        token = create_access_token(identity=str(1))
        assert app.config['JWT_ACCESS_TOKEN_EXPIRES'] == timedelta(minutes=30)

# Test JWT token expiration with protected route
def test_jwt_token_expiration_full(client, app):
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
    
        response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        assert response.json == {"message": "Welcome testuser", "role": "employee"}
    
        with freeze_time(datetime.now(timezone.utc) + timedelta(minutes=31)):
            response = client.get('/protected', headers={'Authorization': f'Bearer {token}'})
            assert response.status_code == 401
            assert response.json.get('msg') == 'Token has expired'
        app.db.drop_all()
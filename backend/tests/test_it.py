import pytest
from flask_jwt_extended import create_access_token
from .test_app import app, client

# Test IT config route access
def test_it_config_access(client, app):
    with app.app_context():
        app.db.create_all()
        it_user = app.IT(
            username="ituser",
            email="it@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        it_user.set_password("Test123!")
        emp_user = app.Employee(
            username="empuser",
            email="emp@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        emp_user.set_password("Test123!")
        app.db.session.add_all([it_user, emp_user])
        app.db.session.commit()
        it_token = create_access_token(identity=str(it_user.id))
        emp_token = create_access_token(identity=str(emp_user.id))
    
        response = client.get('/it/config', headers={'Authorization': f'Bearer {it_token}'})
        assert response.status_code == 200
        assert response.json['message'] == "System configuration retrieved"
        assert response.json['config']['system_version'] == "1.0.0"
        audit = app.AuditLog.query.filter_by(type='it_access', success=True, reason='Viewed system config').first()
        assert audit is not None
    
        response = client.get('/it/config', headers={'Authorization': f'Bearer {emp_token}'})
        assert response.status_code == 403
        assert response.json == {"message": "IT access required"}
        audit = app.AuditLog.query.filter_by(type='it_access', success=False, reason='IT access required').first()
        assert audit is not None
        app.db.drop_all()
import pytest
from .test_app import app, create_test_app

# Test User model password hashing and checking
def test_user_password(app):
    with app.app_context():
        app.db.create_all()
        user = app.Employee(username="testuser2", email="test2@example.com", sponsor_email="sponsor2@example.com")
        user.set_password("Test123!")
        assert user.check_password("Test123!") is True
        assert user.check_password("wrongpassword") is False
        app.db.drop_all()

# Test user inheritance
def test_user_inheritance(app):
    with app.app_context():
        app.db.create_all()
        employee = app.Employee(username="emp1", email="emp1@example.com", sponsor_email="sponsor@example.com")
        hr = app.HR(username="hr1", email="hr1@example.com", sponsor_email="sponsor@example.com")
        it = app.IT(username="it1", email="it1@example.com", sponsor_email="sponsor@example.com")
        employee.set_password("Test123!")
        hr.set_password("Test123!")
        it.set_password("Test123!")
        app.db.session.add_all([employee, hr, it])
        app.db.session.commit()
        
        assert employee.type == 'employee'
        assert hr.type == 'hr'
        assert it.type == 'it'
        assert isinstance(employee, app.User)
        assert isinstance(hr, app.User)
        assert isinstance(it, app.User)
        app.db.drop_all()

# Test initial admin creation
def test_initial_admin_creation(app, client):
    with app.app_context():
        app.db.create_all()
        assert app.db.session.query(app.User).count() == 0
        admin = app.HR(
            username='admin',
            email='admin@example.com',
            sponsor_email='sponsor@example.com',
            is_active=True
        )
        admin.set_password('Admin123!')
        app.db.session.add(admin)
        audit = app.AuditLog(
            type='initial_setup',
            user_id=None,
            success=True,
            reason='Created initial HR user: admin',
            ip_address='127.0.0.1'
        )
        app.db.session.add(audit)
        app.db.session.commit()
        admin = app.db.session.query(app.HR).filter_by(username='admin').first()
        assert admin is not None
        assert admin.email == 'admin@example.com'
        assert admin.is_active is True
        assert admin.check_password('Admin123!')
        audit = app.AuditLog.query.filter_by(type='initial_setup', success=True).first()
        assert audit is not None
        assert audit.reason == 'Created initial HR user: admin'
        app.db.drop_all()
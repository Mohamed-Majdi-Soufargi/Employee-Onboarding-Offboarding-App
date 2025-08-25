import pytest
from flask_jwt_extended import create_access_token
from .test_app import app, client, uuid

# Test HR users route access
def test_hr_users_access(client, app):
    with app.app_context():
        app.db.create_all()
        hr_user = app.HR(
            username="hruser",
            email="hr@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        hr_user.set_password("Test123!")
        emp_user = app.Employee(
            username="empuser",
            email="emp@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        emp_user.set_password("Test123!")
        app.db.session.add_all([hr_user, emp_user])
        app.db.session.commit()
        hr_token = create_access_token(identity=str(hr_user.id))
        emp_token = create_access_token(identity=str(emp_user.id))
    
        response = client.get('/hr/users', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 200
        assert len(response.json) >= 2
        assert any(u['username'] == 'hruser' for u in response.json)
        assert any(u['username'] == 'empuser' for u in response.json)
        audit = app.AuditLog.query.filter_by(type='hr_access', success=True, reason='Viewed user list').first()
        assert audit is not None
    
        response = client.get('/hr/users', headers={'Authorization': f'Bearer {emp_token}'})
        assert response.status_code == 403
        assert response.json == {"message": "HR access required"}
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='HR access required').first()
        assert audit is not None
        app.db.drop_all()

# Test user deactivation
def test_deactivate_user(app, client):
    with app.app_context():
        app.db.create_all()
        hr_user = app.HR(
            username='hruser',
            email='hr@example.com',
            sponsor_email='sponsor@example.com',
            is_active=True
        )
        hr_user.set_password('Test123!')
        emp_user = app.Employee(
            username='empuser',
            email='emp@example.com',
            sponsor_email='sponsor@example.com',
            is_active=True
        )
        emp_user.set_password('Test123!')
        app.db.session.add_all([hr_user, emp_user])
        app.db.session.commit()
        hr_token = create_access_token(identity=str(hr_user.id))
        emp_token = create_access_token(identity=str(emp_user.id))
    
        response = client.post(f'/hr/users/{emp_user.id}/deactivate', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 200
        assert response.json['message'] == f'User {emp_user.username} deactivated successfully'
        emp_user = app.db.session.get(app.User, emp_user.id)
        assert emp_user.is_active is False
        audit = app.AuditLog.query.filter_by(type='hr_access', success=True, reason=f'Deactivated user {emp_user.username}').first()
        assert audit is not None
    
        response = client.post(f'/hr/users/{emp_user.id}/deactivate', headers={'Authorization': f'Bearer {emp_token}'})
        assert response.status_code == 403
        assert response.json['message'] == 'HR access required'
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='HR access required').first()
        assert audit is not None
    
        response = client.post(f'/hr/users/{hr_user.id}/deactivate', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 403
        assert response.json['message'] == 'Cannot deactivate self'
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='Cannot deactivate self').first()
        assert audit is not None
    
        response = client.post('/hr/users/999/deactivate', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 404
        assert response.json['message'] == 'Target user not found'
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='Target user not found').first()
        assert audit is not None
    
        response = client.post(f'/hr/users/{emp_user.id}/deactivate', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 400
        assert response.json['message'] == 'User already deactivated'
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='User already deactivated').first()
        assert audit is not None
        app.db.drop_all()

# Test pending approvals route access
def test_pending_approvals_access(client, app):
    with app.app_context():
        app.db.create_all()
        hr_user = app.HR(
            username="hruser",
            email="hr@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        hr_user.set_password("Test123!")
        pending_user = app.Employee(
            username="pendinguser",
            email="pending@example.com",
            sponsor_email="hr@example.com",
            approval_token=str(uuid.uuid4()),
            is_active=False
        )
        pending_user.set_password("Test123!")
        other_user = app.Employee(
            username="otheruser",
            email="other@example.com",
            sponsor_email="other.sponsor@example.com",
            is_active=False
        )
        other_user.set_password("Test123!")
        emp_user = app.Employee(
            username="empuser",
            email="emp@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        emp_user.set_password("Test123!")
        app.db.session.add_all([hr_user, pending_user, other_user, emp_user])
        app.db.session.commit()
        hr_token = create_access_token(identity=str(hr_user.id))
        emp_token = create_access_token(identity=str(emp_user.id))
    
        response = client.get('/pending_approvals', headers={'Authorization': f'Bearer {hr_token}'})
        assert response.status_code == 200
        assert response.json['pending_approvals'] is not None
        assert len(response.json['pending_approvals']) == 1
        assert response.json['pending_approvals'][0]['username'] == 'pendinguser'
        assert response.json['pending_approvals'][0]['email'] == 'pending@example.com'
        assert response.json['pending_approvals'][0]['role'] == 'employee'
        assert response.json['pending_approvals'][0]['approval_token'] == pending_user.approval_token
        audit = app.AuditLog.query.filter_by(type='hr_access', success=True, reason='Viewed pending approvals').first()
        assert audit is not None
        assert audit.user_id == hr_user.id
    
        response = client.get('/pending_approvals', headers={'Authorization': f'Bearer {emp_token}'})
        assert response.status_code == 403
        assert response.json == {"message": "HR access required"}
        audit = app.AuditLog.query.filter_by(type='hr_access', success=False, reason='HR access required').first()
        assert audit is not None
        assert audit.user_id == emp_user.id
    
        response = client.get('/pending_approvals')
        assert response.status_code == 401
        assert response.json.get('msg') == 'Missing Authorization Header'
    
        response = client.get('/pending_approvals', headers={'Authorization': 'Bearer invalidtoken'})
        assert response.status_code == 422
        assert response.json.get('msg') == 'Not enough segments'
    
        hr_user2 = app.HR(
            username="hruser2",
            email="hr2@example.com",
            sponsor_email="sponsor@example.com",
            is_active=True
        )
        hr_user2.set_password("Test123!")
        app.db.session.add(hr_user2)
        app.db.session.commit()
        hr_token2 = create_access_token(identity=str(hr_user2.id))
        response = client.get('/pending_approvals', headers={'Authorization': f'Bearer {hr_token2}'})
        assert response.status_code == 200
        assert response.json['pending_approvals'] == []
        audit = app.AuditLog.query.filter_by(type='hr_access', success=True, reason='Viewed pending approvals', user_id=hr_user2.id).first()
        assert audit is not None
        app.db.drop_all()
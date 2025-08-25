import pytest
from flask_jwt_extended import create_access_token
from .test_app import app, client
from datetime import datetime, timezone
import logging
from werkzeug.datastructures import FileStorage
import io
import boto3
from unittest.mock import patch
from moto import mock_aws

logger = logging.getLogger(__name__)

def test_upload_file(client, app):
    with app.app_context(), mock_aws():
        # Mock ClamAV scan
        with patch('subprocess.run') as mock_clamscan:
            mock_clamscan.return_value.stdout = 'Infected files: 0'

            # Set up a mock S3 bucket
            s3 = boto3.client('s3', region_name='us-east-1')
            s3.create_bucket(Bucket='test-bucket')

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

            # Test with no file
            logger.debug("Testing /upload with no file")
            response = client.post('/upload', headers={'Authorization': f'Bearer {token}'})
            logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
            assert response.status_code == 400, f"Expected 400, got {response.status_code}. Response: {response.get_data(as_text=True)}"
            assert response.json == {"message": "No file provided"}
            audit = app.AuditLog.query.filter_by(type='file_upload', success=False, reason='No file provided').first()
            assert audit is not None
            assert audit.user_id == user_id

            # Test with empty file
            logger.debug("Testing /upload with empty file")
            file = FileStorage(stream=io.BytesIO(b''), filename='')
            response = client.post('/upload', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data={'file': file})
            logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
            assert response.status_code == 400, f"Expected 400, got {response.status_code}. Response: {response.get_data(as_text=True)}"
            assert response.json == {"message": "No file selected"}
            audit = app.AuditLog.query.filter_by(type='file_upload', success=False, reason='No file selected').first()
            assert audit is not None
            assert audit.user_id == user_id

            # Test with invalid file type
            logger.debug("Testing /upload with invalid file type")
            file = FileStorage(stream=io.BytesIO(b'test content'), filename='test.txt')
            response = client.post('/upload', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data={'file': file})
            logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
            assert response.status_code == 400, f"Expected 400, got {response.status_code}. Response: {response.get_data(as_text=True)}"
            assert response.json == {"message": "Only PDF and PNG files are allowed"}
            audit = app.AuditLog.query.filter_by(type='file_upload', success=False, reason='Invalid file type').first()
            assert audit is not None
            assert audit.user_id == user_id

            # Test with file too large
            logger.debug("Testing /upload with large file")
            large_content = b'x' * (11 * 1024 * 1024)  # 11MB
            file = FileStorage(stream=io.BytesIO(large_content), filename='large.pdf')
            response = client.post('/upload', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data={'file': file})
            logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
            assert response.status_code == 400, f"Expected 400, got {response.status_code}. Response: {response.get_data(as_text=True)}"
            assert response.json == {"message": "File must be less than 10MB"}
            audit = app.AuditLog.query.filter_by(type='file_upload', success=False, reason='File too large').first()
            assert audit is not None
            assert audit.user_id == user_id

            # Test with valid PDF file
            logger.debug("Testing /upload with valid PDF")
            file = FileStorage(stream=io.BytesIO(b'%PDF-1.4 dummy content'), filename='test.pdf')
            response = client.post('/upload', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data={'file': file})
            logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
            assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_data(as_text=True)}"
            assert response.json == {"message": "File uploaded successfully"}
            document = app.Document.query.filter_by(user_id=user_id, file_name='test.pdf').first()
            assert document is not None
            assert document.file_type == 'application/pdf'
            audit = app.AuditLog.query.filter_by(type='file_upload', success=True, reason='File test.pdf uploaded successfully').first()
            assert audit is not None
            assert audit.user_id == user_id

            # Test with valid PNG file
            logger.debug("Testing /upload with valid PNG")
            file = FileStorage(stream=io.BytesIO(b'\x89PNG dummy content'), filename='test.png')
            response = client.post('/upload', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data={'file': file})
            logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
            assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_data(as_text=True)}"
            assert response.json == {"message": "File uploaded successfully"}
            document = app.Document.query.filter_by(user_id=user_id, file_name='test.png').first()
            assert document is not None
            assert document.file_type == 'image/png'
            audit = app.AuditLog.query.filter_by(type='file_upload', success=True, reason='File test.png uploaded successfully').first()
            assert audit is not None
            assert audit.user_id == user_id

            # Test with inactive user
            user.is_active = False
            app.db.session.commit()
            logger.debug("Testing /upload with inactive user")
            file = FileStorage(stream=io.BytesIO(b'%PDF-1.4 dummy content'), filename='test.pdf')
            response = client.post('/upload', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data={'file': file})
            logger.debug(f"Response status: {response.status_code}, Response body: {response.get_data(as_text=True)}")
            assert response.status_code == 403
            assert response.json == {"message": "Unauthorized or account not active"}
            audit = app.AuditLog.query.filter_by(type='file_upload', success=False, reason='Unauthorized or account not active').first()
            assert audit is not None
            assert audit.user_id == user_id

            app.db.drop_all()
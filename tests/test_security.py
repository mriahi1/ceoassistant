import pytest
import os
import json
from flask import session, url_for
from unittest.mock import patch, MagicMock
from pathlib import Path
from app import app
import config

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    with app.test_client() as client:
        with app.app_context():
            yield client

@pytest.fixture
def authenticated_client(client):
    """Fixture for an authenticated client session"""
    with patch('flask_login.utils._get_user') as mock_get_user:
        # Create a mock authenticated user
        mock_user = MagicMock()
        mock_user.is_authenticated = True
        mock_user.id = 'test_user_id'
        mock_user.email = 'test@example.com'
        mock_get_user.return_value = mock_user
        
        with client.session_transaction() as sess:
            sess['user_id'] = 'test_user_id'
        
        yield client

class TestPathTraversal:
    def test_digest_upload_path_traversal(self, authenticated_client):
        """Test path traversal prevention in digest upload"""
        # Try to access files outside the digests directory
        invalid_filenames = [
            '../config.py',            # Relative path traversal
            '/etc/passwd',             # Absolute path
            '..\\..\\app.py',          # Windows-style path traversal
            'digest_2023-01-01.json/', # Directory traversal
            'digest_%252e%252e%252fconfig.py', # URL encoded traversal
            'digest_2023-01-01.json; rm -rf /',  # Command injection
            'digest_"$(rm -rf /)"',     # Command substitution
        ]
        
        for filename in invalid_filenames:
            response = authenticated_client.post(f'/digest/upload_to_drive/{filename}')
            # Should either return 404 (not found) or redirect to digests with an error
            assert response.status_code in [302, 404] 
            # If it's a redirect, it should be to the digests page
            if response.status_code == 302:
                assert '/digests' in response.location

    @patch('app.config.DIGESTS_DIR', Path('/tmp/test_digests'))
    def test_digest_file_access_validation(self, authenticated_client):
        """Test that digest file access is properly validated"""
        # Create test directory
        os.makedirs('/tmp/test_digests', exist_ok=True)
        
        # Create a valid digest file
        valid_filename = 'digest_2023-01-01.json'
        valid_path = Path('/tmp/test_digests') / valid_filename
        with open(valid_path, 'w') as f:
            f.write('{"id": 123, "content": "test"}')
        
        # Try to access it with various modified filenames
        test_cases = [
            ('digest_2023-01-01.json', 302),  # Valid, should redirect after processing
            ('digest_2023-01-01.json.exe', 302),  # Invalid extension
            ('../../etc/passwd', 302),  # Path traversal
            ('digest_2023-01-01.json;touch /tmp/hack', 302),  # Command injection
        ]
        
        with patch('app.upload_digest_to_drive', return_value=True):
            for filename, expected_status in test_cases:
                response = authenticated_client.post(f'/digest/upload_to_drive/{filename}')
                assert response.status_code == expected_status
        
        # Clean up
        if os.path.exists(valid_path):
            os.remove(valid_path)
        if os.path.exists('/tmp/test_digests'):
            os.rmdir('/tmp/test_digests')


class TestXSS:
    def test_user_input_sanitization(self, authenticated_client):
        """Test sanitization of user input to prevent XSS"""
        # Test cases with potentially malicious inputs
        test_cases = [
            {'to': '<script>alert("xss")</script>'},
            {'subject': 'javascript:alert("xss")'},
            {'body': '<img src="x" onerror="alert(\'xss\')">'},
            {'query': '<iframe src="javascript:alert(\'xss\')">'},
        ]
        
        with patch('app.send_email', return_value=True):
            for data in test_cases:
                response = authenticated_client.post('/gmail/compose', data=data)
                # Should not reflect the unsanitized input
                assert '<script>' not in response.data.decode('utf-8')
                assert 'javascript:' not in response.data.decode('utf-8')
                assert 'onerror=' not in response.data.decode('utf-8')


class TestSecurityHeaders:
    def test_security_headers_present(self, client):
        """Test that security headers are correctly set"""
        response = client.get('/')
        
        # Check for required security headers
        assert 'Strict-Transport-Security' in response.headers
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
        assert 'X-XSS-Protection' in response.headers
        assert 'Content-Security-Policy' in response.headers
        
        # Verify header values
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert response.headers['X-Frame-Options'] == 'SAMEORIGIN'
        assert response.headers['X-XSS-Protection'] == '1; mode=block'


class TestRateLimiting:
    def test_rate_limiting_headers(self, client):
        """Test rate limiting headers are present"""
        # Choose an endpoint with rate limiting applied
        response = client.get('/api/platform_summary')
        
        # Check for rate limiting headers
        assert any('X-RateLimit' in header for header in response.headers)

    @patch('flask_limiter.limiter.storage.Storage.get')
    @patch('flask_limiter.limiter.storage.Storage.incr')
    def test_rate_limit_exceeded(self, mock_incr, mock_get, client):
        """Test behavior when rate limit is exceeded"""
        # Mock rate limit as already exceeded
        mock_get.return_value = 60  # Over the 50 per hour limit
        mock_incr.return_value = 61
        
        # Make request to rate-limited endpoint
        response = client.get('/api/platform_summary')
        
        # Should return 429 Too Many Requests
        assert response.status_code == 429


class TestCSRF:
    def test_csrf_ajax_validation(self, client):
        """Test CSRF token validation for AJAX requests"""
        # Test with missing CSRF token
        response = client.post('/test_integration/hubspot', 
                              headers={'X-Requested-With': 'XMLHttpRequest'})
        assert response.status_code == 403
        
        # Test with CSRF token in header
        app.config['WTF_CSRF_ENABLED'] = True
        with client.session_transaction() as sess:
            csrf_token = 'test_csrf_token'
            sess['csrf_token'] = csrf_token
        
        with patch('app.csrf._validate_token', return_value=True):
            response = client.post('/test_integration/hubspot',
                                   headers={
                                       'X-Requested-With': 'XMLHttpRequest',
                                       'X-CSRFToken': csrf_token
                                   })
            assert response.status_code != 403
        
        app.config['WTF_CSRF_ENABLED'] = False 
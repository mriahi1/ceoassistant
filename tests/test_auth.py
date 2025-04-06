import pytest
import json
from flask import session, url_for
from unittest.mock import patch
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing only
    with app.test_client() as client:
        with app.app_context():
            yield client

class TestAuthentication:
    def test_login_page_redirects_to_google(self, client):
        """Test that login page redirects to Google OAuth"""
        response = client.get('/login', follow_redirects=False)
        assert response.status_code == 302
        assert '/google_login/callback' in response.location

    def test_protected_routes_require_auth(self, client):
        """Test that protected routes redirect to login when not authenticated"""
        protected_routes = [
            '/integrations',
            '/digests',
            '/generate_digest',
            '/settings',
            '/gmail',
            '/drive',
            '/calendar',
            '/financials',
            '/scorecard',
            '/slack',
            '/monitoring'
        ]
        
        for route in protected_routes:
            response = client.get(route, follow_redirects=False)
            assert response.status_code == 302
            assert '/login' in response.location

    @patch('auth.users_db')
    @patch('flask_login.utils._get_user')
    def test_logout_clears_session(self, mock_get_user, mock_users_db, client):
        """Test that logout clears session and removes user from users_db"""
        # Setup mock user
        mock_user = type('obj', (object,), {
            'is_authenticated': True,
            'id': 'test_user_id'
        })
        mock_get_user.return_value = mock_user
        mock_users_db.get.return_value = mock_user
        mock_users_db.__contains__.return_value = True
        
        # Perform logout
        with client.session_transaction() as sess:
            sess['user_id'] = 'test_user_id'
        
        response = client.get('/logout', follow_redirects=False)
        
        # Check session is cleared
        with client.session_transaction() as sess:
            assert 'user_id' not in sess
        
        # Check user removed from users_db
        mock_users_db.pop.assert_called_once_with('test_user_id', None)

    @patch('auth.WebApplicationClient.prepare_request_uri')
    def test_oauth_state_parameter_is_set(self, mock_prepare_request, client):
        """Test that OAuth state parameter is set in session for CSRF protection"""
        mock_prepare_request.return_value = "https://accounts.google.com/auth?state=test_state"
        
        with patch('auth.GOOGLE_CLIENT_ID', 'test_client_id'):
            response = client.get('/login', follow_redirects=False)
            
            with client.session_transaction() as sess:
                assert 'oauth_state' in sess
                assert len(sess['oauth_state']) > 0


class TestCsrfProtection:
    def test_ajax_csrf_protection(self, client):
        """Test CSRF protection for AJAX requests"""
        response = client.post('/test_integration/hubspot', 
                              data={},
                              headers={'X-Requested-With': 'XMLHttpRequest'})
        
        # Should receive 403 without CSRF token
        assert response.status_code == 403
        data = json.loads(response.data)
        assert 'CSRF' in data['error']
    
    def test_form_csrf_protection(self, client):
        """Test CSRF protection for form submissions"""
        app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF for this test
        
        with client.session_transaction() as sess:
            sess['user_id'] = 'test_user_id'  # Mock authentication
        
        response = client.post('/generate_digest')
        assert response.status_code == 400
        
        app.config['WTF_CSRF_ENABLED'] = False  # Reset setting


class TestSessionSecurity:
    def test_session_cookie_attributes(self, client):
        """Test secure session cookie attributes"""
        response = client.get('/')
        
        assert app.config['SESSION_COOKIE_HTTPONLY'] is True
        assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
        
        # Test secure flag (should be True in production, may be False in development)
        assert app.config['SESSION_COOKIE_SECURE'] == (
            app.config.get('FLASK_ENV', 'production').lower() != 'development'
        )

    @patch('auth.users_db')
    @patch('flask_login.utils._get_user')
    def test_session_expiration(self, mock_get_user, mock_users_db, client):
        """Test that sessions expire after configured lifetime"""
        from datetime import datetime, timedelta
        import time
        
        # Setup mock user with login time in the past
        old_login_time = int(time.time()) - int(app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()) - 10
        mock_user = type('obj', (object,), {
            'is_authenticated': True,
            'id': 'test_user_id',
            'login_time': old_login_time,
            'last_active': old_login_time,
            'email': 'test@example.com'
        })
        mock_get_user.return_value = mock_user
        mock_users_db.get.return_value = mock_user
        
        # Set up the session
        with client.session_transaction() as sess:
            sess['user_id'] = 'test_user_id'
            sess['created_at'] = old_login_time
        
        # Access a protected route
        from models.user import User
        with patch.object(User, 'get', return_value=None):
            response = client.get('/integrations', follow_redirects=False)
            
            # Should redirect to login because session is expired
            assert response.status_code == 302
            assert '/login' in response.location 
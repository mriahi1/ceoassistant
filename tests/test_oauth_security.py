import pytest
import json
import time
from unittest.mock import patch, MagicMock
from flask import session, url_for
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    with app.test_client() as client:
        with app.app_context():
            yield client

class TestOAuthSecurity:
    @patch('auth.GOOGLE_CLIENT_ID', 'test_client_id')
    @patch('auth.client')
    @patch('auth.requests.get')
    def test_state_parameter_validation(self, mock_get, mock_client, client):
        """Test OAuth state parameter validation to prevent CSRF attacks"""
        # Mock the discovery URL response
        mock_get.return_value.json.return_value = {
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo"
        }

        # Mock client.prepare_request_uri to return a URL
        mock_client.prepare_request_uri.return_value = "https://accounts.google.com/o/oauth2/auth?state=test_state"
        
        # First visit login page to generate state
        response = client.get('/login')
        
        # Now attempt callback with invalid state
        response = client.get('/google_login/callback?code=test_code&state=invalid_state')
        
        # Should return 403 Forbidden for CSRF prevention
        assert response.status_code == 403
        assert b'Invalid security parameters' in response.data
    
    @patch('auth.GOOGLE_CLIENT_ID', 'test_client_id')
    @patch('auth.GOOGLE_CLIENT_SECRET', 'test_client_secret')
    @patch('auth.client')
    @patch('auth.requests.get')
    @patch('auth.requests.post')
    def test_missing_code_parameter(self, mock_post, mock_get, mock_client, client):
        """Test handling of missing authorization code in OAuth callback"""
        # Mock the discovery URL response
        mock_get.return_value.json.return_value = {
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo"
        }
        
        # Set state in session
        with client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
        
        # Attempt callback with missing code
        response = client.get('/google_login/callback?state=test_state')
        
        # Should return 400 Bad Request
        assert response.status_code == 400
        assert b'Authorization code not received' in response.data
    
    @patch('auth.GOOGLE_CLIENT_ID', 'test_client_id')
    @patch('auth.GOOGLE_CLIENT_SECRET', 'test_client_secret')
    @patch('auth.client')
    @patch('auth.requests.get')
    @patch('auth.requests.post')
    def test_token_request_error(self, mock_post, mock_get, mock_client, client):
        """Test handling of errors in token request"""
        # Mock discovery URL
        mock_get.return_value.json.return_value = {
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo"
        }
        
        # Mock token response with error
        mock_post.return_value.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Invalid code"
        }
        
        # Set up client mock
        mock_client.prepare_token_request.return_value = ("https://oauth2.googleapis.com/token", {}, "")
        
        # Set state in session
        with client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
        
        # Attempt callback
        response = client.get('/google_login/callback?code=test_code&state=test_state')
        
        # Should return 500 with error message
        assert response.status_code == 500
        assert b'Authentication error' in response.data
    
    @patch('auth.GOOGLE_CLIENT_ID', 'test_client_id')
    @patch('auth.GOOGLE_CLIENT_SECRET', 'test_client_secret')
    @patch('auth.client')
    @patch('auth.requests.get')
    @patch('auth.requests.post')
    def test_email_verification_check(self, mock_post, mock_get, mock_client, client):
        """Test that unverified emails are rejected"""
        # Mock discovery URL
        mock_get.side_effect = [
            # First call for discovery URL
            MagicMock(json=lambda: {
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo"
            }),
            # Second call for userinfo endpoint
            MagicMock(
                ok=True,
                json=lambda: {
                    "sub": "123456789",
                    "email": "user@example.com",
                    "email_verified": False,  # Unverified email
                    "given_name": "Test",
                    "picture": "https://example.com/picture.jpg"
                }
            )
        ]
        
        # Mock token response
        mock_post.return_value.json.return_value = {
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "expires_in": 3600
        }
        
        # Set up client mocks
        mock_client.prepare_token_request.return_value = ("https://oauth2.googleapis.com/token", {}, "")
        mock_client.parse_request_body_response.return_value = None
        mock_client.add_token.return_value = ("https://openidconnect.googleapis.com/v1/userinfo", {}, "")
        
        # Set state in session
        with client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
        
        # Attempt callback
        response = client.get('/google_login/callback?code=test_code&state=test_state')
        
        # Should reject unverified email
        assert response.status_code == 400
        assert b'not verified' in response.data.lower()
    
    @patch('auth.GOOGLE_CLIENT_ID', 'test_client_id')
    @patch('auth.GOOGLE_CLIENT_SECRET', 'test_client_secret')
    @patch('auth.client')
    @patch('auth.requests.get')
    @patch('auth.requests.post')
    def test_unauthorized_email_domain(self, mock_post, mock_get, mock_client, client):
        """Test that unauthorized email domains are rejected"""
        # Mock discovery URL
        mock_get.side_effect = [
            # First call for discovery URL
            MagicMock(json=lambda: {
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo"
            }),
            # Second call for userinfo endpoint
            MagicMock(
                ok=True,
                json=lambda: {
                    "sub": "123456789",
                    "email": "user@unauthorized-domain.com",  # Unauthorized email domain
                    "email_verified": True,
                    "given_name": "Test",
                    "picture": "https://example.com/picture.jpg"
                }
            )
        ]
        
        # Mock token response
        mock_post.return_value.json.return_value = {
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "expires_in": 3600
        }
        
        # Set up client mocks
        mock_client.prepare_token_request.return_value = ("https://oauth2.googleapis.com/token", {}, "")
        mock_client.parse_request_body_response.return_value = None
        mock_client.add_token.return_value = ("https://openidconnect.googleapis.com/v1/userinfo", {}, "")
        
        # Set state in session
        with client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
        
        # Attempt callback
        response = client.get('/google_login/callback?code=test_code&state=test_state')
        
        # Should reject unauthorized domain
        assert response.status_code == 403
        assert b'access denied' in response.data.lower()
    
    @patch('auth.GOOGLE_CLIENT_ID', 'test_client_id')
    @patch('auth.GOOGLE_CLIENT_SECRET', 'test_client_secret')
    @patch('auth.client')
    @patch('auth.requests.get')
    @patch('auth.requests.post')
    @patch('auth.users_db')
    @patch('auth.login_user')
    def test_successful_login_session_security(self, mock_login_user, mock_users_db, mock_post, mock_get, mock_client, client):
        """Test session security measures on successful login"""
        # Mock discovery URL
        mock_get.side_effect = [
            # First call for discovery URL
            MagicMock(json=lambda: {
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo"
            }),
            # Second call for userinfo endpoint
            MagicMock(
                ok=True,
                json=lambda: {
                    "sub": "123456789",
                    "email": "mriahi@ooti.co",  # Authorized email
                    "email_verified": True,
                    "given_name": "Test",
                    "picture": "https://example.com/picture.jpg"
                }
            )
        ]
        
        # Mock token response
        mock_post.return_value.json.return_value = {
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "expires_in": 3600
        }
        
        # Set up client mocks
        mock_client.prepare_token_request.return_value = ("https://oauth2.googleapis.com/token", {}, "")
        mock_client.parse_request_body_response.return_value = None
        mock_client.add_token.return_value = ("https://openidconnect.googleapis.com/v1/userinfo", {}, "")
        
        # Set initial state in session
        with client.session_transaction() as sess:
            sess['oauth_state'] = 'test_state'
            sess['previous_session_data'] = 'should_be_cleared'
        
        # Attempt callback
        response = client.get('/google_login/callback?code=test_code&state=test_state')
        
        # Verify session was cleared (session fixation prevention)
        with client.session_transaction() as sess:
            assert 'previous_session_data' not in sess
            assert 'created_at' in sess  # New session data should be set
            
        # Verify user was created with the current timestamp
        from auth import User
        mock_users_db.__setitem__.assert_called_once()
        user = mock_users_db.__setitem__.call_args[0][1]
        assert isinstance(user, User)
        assert user.id == "123456789"
        assert user.email == "mriahi@ooti.co"
        assert abs(user.login_time - int(time.time())) < 10  # Should be within 10 seconds
        
        # Verify login_user was called
        mock_login_user.assert_called_once_with(user)
        
        # Should redirect to index
        assert response.status_code == 302
        assert response.location == '/' 
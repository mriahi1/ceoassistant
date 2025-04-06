import pytest
import json
import sys
import os
from flask import Flask
from flask_login import login_user

# Add the project root to the path so we can import modules properly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Reuse fixtures from test_app_integration.py
from minimal_tests.test_app_integration import app, client, runner, MockUser, authorized_user, unauthorized_user

# Test email-based access control for API endpoints
def test_email_based_api_restrictions(client, monkeypatch):
    """Test that only authorized emails can access restricted API endpoints."""
    # Mock the User.get method to return our mock user
    from models.user import User
    monkeypatch.setattr(User, "get", lambda user_id: MockUser.get(user_id))
    
    # Test with authorized email (maxriahi@gmail.com)
    with client.session_transaction() as session:
        session['user_id'] = authorized_user.id
        session['_fresh'] = True
    
    # Access restricted endpoint
    response = client.get('/api/metrics')
    assert response.status_code == 200, "Authorized user should have access"
    
    # Test with unauthorized email
    with client.session_transaction() as session:
        session['user_id'] = unauthorized_user.id
        session['_fresh'] = True
    
    # Access restricted endpoint
    response = client.get('/api/metrics')
    assert response.status_code == 403, "Unauthorized user should be forbidden"

# Test API authentication requirements
def test_api_authentication_required(client):
    """Test that API endpoints require authentication."""
    # Try to access an API endpoint without being logged in
    response = client.get('/api/platform_summary')
    assert response.status_code in [401, 302], "Unauthenticated access should be rejected or redirected"
    
    # Also test the restricted endpoint
    response = client.get('/api/metrics')
    assert response.status_code in [401, 302], "Unauthenticated access should be rejected or redirected"

# Test CSRF protection for API endpoints that modify data
def test_api_csrf_protection(client, monkeypatch):
    """Test that API endpoints that modify data are CSRF protected."""
    # Mock the User.get method to return our mock user
    from models.user import User
    monkeypatch.setattr(User, "get", lambda user_id: MockUser.get(user_id))
    
    # Log in as authorized user
    with client.session_transaction() as session:
        session['user_id'] = authorized_user.id
        session['_fresh'] = True
    
    # Try to POST without CSRF token (should fail)
    response = client.post('/refresh_data')
    assert response.status_code in [400, 403], "Request without CSRF token should be rejected"

# Test API response format and content
def test_api_response_format(client, monkeypatch):
    """Test that API endpoints return properly formatted JSON responses."""
    # Mock the User.get method to return our mock user
    from models.user import User
    monkeypatch.setattr(User, "get", lambda user_id: MockUser.get(user_id))
    
    # Mock the get_cached_data function to return test data
    import app
    
    def mock_get_cached_data():
        return {
            "hubspot": {
                "deals": [{"amount": 1000}, {"amount": 2000}],
                "contacts": [{"id": 1}, {"id": 2}]
            },
            "chargebee": {
                "subscriptions": [{"id": 1}, {"id": 2}],
                "mrr": 3000,
                "invoices": [{"id": 1}, {"id": 2}]
            },
            "ooti": {
                "projects": [{"id": 1}, {"id": 2}],
                "finance_summary": {"balance": 5000}
            }
        }
    
    monkeypatch.setattr(app, "get_cached_data", mock_get_cached_data)
    
    # Log in as authorized user
    with client.session_transaction() as session:
        session['user_id'] = authorized_user.id
        session['_fresh'] = True
    
    # Get API response
    response = client.get('/api/platform_summary')
    
    # Check response format
    assert response.status_code == 200, "API should return success status"
    assert response.content_type == 'application/json', "API should return JSON content type"
    
    # Parse and validate response data
    try:
        data = json.loads(response.data)
        assert isinstance(data, dict), "API should return a JSON object"
        assert "hubspot" in data, "Response should contain hubspot data"
        assert "chargebee" in data, "Response should contain chargebee data"
        assert "ooti" in data, "Response should contain ooti data"
    except json.JSONDecodeError:
        pytest.fail("API response is not valid JSON")

# Test security-related headers for API endpoints
def test_api_security_headers(client, monkeypatch):
    """Test that API endpoints include security headers."""
    # Mock the User.get method to return our mock user
    from models.user import User
    monkeypatch.setattr(User, "get", lambda user_id: MockUser.get(user_id))
    
    # Log in as authorized user
    with client.session_transaction() as session:
        session['user_id'] = authorized_user.id
        session['_fresh'] = True
    
    # Get API response
    response = client.get('/api/platform_summary')
    
    # Check security headers
    assert 'Strict-Transport-Security' in response.headers, "HSTS header should be present"
    assert 'X-Content-Type-Options' in response.headers, "X-Content-Type-Options header should be present"
    assert 'X-Frame-Options' in response.headers, "X-Frame-Options header should be present"
    assert 'X-XSS-Protection' in response.headers, "X-XSS-Protection header should be present"
    assert 'Content-Security-Policy' in response.headers, "CSP header should be present" 
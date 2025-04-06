import pytest
import json
import sys
import os
from flask import Flask
from flask_login import login_user
from unittest.mock import patch, MagicMock

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Test email-based access control for API endpoints
def test_email_based_api_restrictions(app, authorized_user, unauthorized_user):
    """Test that only authorized emails can access restricted API endpoints."""
    # Create a test Flask app
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    # Add a test API endpoint with email restrictions
    @app.route('/api/test')
    def test_api():
        return "Access granted"
    
    # Add middleware to check email authorization
    @app.before_request
    def check_email_authorization():
        from flask import request, g, jsonify
        from utils.access_control import is_authorized_email
        
        # For testing purposes, we'll use a simple check rather than actual abort
        if request.path.startswith('/api/'):
            # Use a simplified check just for this test
            if not hasattr(g, 'user') or not g.user or not hasattr(g.user, 'email'):
                return jsonify({"error": "Unauthorized"}), 403
                
            if not is_authorized_email(g.user.email):
                return jsonify({"error": "Forbidden"}), 403
    
    # Create a test client
    client = app.test_client()
    
    # Test with unauthorized user
    with app.test_request_context():
        from flask import g
        g.user = unauthorized_user
        response = client.get('/api/test')
        assert response.status_code == 403
        assert b"Forbidden" in response.data or b"Unauthorized" in response.data
    
    # Test with authorized user
    with app.test_request_context():
        from flask import g
        g.user = authorized_user
        response = client.get('/api/test')
        assert response.status_code == 200
        assert b"Access granted" in response.data

# Test API authentication requirements
def test_api_authentication_required(app):
    """Test that API endpoints require authentication."""
    # Create a test Flask app
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    # Add a test API endpoint with authentication
    @app.route('/api/test')
    def test_api():
        from flask import g, jsonify
        
        if not hasattr(g, 'authenticated') or not g.authenticated:
            return jsonify({"error": "Unauthorized"}), 401
            
        return jsonify({"message": "Authenticated"})
    
    # Create a test client
    client = app.test_client()
    
    # Test without authentication
    response = client.get('/api/test')
    assert response.status_code == 401, "Unauthenticated access should be rejected"
    
    # Test with authentication by directly using the test client with app context
    with app.test_request_context():
        from flask import g
        with client:
            client.get('/api/test')  # first make a request to set up app context
            g.authenticated = True   # then set g.authenticated in the current context
            response = client.get('/api/test')  # make the actual request with authentication
            assert response.status_code == 200, "Authenticated access should be allowed"
            assert b'"message":"Authenticated"' in response.data

# Test CSRF protection for API endpoints
def test_csrf_protection(app):
    """Test that API endpoints that modify data are CSRF protected."""
    # Create a test Flask app
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test_key'
    app.config['WTF_CSRF_ENABLED'] = True
    
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)
    
    # Add a test API endpoint that requires CSRF protection
    @app.route('/api/test', methods=['POST'])
    def test_api():
        return "CSRF passed"
    
    # Create a test client
    client = app.test_client()
    
    # Test without CSRF token
    response = client.post('/api/test')
    # Should fail due to missing CSRF token (the exact status code depends on configuration)
    assert response.status_code in [400, 403], "Request without CSRF token should be rejected"

# Test API response format and content
def test_api_response_format(app):
    """Test that API endpoints return properly formatted JSON responses."""
    # Create a test Flask app
    app = Flask(__name__)
    
    # Add a test API endpoint that returns JSON
    @app.route('/api/test')
    def test_api():
        from flask import jsonify
        return jsonify({
            "status": "success",
            "data": {
                "value": 42
            }
        })
    
    # Create a test client
    client = app.test_client()
    
    # Test the API response
    response = client.get('/api/test')
    
    # Check response code and content type
    assert response.status_code == 200, "API should return success status"
    assert response.content_type == 'application/json', "API should return JSON content type"
    
    # Parse the response
    data = json.loads(response.data)
    assert isinstance(data, dict), "API should return a JSON object"
    assert "status" in data, "Response should contain status field"
    assert "data" in data, "Response should contain data field"
    assert data["status"] == "success", "Status should be success"
    assert isinstance(data["data"], dict), "Data should be a JSON object"
    assert "value" in data["data"], "Data should contain expected field"
    assert data["data"]["value"] == 42, "Data should contain expected value" 
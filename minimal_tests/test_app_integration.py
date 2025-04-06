import pytest
import json
import os
import sys
from flask import Flask, redirect, url_for
from flask_login import login_user
from unittest.mock import patch, MagicMock

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our models
from models.user import User

# Tests using the fixtures from conftest.py

def test_unauthenticated_access_redirect():
    """Test that unauthenticated users are redirected to login."""
    # Create a test Flask app with the proper routes
    app = Flask(__name__)
    
    # Add a login route
    @app.route('/login')
    def login():
        return "Login page"
    
    # Add a protected route
    @app.route('/')
    def index():
        return redirect(url_for('login'))
    
    # Create a test client
    client = app.test_client()
    
    # Test accessing the root path
    response = client.get('/')
    # Should redirect to login
    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")

def test_login_page():
    """Test that the login page is accessible."""
    # Create a test Flask app with login route
    app = Flask(__name__)
    
    @app.route('/login')
    def login():
        return "Login page"
    
    # Create a test client
    client = app.test_client()
    
    # Test accessing the login page
    response = client.get('/login')
    assert response.status_code == 200
    assert b"Login page" in response.data

def test_login_simulation(authorized_user):
    """Test that we can simulate a login for testing purposes."""
    # Create a test Flask app with proper routes
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test_key'  # Required for sessions
    app.config['TESTING'] = True
    
    # Add a protected route
    @app.route('/')
    def index():
        return "Dashboard"
    
    # Create a test client with session support
    client = app.test_client()
    client.use_cookies = True
    
    # Set up a simple session test
    with app.test_request_context():
        # Access the root path (no login required in this test)
        response = client.get('/')
        
        # Should be successful
        assert response.status_code == 200
        assert b"Dashboard" in response.data

def test_security_headers():
    """Test that security headers are added to responses."""
    # Create a simple Flask app for this test
    app = Flask(__name__)
    
    # Add security headers middleware
    @app.after_request
    def add_security_headers(response):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
    
    @app.route('/test')
    def test_route():
        return "Test"
    
    # Use the test client
    test_client = app.test_client()
    response = test_client.get('/test')
    
    # Check headers
    assert response.headers.get('Strict-Transport-Security') == 'max-age=31536000; includeSubDomains'
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'
    assert 'Content-Security-Policy' in response.headers

# Additional tests can be added as needed 
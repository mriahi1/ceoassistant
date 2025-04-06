import pytest
import json
import os
import sys
from flask import Flask
from flask_login import login_user

# Add the project root to the path so we can import modules properly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import User model directly rather than through app
from models.user import User

# The app will be imported in the fixtures after setting environment variables

# Set up for Flask testing
@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    # Set testing mode
    os.environ["FLASK_ENV"] = "testing"
    os.environ["TESTING"] = "True"
    
    # Set required environment variables
    os.environ["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    os.environ["SESSION_SECRET"] = "test_secret_key"
    
    # Mock API keys for testing
    os.environ["HUBSPOT_API_KEY"] = "test_hubspot_key"
    os.environ["CHARGEBEE_API_KEY"] = "test_chargebee_key"
    os.environ["CHARGEBEE_SITE"] = "test_chargebee_site"
    os.environ["OPENAI_API_KEY"] = "test_openai_key"
    
    # Import flask_app only after setting environment variables
    import sys
    old_modules = dict(sys.modules)
    
    # Remove app module if it's already loaded to force reload with new env vars
    if 'app' in sys.modules:
        del sys.modules['app']
        
    # Import app with fresh environment
    from app import app as flask_app
    
    # Configure app for testing
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,  # Disable CSRF for testing
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    })
    
    # Create an application context
    with flask_app.app_context():
        yield flask_app
        
    # Restore original modules
    sys.modules.clear()
    sys.modules.update(old_modules)

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """A test CLI runner for the app."""
    return app.test_cli_runner()

class MockUser(User):
    """Mock user class for testing."""
    def __init__(self, id, email, name):
        # Call the parent constructor with required arguments
        super().__init__(id, email, name)
        # is_authenticated is provided by UserMixin, no need to set it
    
    @staticmethod
    def get(id):
        """Override the get method to return our mock users"""
        if id == "auth_user":
            return authorized_user
        elif id == "unauth_user":
            return unauthorized_user
        return None

# Create some test users
authorized_user = MockUser("auth_user", "maxriahi@gmail.com", "Authorized User")
unauthorized_user = MockUser("unauth_user", "random@example.com", "Unauthorized User")

# Test unauthenticated access to protected pages
def test_unauthenticated_access_redirect(client):
    """Test that unauthenticated users are redirected to login."""
    # Try accessing protected endpoints
    protected_routes = ['/', '/settings', '/integrations', '/digests']
    
    for route in protected_routes:
        response = client.get(route)
        # Should redirect to login
        assert response.status_code == 302
        assert "/login" in response.headers.get("Location", "")

# Test public pages are accessible
def test_public_pages(client):
    """Test that public pages are accessible without login."""
    response = client.get('/login')
    assert response.status_code == 200

# Mock the necessary methods to simulate login (this replaces need for auth)
def test_login_simulation(client, app, monkeypatch):
    """Test that we can simulate a login for testing purposes."""
    # Mock the User.get method to return our mock user
    monkeypatch.setattr(User, "get", lambda user_id: MockUser.get(user_id))
    
    # Set up the session to include the user ID
    with client.session_transaction() as session:
        session['user_id'] = authorized_user.id
        session['_fresh'] = True  # Mark the session as fresh
    
    # Access a protected page that requires login
    response = client.get('/settings')
    # Should now succeed (status 200) or at least not redirect to login
    assert response.status_code != 302, "Should not redirect to login"
    
    # If there's still an issue, it might be related to the actual view, not auth
    if response.status_code != 200:
        print(f"Status code: {response.status_code}")
        print(f"Response data: {response.data.decode('utf-8')}")

# Test the security headers
def test_security_headers(client):
    """Test that security headers are added to responses."""
    response = client.get('/login')  # Use a public route that should return 200
    
    # Check security headers
    assert response.headers.get('Strict-Transport-Security') == 'max-age=31536000; includeSubDomains'
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN' 
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'
    assert 'Content-Security-Policy' in response.headers

# Additional tests can be added as needed 
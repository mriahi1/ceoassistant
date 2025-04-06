"""
Common fixtures for tests
"""
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Add the project root to the path so we can import modules properly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up the test environment with required environment variables"""
    # Back up existing environment variables
    original_env = os.environ.copy()
    
    # Set required environment variables for testing
    os.environ["FLASK_ENV"] = "testing"
    os.environ["TESTING"] = "True"
    os.environ["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    os.environ["SESSION_SECRET"] = "test_secret_key"
    
    # Mock API keys
    os.environ["HUBSPOT_API_KEY"] = "test_hubspot_key"
    os.environ["CHARGEBEE_API_KEY"] = "test_chargebee_key"
    os.environ["CHARGEBEE_SITE"] = "test_chargebee_site"
    os.environ["OPENAI_API_KEY"] = "test_openai_key"
    
    # Set up mock users database
    from auth import users_db
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)

@pytest.fixture
def mock_user_db():
    """Create a mock user database for testing"""
    with patch('auth.users_db') as mock_db:
        # Set up mock users
        mock_db.get.side_effect = lambda user_id: {
            "auth_user": MockUser("auth_user", "maxriahi@gmail.com", "Authorized User"),
            "unauth_user": MockUser("unauth_user", "unauthorized@example.com", "Unauthorized User")
        }.get(user_id)
        
        yield mock_db

class MockUser:
    """Mock user class for testing"""
    def __init__(self, id, email, name, picture=None):
        self.id = id
        self.email = email.lower()
        self.name = name
        self.picture = picture
        self.login_time = 1000  # Some dummy time
        self.last_active = 1000
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
    
    def get_id(self):
        return self.id

@pytest.fixture
def authorized_user():
    """Return an authorized user for testing"""
    return MockUser("auth_user", "maxriahi@gmail.com", "Authorized User")

@pytest.fixture
def unauthorized_user():
    """Return an unauthorized user for testing"""
    return MockUser("unauth_user", "unauthorized@example.com", "Unauthorized User")

@pytest.fixture
def app():
    """Create and configure a Flask app for testing"""
    from flask import Flask
    
    # Create a Flask app for testing
    app = Flask(__name__)
    app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test_secret_key",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "PERMANENT_SESSION_LIFETIME": 3600
    })
    
    # Create request context
    with app.app_context():
        yield app

@pytest.fixture
def client(app):
    """Create a test client for the app"""
    return app.test_client()

@pytest.fixture
def logged_in_authorized_client(client, authorized_user):
    """Create a client with an authorized user logged in"""
    with client.session_transaction() as sess:
        sess['user_id'] = authorized_user.id
        sess['_fresh'] = True
    
    return client

@pytest.fixture
def logged_in_unauthorized_client(client, unauthorized_user):
    """Create a client with an unauthorized user logged in"""
    with client.session_transaction() as sess:
        sess['user_id'] = unauthorized_user.id
        sess['_fresh'] = True
    
    return client 
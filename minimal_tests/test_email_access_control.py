import pytest
import sys
import os
from unittest.mock import MagicMock, patch

# Add the project root to the path so we can import modules properly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.access_control import is_authorized_email, AUTHORIZED_EMAILS, check_user_email_authorization

# Define test users
class MockUser:
    def __init__(self, email):
        self.email = email
        self.is_authenticated = True  # Add is_authenticated attribute

@pytest.fixture
def authorized_user1():
    return MockUser("maxriahi@gmail.com")

@pytest.fixture
def authorized_user2():
    return MockUser("mriahi@ooti.co")

@pytest.fixture
def unauthorized_user1():
    return MockUser("someone@example.com")

@pytest.fixture
def unauthorized_user2():
    return MockUser("another@gmail.com")

@pytest.fixture
def empty_email_user():
    return MockUser("")

@pytest.fixture
def case_variant_user():
    return MockUser("MaxRiahi@Gmail.com")  # Different case

def test_authorized_emails_list_validity():
    """Test that the authorized emails list contains the expected values."""
    assert "maxriahi@gmail.com" in AUTHORIZED_EMAILS
    assert "mriahi@ooti.co" in AUTHORIZED_EMAILS
    assert len(AUTHORIZED_EMAILS) == 2

def test_authorized_email_validation(authorized_user1, authorized_user2, 
                                   unauthorized_user1, unauthorized_user2):
    """Test that only authorized emails pass validation."""
    # Authorized emails
    assert is_authorized_email(authorized_user1.email) is True
    assert is_authorized_email(authorized_user2.email) is True
    
    # Unauthorized emails
    assert is_authorized_email(unauthorized_user1.email) is False
    assert is_authorized_email(unauthorized_user2.email) is False

def test_empty_email_validation(empty_email_user):
    """Test that empty emails are rejected."""
    assert is_authorized_email(empty_email_user.email) is False
    assert is_authorized_email(None) is False

def test_case_insensitivity(case_variant_user):
    """Test that email validation is case-insensitive."""
    assert is_authorized_email(case_variant_user.email) is True

def test_user_email_authorization(authorized_user1, unauthorized_user1):
    """Test the user object authorization function."""
    assert check_user_email_authorization(authorized_user1) is True
    assert check_user_email_authorization(unauthorized_user1) is False
    assert check_user_email_authorization(None) is False

def test_user_without_email_attribute():
    """Test handling of objects without an email attribute."""
    user_without_email = MagicMock()
    del user_without_email.email  # Remove the email attribute
    
    assert check_user_email_authorization(user_without_email) is False

def test_integration_with_decorator():
    """Test the decorator's effect on functions requiring email authorization."""
    from utils.access_control import restricted_access_required
    from flask import g, request_started
    from flask_login import current_user
    
    # Create a test Flask app for the context
    from flask import Flask
    app = Flask(__name__)
    
    # Create a mock function to decorate
    mock_fn = MagicMock(return_value="success")
    decorated_fn = restricted_access_required(mock_fn)
    
    # Use the Flask app context for testing
    with app.test_request_context():
        # Test with authorized email
        with patch('utils.access_control.current_user', 
                   MockUser("maxriahi@gmail.com")):
            with patch('utils.access_control.check_user_email_authorization', return_value=True):
                result = decorated_fn()
                assert result == "success"  # Function should execute
                mock_fn.assert_called_once()
        
        # Reset the mock
        mock_fn.reset_mock()
        
        # Test with unauthorized email
        with patch('utils.access_control.current_user', 
                   MockUser("unauthorized@example.com")):
            with patch('utils.access_control.check_user_email_authorization', return_value=False):
                with patch('utils.access_control.abort') as mock_abort:
                    decorated_fn()
                    # Should abort with 403 Forbidden
                    mock_abort.assert_called_once_with(403) 
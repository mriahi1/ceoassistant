from unittest.mock import MagicMock, patch

def test_email_access_restriction():
    """Test that only specified email addresses can access data"""
    
    # Authorized email addresses list
    AUTHORIZED_EMAILS = ["maxriahi@gmail.com", "mriahi@ooti.co"]
    
    # Mock user access control function
    def can_access_data(user):
        """Check if a user can access data based on email"""
        if not user or not hasattr(user, 'email'):
            return False
        
        return user.email.lower() in [email.lower() for email in AUTHORIZED_EMAILS]
    
    # Create mock users with different email addresses
    authorized_user1 = MagicMock(email="maxriahi@gmail.com")
    authorized_user2 = MagicMock(email="mriahi@ooti.co")
    unauthorized_user1 = MagicMock(email="random@example.com")
    unauthorized_user2 = MagicMock(email="attacker@malicious.com")
    case_different_user = MagicMock(email="MaxRiahi@Gmail.com")  # Test case insensitivity
    none_user = None
    user_without_email = MagicMock()
    delattr(user_without_email, 'email')  # Remove email attribute
    
    # Test authorized emails
    assert can_access_data(authorized_user1), "Authorized user 1 (maxriahi@gmail.com) should have access"
    assert can_access_data(authorized_user2), "Authorized user 2 (mriahi@ooti.co) should have access"
    
    # Test case insensitivity
    assert can_access_data(case_different_user), "Case-different email (MaxRiahi@Gmail.com) should have access"
    
    # Test unauthorized emails
    assert not can_access_data(unauthorized_user1), "Unauthorized user (random@example.com) should be denied access"
    assert not can_access_data(unauthorized_user2), "Unauthorized user (attacker@malicious.com) should be denied access"
    
    # Test edge cases
    assert not can_access_data(none_user), "None user should be denied access"
    assert not can_access_data(user_without_email), "User without email attribute should be denied access"

def test_email_access_in_request_handler():
    """Test email access restriction in a simulated request handler"""
    
    # Authorized email addresses
    AUTHORIZED_EMAILS = ["maxriahi@gmail.com", "mriahi@ooti.co"]
    
    # Mock request handler function
    def handle_data_request(user, requested_data_id):
        """Handle data request with email authorization check"""
        # First check if user is authorized by email
        if not user or not hasattr(user, 'email') or user.email.lower() not in [email.lower() for email in AUTHORIZED_EMAILS]:
            return {"error": "Access denied", "status": 403}
        
        # If authorized, return the requested data
        return {
            "data": f"Sensitive data for ID: {requested_data_id}",
            "status": 200
        }
    
    # Create mock users with different emails
    authorized_user = MagicMock(email="maxriahi@gmail.com")
    unauthorized_user = MagicMock(email="unauthorized@example.com")
    
    # Test authorized request
    response = handle_data_request(authorized_user, "data123")
    assert response["status"] == 200, "Authorized user should get status 200"
    assert "Sensitive data" in response["data"], "Authorized user should get the data"
    
    # Test unauthorized request
    response = handle_data_request(unauthorized_user, "data123")
    assert response["status"] == 403, "Unauthorized user should get status 403"
    assert "error" in response, "Unauthorized user should get an error message"
    assert "Access denied" in response["error"], "Error should indicate access is denied"

def test_endpoint_integration():
    """Test email restriction integrated with endpoint handler simulation"""
    
    # Configuration
    AUTHORIZED_EMAILS = ["maxriahi@gmail.com", "mriahi@ooti.co"]
    
    # Mock authentication and access control systems
    class AuthSystem:
        def get_current_user(self, request):
            # In a real system, this would extract user info from the request
            return request.get("user", None)
        
        def is_email_authorized(self, email):
            if not email:
                return False
            return email.lower() in [e.lower() for e in AUTHORIZED_EMAILS]
    
    # Mock endpoint handler
    def api_endpoint_handler(request, auth_system):
        """Simulate an API endpoint that handles data access requests"""
        # Get the current user
        current_user = auth_system.get_current_user(request)
        
        # Check if user exists and has an email
        if not current_user or not hasattr(current_user, 'email'):
            return {"error": "Authentication required", "status": 401}
        
        # Check if the email is authorized
        if not auth_system.is_email_authorized(current_user.email):
            return {"error": "Access denied", "status": 403}
        
        # Return the requested data if authorized
        return {
            "data": "Sensitive business metrics and KPIs",
            "user": current_user.email,
            "status": 200
        }
    
    # Create an instance of the auth system
    auth_system = AuthSystem()
    
    # Test with authorized user
    authorized_user = MagicMock(email="maxriahi@gmail.com")
    authorized_request = {"user": authorized_user, "path": "/api/data"}
    
    response = api_endpoint_handler(authorized_request, auth_system)
    assert response["status"] == 200, "Authorized request should succeed"
    assert "Sensitive business metrics" in response["data"], "Data should be returned for authorized user"
    
    # Test with unauthorized user
    unauthorized_user = MagicMock(email="hacker@example.com")
    unauthorized_request = {"user": unauthorized_user, "path": "/api/data"}
    
    response = api_endpoint_handler(unauthorized_request, auth_system)
    assert response["status"] == 403, "Unauthorized request should be forbidden"
    assert "error" in response, "Error should be returned for unauthorized user"
    
    # Test with unauthenticated request
    unauthenticated_request = {"path": "/api/data"}  # No user provided
    
    response = api_endpoint_handler(unauthenticated_request, auth_system)
    assert response["status"] == 401, "Unauthenticated request should require authentication"
    assert "Authentication required" in response["error"], "Error should indicate authentication is required" 
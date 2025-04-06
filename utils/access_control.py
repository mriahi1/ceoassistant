from functools import wraps
from flask import current_app, request, jsonify, abort
from flask_login import current_user
from utils.audit_logger import log_access_attempt

# Authorized email addresses - these are the only emails allowed to access restricted data
AUTHORIZED_EMAILS = ["maxriahi@gmail.com", "mriahi@ooti.co"]

def is_authorized_email(email):
    """
    Check if an email address is in the authorized list
    
    Args:
        email (str): Email address to check
        
    Returns:
        bool: True if authorized, False otherwise
    """
    if not email:
        return False
    
    return email.lower() in [authorized_email.lower() for authorized_email in AUTHORIZED_EMAILS]

def check_user_email_authorization(user):
    """
    Check if a user object has an authorized email address
    
    Args:
        user: User object with email attribute
        
    Returns:
        bool: True if authorized, False otherwise
    """
    if not user:
        return False
    
    # Check if the user object has an email attribute
    if not hasattr(user, 'email'):
        return False
    
    return is_authorized_email(user.email)

def restricted_access_required(f):
    """
    Decorator to restrict access to only authorized email addresses
    
    This decorator should be applied to routes that contain sensitive business data
    that should only be accessible to specific email addresses.
    
    Usage:
        @app.route('/api/sensitive-data')
        @login_required  # Make sure user is logged in first
        @restricted_access_required  # Then check if their email is authorized
        def sensitive_data():
            return jsonify({"data": "sensitive information"})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First, ensure we have a valid logged-in user
        if not current_user or not current_user.is_authenticated:
            # Log unauthorized attempt
            log_access_attempt(None, request.path, False, "User not authenticated")
            return abort(401)  # Unauthorized
            
        # Then check if the user's email is authorized
        if not check_user_email_authorization(current_user):
            # Log forbidden attempt
            log_access_attempt(current_user, request.path, False, "Email not authorized")
            return abort(403)  # Forbidden
            
        # Log successful access
        log_access_attempt(current_user, request.path, True)
        
        # Allow access to the route
        return f(*args, **kwargs)
    return decorated_function

def can_access_data(user, data_type=None):
    """
    Function to check if a user can access a specific type of data
    
    Args:
        user: User object with email attribute
        data_type (str, optional): Type of data being accessed, for more granular control
        
    Returns:
        bool: True if user can access the data, False otherwise
    """
    # First check basic email authorization
    if not check_user_email_authorization(user):
        return False
    
    # If needed, add more granular access control based on data_type
    # For example, certain data might require additional checks beyond email
    
    return True 
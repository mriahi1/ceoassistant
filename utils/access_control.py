from functools import wraps
from flask import current_app, request, jsonify, abort
from flask_login import current_user

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
    if not user or not hasattr(user, 'email'):
        return False
    
    return is_authorized_email(user.email)

def restricted_access_required(f):
    """
    Decorator for routes that require email-based access restrictions.
    This ensures only users with specific email addresses can access the route.
    
    Usage:
        @app.route('/protected-data')
        @login_required  # First ensure the user is logged in
        @restricted_access_required  # Then check if their email is authorized
        def protected_data():
            return render_template('protected_data.html')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Ensure user is authenticated (should be handled by login_required)
        if not current_user.is_authenticated:
            abort(401)  # Unauthorized
        
        # Check if user's email is in the authorized list
        if not check_user_email_authorization(current_user):
            # If not authorized, return 403 Forbidden
            if request.content_type == 'application/json':
                return jsonify({
                    'error': 'Access denied',
                    'message': 'Your email address is not authorized to access this resource'
                }), 403
            else:
                abort(403)  # Forbidden
                
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
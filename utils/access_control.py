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
    Decorator to restrict access to only authorized email addresses.
    Must be used after @login_required to ensure user is authenticated.
    
    Example:
        @app.route('/api/sensitive-data')
        @login_required
        @restricted_access_required
        def sensitive_data_endpoint():
            return jsonify({"data": "sensitive"})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Ensure user is authenticated (should be handled by login_required)
        if not current_user.is_authenticated:
            # Log the unauthorized access attempt
            log_access_attempt(
                endpoint=request.path,
                access_granted=False,
                details={"reason": "User not authenticated"}
            )
            abort(401)
        
        # Check if the user's email is authorized
        if check_user_email_authorization(current_user):
            # Log successful access
            log_access_attempt(
                endpoint=request.path,
                access_granted=True,
                user_email=current_user.email,
                user_id=current_user.id
            )
            # Allow access
            return f(*args, **kwargs)
        else:
            # Log denied access
            log_access_attempt(
                endpoint=request.path,
                access_granted=False,
                user_email=current_user.email if hasattr(current_user, 'email') else None,
                user_id=current_user.id if hasattr(current_user, 'id') else None,
                details={"reason": "Email not authorized"}
            )
            
            # Check content type to determine response format
            if request.content_type == 'application/json':
                return jsonify({
                    "error": "Access denied",
                    "message": "Your email is not authorized to access this resource."
                }), 403
            else:
                # HTML response - redirect to a forbidden page or abort
                abort(403)
    
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
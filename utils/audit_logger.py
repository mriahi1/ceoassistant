import os
import json
import logging
import time
from datetime import datetime
from functools import wraps
from logging.handlers import RotatingFileHandler
from flask import request, current_app, g, session
from flask_login import current_user

# Set up a dedicated audit logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

# Ensure log directory exists
def ensure_log_dir():
    """Create the log directory if it doesn't exist"""
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    return log_dir

# Configure file handler for audit logs with rotation
log_dir = ensure_log_dir()
audit_log_file = os.path.join(log_dir, 'access_audit.log')

# Set up rotating file handler - 10MB max size, keep 5 backup files
file_handler = RotatingFileHandler(
    audit_log_file,
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.INFO)

# Create a formatter that includes all relevant details
formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)
audit_logger.addHandler(file_handler)

def log_access_attempt(endpoint, access_granted, user_email=None, user_id=None, details=None):
    """
    Log an access attempt to a restricted resource
    
    Args:
        endpoint (str): The endpoint or resource being accessed
        access_granted (bool): Whether access was granted
        user_email (str, optional): The email of the user making the request
        user_id (str, optional): The ID of the user making the request
        details (dict, optional): Additional details about the request
    """
    # Get user information if not provided
    if not user_email and hasattr(current_user, 'email'):
        user_email = current_user.email
    
    if not user_id and hasattr(current_user, 'id'):
        user_id = current_user.id
    
    # Create the log entry
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'endpoint': endpoint,
        'access_granted': access_granted,
        'user_email': user_email,
        'user_id': user_id,
        'ip_address': request.remote_addr,
        'method': request.method,
        'user_agent': request.user_agent.string,
        'session_id': session.get('_id', None)
    }
    
    # Add any additional details
    if details:
        log_data.update(details)
    
    # Determine log level based on whether access was granted
    log_level = logging.INFO if access_granted else logging.WARNING
    
    # Create a log message
    status = "GRANTED" if access_granted else "DENIED"
    log_message = f"ACCESS {status} | {user_email or 'Unknown'} | {endpoint} | {request.remote_addr}"
    
    # Log the message and detailed JSON data
    audit_logger.log(log_level, log_message)
    audit_logger.log(log_level, json.dumps(log_data))
    
    # Also log to the application logger for visibility
    if not access_granted:
        current_app.logger.warning(f"Access denied to {endpoint} for {user_email or 'Unknown'}")
    
    return log_data

def audit_access_decorator(func):
    """
    Decorator to audit access to a function or route
    
    Example:
        @app.route('/api/sensitive-data')
        @login_required
        @restricted_access_required
        @audit_access_decorator
        def sensitive_data_endpoint():
            return jsonify({"data": "sensitive"})
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        access_granted = True
        start_time = time.time()
        
        try:
            # Attempt to execute the function
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            # If an exception occurs, access is considered denied
            access_granted = False
            
            # Log details about the exception
            details = {
                'error': str(e),
                'error_type': type(e).__name__
            }
            
            # Re-raise the exception
            raise
        finally:
            # Calculate response time
            response_time = time.time() - start_time
            
            # Endpoint information
            endpoint = request.path
            
            # Additional details
            details = {
                'response_time': round(response_time, 6),
                'query_params': dict(request.args),
                'referrer': request.referrer,
            }
            
            # Log the access attempt
            log_access_attempt(endpoint, access_granted, details=details)
    
    return decorated_function

# Helper function to manually log access when decorator can't be used
def log_resource_access(resource_name, access_granted, details=None):
    """
    Manually log access to a resource when the decorator can't be used
    
    Args:
        resource_name (str): Name of the resource being accessed
        access_granted (bool): Whether access was granted
        details (dict, optional): Additional details about the access
    """
    endpoint = f"resource:{resource_name}"
    return log_access_attempt(endpoint, access_granted, details=details) 
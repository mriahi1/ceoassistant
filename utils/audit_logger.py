import os
import json
import logging
import time
from datetime import datetime
from functools import wraps
from logging.handlers import RotatingFileHandler
from flask import request, current_app, g, session
from flask_login import current_user

# Set up logging configuration
log_directory = os.environ.get('LOG_DIR', 'logs')
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Configure the logger
audit_logger = logging.getLogger('audit_logger')
audit_logger.setLevel(logging.INFO)

# Create a rotating file handler
audit_file_handler = RotatingFileHandler(
    os.path.join(log_directory, 'access_audit.log'),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
audit_file_handler.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
audit_file_handler.setFormatter(formatter)

# Add the handler to the logger
audit_logger.addHandler(audit_file_handler)

def log_access_attempt(user, endpoint, granted, reason=None):
    """
    Log an access attempt to a restricted endpoint
    
    Args:
        user: The user attempting to access the endpoint
        endpoint: The endpoint being accessed
        granted: Whether access was granted (True) or denied (False)
        reason: Reason for denial if access was denied
    """
    try:
        # Get user information
        user_email = getattr(user, 'email', 'unknown') if user else 'anonymous'
        user_id = getattr(user, 'id', 'unknown') if user else 'anonymous'
        
        # Create log entry
        log_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'user_email': user_email,
            'user_id': user_id,
            'endpoint': endpoint,
            'ip_address': request.remote_addr if request else 'unknown',
            'access_granted': granted,
            'method': request.method if request else 'unknown',
            'reason': reason or ('Access granted' if granted else 'Access denied')
        }
        
        # Log the access attempt
        audit_logger.info(json.dumps(log_data))
        
        # For particularly sensitive actions, also log to application log
        if not granted or 'api/metrics' in endpoint or 'api/insights' in endpoint:
            app_logger = current_app.logger if current_app else logging.getLogger('app')
            log_message = f"Access {'GRANTED' if granted else 'DENIED'} to {endpoint} for user {user_email}"
            if not granted:
                app_logger.warning(log_message)
            else:
                app_logger.info(log_message)
                
    except Exception as e:
        # Log any errors with the logging process itself
        error_message = f"Error logging access attempt: {str(e)}"
        current_app.logger.error(error_message) if current_app else print(error_message)

def get_access_logs(email=None, endpoint=None, granted=None, start_date=None, end_date=None):
    """
    Get filtered access logs from the audit log file
    
    Args:
        email (str, optional): Filter by user email
        endpoint (str, optional): Filter by endpoint
        granted (bool, optional): Filter by access granted/denied
        start_date (str, optional): Filter by start date (ISO format)
        end_date (str, optional): Filter by end date (ISO format)
        
    Returns:
        list: Filtered log entries
    """
    logs = []
    try:
        log_file = os.path.join(log_directory, 'access_audit.log')
        if not os.path.exists(log_file):
            return []
            
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    # Extract the JSON part from the log entry
                    json_str = line.split(' - INFO - ')[1].strip() if ' - INFO - ' in line else None
                    if not json_str:
                        continue
                        
                    entry = json.loads(json_str)
                    
                    # Apply filters
                    if email and entry.get('user_email') != email:
                        continue
                    if endpoint and endpoint not in entry.get('endpoint', ''):
                        continue
                    if granted is not None and entry.get('access_granted') != granted:
                        continue
                    if start_date:
                        entry_date = datetime.datetime.fromisoformat(entry.get('timestamp'))
                        if entry_date < datetime.datetime.fromisoformat(start_date):
                            continue
                    if end_date:
                        entry_date = datetime.datetime.fromisoformat(entry.get('timestamp'))
                        if entry_date > datetime.datetime.fromisoformat(end_date):
                            continue
                            
                    logs.append(entry)
                except (json.JSONDecodeError, IndexError) as e:
                    # Skip entries that can't be parsed
                    continue
    except Exception as e:
        # Handle any errors reading the log file
        error_message = f"Error reading access logs: {str(e)}"
        if current_app:
            current_app.logger.error(error_message)
        else:
            print(error_message)
            
    return logs

def get_access_stats(start_date=None, end_date=None):
    """
    Get statistics from access logs
    
    Args:
        start_date (str, optional): Start date in ISO format
        end_date (str, optional): End date in ISO format
        
    Returns:
        dict: Statistics about access attempts
    """
    logs = get_access_logs(start_date=start_date, end_date=end_date)
    
    stats = {
        'total_attempts': len(logs),
        'granted': sum(1 for log in logs if log.get('access_granted')),
        'denied': sum(1 for log in logs if not log.get('access_granted')),
        'endpoints': {},
        'users': {}
    }
    
    # Group by endpoint
    for log in logs:
        endpoint = log.get('endpoint', 'unknown')
        if endpoint not in stats['endpoints']:
            stats['endpoints'][endpoint] = {
                'total': 0,
                'granted': 0,
                'denied': 0
            }
        
        stats['endpoints'][endpoint]['total'] += 1
        if log.get('access_granted'):
            stats['endpoints'][endpoint]['granted'] += 1
        else:
            stats['endpoints'][endpoint]['denied'] += 1
            
    # Group by user
    for log in logs:
        user = log.get('user_email', 'unknown')
        if user not in stats['users']:
            stats['users'][user] = {
                'total': 0,
                'granted': 0,
                'denied': 0
            }
            
        stats['users'][user]['total'] += 1
        if log.get('access_granted'):
            stats['users'][user]['granted'] += 1
        else:
            stats['users'][user]['denied'] += 1
            
    return stats

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
            log_access_attempt(current_user, endpoint, access_granted, details=details)
    
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
    return log_access_attempt(current_user, endpoint, access_granted, details=details) 
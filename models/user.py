from flask_login import UserMixin
import time

class User(UserMixin):
    """User class for authentication"""
    
    def __init__(self, id, email, name, picture=None, login_time=None):
        self.id = id
        self.email = email.lower()  # Store emails in lowercase for consistency
        self.name = name
        self.picture = picture
        self.login_time = login_time or int(time.time())
        self.last_active = self.login_time
    
    @staticmethod
    def get(user_id):
        """Retrieve a user by ID from the session"""
        from auth import users_db
        user = users_db.get(user_id)
        
        if user:
            # Update the last_active timestamp
            user.last_active = int(time.time())
            
            # Validate session lifetime
            # If it's been more than the allowed time, invalidate the session
            from flask import current_app
            max_session_seconds = current_app.config.get('PERMANENT_SESSION_LIFETIME').total_seconds()
            if (user.last_active - user.login_time) > max_session_seconds:
                # Session expired, remove from users_db
                users_db.pop(user_id, None)
                return None
        
        return user
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
        from flask import current_app
        
        if not user_id:
            current_app.logger.warning("User.get called with empty user_id")
            return None
            
        current_app.logger.debug(f"User.get: Looking up user_id: {user_id}")
        current_app.logger.debug(f"User.get: users_db contains {len(users_db)} users")
        
        user = users_db.get(user_id)
        
        if not user:
            current_app.logger.warning(f"User.get: User {user_id} not found in users_db")
            return None
            
        # Update the last_active timestamp
        user.last_active = int(time.time())
        
        # Validate session lifetime
        # If it's been more than the allowed time, invalidate the session
        max_session_seconds = current_app.config.get('PERMANENT_SESSION_LIFETIME').total_seconds()
        if (user.last_active - user.login_time) > max_session_seconds:
            # Session expired, remove from users_db
            current_app.logger.info(f"User.get: Session expired for user {user_id}")
            users_db.pop(user_id, None)
            return None
        
        current_app.logger.debug(f"User.get: Successfully retrieved user {user_id} ({user.email})")
        return user
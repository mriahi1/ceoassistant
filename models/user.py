from flask_login import UserMixin

class User(UserMixin):
    """User class for authentication"""
    
    def __init__(self, id, email, name, picture=None):
        self.id = id
        self.email = email
        self.name = name
        self.picture = picture
    
    @staticmethod
    def get(user_id):
        """Retrieve a user by ID from the session"""
        from auth import users_db
        return users_db.get(user_id)
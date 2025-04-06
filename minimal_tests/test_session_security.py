import time
import secrets
import hashlib
import json
from unittest.mock import MagicMock, patch

def test_session_expiration():
    """Test that sessions expire correctly after inactivity"""
    # Mock session class
    class Session:
        def __init__(self, user_id, max_age=3600):
            self.user_id = user_id
            self.created_at = int(time.time())
            self.last_activity = self.created_at
            self.max_age = max_age  # Session max age in seconds
            self.data = {}
        
        def is_expired(self, current_time=None):
            if not current_time:
                current_time = int(time.time())
            
            # Check if session is older than max_age
            session_age = current_time - self.last_activity
            return session_age > self.max_age
    
    # Create a session
    user_session = Session(user_id="user123", max_age=10)  # 10 seconds max age for testing
    
    # Session should not be expired immediately
    assert not user_session.is_expired(), "Session incorrectly expired when created"
    
    # Session should expire after max_age
    future_time = user_session.created_at + 15  # 15 seconds later
    assert user_session.is_expired(future_time), "Session did not expire after max_age"
    
    # Test activity extending session lifetime
    user_session = Session(user_id="user123", max_age=10)
    half_lifetime = user_session.created_at + 5  # 5 seconds later
    user_session.last_activity = half_lifetime  # User activity updates last_activity
    
    # Session should not expire after max_age from creation if there was activity
    future_time = user_session.created_at + 12  # 12 seconds after creation
    assert not user_session.is_expired(future_time), "Session expired despite recent activity"
    
    # Session should expire after max_age from last activity
    far_future_time = half_lifetime + 12  # 12 seconds after last activity
    assert user_session.is_expired(far_future_time), "Session did not expire after max_age from last activity"

def test_session_cookie_security():
    """Test session cookie security attributes"""
    # Mock secure cookie settings
    secure_cookie_settings = {
        "httponly": True,
        "secure": True,
        "samesite": "Strict",
        "path": "/",
        "max_age": 3600,
        "domain": "example.com"
    }
    
    # Mock insecure cookie settings
    insecure_cookie_settings = {
        "httponly": False,
        "secure": False,
        "samesite": None,
        "path": "/",
        "max_age": 3600,
        "domain": "example.com"
    }
    
    # Check secure cookie settings
    assert secure_cookie_settings["httponly"], "HttpOnly flag not set"
    assert secure_cookie_settings["secure"], "Secure flag not set"
    assert secure_cookie_settings["samesite"] == "Strict", "SameSite not set to Strict"
    
    # Validate cookie settings function
    def validate_cookie_settings(settings):
        # Minimum security requirements
        if not settings.get("httponly"):
            return False, "HttpOnly flag is required"
        
        if not settings.get("secure"):
            return False, "Secure flag is required for HTTPS"
        
        if not settings.get("samesite") or settings["samesite"] not in ["Strict", "Lax"]:
            return False, "SameSite must be Strict or Lax"
        
        # Path should be restricted
        if settings.get("path") == "/":
            # Root path is acceptable but not ideal for sensitive cookies
            pass
        
        return True, None
    
    # Secure settings should pass validation
    is_valid, error = validate_cookie_settings(secure_cookie_settings)
    assert is_valid, f"Secure cookie settings failed validation: {error}"
    
    # Insecure settings should fail validation
    is_valid, error = validate_cookie_settings(insecure_cookie_settings)
    assert not is_valid, "Insecure cookie settings passed validation"
    assert "HttpOnly" in error or "Secure" in error or "SameSite" in error, "Wrong error for insecure cookies"

def test_secure_session_id_generation():
    """Test generation of secure session IDs"""
    # Function to generate a secure session ID
    def generate_session_id(bit_length=128):
        """Generate a cryptographically secure session ID"""
        # Use secrets module for secure random token
        random_bytes = secrets.token_bytes(bit_length // 8)
        
        # Convert to hexadecimal
        return random_bytes.hex()
    
    # Generate multiple session IDs
    session_ids = [generate_session_id() for _ in range(10)]
    
    # Check session ID uniqueness
    assert len(session_ids) == len(set(session_ids)), "Session IDs are not unique"
    
    # Check session ID length (256 characters for 128 bytes in hex)
    for session_id in session_ids:
        assert len(session_id) == 32, f"Session ID has incorrect length: {len(session_id)}"
    
    # Check for sufficient entropy
    # This is a simplified check - real entropy measurement would be more complex
    unique_chars = []
    for session_id in session_ids:
        unique_chars.extend(list(session_id))
    
    unique_chars = set(unique_chars)
    assert len(unique_chars) >= 16, "Session IDs have insufficient character variety"

def test_session_invalidation():
    """Test proper session invalidation on logout and security events"""
    # Mock session store
    class SessionStore:
        def __init__(self):
            self.sessions = {}
        
        def create_session(self, user_id):
            session_id = secrets.token_hex(16)
            self.sessions[session_id] = {
                "user_id": user_id,
                "created_at": int(time.time()),
                "last_activity": int(time.time())
            }
            return session_id
        
        def get_session(self, session_id):
            return self.sessions.get(session_id)
        
        def invalidate_session(self, session_id):
            if session_id in self.sessions:
                del self.sessions[session_id]
                return True
            return False
        
        def invalidate_all_user_sessions(self, user_id):
            """Invalidate all sessions for a specific user"""
            invalidated_count = 0
            sessions_to_remove = []
            
            for session_id, session in self.sessions.items():
                if session["user_id"] == user_id:
                    sessions_to_remove.append(session_id)
                    invalidated_count += 1
            
            for session_id in sessions_to_remove:
                del self.sessions[session_id]
            
            return invalidated_count
    
    # Create session store and sessions
    store = SessionStore()
    
    # Create multiple sessions for the same user
    user1_session1 = store.create_session("user1")
    user1_session2 = store.create_session("user1")
    user1_session3 = store.create_session("user1")
    
    # Create a session for a different user
    user2_session = store.create_session("user2")
    
    # Check that all sessions exist
    assert store.get_session(user1_session1) is not None
    assert store.get_session(user1_session2) is not None
    assert store.get_session(user1_session3) is not None
    assert store.get_session(user2_session) is not None
    
    # Test single session invalidation (e.g., logout from one device)
    assert store.invalidate_session(user1_session1), "Session invalidation failed"
    assert store.get_session(user1_session1) is None, "Session still exists after invalidation"
    assert store.get_session(user1_session2) is not None, "Unrelated session was incorrectly invalidated"
    
    # Test all user sessions invalidation (e.g., password change, security breach)
    invalidated_count = store.invalidate_all_user_sessions("user1")
    assert invalidated_count == 2, f"Expected 2 sessions to be invalidated, got {invalidated_count}"
    assert store.get_session(user1_session2) is None, "User session still exists after invalidation"
    assert store.get_session(user1_session3) is None, "User session still exists after invalidation"
    assert store.get_session(user2_session) is not None, "Other user's session was incorrectly invalidated"

def test_session_fixation_prevention():
    """Test prevention of session fixation attacks"""
    # Mock session manager
    class SessionManager:
        def __init__(self):
            self.sessions = {}
        
        def create_session(self, user_id=None):
            """Create a new session"""
            session_id = secrets.token_hex(16)
            self.sessions[session_id] = {
                "user_id": user_id,
                "created_at": int(time.time())
            }
            return session_id
        
        def regenerate_session_id(self, old_session_id):
            """Regenerate session ID while preserving data (prevents fixation)"""
            if old_session_id not in self.sessions:
                return None
            
            # Create new session with same data
            old_session_data = self.sessions[old_session_id]
            new_session_id = secrets.token_hex(16)
            self.sessions[new_session_id] = old_session_data.copy()
            
            # Delete old session
            del self.sessions[old_session_id]
            
            return new_session_id
        
        def assign_user_to_session(self, session_id, user_id):
            """Assign user to session and regenerate session ID"""
            if session_id not in self.sessions:
                return None
            
            # Regenerate session ID when a user authenticates
            new_session_id = self.regenerate_session_id(session_id)
            
            # Update user info
            self.sessions[new_session_id]["user_id"] = user_id
            
            return new_session_id
    
    # Create session manager
    manager = SessionManager()
    
    # Simulate a user browsing anonymously
    anonymous_session_id = manager.create_session()
    assert anonymous_session_id in manager.sessions, "Anonymous session not created"
    
    # Simulate user login - this should regenerate the session ID
    authenticated_session_id = manager.assign_user_to_session(anonymous_session_id, "user123")
    
    # Original session ID should be invalidated
    assert anonymous_session_id not in manager.sessions, "Original session not invalidated after login"
    
    # New session ID should exist and contain the user ID
    assert authenticated_session_id in manager.sessions, "New session not created after login"
    assert manager.sessions[authenticated_session_id]["user_id"] == "user123", "User ID not assigned to new session"
    
    # Session IDs should be different
    assert anonymous_session_id != authenticated_session_id, "Session ID not regenerated after login" 
import hashlib
import secrets
import re

def test_password_strength():
    """Test password complexity requirements"""
    # Weak passwords that should fail
    weak_passwords = [
        "password",
        "12345678",
        "qwerty",
        "abc123",
        "letmein"
    ]
    
    # Strong passwords that should pass
    strong_passwords = [
        "P@ssw0rd123!",
        "Compl3x-P@ssw0rd",
        "W3!rd&W0nd3rful",
        "Dr0p$T@ble5",
        # Remove random token since it won't have special chars
    ]
    
    # Password complexity regex (uppercase, lowercase, digit, special char, 10+ chars)
    pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&\-])[A-Za-z\d@$!%*?&\-]{10,}$')
    
    # Test weak passwords (should fail)
    for password in weak_passwords:
        assert not pattern.match(password), f"Weak password '{password}' incorrectly passed complexity check"
    
    # Test strong passwords (should pass)
    for password in strong_passwords:
        assert pattern.match(password), f"Strong password '{password}' failed complexity check"

def test_token_generation():
    """Test secure token generation"""
    # Generate multiple tokens and verify they're different
    tokens = [secrets.token_hex(32) for _ in range(10)]
    
    # Check all tokens are unique (no collisions)
    assert len(tokens) == len(set(tokens)), "Token generation produced duplicates"
    
    # Check token length (64 chars for a 32-byte hex token)
    for token in tokens:
        assert len(token) == 64, f"Token has incorrect length: {len(token)}"

def test_password_hashing():
    """Test password hashing and verification"""
    password = "securepassword123"
    
    # Simple password hashing with salt
    salt = secrets.token_hex(16)
    hash1 = hashlib.sha256((password + salt).encode()).hexdigest()
    hash2 = hashlib.sha256((password + salt).encode()).hexdigest()
    wrong_hash = hashlib.sha256(("wrongpassword" + salt).encode()).hexdigest()
    
    # Same password + same salt should yield same hash
    assert hash1 == hash2, "Same password with same salt produced different hashes"
    
    # Different passwords should yield different hashes
    assert hash1 != wrong_hash, "Different passwords produced same hash"

def test_csrf_token_validation():
    """Test CSRF token validation logic"""
    def generate_token():
        return secrets.token_hex(16)
        
    def validate_token(token1, token2):
        # Tokens must be present and match
        return token1 and token2 and token1 == token2
    
    # Generate tokens
    real_token = generate_token()
    fake_token = generate_token()
    empty_token = ""
    
    # Valid comparison (same tokens)
    assert validate_token(real_token, real_token), "Valid tokens failed validation"
    
    # Invalid comparisons
    assert not validate_token(real_token, fake_token), "Different tokens passed validation"
    assert not validate_token(real_token, empty_token), "Empty token passed validation"
    assert not validate_token(empty_token, real_token), "Empty token passed validation"

def test_input_sanitization():
    """Test input sanitization for XSS prevention"""
    def sanitize_input(text):
        """Enhanced HTML sanitization with attribute filtering"""
        if not isinstance(text, str):
            return ""
        
        # Block dangerous event attributes
        dangerous_attributes = [
            "onerror", "onclick", "onload", "onmouseover", "onfocus", 
            "onblur", "onchange", "onsubmit", "onkeydown", "onkeypress", "onkeyup"
        ]
        
        # First replace all dangerous attributes with blocked versions
        for attr in dangerous_attributes:
            pattern = re.compile(f'({attr}=)', re.IGNORECASE)
            text = pattern.sub('blocked_', text)
        
        # Replace potentially dangerous characters
        replacements = {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;",
            "/": "&#x2F;",
            "&": "&amp;"
        }
            
        # Process & first to avoid double-encoding
        if "&" in text:
            text = text.replace("&", "&amp;")
            
        # Then replace other characters
        for char, replacement in replacements.items():
            if char != "&":  # Skip & since we already handled it
                text = text.replace(char, replacement)
        
        # Also replace javascript: protocol (case insensitive)
        text = re.sub(r'(?i)javascript:', '[blocked]', text)
        
        return text
    
    # Test various malicious inputs
    xss_attempts = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        '<img src="x" onerror="alert(\'XSS\')">',
        '<a href="javascript:alert(\'XSS\')">Click me</a>',
        '"><script>alert("XSS")</script>',
        '<scr<script>ipt>alert("XSS")</script>'
    ]
    
    for attempt in xss_attempts:
        sanitized = sanitize_input(attempt)
        # Check that the sanitized string doesn't contain dangerous HTML tags
        assert "<script>" not in sanitized, f"Sanitization failed for: {attempt}"
        assert "javascript:" not in sanitized, f"Sanitization failed for: {attempt}"
        assert "onerror=" not in sanitized, f"Sanitization failed for: {attempt}" 
import re
import json
import time
import hashlib
import hmac
from unittest.mock import MagicMock, patch

def test_api_rate_limiting():
    """Test rate limiting for API requests"""
    # Mock rate limiter class
    class RateLimiter:
        def __init__(self, limit=10, window=60):
            # Rate limit: `limit` requests per `window` seconds
            self.limit = limit
            self.window = window
            self.requests = {}  # ip -> list of timestamps
        
        def check_rate_limit(self, ip):
            current_time = time.time()
            if ip not in self.requests:
                self.requests[ip] = []
            
            # Remove old requests outside the time window
            self.requests[ip] = [t for t in self.requests[ip] if current_time - t < self.window]
            
            # Check if client exceeded the rate limit
            if len(self.requests[ip]) >= self.limit:
                return False
            
            # Add the current request
            self.requests[ip].append(current_time)
            return True
    
    # Test rate limiting
    limiter = RateLimiter(limit=5, window=10)
    ip = "192.168.1.1"
    
    # First 5 requests should be allowed
    for _ in range(5):
        assert limiter.check_rate_limit(ip), "Request within rate limit was blocked"
    
    # 6th request should be blocked
    assert not limiter.check_rate_limit(ip), "Request exceeding rate limit was allowed"
    
    # Different IP should not be affected
    different_ip = "192.168.1.2"
    assert limiter.check_rate_limit(different_ip), "Request from different IP was incorrectly blocked"
    
    # After window expires, requests should be allowed again
    # Patch the rate limiter's request list to simulate time passing
    limiter.requests[ip] = [time.time() - 11]  # Request from 11 seconds ago (outside window)
    assert limiter.check_rate_limit(ip), "Request after window expired was incorrectly blocked"

def test_api_key_validation():
    """Test API key validation"""
    # Mock API key validation function
    def validate_api_key(api_key, stored_keys):
        if not api_key:
            return False
        
        # Check if API key exists in stored keys
        return api_key in stored_keys
    
    # Mock stored API keys
    stored_keys = [
        "sk_test_123456789abcdef",
        "sk_live_abcdef123456789",
        "sk_test_validtestapikey"
    ]
    
    # Valid API key should pass validation
    assert validate_api_key("sk_test_123456789abcdef", stored_keys), "Valid API key failed validation"
    
    # Invalid API key should fail validation
    assert not validate_api_key("invalid_key", stored_keys), "Invalid API key passed validation"
    
    # Empty API key should fail validation
    assert not validate_api_key("", stored_keys), "Empty API key passed validation"
    assert not validate_api_key(None, stored_keys), "None API key passed validation"

def test_jwt_token_validation():
    """Test JWT token validation"""
    # Simple JWT token structure (this is a bare-bones implementation for testing)
    class JWTToken:
        def __init__(self, payload, secret_key):
            self.payload = payload
            self.secret_key = secret_key
            self.issued_at = int(time.time())
            self.expires_at = self.issued_at + 3600  # 1 hour expiration
        
        def generate_token(self):
            # In a real implementation, this would properly encode the JWT
            header = {"alg": "HS256", "typ": "JWT"}
            claims = {
                "sub": self.payload.get("sub", ""),
                "iat": self.issued_at,
                "exp": self.expires_at,
                **self.payload
            }
            token_data = {
                "header": header,
                "claims": claims,
                "signature": "mock_signature"
            }
            return json.dumps(token_data)
    
    # Mock JWT validator
    def validate_jwt(token_str, secret_key):
        try:
            token_data = json.loads(token_str)
            claims = token_data["claims"]
            
            # Check token expiration
            current_time = int(time.time())
            if current_time > claims["exp"]:
                return False, "Token expired"
            
            # In a real implementation, verify the signature
            # Here we just do a basic check
            if "signature" not in token_data:
                return False, "Invalid token format"
            
            return True, claims
        except Exception as e:
            return False, f"Invalid token: {str(e)}"
    
    # Create a valid token
    secret_key = "super_secret_key"
    valid_payload = {"sub": "user123", "role": "admin"}
    valid_token = JWTToken(valid_payload, secret_key)
    token_str = valid_token.generate_token()
    
    # Valid token should pass validation
    is_valid, claims = validate_jwt(token_str, secret_key)
    assert is_valid, "Valid JWT token failed validation"
    assert claims["sub"] == "user123", "JWT payload data corrupted"
    
    # Create an expired token (simulate by directly modifying the claims)
    token_data = json.loads(token_str)
    token_data["claims"]["exp"] = int(time.time()) - 3600  # 1 hour in the past
    expired_token_str = json.dumps(token_data)
    
    # Expired token should fail validation
    is_valid, error = validate_jwt(expired_token_str, secret_key)
    assert not is_valid, "Expired JWT token passed validation"
    assert "expired" in error.lower(), "Wrong error for expired token"
    
    # Invalid token format should fail validation
    invalid_token = '{"not-a-valid-token": true}'
    is_valid, error = validate_jwt(invalid_token, secret_key)
    assert not is_valid, "Invalid JWT token passed validation"

def test_api_request_signing():
    """Test API request signing and validation"""
    # Mock request signing function
    def sign_request(request_data, api_key):
        # Create a string representation of the request
        canonical_request = json.dumps(request_data, sort_keys=True)
        
        # Sign the request using HMAC-SHA256
        signature = hmac.new(
            api_key.encode(), 
            canonical_request.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    # Mock request validation function
    def validate_signed_request(request_data, signature, api_key):
        expected_signature = sign_request(request_data, api_key)
        return signature == expected_signature
    
    # Test data
    api_key = "test_api_key_for_signing"
    request_data = {
        "user_id": 123,
        "action": "get_data",
        "timestamp": "2023-07-01T12:00:00Z"
    }
    
    # Generate signature
    signature = sign_request(request_data, api_key)
    
    # Valid request should pass validation
    assert validate_signed_request(request_data, signature, api_key), "Valid signed request failed validation"
    
    # Tampered request should fail validation
    tampered_data = request_data.copy()
    tampered_data["user_id"] = 456
    assert not validate_signed_request(tampered_data, signature, api_key), "Tampered request passed validation"
    
    # Invalid signature should fail validation
    invalid_signature = "invalid_signature"
    assert not validate_signed_request(request_data, invalid_signature, api_key), "Invalid signature passed validation"

def test_api_input_validation():
    """Test API input validation"""
    # Mock input validation function
    def validate_api_input(input_data, schema):
        # Check required fields
        for field, properties in schema.items():
            if properties.get("required", False):
                if field not in input_data:
                    return False, f"Missing required field: {field}"
                
                # Check if field is empty
                if input_data[field] is None or input_data[field] == "":
                    return False, f"Required field '{field}' cannot be empty"
            
            # If field is present, validate its type
            if field in input_data and input_data[field] is not None:
                expected_type = properties.get("type")
                if expected_type:
                    # Type validation
                    if expected_type == "string" and not isinstance(input_data[field], str):
                        return False, f"Field '{field}' must be a string"
                    elif expected_type == "number" and not isinstance(input_data[field], (int, float)):
                        return False, f"Field '{field}' must be a number"
                    elif expected_type == "boolean" and not isinstance(input_data[field], bool):
                        return False, f"Field '{field}' must be a boolean"
                    elif expected_type == "array" and not isinstance(input_data[field], list):
                        return False, f"Field '{field}' must be an array"
                    elif expected_type == "object" and not isinstance(input_data[field], dict):
                        return False, f"Field '{field}' must be an object"
                
                # Pattern validation for strings
                if expected_type == "string" and "pattern" in properties:
                    pattern = re.compile(properties["pattern"])
                    if not pattern.match(input_data[field]):
                        return False, f"Field '{field}' does not match required pattern"
                
                # Range validation for numbers
                if expected_type == "number":
                    if "min" in properties and input_data[field] < properties["min"]:
                        return False, f"Field '{field}' is less than minimum value {properties['min']}"
                    if "max" in properties and input_data[field] > properties["max"]:
                        return False, f"Field '{field}' is greater than maximum value {properties['max']}"
        
        return True, None
    
    # Test schema
    schema = {
        "username": {
            "type": "string",
            "required": True,
            "pattern": r"^[a-zA-Z0-9_]{3,16}$"
        },
        "email": {
            "type": "string",
            "required": True,
            "pattern": r"^[\w.-]+@[a-zA-Z\d.-]+\.[a-zA-Z]{2,}$"
        },
        "age": {
            "type": "number",
            "required": False,
            "min": 13,
            "max": 120
        },
        "is_active": {
            "type": "boolean",
            "required": False
        }
    }
    
    # Valid input should pass validation
    valid_input = {
        "username": "testuser",
        "email": "test@example.com",
        "age": 25,
        "is_active": True
    }
    is_valid, error = validate_api_input(valid_input, schema)
    assert is_valid, f"Valid input failed validation: {error}"
    
    # Missing required field should fail validation
    missing_required = {
        "username": "testuser"
        # missing email
    }
    is_valid, error = validate_api_input(missing_required, schema)
    assert not is_valid, "Input with missing required field passed validation"
    assert "Missing required field: email" in error
    
    # Invalid type should fail validation
    invalid_type = {
        "username": "testuser",
        "email": "test@example.com",
        "age": "twenty-five"  # should be a number
    }
    is_valid, error = validate_api_input(invalid_type, schema)
    assert not is_valid, "Input with invalid type passed validation"
    assert "must be a number" in error
    
    # Invalid pattern should fail validation
    invalid_pattern = {
        "username": "test user",  # contains a space
        "email": "test@example.com"
    }
    is_valid, error = validate_api_input(invalid_pattern, schema)
    assert not is_valid, "Input with invalid pattern passed validation"
    assert "does not match required pattern" in error
    
    # Value outside of range should fail validation
    out_of_range = {
        "username": "testuser",
        "email": "test@example.com",
        "age": 10  # below minimum age
    }
    is_valid, error = validate_api_input(out_of_range, schema)
    assert not is_valid, "Input with value out of range passed validation"
    assert "less than minimum value" in error 
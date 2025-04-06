def test_basic_addition():
    """A simple test to verify pytest is working"""
    assert 1 + 1 == 2

def test_string_operations():
    """Test basic string operations"""
    s = "hello"
    assert s.upper() == "HELLO"
    assert s.capitalize() == "Hello"
    assert s.replace("e", "a") == "hallo" 
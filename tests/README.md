# CEO Assistant AI - Test Suite

This directory contains comprehensive tests to ensure the security and proper functioning of the CEO Assistant AI application.

## Test Coverage

The test suite covers the following areas:

### Security Tests
- **Authentication & Authorization**: Tests for login/logout flows, session management, and protected route access.
- **CSRF Protection**: Verifies proper CSRF token validation for both form submissions and AJAX requests.
- **OAuth Security**: Tests for OAuth state parameter validation, email verification, and session fixation prevention.
- **Path Traversal Prevention**: Tests for proper validation of file paths to prevent directory traversal attacks.
- **XSS Protection**: Tests sanitization of user inputs to prevent cross-site scripting attacks.
- **Security Headers**: Verifies that secure HTTP headers are correctly set.
- **Rate Limiting**: Tests rate limiting functionality to prevent abuse.

### Functional Tests
- **Core Routes**: Tests for proper rendering of pages and error handling.
- **Integration Status**: Tests for proper reporting of integration status.
- **Digest Generation**: Tests for generation and handling of daily digests.
- **Monitoring System**: Tests system monitoring functionality.
- **Scorecard System**: Tests for proper display of business performance metrics.
- **API Endpoints**: Tests API endpoints for proper data formatting and security.

## Running the Tests

### Prerequisites

- Python 3.8+
- pytest
- pytest-cov (for coverage reports)

### Installation

```bash
pip install -r requirements-dev.txt
```

### Running All Tests

```bash
pytest -v
```

### Running With Coverage

```bash
pytest --cov=app tests/
```

### Running Specific Test Categories

```bash
# Run just the security tests
pytest -v tests/test_security.py

# Run authentication tests
pytest -v tests/test_auth.py

# Run OAuth security tests
pytest -v tests/test_oauth_security.py

# Run functional tests
pytest -v tests/test_functionality.py
```

## Test Reports

You can generate HTML coverage reports with:

```bash
pytest --cov=app --cov-report=html tests/
```

This will create a `htmlcov` directory with an HTML report that you can open in your browser.

## Security Focus Areas

The test suite places special emphasis on security vulnerabilities that are common in web applications:

1. **Authentication Bypass**: Tests ensure protected routes cannot be accessed without authentication.
2. **CSRF Vulnerabilities**: Tests verify CSRF protection for all state-changing operations.
3. **Path Traversal**: Tests check that file operations are properly validated and sanitized.
4. **Session Security**: Tests ensure session fixation protection and proper session expiration.
5. **Input Validation**: Tests verify that user inputs are properly sanitized.
6. **OAuth Security**: Tests validate the secure implementation of Google OAuth authentication.

## Adding New Tests

When adding new features to the application, please also add corresponding tests. Follow these guidelines:

1. Create test functions within the appropriate test file
2. Use fixtures from `conftest.py` where possible
3. Mock external dependencies
4. Focus on both security and functionality aspects

## Contributors

If you find security issues while running these tests, please report them immediately to the development team. 
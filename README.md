# CEO Assistant AI

A comprehensive AI-powered dashboard for CEOs to centralize and automate data management, communication, and decision-making processes.

## Overview

CEO Assistant AI combines data from various business platforms to provide real-time insights, automate routine tasks, and generate daily briefings. The application integrates with:

- HubSpot (CRM data, deals, contacts)
- Chargebee (Subscription management)
- OOTI (Project management, KPIs)
- Google Workspace (Gmail, Drive, Calendar)
- Slack (Team communication)
- OpenAI (AI-powered insights and summaries)

## Features

- **Dashboard**: Central view of key metrics, insights, and action items
- **Daily Digests**: AI-generated summaries of business performance
- **Email Management**: View, search, and send emails through Gmail
- **Document Management**: Access and manage files in Google Drive
- **Calendar Integration**: View schedule, meetings, and conflicts
- **Financial Overview**: Track financial metrics from accounting platforms
- **Communication**: Send messages to Slack channels
- **KPI Scorecard**: Monitor business performance metrics
- **Secure Authentication**: Google OAuth 2.0 integration

## Installation

### Prerequisites

- Python 3.11+
- PostgreSQL (optional, for production)
- Access to third-party APIs (Google, HubSpot, Chargebee, etc.)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/your-username/ceo-assistant-ai.git
   cd ceo-assistant-ai
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure environment variables (see Configuration section)

4. Run the application:
   ```
   python main.py
   ```

5. Access the application at http://localhost:5001

## Configuration

The application requires several API keys and credentials to function. You can set these as environment variables or create a `.env` file in the project root.

### Required Environment Variables

```
# Google OAuth (for authentication)
GOOGLE_OAUTH_CLIENT_ID=your-google-client-id
GOOGLE_OAUTH_CLIENT_SECRET=your-google-client-secret

# Session security
SESSION_SECRET=your-session-secret-key

# API Keys
HUBSPOT_API_KEY=your-hubspot-api-key
CHARGEBEE_API_KEY=your-chargebee-api-key
CHARGEBEE_SITE=your-chargebee-site
OPENAI_API_KEY=your-openai-api-key
OOTI_API_KEY=your-ooti-api-key

# Slack (optional)
SLACK_BOT_TOKEN=your-slack-bot-token
SLACK_CHANNEL_ID=your-slack-channel-id
```

### Google API Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new OAuth 2.0 Client ID
3. Add `http://localhost:5001/google_login/callback` to Authorized redirect URIs
4. Enable the Gmail, Drive, and Calendar APIs in your Google Cloud project
5. Download credentials and save as `credentials.json` in the root directory

## Usage

1. Run the application: `python main.py`
2. Navigate to http://localhost:5001 in your browser
3. Log in with your Google account
4. Configure API keys in the Settings page if not set via environment variables
5. Navigate through the dashboard to access different features

## Security

This application implements several security measures:

- OAuth 2.0 for secure authentication
- CSRF protection for all forms
- Rate limiting to prevent abuse
- Content Security Policy to mitigate XSS attacks
- Secure session management
- HTTPS enforcement (in production)

## Development

### Directory Structure

```
ceo-assistant-ai/
├── api/                # API integrations
├── data/               # Data storage
├── models/             # Data models
├── services/           # Business logic
├── static/             # CSS, JS, images
├── templates/          # HTML templates
├── utils/              # Utility functions
├── app.py              # Main application
├── auth.py             # Authentication
├── config.py           # Configuration
└── main.py             # Entry point
```

### Running Tests

```
pytest
```

## License

[MIT License](LICENSE)

## Support

For issues or questions, please open an issue on GitHub or contact support@example.com.

## Testing Infrastructure

The project includes a comprehensive testing infrastructure to ensure code quality before deployment:

### Basic Testing

Run basic tests with:

```bash
make test
```

This runs simple tests to verify the testing environment is working correctly.

### Security and Access Control Testing

Run security and access control tests with:

```bash
make test-security
```

This will run tests covering:
- Password strength and secure storage
- CSRF token validation and protection
- XSS prevention through input sanitization
- Role-based access control (RBAC)
- Route access permissions
- Session security and fixation prevention
- API security (rate limiting, input validation, token security)
- Email-based access restrictions
- Dependency vulnerability scanning with Safety

### Pre-Deployment Testing

Before deploying, run the full test suite:

```bash
./run_tests_before_deploy.sh
```

or

```bash
make test-all
```

This will:
1. Install all required test dependencies
2. Run the test suite with minimal tests
3. Perform linting checks to catch potential code issues
4. Run security checks on dependencies (if safety is installed)
5. Run all security and access control tests

The script will exit with a failure code if any tests fail, preventing deployment of broken code.

### Test Environment

To work around compatibility issues between Flask 3.1.0 and pytest-flask, we use a separate test directory (`minimal_tests/`) for basic tests that don't depend on the Flask application context.

## Development Environment

To set up the development environment:

```bash
make setup
make install-dev  # Installs development dependencies
```

## Running the Application

```bash
make run      # Development mode
make prod     # Production mode
```

## Security and Access Control

### Email-Based Access Restrictions

The application is configured to only allow access to sensitive data for specific authorized email addresses:
- `maxriahi@gmail.com`
- `mriahi@ooti.co`

This restriction is implemented using the `restricted_access_required` decorator in `utils/access_control.py`. This decorator can be applied to any route that should be restricted to these authorized users:

```python
@app.route('/api/sensitive-data')
@login_required  # First ensure the user is logged in
@restricted_access_required  # Then check if their email is authorized
def sensitive_data():
    # Only accessible to authorized email addresses
    return jsonify({"data": "sensitive information"})
```

#### Testing Email Access Control

The email access control functionality is tested in `minimal_tests/test_email_access_control.py`. These tests verify that:
- Only authorized emails can access protected data
- Requests from unauthorized emails are properly rejected
- The system handles edge cases correctly (missing emails, case variations, etc.)

Run these tests with:
```bash
pytest -v minimal_tests/test_email_access_control.py
```

### Security and Access Control Testing

Run security and access control tests with:

```bash
make test-security
```

This will run tests covering:
- Password strength and secure storage
- CSRF token validation and protection
- XSS prevention through input sanitization
- Role-based access control (RBAC)
- Route access permissions
- Session security and fixation prevention
- API security (rate limiting, input validation, token security)
- Email-based access restrictions
- Dependency vulnerability scanning with Safety

## Security and Access Control Testing

The application includes comprehensive security testing to ensure that data is protected and only authorized users have access to sensitive information.

### Security Testing Overview

The security test suite is divided into multiple components:

1. **Email Access Control Tests**: Verify that only specific email addresses (`maxriahi@gmail.com` and `mriahi@ooti.co`) can access sensitive data endpoints.

2. **Security Tests**: Cover password strength validation, token generation and validation, password hashing, CSRF protection, and input sanitization.

3. **Access Control Tests**: Ensure that role-based permissions, route access control, and data access levels are properly enforced.

4. **API Security Tests**: Validate that API endpoints are protected with proper authentication, rate limiting, and input validation.

5. **Session Security Tests**: Check that sessions are managed securely, with proper expiration, secure cookies, and prevention of session fixation.

### Running Security Tests

To run the security test suite, use the following command:

```
make test-security
```

This command will:
- Check for vulnerabilities in dependencies using Safety
- Run a static code analysis using Bandit
- Execute all security-related test files

### Test Implementation

The tests are designed to verify security at multiple levels:

1. **Unit Tests**: Test individual security functions in isolation
2. **Integration Tests**: Test how security components work together
3. **End-to-End Tests**: Test the full security workflow from user interaction to data access

All security tests are located in the `minimal_tests/` directory and follow the naming pattern `test_*_security.py` or `test_access_control.py`.

### Email-Based Access Control

The application is configured to only allow specific email addresses (`maxriahi@gmail.com` and `mriahi@ooti.co`) to access sensitive data endpoints. This restriction is implemented through the `utils/access_control.py` module and is applied to sensitive API endpoints using the `@restricted_access_required` decorator.

The email access control tests verify:
- Authorized emails are allowed access
- Unauthorized emails are correctly denied
- Proper handling of edge cases (case sensitivity, empty emails, etc.)
- Proper integration with the Flask application 

## Continuous Integration Security Checks

This project includes automated security checks in the CI pipeline to prevent accidental data leaks or security regressions. These checks will fail the build if any security issues are detected, blocking potentially dangerous changes from being merged.

### Pre-merge Security Verification

A dedicated pre-merge workflow (`pre-merge-security-check.yml`) runs specific tests to ensure:

1. **Email Access Control**: Verifies that only the authorized email addresses (`maxriahi@gmail.com` and `mriahi@ooti.co`) can access sensitive data
2. **API Endpoint Protection**: Checks that sensitive API endpoints have proper access controls
3. **Authorization Whitelist Integrity**: Ensures the authorized emails list hasn't been tampered with
4. **Sensitive Data Exposure**: Scans code for potential exposure of sensitive business metrics

### Integration with Main CI Pipeline

The main CI workflow also includes:

1. **Security Scanning**: Checks for vulnerabilities in dependencies using Safety
2. **Static Code Analysis**: Analyzes code for security issues using Bandit
3. **Comprehensive Security Tests**: Runs all security-related test suites
4. **Data Leak Prevention**: Dedicated job to verify email access restrictions

### When Adding New Features

When adding new features or API endpoints that expose sensitive business data:

1. Always apply the `@restricted_access_required` decorator to sensitive API endpoints
2. Write tests to verify the access control is working correctly
3. Run `make test-security` locally before pushing to ensure security tests pass

These CI checks help maintain a high security standard and prevent accidental data leaks, ensuring that only specifically authorized emails have access to sensitive company data.

## Audit Logging System

The application includes a comprehensive audit logging system that records all attempts to access restricted resources. This provides visibility into who is accessing sensitive data and helps detect potential security incidents.

### Audit Log Features

- **Comprehensive Logging**: Every access attempt to restricted endpoints is logged
- **Detailed Information**: Logs include user email, IP address, session ID, timestamp, and access result
- **JSON Format**: Logs are stored in both human-readable and JSON formats for easy parsing
- **Performance Metrics**: Response times are captured to identify potential issues

### Logged Information

Each audit log entry includes:

- Timestamp of the access attempt
- User email and ID
- IP address and user agent
- Session ID
- Endpoint being accessed
- Whether access was granted or denied
- Request method and parameters
- Response time

### Viewing Audit Logs

#### Command-Line Interface

A command-line utility is provided to search and analyze audit logs:

```bash
# View recent access attempts
python utils/audit_viewer.py

# View only denied access attempts
python utils/audit_viewer.py --status denied

# Filter by user email
python utils/audit_viewer.py --email maxriahi@gmail.com

# Show summary statistics
python utils/audit_viewer.py --summary

# Filter by date range
python utils/audit_viewer.py --start-date 2023-01-01 --end-date 2023-01-31
```

#### Web Interface

Authorized users (with emails `maxriahi@gmail.com` or `mriahi@ooti.co`) can view audit logs through the web interface:

1. Navigate to `/admin/audit-logs`
2. Use the filters to search logs by email, endpoint, or status
3. Click on any log entry to view detailed information
4. View summary statistics at the top of the page

The web interface provides:
- Colorful summary cards showing total attempts, successes, and failures
- Filtering options for detailed investigation
- Interactive log entries that expand to show full details
- Highlighted denied access attempts for easy identification

### Implementation

Audit logging is implemented using:

1. **Centralized Logging Module**: `utils/audit_logger.py` provides logging functions
2. **Decorator-Based Logging**: `@audit_access_decorator` can be applied to any sensitive endpoint
3. **Integration with Access Control**: Automatically logs both successful and failed access attempts

### Log File Location

Audit logs are stored in `logs/access_audit.log` and are rotated automatically to prevent file size issues. 
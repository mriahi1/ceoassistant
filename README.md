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
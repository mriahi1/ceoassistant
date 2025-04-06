import os
from pathlib import Path

# Security settings
READ_ONLY_MODE = True  # When True, all write operations to external systems are disabled

# Environment variables for API keys and credentials
HUBSPOT_API_KEY = os.environ.get("HUBSPOT_API_KEY")
CHARGEBEE_API_KEY = os.environ.get("CHARGEBEE_API_KEY")
CHARGEBEE_SITE = os.environ.get("CHARGEBEE_SITE")
OOTI_API_KEY = os.environ.get("OOTI_API_KEY")
OOTI_BASE_URL = os.environ.get("OOTI_BASE_URL", "https://api.ooti.co")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID")
GOOGLE_CREDENTIALS_PATH = os.environ.get("GOOGLE_CREDENTIALS_PATH")
GMAIL_ENABLED = os.environ.get("GMAIL_ENABLED", "false").lower() == "true"
GDRIVE_ENABLED = os.environ.get("GDRIVE_ENABLED", "false").lower() == "true"
CALENDAR_ENABLED = os.environ.get("CALENDAR_ENABLED", "false").lower() == "true"
PENNYLANE_API_KEY = os.environ.get("PENNYLANE_API_KEY")
PENNYLANE_COMPANY_ID = os.environ.get("PENNYLANE_COMPANY_ID")
PENNYLANE_BASE_URL = os.environ.get("PENNYLANE_BASE_URL", "https://api.pennylane.tech/api/v1")
PENNYLANE_ENABLED = bool(PENNYLANE_API_KEY)

# New integrations
JIRA_API_KEY = os.environ.get("JIRA_API_KEY")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "mriahi@ooti.co")
JIRA_DOMAIN = os.environ.get("JIRA_DOMAIN", "ooti.atlassian.net")
JIRA_ENABLED = bool(JIRA_API_KEY)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_ORG = os.environ.get("GITHUB_ORG", "ooti-co")
GITHUB_ENABLED = bool(GITHUB_TOKEN)

SENTRY_API_KEY = os.environ.get("SENTRY_API_KEY")
SENTRY_ORG = os.environ.get("SENTRY_ORG", "ooti")
SENTRY_ENABLED = bool(SENTRY_API_KEY)

MODJO_API_KEY = os.environ.get("MODJO_API_KEY")
MODJO_BASE_URL = os.environ.get("MODJO_BASE_URL", "https://api.modjo.ai/v1")
MODJO_ENABLED = bool(MODJO_API_KEY)

# Application settings
APP_NAME = "CEO AI Assistant"
APP_VERSION = "1.0.0"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 5000))
DEBUG = os.environ.get("FLASK_ENV", "production").lower() != "production"

# Data storage paths
DATA_DIR = Path("./data")
DATA_DIR.mkdir(exist_ok=True)
DIGESTS_DIR = DATA_DIR / "digests"
DIGESTS_DIR.mkdir(exist_ok=True)

# OpenAI model settings
OPENAI_MODEL = "gpt-4o"  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
                           # do not change this unless explicitly requested by the user

# API endpoints
HUBSPOT_BASE_URL = "https://api.hubapi.com"
CHARGEBEE_BASE_URL = f"https://{CHARGEBEE_SITE}.chargebee.com/api/v2"

# Feature flags
ENABLE_SLACK_NOTIFICATIONS = True
ENABLE_EMAIL_DIGESTS = False  # Not implemented in initial version

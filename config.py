import os
from pathlib import Path

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

# Application settings
APP_NAME = "CEO AI Assistant"
APP_VERSION = "1.0.0"
HOST = "0.0.0.0"
PORT = 5000
DEBUG = True

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

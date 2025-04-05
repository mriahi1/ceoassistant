import os
import logging

# Configure logging first, before any other imports
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Import the app after configuring logging
from app import app as application

if __name__ == "__main__":
    application.run()

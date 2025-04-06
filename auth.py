import json
import os
import secrets
import hashlib
import logging
import time

import requests
from flask import Blueprint, redirect, request, url_for, session, current_app, abort
from flask_login import login_required, login_user, logout_user, current_user
from oauthlib.oauth2 import WebApplicationClient

from models.user import User

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Redirect URL - use localhost for development
DEV_REDIRECT_URL = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5001') + '/google_login/callback'

# User database
users_db = {}

# OAuth client
client = WebApplicationClient(GOOGLE_CLIENT_ID) if GOOGLE_CLIENT_ID else None

# Create blueprint
auth = Blueprint("auth", __name__)


@auth.route("/login")
def login():
    if not GOOGLE_CLIENT_ID:
        return "Google OAuth Client ID not configured. Please check environment variables.", 500
    
    # Generate and store CSRF token for OAuth 2.0 state parameter
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    
    # Find Google provider configuration
    try:
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    except Exception as e:
        current_app.logger.error(f"Error fetching Google OIDC configuration: {str(e)}")
        return "Error connecting to Google. Please try again later.", 500
    
    # Prepare OAuth request
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url.replace("http://", "https://").replace("login", "google_login/callback"),
        scope=["openid", "email", "profile"],
        state=state
    )
    return redirect(request_uri)


@auth.route("/google_login/callback")
def callback():
    if not GOOGLE_CLIENT_ID:
        return "Google OAuth Client ID not configured. Please check environment variables.", 500
    
    # Verify state parameter to prevent CSRF
    stored_state = session.get('oauth_state')
    received_state = request.args.get('state')
    
    if not stored_state or not received_state or stored_state != received_state:
        current_app.logger.warning("OAuth state parameter mismatch - possible CSRF attack")
        # Log additional details for security analysis
        current_app.logger.warning(f"Stored state: {stored_state}, Received state: {received_state}")
        current_app.logger.warning(f"Request IP: {request.remote_addr}")
        current_app.logger.warning(f"Request User-Agent: {request.headers.get('User-Agent')}")
        abort(403, description="Invalid security parameters. Please try logging in again.")
    
    # Clear the state parameter now that it's been used
    session.pop('oauth_state', None)
    
    # Get authorization code
    code = request.args.get("code")
    if not code:
        current_app.logger.warning("Missing authorization code in OAuth callback")
        return "Authorization code not received from Google", 400
    
    try:
        # Get Google provider configuration
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL, timeout=10).json()
        token_endpoint = google_provider_cfg["token_endpoint"]
        
        # Prepare token request
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url.replace("http://", "https://"),
            redirect_url=request.base_url.replace("http://", "https://"),
            code=code,
        )
        
        # Request token
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
            timeout=10  # Add timeout for security
        )
        
        # Validate token response
        token_data = token_response.json()
        if 'error' in token_data:
            current_app.logger.error(f"OAuth token error: {token_data.get('error')}")
            return "Authentication error. Please try again later.", 500
        
        # Parse token response
        client.parse_request_body_response(json.dumps(token_data))
        
        # Get user info
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body, timeout=10)
        
        # Verify user info
        userinfo = userinfo_response.json()
        if not userinfo_response.ok:
            current_app.logger.error(f"Failed to get user info: {userinfo.get('error', 'Unknown error')}")
            return "Failed to retrieve user information. Please try again.", 500
            
        if userinfo.get("email_verified"):
            user_id = userinfo["sub"]
            user_email = userinfo["email"]
            user_name = userinfo.get("given_name", "User")  # Provide fallback
            user_picture = userinfo.get("picture")
            
            # Check if email is allowed
            allowed_emails = ["mriahi@ooti.co", "maxriahi@gmail.com"]
            if user_email.lower() not in [email.lower() for email in allowed_emails]:
                current_app.logger.warning(f"Login attempt from unauthorized email: {user_email}")
                return "Access denied. This application is restricted to authorized users only.", 403
        else:
            current_app.logger.warning(f"Unverified email attempted login: {userinfo.get('email', 'unknown')}")
            return "User email not available or not verified by Google.", 400
        
        # Create user with login timestamp for session management
        login_timestamp = int(time.time())
        user = User(id=user_id, email=user_email, name=user_name, picture=user_picture, login_time=login_timestamp)
        users_db[user_id] = user
        
        # Create completely new session to prevent session fixation
        session.clear()
        
        # Log in user with Flask-Login which will set user_id in the session
        login_user(user)
        
        # Set additional session data
        session.permanent = True
        session['created_at'] = login_timestamp
        
        # Debug logging for troubleshooting
        current_app.logger.info(f"Successful login: {user_email}, User ID: {user_id}")
        current_app.logger.debug(f"Session contents after login: {dict(session)}")
        current_app.logger.debug(f"Flask-Login current_user.is_authenticated: {current_user.is_authenticated}")
        
        # Redirect to home page
        return redirect(url_for("index"))
        
    except Exception as e:
        current_app.logger.error(f"Error during OAuth authentication: {str(e)}", exc_info=True)
        return "Authentication error. Please try again later.", 500


@auth.route("/logout")
@login_required
def logout():
    # Revoke all sessions for the current user by clearing the users_db entry
    if current_user.is_authenticated:
        user_id = current_user.id
        if user_id in users_db:
            users_db.pop(user_id, None)
            
    logout_user()
    
    # Clear and regenerate the session
    session.clear()
    
    return redirect(url_for("index"))


def check_authentication():
    """Print authentication status and required configuration"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        print("\nGoogle OAuth is not configured.")
        print("To enable Google authentication, set these environment variables:")
        print("  - GOOGLE_OAUTH_CLIENT_ID")
        print("  - GOOGLE_OAUTH_CLIENT_SECRET")
        print("\nSetup Instructions:")
        print("1. Go to https://console.cloud.google.com/apis/credentials")
        print("2. Create a new OAuth 2.0 Client ID")
        print(f"3. Add {DEV_REDIRECT_URL} to Authorized redirect URIs")
        print("\nFor detailed instructions, see:")
        print("https://developers.google.com/identity/protocols/oauth2/web-server")
    else:
        print("\nGoogle OAuth is configured.")
        print(f"Callback URL: {DEV_REDIRECT_URL}")
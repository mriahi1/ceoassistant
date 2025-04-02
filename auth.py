import json
import os

import requests
from flask import Blueprint, redirect, request, url_for, session, current_app
from flask_login import login_required, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient

from models.user import User

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Redirect URL
DEV_REDIRECT_URL = f'https://{os.environ.get("REPLIT_DEV_DOMAIN", "")}/google_login/callback'

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
    
    # Find Google provider configuration
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Prepare OAuth request
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url.replace("http://", "https://").replace("login", "google_login/callback"),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@auth.route("/google_login/callback")
def callback():
    if not GOOGLE_CLIENT_ID:
        return "Google OAuth Client ID not configured. Please check environment variables.", 500
    
    # Get authorization code
    code = request.args.get("code")
    
    # Get Google provider configuration
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
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
    )
    
    # Parse token response
    client.parse_request_body_response(json.dumps(token_response.json()))
    
    # Get user info
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    
    # Verify user info
    userinfo = userinfo_response.json()
    if userinfo.get("email_verified"):
        user_id = userinfo["sub"]
        user_email = userinfo["email"]
        user_name = userinfo["given_name"]
        user_picture = userinfo.get("picture")
    else:
        return "User email not available or not verified by Google.", 400
    
    # Create user
    user = User(id=user_id, email=user_email, name=user_name, picture=user_picture)
    users_db[user_id] = user
    
    # Log in user
    login_user(user)
    
    # Redirect to home page
    return redirect(url_for("index"))


@auth.route("/logout")
@login_required
def logout():
    logout_user()
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
        print("https://docs.replit.com/additional-resources/google-auth-in-flask#set-up-your-oauth-app--client")
    else:
        print("\nGoogle OAuth is configured.")
        print(f"Callback URL: {DEV_REDIRECT_URL}")
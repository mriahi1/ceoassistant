import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
from datetime import datetime, timedelta

# ================================================================
# SECURITY NOTICE: All external integrations are in READ-ONLY mode
# No modifications will be made to external systems (Google, Slack, etc.)
# All write operations are disabled for security reasons
# ================================================================

# Configure logging first, before any imports that use it
if os.environ.get("FLASK_ENV", "production").lower() == "development":
    logging_level = logging.DEBUG
else:
    logging_level = logging.INFO

logging.basicConfig(
    level=logging_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

import json
from pathlib import Path
from flask_login import LoginManager, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

import config
from services.daily_digest import generate_daily_digest
from services.integrations import get_all_platform_data
from api.slack_integration import post_message
from utils.insights_generator import generate_insights, generate_action_items
from utils.data_processor import consolidate_data
from api.ooti import OOTIAPI
from models.user import User
from api.openai_integration import generate_key_metrics, analyze_okr_alignment, generate_strategic_insights
from api.hubspot import HubSpotAPI
from api.chargebee import ChargebeeAPI
from utils.access_control import restricted_access_required, check_user_email_authorization
from utils.audit_logger import audit_access_decorator, log_access_attempt


# Initialize Flask app - IMPORTANT: This must be defined before using app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# Add CSRF protection
csrf = CSRFProtect(app)

# Add to app configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("FLASK_ENV", "production").lower() != "development"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Import Google services if enabled
gmail_integration = None
google_drive_integration = None
calendar_integration = None
if config.GMAIL_ENABLED:
    try:
        from api.gmail_integration import (
            get_unread_emails, get_recent_emails, get_email, 
            send_email, search_emails, mark_email_read, 
            analyze_email_thread, initialize_gmail_client
        )
        # Initialize Gmail client
        if initialize_gmail_client():
            logger.debug("Gmail client initialized successfully")
    except ImportError as e:
        logger.error(f"Error importing Gmail integration: {str(e)}")

if config.GDRIVE_ENABLED:
    try:
        from api.google_drive_integration import (
            list_files, search_files, get_file, upload_file,
            create_folder, share_file, export_file_as_pdf,
            upload_digest_to_drive, initialize_drive_client
        )
        # Initialize Drive client
        if initialize_drive_client():
            logger.debug("Google Drive client initialized successfully")
    except ImportError as e:
        logger.error(f"Error importing Google Drive integration: {str(e)}")

# Import Calendar integration if enabled
if config.CALENDAR_ENABLED:
    try:
        from api.calendar_integration import (
            get_calendar_list, get_calendar_events, get_weekly_schedule,
            get_daily_meeting_load, identify_meeting_conflicts,
            identify_meeting_priorities, find_free_time_slots,
            get_calendar_summary, get_all_calendar_data,
            initialize_calendar_client
        )
        # Initialize Calendar client
        if initialize_calendar_client():
            logger.debug("Google Calendar client initialized successfully")
    except ImportError as e:
        logger.error(f"Error importing Google Calendar integration: {str(e)}")

# Import Pennylane integration if enabled
if config.PENNYLANE_ENABLED:
    try:
        from api.pennylane_integration import (
            get_company_info, get_bank_accounts, get_bank_balance,
            get_invoices, get_expenses, get_expense_categories,
            get_expense_trends, get_profitability, get_cash_flow,
            get_all_pennylane_data, initialize_pennylane_client
        )
        # Initialize Pennylane client
        if initialize_pennylane_client():
            logger.debug("Pennylane client initialized successfully")
    except ImportError as e:
        logger.error(f"Error importing Pennylane integration: {str(e)}")

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
csrf = CSRFProtect(app)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net;"
    return response

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_page"
login_manager.login_message = "Please sign in to access this page."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Register authentication blueprint
from auth import auth, check_authentication
app.register_blueprint(auth, url_prefix='')
check_authentication()  # Print authentication status and setup instructions

# Check required API keys
missing_keys = []
if not config.HUBSPOT_API_KEY:
    missing_keys.append("HUBSPOT_API_KEY")
if not config.CHARGEBEE_API_KEY:
    missing_keys.append("CHARGEBEE_API_KEY")
if not config.CHARGEBEE_SITE:
    missing_keys.append("CHARGEBEE_SITE")
if not config.OPENAI_API_KEY:
    missing_keys.append("OPENAI_API_KEY")
if not config.SLACK_BOT_TOKEN and config.ENABLE_SLACK_NOTIFICATIONS:
    missing_keys.append("SLACK_BOT_TOKEN")
if not config.SLACK_CHANNEL_ID and config.ENABLE_SLACK_NOTIFICATIONS:
    missing_keys.append("SLACK_CHANNEL_ID")
if not os.environ.get("GOOGLE_OAUTH_CLIENT_ID"):
    missing_keys.append("GOOGLE_OAUTH_CLIENT_ID")
if not os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET"):
    missing_keys.append("GOOGLE_OAUTH_CLIENT_SECRET")

# Cache for platform data
data_cache = {
    "last_updated": None,
    "data": None
}

def get_cached_data():
    """Get data from cache or refresh if outdated"""
    now = datetime.now()
    if (data_cache["last_updated"] is None or 
            now - data_cache["last_updated"] > timedelta(minutes=30) or 
            data_cache["data"] is None):
        logger.debug("Refreshing data cache")
        try:
            data = get_all_platform_data()
            data_cache["data"] = data
            data_cache["last_updated"] = now
            return data
        except Exception as e:
            logger.error(f"Error refreshing cache: {str(e)}")
            if data_cache["data"] is not None:
                return data_cache["data"]
            return None
    else:
        return data_cache["data"]

@app.route('/')
@login_required
def index():
    """Dashboard home page"""
    platform_data = get_cached_data()
    if not platform_data:
        logger.warning("No platform data available")
        return render_template('dashboard.html', platform_data=None, error=True)
    
    # Pass data_sources to the template to show if data is real or mock
    data_sources = platform_data.get('data_sources', {})
    
    # Get missing API keys to show setup instructions
    missing_keys = []
    if not config.HUBSPOT_API_KEY:
        missing_keys.append("HubSpot API Key")
    if not (config.CHARGEBEE_API_KEY and config.CHARGEBEE_SITE):
        missing_keys.append("Chargebee Credentials")
    if not config.OOTI_API_KEY:
        missing_keys.append("OOTI API Key")
    if not config.OPENAI_API_KEY:
        missing_keys.append("OpenAI API Key")
    
    # Get latest digest for executive summary
    latest_digest = None
    try:
        latest = Digest.query.order_by(Digest.created_at.desc()).first()
        if latest:
            digest_content = json.loads(latest.content)
            latest_digest = {
                "id": latest.id,
                "date": latest.date,
                "executive_summary": digest_content.get("executive_summary", "No summary available.")
            }
    except Exception as e:
        logger.error(f"Error retrieving latest digest: {str(e)}")
    
    insights = generate_insights(platform_data) if platform_data else []
    action_items = generate_action_items(platform_data) if platform_data else []
    
    return render_template('dashboard.html', 
                          platform_data=platform_data, 
                          missing_keys=missing_keys,
                          latest_digest=latest_digest,
                          insights=insights,
                          action_items=action_items,
                          last_updated=data_cache.get("last_updated"),
                          data_sources=data_sources,
                          error=False)

@app.route('/integrations')
@login_required
def integrations():
    """Shows the status of various integrations"""
    # Get current platform data
    platform_data = get_cached_data()
    data_sources = platform_data.get('data_sources', {}) if platform_data else {}
    
    integration_status = {
        "hubspot": bool(config.HUBSPOT_API_KEY),
        "chargebee": bool(config.CHARGEBEE_API_KEY and config.CHARGEBEE_SITE),
        "ooti": bool(config.OOTI_API_KEY),
        "slack": bool(config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL_ID),
        "openai": bool(config.OPENAI_API_KEY),
        "gmail": config.GMAIL_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "google_drive": config.GDRIVE_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "calendar": config.CALENDAR_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "pennylane": config.PENNYLANE_ENABLED and bool(config.PENNYLANE_API_KEY),
        "jira": config.JIRA_ENABLED and bool(config.JIRA_API_KEY),
        "github": config.GITHUB_ENABLED and bool(config.GITHUB_TOKEN),
        "sentry": config.SENTRY_ENABLED and bool(config.SENTRY_API_KEY),
        "modjo": config.MODJO_ENABLED and bool(config.MODJO_API_KEY)
    }
    
    return render_template('integrations.html', integration_status=integration_status, data_sources=data_sources)

@app.route('/digests')
@login_required
def digests():
    """View all generated daily digests"""
    digest_list = Digest.query.order_by(Digest.created_at.desc()).all()
    return render_template('digests.html', digests=[d.to_dict() for d in digest_list])

@app.route('/digest/<int:digest_id>')
@login_required
def view_digest(digest_id):
    """View a specific digest"""
    digest = Digest.query.get_or_404(digest_id)
    return render_template('digest_view.html', digest=json.loads(digest.content))

@app.route('/generate_digest', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def generate_digest():
    """Generate a new daily digest"""
    try:
        platform_data = get_cached_data()
        if not platform_data:
            flash("Could not retrieve platform data. Please check your API credentials.", "danger")
            return redirect(url_for('index'))
        
        # Generate and save digest
        digest = generate_daily_digest(platform_data, user_id=current_user.id)
        
        flash("Digest generated successfully", "success")
        return redirect(url_for('digests'))
    except Exception as e:
        # Log the detailed error but show a generic message to the user
        logger.error(f"Error generating digest: {str(e)}", exc_info=True)
        flash("An error occurred while generating the digest. Please try again or contact support.", "danger")
        return redirect(url_for('index'))

@app.route('/settings')
@login_required
def settings():
    """Settings page"""
    integration_status = {
        "hubspot": bool(config.HUBSPOT_API_KEY),
        "chargebee": bool(config.CHARGEBEE_API_KEY and config.CHARGEBEE_SITE),
        "ooti": bool(config.OOTI_API_KEY),
        "slack": bool(config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL_ID),
        "openai": bool(config.OPENAI_API_KEY),
        "gmail": config.GMAIL_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "google_drive": config.GDRIVE_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "calendar": config.CALENDAR_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "pennylane": config.PENNYLANE_ENABLED and bool(config.PENNYLANE_API_KEY)
    }
    return render_template('settings.html', integration_status=integration_status)

@app.route('/refresh_data', methods=['POST'])
@login_required
def refresh_data():
    """Force refresh the cached data"""
    try:
        # Clear the cache timestamp to force refresh
        data_cache["last_updated"] = None
        get_cached_data()  # This will refresh the cache
        flash("Data refreshed successfully", "success")
    except Exception as e:
        # Log the detailed error but show a generic message to the user
        logger.error(f"Error refreshing data: {str(e)}", exc_info=True)
        flash("An error occurred while refreshing data. Please try again later.", "danger")
    
    return redirect(url_for('index'))

@app.route('/api/platform_summary')
@login_required
@limiter.limit("60 per hour")
def platform_summary_api():
    """API endpoint to get platform summary data"""
    try:
        platform_data = get_cached_data()
        if not platform_data:
            return jsonify({"error": "Could not retrieve platform data"}), 500
        
        # Create a summary of the data for the API
        summary = {
            "hubspot": {
                "deals_count": len(platform_data.get("hubspot", {}).get("deals", [])),
                "total_deal_value": sum(deal.get("amount", 0) for deal in platform_data.get("hubspot", {}).get("deals", [])),
                "contacts_count": len(platform_data.get("hubspot", {}).get("contacts", []))
            },
            "chargebee": {
                "active_subscriptions": len(platform_data.get("chargebee", {}).get("subscriptions", [])),
                "mrr": platform_data.get("chargebee", {}).get("mrr", 0),
                "recent_invoices": len(platform_data.get("chargebee", {}).get("invoices", []))
            },
            "ooti": {
                "active_projects": len(platform_data.get("ooti", {}).get("projects", [])),
                "finance_summary": platform_data.get("ooti", {}).get("finance_summary", {})
            },
            "last_updated": data_cache["last_updated"].isoformat() if data_cache["last_updated"] else None
        }
        
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error in platform summary API: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    logger.warning(f"Forbidden access attempt: {str(e)}")
    return render_template('403.html', error_message="You don't have permission to access this resource."), 403

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {str(e)}")
    return render_template('429.html', error_message="Rate limit exceeded. Please try again later."), 429

# Register CSRF error handler with enhanced logging
@app.errorhandler(400)
def csrf_error(e):
    if 'CSRF' in str(e):
        # Log detailed information about the request for security analysis
        logger.warning(f"CSRF error: {str(e)}")
        logger.warning(f"Request path: {request.path}")
        logger.warning(f"Request method: {request.method}")
        logger.warning(f"Request IP: {request.remote_addr}")
        logger.warning(f"Request User-Agent: {request.headers.get('User-Agent')}")
        
        # Check if this is an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                "success": False, 
                "error": "CSRF token validation failed"
            }), 403
        else:
            return render_template('403.html', error_message="Security validation failed. Please try again."), 403
    return e

# Gmail routes
@app.route('/gmail')
@login_required
def gmail_inbox():
    """Gmail inbox view"""
    if not config.GMAIL_ENABLED or 'get_unread_emails' not in globals():
        flash("Gmail integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    try:
        # Get unread emails
        unread_emails = get_unread_emails(max_results=10)
        
        # Get recent emails
        recent_emails = get_recent_emails(max_results=20)
        
        return render_template('gmail.html', 
                              unread_emails=unread_emails,
                              recent_emails=recent_emails)
    except Exception as e:
        # Log the detailed error but show a generic message to the user
        logger.error(f"Error accessing Gmail: {str(e)}", exc_info=True)
        flash("Unable to access Gmail. Please check your connection and try again.", "danger")
        return redirect(url_for('index'))

@app.route('/gmail/email/<email_id>')
@login_required
def view_email(email_id):
    """View a specific email"""
    if not config.GMAIL_ENABLED or 'get_email' not in globals():
        flash("Gmail integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    try:
        # Get the email
        email_data = get_email(email_id)
        
        if not email_data:
            flash("Email not found", "danger")
            return redirect(url_for('gmail_inbox'))
        
        # Check if this is part of a thread
        thread_id = email_data.get('threadId')
        thread_data = None
        
        if thread_id:
            thread_data = analyze_email_thread(thread_id)
        
        return render_template('email_view.html', 
                              email=email_data,
                              thread=thread_data)
    except Exception as e:
        logger.error(f"Error viewing email {email_id}: {str(e)}")
        flash(f"Error viewing email: {str(e)}", "danger")
        return redirect(url_for('gmail_inbox'))

@app.route('/gmail/search', methods=['GET', 'POST'])
@login_required
def search_gmail():
    """Search Gmail"""
    if not config.GMAIL_ENABLED or 'search_emails' not in globals():
        flash("Gmail integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    if request.method == 'POST':
        # Get and validate query parameter
        query = request.form.get('query', '').strip()
        
        # Input validation
        if not query:
            flash("Please enter a search query", "warning")
            return render_template('gmail_search.html', query='', results=[])
        
        # Limit query length for security
        if len(query) > 200:
            flash("Search query is too long. Please limit to 200 characters.", "warning")
            return render_template('gmail_search.html', query=query[:200], results=[])
        
        # Basic sanitization to prevent Gmail API query injection
        # Remove potentially harmful characters
        import re
        sanitized_query = re.sub(r'[^\w\s@.\-:;,\'\"]+', '', query)
        
        try:
            # Search emails with sanitized query
            results = search_emails(sanitized_query, max_results=20)
            
            return render_template('gmail_search.html', 
                                  query=query,  # Show the original query to the user
                                  results=results)
        except Exception as e:
            # Log the detailed error but show a generic message to the user
            logger.error(f"Error searching Gmail: {str(e)}", exc_info=True)
            flash("Unable to search Gmail. Please try again.", "danger")
            return redirect(url_for('gmail_inbox'))
    else:
        return render_template('gmail_search.html', 
                              query='',
                              results=[])

@app.route('/gmail/compose', methods=['GET', 'POST'])
@login_required
def compose_email():
    """Compose a new email"""
    if not config.GMAIL_ENABLED or 'send_email' not in globals():
        flash("Gmail integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    if request.method == 'POST':
        to = request.form.get('to', '')
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        reply_to = request.form.get('reply_to', None)
        
        try:
            # Send the email
            success = send_email(to, subject, body, reply_to)
            
            if success:
                flash("Email sent successfully", "success")
                return redirect(url_for('gmail_inbox'))
            else:
                flash("Failed to send email", "danger")
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            flash(f"Error sending email: {str(e)}", "danger")
        
        # If we get here, there was an error, so return to the compose form
        return render_template('email_compose.html', 
                              to=to,
                              subject=subject,
                              body=body,
                              reply_to=reply_to)
    else:
        # Check if this is a reply
        reply_to = request.args.get('reply_to', None)
        to = request.args.get('to', '')
        subject = request.args.get('subject', '')
        
        if reply_to:
            # Get the original email to quote it
            email_data = get_email(reply_to)
            
            if email_data:
                if not to:
                    to = email_data.get('sender', '')
                
                if not subject and email_data.get('subject'):
                    subject = f"Re: {email_data.get('subject')}"
                
                body = f"\n\n----- Original Message -----\n"
                body += f"From: {email_data.get('sender')}\n"
                body += f"Date: {email_data.get('date')}\n"
                body += f"Subject: {email_data.get('subject')}\n\n"
                
                # Quote the original message
                if email_data.get('body'):
                    lines = email_data.get('body').split('\n')
                    body += '\n'.join([f"> {line}" for line in lines])
            else:
                body = ""
        else:
            body = ""
        
        return render_template('email_compose.html', 
                              to=to,
                              subject=subject,
                              body=body,
                              reply_to=reply_to)

# Google Drive routes
@app.route('/drive')
@login_required
def drive_files():
    """Google Drive files view"""
    if not config.GDRIVE_ENABLED or 'list_files' not in globals():
        flash("Google Drive integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    folder_id = request.args.get('folder', None)
    
    try:
        # Get files
        files = list_files(folder_id=folder_id, max_results=50)
        
        # Get folder info if this is a subfolder
        current_folder = None
        if folder_id:
            current_folder = get_file(folder_id)
        
        return render_template('drive.html', 
                              files=files,
                              current_folder=current_folder)
    except Exception as e:
        logger.error(f"Error accessing Google Drive: {str(e)}")
        flash(f"Error accessing Google Drive: {str(e)}", "danger")
        return redirect(url_for('index'))

@app.route('/drive/search', methods=['GET', 'POST'])
@login_required
def search_drive():
    """Search Google Drive"""
    if not config.GDRIVE_ENABLED or 'search_files' not in globals():
        flash("Google Drive integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    if request.method == 'POST':
        # Get and validate query parameter
        query = request.form.get('query', '').strip()
        
        # Input validation
        if not query:
            flash("Please enter a search query", "warning")
            return render_template('drive_search.html', query='', results=[])
        
        # Limit query length for security
        if len(query) > 200:
            flash("Search query is too long. Please limit to 200 characters.", "warning")
            return render_template('drive_search.html', query=query[:200], results=[])
        
        # Basic sanitization
        import re
        sanitized_query = re.sub(r'[^\w\s@.\-_:;,\'\"]+', '', query)
        
        try:
            # Search files with sanitized query
            results = search_files(sanitized_query, max_results=30)
            
            return render_template('drive_search.html', 
                                  query=query,  # Show the original query to the user
                                  results=results)
        except Exception as e:
            # Log the detailed error but show a generic message to the user
            logger.error(f"Error searching Google Drive: {str(e)}", exc_info=True)
            flash("Unable to search Google Drive. Please try again.", "danger")
            return redirect(url_for('drive_files'))
    else:
        return render_template('drive_search.html', 
                              query='',
                              results=[])

@app.route('/drive/file/<file_id>')
@login_required
def view_drive_file(file_id):
    """View a specific Google Drive file"""
    if not config.GDRIVE_ENABLED or 'get_file' not in globals():
        flash("Google Drive integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    try:
        # Get the file metadata
        file_data = get_file(file_id)
        
        if not file_data:
            flash("File not found", "danger")
            return redirect(url_for('drive_files'))
        
        # If this is a folder, redirect to the drive view with this folder
        if file_data.get('isFolder'):
            return redirect(url_for('drive_files', folder=file_id))
        
        return render_template('file_view.html', file=file_data)
    except Exception as e:
        logger.error(f"Error viewing file {file_id}: {str(e)}")
        flash(f"Error viewing file: {str(e)}", "danger")
        return redirect(url_for('drive_files'))

@app.route('/drive/create_folder', methods=['GET', 'POST'])
@login_required
def create_drive_folder():
    """Create a new folder in Google Drive"""
    if not config.GDRIVE_ENABLED or 'create_folder' not in globals():
        flash("Google Drive integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    parent_id = request.args.get('parent', None)
    
    if request.method == 'POST':
        folder_name = request.form.get('name', '').strip()
        parent_id = request.form.get('parent_id', None)
        
        # Input validation
        if not folder_name:
            flash("Folder name is required", "danger")
            return render_template('folder_create.html', parent_id=parent_id)
        
        # Sanitize folder name
        import re
        folder_name = re.sub(r'[<>:"/\\|?*]', '', folder_name)  # Remove invalid chars
        folder_name = folder_name[:100]  # Limit length
        
        try:
            # Create the folder
            folder = create_folder(folder_name, parent_id)
            
            if folder:
                flash(f"Folder '{folder_name}' created successfully", "success")
                
                # Redirect to the new folder
                return redirect(url_for('drive_files', folder=folder.get('id')))
            else:
                flash("Failed to create folder", "danger")
        except Exception as e:
            logger.error(f"Error creating folder: {str(e)}", exc_info=True)
            flash("Error creating folder. Please try again.", "danger")
        
        return render_template('folder_create.html', parent_id=parent_id)
    else:
        return render_template('folder_create.html', parent_id=parent_id)

@app.route('/drive/upload', methods=['GET', 'POST'])
@login_required
def upload_to_drive():
    """Upload a file to Google Drive"""
    if not config.GDRIVE_ENABLED or 'upload_file' not in globals():
        flash("Google Drive integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    parent_id = request.args.get('parent', None)
    
    if request.method == 'POST':
        parent_id = request.form.get('parent_id', None)
        description = request.form.get('description', '')
        
        # Check if a file was uploaded
        if 'file' not in request.files:
            flash("No file selected", "danger")
            return render_template('file_upload.html', parent_id=parent_id)
        
        file = request.files['file']
        
        if file.filename == '':
            flash("No file selected", "danger")
            return render_template('file_upload.html', parent_id=parent_id)
        
        import tempfile
        
        temp_file = None
        try:
            # Create a secure temporary file
            temp_fd, temp_path = tempfile.mkstemp(prefix="ceo_assistant_upload_")
            temp_file = os.fdopen(temp_fd, 'wb')
            file.save(temp_path)
            temp_file.close()
            
            # Upload the file to Google Drive
            uploaded_file = upload_file(temp_path, parent_id, description)
            
            if uploaded_file:
                flash(f"File '{file.filename}' uploaded successfully", "success")
                return redirect(url_for('drive_files', folder=parent_id))
            else:
                flash("Failed to upload file", "danger")
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            flash("Error uploading file. Please try again.", "danger")
        finally:
            # Ensure proper cleanup
            if temp_file:
                temp_file.close()
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception as e:
                    logger.error(f"Error removing temporary file: {str(e)}")
        
        return render_template('file_upload.html', parent_id=parent_id)
    else:
        return render_template('file_upload.html', parent_id=parent_id)

@app.route('/drive/share/<file_id>', methods=['GET', 'POST'])
@login_required
def share_drive_file(file_id):
    """Share a Google Drive file with someone"""
    if not config.GDRIVE_ENABLED or 'share_file' not in globals():
        flash("Google Drive integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    try:
        # Get the file metadata
        file_data = get_file(file_id)
        
        if not file_data:
            flash("File not found", "danger")
            return redirect(url_for('drive_files'))
        
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            role = request.form.get('role', 'reader')
            
            # Input validation for email
            if not email:
                flash("Email address is required", "danger")
                return render_template('file_share.html', file=file_data)
            
            # Validate email format
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                flash("Please enter a valid email address", "warning")
                return render_template('file_share.html', file=file_data, email=email)
            
            # Validate role - only allow specific roles
            allowed_roles = ['reader', 'commenter', 'writer']
            if role not in allowed_roles:
                flash("Invalid role specified", "danger")
                return render_template('file_share.html', file=file_data, email=email)
            
            try:
                # Share the file
                success = share_file(file_id, email, role)
                
                if success:
                    flash(f"File shared with {email} successfully", "success")
                    return redirect(url_for('view_drive_file', file_id=file_id))
                else:
                    flash("Failed to share file", "danger")
            except Exception as e:
                logger.error(f"Error sharing file: {str(e)}", exc_info=True)
                flash("Error sharing file. Please try again.", "danger")
            
            return render_template('file_share.html', file=file_data, email=email)
        else:
            return render_template('file_share.html', file=file_data)
    except Exception as e:
        logger.error(f"Error accessing file for sharing: {str(e)}", exc_info=True)
        flash("Error accessing file. Please try again.", "danger")
        return redirect(url_for('drive_files'))

@app.route('/digest/upload_to_drive/<filename>', methods=['POST'])
@login_required
def upload_digest_to_drive_route(filename):
    """Upload a digest to Google Drive"""
    if not config.GDRIVE_ENABLED or 'upload_digest_to_drive' not in globals():
        flash("Google Drive integration is not enabled or properly configured.", "warning")
        return redirect(url_for('digests'))
    
    # Validate filename to prevent path traversal
    import re
    import os
    
    # Check for invalid characters and patterns
    if not filename or '..' in filename or '/' in filename or '\\' in filename:
        logger.warning(f"Possible path traversal attempt detected with filename: {filename}")
        flash("Invalid digest filename", "danger")
        return redirect(url_for('digests'))
    
    # Ensure filename matches expected pattern (e.g., digest_YYYY-MM-DD.json)
    if not re.match(r'^[a-zA-Z0-9_\-\.]+\.json$', filename):
        logger.warning(f"Invalid digest filename format: {filename}")
        flash("Invalid digest filename format", "danger")
        return redirect(url_for('digests'))
    
    # Construct path safely using pathlib to prevent path traversal
    digest_path = config.DIGESTS_DIR / os.path.basename(filename)
    
    if not digest_path.exists() or not digest_path.is_file():
        flash("Digest not found", "danger")
        return redirect(url_for('digests'))
    
    try:
        # Load the digest
        with open(digest_path, 'r') as f:
            digest = json.load(f)
        
        # Validate digest contains an ID
        if not digest or not isinstance(digest, dict) or 'id' not in digest:
            logger.warning(f"Invalid digest content in file: {filename}")
            flash("Invalid digest content", "danger")
            return redirect(url_for('digests'))
        
        # Upload to Google Drive
        result = upload_digest_to_drive(digest)
        
        if result:
            flash("Digest uploaded to Google Drive successfully", "success")
        else:
            flash("Failed to upload digest to Google Drive", "danger")
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in digest file: {filename}", exc_info=True)
        flash("Invalid digest file format", "danger")
    except Exception as e:
        logger.error(f"Error uploading digest to Google Drive: {str(e)}", exc_info=True)
        flash("Error uploading digest to Google Drive", "danger")
    
    return redirect(url_for('view_digest', digest_id=digest['id']))

# Calendar routes
@app.route('/calendar')
@login_required
def calendar_view():
    """Google Calendar overview page"""
    if not config.CALENDAR_ENABLED or 'get_all_calendar_data' not in globals():
        flash("Google Calendar integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    try:
        # Get calendar data
        calendar_data = get_all_calendar_data()
        
        return render_template('calendar.html', calendar_data=calendar_data)
    except Exception as e:
        logger.error(f"Error accessing Google Calendar: {str(e)}")
        flash(f"Error accessing Google Calendar: {str(e)}", "danger")
        return redirect(url_for('index'))

# Pennylane routes
@app.route('/financials')
@login_required
def financials_view():
    """Pennylane financial overview page"""
    if not config.PENNYLANE_ENABLED or 'get_all_pennylane_data' not in globals():
        flash("Pennylane integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    try:
        # Get financial data
        financial_data = get_all_pennylane_data()
        
        return render_template('pennylane.html', financial_data=financial_data)
    except Exception as e:
        logger.error(f"Error accessing Pennylane: {str(e)}")
        flash(f"Error accessing Pennylane: {str(e)}", "danger")
        return redirect(url_for('index'))

# OOTI Scorecard route
@app.route('/scorecard')
@login_required
def scorecard_view():
    """Business Objectives Scorecard page"""
    try:
        # Create a predefined set of business objectives that don't depend on any external API
        objectives_data = {
            "company_objectives": [
                {
                    "title": "Revenue Growth",
                    "target": "$250,000 MRR",
                    "current": "$210,000 MRR",
                    "progress": 84,
                    "status": "on_track",
                    "details": "Targeting 20% annual growth through expansion of enterprise tier"
                },
                {
                    "title": "Customer Satisfaction",
                    "target": "NPS Score: 60+",
                    "current": "NPS Score: 52",
                    "progress": 87,
                    "status": "on_track",
                    "details": "Implementing product enhancements based on customer feedback"
                },
                {
                    "title": "Market Expansion",
                    "target": "3 New Markets",
                    "current": "1 Market",
                    "progress": 33,
                    "status": "at_risk",
                    "details": "Healthcare sector successful, delays in financial services rollout"
                },
                {
                    "title": "Product Development",
                    "target": "Launch Advanced Analytics",
                    "current": "Beta Testing Phase",
                    "progress": 75,
                    "status": "on_track",
                    "details": "On track for Q3 launch with 45 current beta testers"
                }
            ],
            "department_objectives": [
                {
                    "department": "Sales",
                    "objectives": [
                        {"title": "New Customer Acquisition", "target": "15 new enterprise customers", "current": "11 acquired", "progress": 73},
                        {"title": "Sales Cycle Reduction", "target": "30 days average", "current": "42 days average", "progress": 60}
                    ]
                },
                {
                    "department": "Engineering",
                    "objectives": [
                        {"title": "System Reliability", "target": "99.9% uptime", "current": "99.7% uptime", "progress": 97},
                        {"title": "Feature Deployment", "target": "12 major features", "current": "7 completed", "progress": 58}
                    ]
                },
                {
                    "department": "Customer Success",
                    "objectives": [
                        {"title": "Retention Rate", "target": "95% annual retention", "current": "92% current rate", "progress": 96},
                        {"title": "Support Response Time", "target": "< 2 hours", "current": "2.4 hours average", "progress": 83}
                    ]
                }
            ],
            "key_metrics": [
                {"name": "Monthly Recurring Revenue", "value": "$210,000", "trend": "+5.2%", "status": "positive"},
                {"name": "Customer Acquisition Cost", "value": "$2,800", "trend": "-3.1%", "status": "positive"},
                {"name": "Customer Lifetime Value", "value": "$48,500", "trend": "+2.8%", "status": "positive"},
                {"name": "Feature Adoption Rate", "value": "76%", "trend": "+4.5%", "status": "positive"},
                {"name": "Churn Rate", "value": "2.3%", "trend": "+0.2%", "status": "negative"}
            ],
            "action_items": [
                "Schedule executive review of financial services market entry strategy",
                "Prioritize product roadmap for Q3 and Q4",
                "Implement customer feedback loop for beta analytics features",
                "Address support response time bottlenecks in EMEA region"
            ]
        }
        
        # Try to get data from the OOTI API but don't depend on it
        try:
            ooti_api = OOTIAPI()
            scorecard_data = ooti_api.get_all_ooti_data()
            # Merge any available OOTI data with our predefined data
            if scorecard_data:
                objectives_data["ooti_data"] = scorecard_data
        except Exception as e:
            logger.info(f"Using default objectives data without OOTI: {str(e)}")
            
        # Always render the template with our reliable objectives data
        return render_template('objectives_scorecard.html', objectives_data=objectives_data)
    except Exception as e:
        logger.error(f"Error rendering scorecard: {str(e)}")
        flash(f"Error displaying objectives scorecard: {str(e)}", "danger")
        return redirect(url_for('index'))

# Slack routes
@app.route('/slack')
@login_required
def slack_channel():
    """Slack channel view"""
    if not config.ENABLE_SLACK_NOTIFICATIONS or not config.SLACK_BOT_TOKEN or not config.SLACK_CHANNEL_ID:
        flash("Slack integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    try:
        from slack_sdk import WebClient
        from slack_sdk.errors import SlackApiError
        
        # Initialize the Slack client
        client = WebClient(token=config.SLACK_BOT_TOKEN)
        
        # Get channel info
        channel_info = client.conversations_info(channel=config.SLACK_CHANNEL_ID)
        
        # Get channel history
        history = client.conversations_history(channel=config.SLACK_CHANNEL_ID, limit=30)
        
        messages = []
        for msg in history["messages"]:
            # Process messages
            message_data = {
                'text': msg.get('text', ''),
                'timestamp': datetime.fromtimestamp(float(msg['ts'])).strftime('%Y-%m-%d %H:%M:%S'),
                'user': msg.get('user', ''),
                'thread_ts': msg.get('thread_ts', None),
                'reply_count': msg.get('reply_count', 0),
                'reactions': msg.get('reactions', [])
            }
            
            # Get user info to replace user ID with real name
            if msg.get('user'):
                try:
                    user_info = client.users_info(user=msg['user'])
                    if user_info["ok"] and user_info["user"]:
                        message_data['user'] = user_info["user"].get('real_name', message_data['user'])
                except SlackApiError:
                    # If we can't get user info, just use the user ID
                    pass
            
            messages.append(message_data)
        
        # Determine most active user
        if messages:
            user_counts = {}
            for msg in messages:
                user = msg['user']
                user_counts[user] = user_counts.get(user, 0) + 1
            
            most_active_user = max(user_counts.items(), key=lambda x: x[1])[0]
        else:
            most_active_user = None
        
        return render_template('slack.html', 
                             channel_info=channel_info["channel"],
                             messages=messages,
                             most_active_user=most_active_user)
    except Exception as e:
        logger.error(f"Error accessing Slack: {str(e)}")
        flash(f"Error accessing Slack: {str(e)}", "danger")
        return redirect(url_for('index'))

@app.route('/slack/send_message', methods=['POST'])
@login_required
def send_slack_message():
    """Send a Slack message"""
    if not config.ENABLE_SLACK_NOTIFICATIONS or not config.SLACK_BOT_TOKEN or not config.SLACK_CHANNEL_ID:
        flash("Slack integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    message = request.form.get('message', '')
    use_blocks = request.form.get('use_blocks', False)
    
    if not message:
        flash("Message content is required", "danger")
        return redirect(url_for('slack_channel'))
    
    try:
        # Send the message
        success = post_message(message, blocks=None if not use_blocks else True)
        
        if success:
            flash("Message sent to Slack successfully", "success")
        else:
            flash("Failed to send message to Slack", "danger")
    except Exception as e:
        logger.error(f"Error sending Slack message: {str(e)}")
        flash(f"Error sending Slack message: {str(e)}", "danger")
    
    return redirect(url_for('slack_channel'))

# Create necessary directories
os.makedirs(config.DATA_DIR, exist_ok=True)
os.makedirs(config.DIGESTS_DIR, exist_ok=True)

# Create a new route for an anonymous landing page that auto-redirects to Google
@app.route('/login')
def login_page():
    """Login page that redirects to Google OAuth"""
    if current_user.is_authenticated:
        logger.debug(f"User already authenticated as {current_user.email}, redirecting to index")
        return redirect(url_for('index'))
    
    # Log the redirection for debugging
    logger.info("Redirecting unauthenticated user to Google OAuth login")
    # Redirect to Google authentication
    return redirect(url_for('auth.login'))

@app.before_request
def enforce_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# After app initialization
db = SQLAlchemy(app)

# Add model definitions
class Digest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    date = db.Column(db.String(10))  # YYYY-MM-DD
    content = db.Column(db.Text)  # JSON stored as text
    user_id = db.Column(db.String(100))  # Store who created it

    def to_dict(self):
        """Convert JSON content to Python dict"""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat(),
            'date': self.date,
            'content': json.loads(self.content),
            'user_id': self.user_id
        }

# Add this after registering blueprints
with app.app_context():
    db.create_all()
    logger.info("Database tables created if they didn't exist")

@app.route('/monitoring')
@login_required
def monitoring():
    """System monitoring and health dashboard"""
    # Get current platform data
    platform_data = get_cached_data()
    data_sources = platform_data.get('data_sources', {}) if platform_data else {}
    
    # Get integration status
    integration_status = {
        "hubspot": bool(config.HUBSPOT_API_KEY),
        "chargebee": bool(config.CHARGEBEE_API_KEY and config.CHARGEBEE_SITE),
        "ooti": bool(config.OOTI_API_KEY),
        "slack": bool(config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL_ID),
        "openai": bool(config.OPENAI_API_KEY),
        "gmail": config.GMAIL_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "google_drive": config.GDRIVE_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "calendar": config.CALENDAR_ENABLED and bool(config.GOOGLE_CREDENTIALS_PATH),
        "pennylane": config.PENNYLANE_ENABLED and bool(config.PENNYLANE_API_KEY),
        "jira": config.JIRA_ENABLED and bool(config.JIRA_API_KEY),
        "github": config.GITHUB_ENABLED and bool(config.GITHUB_TOKEN),
        "sentry": config.SENTRY_ENABLED and bool(config.SENTRY_API_KEY),
        "modjo": config.MODJO_ENABLED and bool(config.MODJO_API_KEY)
    }
    
    # Get the timestamp of the last data refresh
    last_refresh = data_cache["last_updated"].strftime("%Y-%m-%d %H:%M:%S") if data_cache["last_updated"] else "Never"
    
    # Calculate core integrations health percentage
    core_integrations = ["hubspot", "chargebee", "ooti", "openai"]
    core_online = sum(1 for integration in core_integrations if integration_status.get(integration, False))
    core_integrations_health = int((core_online / len(core_integrations)) * 100) if core_integrations else 0
    
    # Mock data for integration history
    integration_last_success = {
        "hubspot": (datetime.now() - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S") if integration_status["hubspot"] else "Never",
        "chargebee": (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S") if integration_status["chargebee"] else "Never",
        "ooti": (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S") if integration_status["ooti"] else "Never",
        "jira": (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S") if integration_status["jira"] else "Never",
        "github": (datetime.now() - timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S") if integration_status["github"] else "Never",
        "sentry": (datetime.now() - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S") if integration_status["sentry"] else "Never",
        "modjo": (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S") if integration_status["modjo"] else "Never",
        "gmail": (datetime.now() - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S") if integration_status["gmail"] else "Never"
    }
    
    integration_error_rates = {
        "hubspot": "0%" if integration_status["hubspot"] else "100%",
        "chargebee": "0%" if integration_status["chargebee"] else "100%",
        "ooti": "0%" if integration_status["ooti"] else "100%",
        "jira": "0%" if integration_status["jira"] else "100%",
        "github": "0%" if integration_status["github"] else "100%",
        "sentry": "0%" if integration_status["sentry"] else "100%",
        "modjo": "0%" if integration_status["modjo"] else "100%",
        "gmail": "0%" if integration_status["gmail"] else "100%"
    }
    
    # Get environment variables
    environment_vars = [
        {"name": "HUBSPOT_API_KEY", "configured": bool(config.HUBSPOT_API_KEY), "description": "HubSpot API key for CRM integration"},
        {"name": "CHARGEBEE_API_KEY", "configured": bool(config.CHARGEBEE_API_KEY), "description": "Chargebee API key for subscription management"},
        {"name": "CHARGEBEE_SITE", "configured": bool(config.CHARGEBEE_SITE), "description": "Chargebee site name"},
        {"name": "OOTI_API_KEY", "configured": bool(config.OOTI_API_KEY), "description": "OOTI API key for ERP integration"},
        {"name": "OPENAI_API_KEY", "configured": bool(config.OPENAI_API_KEY), "description": "OpenAI API key for AI features"},
        {"name": "SLACK_BOT_TOKEN", "configured": bool(config.SLACK_BOT_TOKEN), "description": "Slack bot token for notifications"},
        {"name": "SLACK_CHANNEL_ID", "configured": bool(config.SLACK_CHANNEL_ID), "description": "Slack channel ID for notifications"},
        {"name": "GOOGLE_CREDENTIALS_PATH", "configured": bool(config.GOOGLE_CREDENTIALS_PATH), "description": "Path to Google service account credentials"},
        {"name": "GMAIL_ENABLED", "configured": config.GMAIL_ENABLED, "description": "Enable Gmail integration"},
        {"name": "GDRIVE_ENABLED", "configured": config.GDRIVE_ENABLED, "description": "Enable Google Drive integration"},
        {"name": "CALENDAR_ENABLED", "configured": config.CALENDAR_ENABLED, "description": "Enable Google Calendar integration"},
        {"name": "JIRA_API_KEY", "configured": bool(config.JIRA_API_KEY), "description": "Jira API key for project management"},
        {"name": "GITHUB_TOKEN", "configured": bool(config.GITHUB_TOKEN), "description": "GitHub token for repository access"},
        {"name": "SENTRY_API_KEY", "configured": bool(config.SENTRY_API_KEY), "description": "Sentry API key for error tracking"},
        {"name": "MODJO_API_KEY", "configured": bool(config.MODJO_API_KEY), "description": "Modjo API key for conversation insights"}
    ]
    
    # Get recent logs
    recent_logs = get_recent_logs(50)
    
    # Determine overall app status
    app_status = core_integrations_health >= 75
    
    return render_template('monitoring.html',
                           integration_status=integration_status,
                           integration_last_success=integration_last_success,
                           integration_error_rates=integration_error_rates,
                           environment_vars=environment_vars,
                           recent_logs=recent_logs,
                           last_refresh=last_refresh,
                           core_integrations_health=core_integrations_health,
                           app_status=app_status,
                           data_sources=data_sources,
                           system_load="Normal")

@app.route('/test_integration/<integration>', methods=['POST'])
@login_required
@csrf.exempt  # Exempt the route, but we'll manually validate CSRF below
@limiter.limit("20 per hour")  # Add rate limiting to prevent abuse
def test_integration(integration):
    """Test a specific integration"""
    # Implement CSRF validation for AJAX requests
    token = request.form.get('csrf_token')
    # If no token in form data, check the header
    if not token and request.headers.get('X-CSRFToken'):
        token = request.headers.get('X-CSRFToken')
    
    if not token or not csrf._validate_token(token):
        logger.warning(f"CSRF validation failed in test_integration for {integration}")
        return jsonify({"success": False, "error": "CSRF validation failed"}), 403

    # Validate integration parameter to prevent injection
    valid_integrations = ["hubspot", "chargebee", "ooti", "jira", "github", 
                         "sentry", "modjo", "gmail", "google_drive", "calendar", 
                         "pennylane", "slack", "openai"]
    
    if integration not in valid_integrations:
        logger.warning(f"Invalid integration parameter: {integration}")
        return jsonify({"success": False, "error": "Invalid integration parameter"}), 400
    
    try:
        # Check if the integration is enabled and configured
        if integration == "hubspot":
            if not config.HUBSPOT_API_KEY:
                return jsonify({"success": False, "error": "HubSpot API key is not configured"})
            from api.hubspot import HubSpotAPI
            client = HubSpotAPI()
            result = client.test_connection()
            return jsonify({"success": result, "error": None if result else "Could not connect to HubSpot API"})
        
        elif integration == "chargebee":
            if not (config.CHARGEBEE_API_KEY and config.CHARGEBEE_SITE):
                return jsonify({"success": False, "error": "Chargebee credentials are not configured"})
            from api.chargebee import ChargebeeAPI
            client = ChargebeeAPI()
            result = client.test_connection()
            return jsonify({"success": result, "error": None if result else "Could not connect to Chargebee API"})
        
        elif integration == "ooti":
            if not config.OOTI_API_KEY:
                return jsonify({"success": False, "error": "OOTI API key is not configured"})
            from api.ooti import OOTIAPI
            client = OOTIAPI()
            result = client.test_connection()
            return jsonify({"success": result, "error": None if result else "Could not connect to OOTI API"})
        
        elif integration == "jira":
            if not config.JIRA_API_KEY:
                return jsonify({"success": False, "error": "Jira API key is not configured"})
            from api.jira_integration import initialize_jira_client
            result = initialize_jira_client()
            return jsonify({"success": result, "error": None if result else "Could not connect to Jira API"})
        
        elif integration == "github":
            if not config.GITHUB_TOKEN:
                return jsonify({"success": False, "error": "GitHub token is not configured"})
            from api.github_integration import initialize_github_client
            result = initialize_github_client()
            return jsonify({"success": result, "error": None if result else "Could not connect to GitHub API"})
        
        elif integration == "sentry":
            if not config.SENTRY_API_KEY:
                return jsonify({"success": False, "error": "Sentry API key is not configured"})
            from api.sentry_integration import initialize_sentry_client
            result = initialize_sentry_client()
            return jsonify({"success": result, "error": None if result else "Could not connect to Sentry API"})
        
        elif integration == "modjo":
            if not config.MODJO_API_KEY:
                return jsonify({"success": False, "error": "Modjo API key is not configured"})
            from api.modjo_integration import initialize_modjo_client
            result = initialize_modjo_client()
            return jsonify({"success": result, "error": None if result else "Could not connect to Modjo API"})
        
        elif integration == "gmail":
            if not (config.GMAIL_ENABLED and config.GOOGLE_CREDENTIALS_PATH):
                return jsonify({"success": False, "error": "Gmail integration is not enabled or credentials are missing"})
            from api.gmail_integration import initialize_gmail_client
            result = initialize_gmail_client()
            return jsonify({"success": result, "error": None if result else "Could not connect to Gmail API"})
        
        else:
            return jsonify({"success": False, "error": f"Unknown integration: {integration}"})
    
    except Exception as e:
        logger.error(f"Error testing integration {integration}: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": "An error occurred while testing the integration"}), 500

@app.route('/test_all_integrations', methods=['POST'])
@login_required
def test_all_integrations():
    """Test all configured integrations"""
    results = {}
    
    # Test each integration that is enabled
    if config.HUBSPOT_API_KEY:
        try:
            from api.hubspot import HubSpotAPI
            client = HubSpotAPI()
            results["hubspot"] = client.test_connection()
        except Exception as e:
            logger.error(f"Error testing HubSpot integration: {str(e)}")
            results["hubspot"] = False
    
    if config.CHARGEBEE_API_KEY and config.CHARGEBEE_SITE:
        try:
            from api.chargebee import ChargebeeAPI
            client = ChargebeeAPI()
            results["chargebee"] = client.test_connection()
        except Exception as e:
            logger.error(f"Error testing Chargebee integration: {str(e)}")
            results["chargebee"] = False
    
    if config.OOTI_API_KEY:
        try:
            from api.ooti import OOTIAPI
            client = OOTIAPI()
            results["ooti"] = client.test_connection()
        except Exception as e:
            logger.error(f"Error testing OOTI integration: {str(e)}")
            results["ooti"] = False
            
    if config.JIRA_API_KEY:
        try:
            from api.jira_integration import initialize_jira_client
            results["jira"] = initialize_jira_client()
        except Exception as e:
            logger.error(f"Error testing Jira integration: {str(e)}")
            results["jira"] = False
            
    if config.GITHUB_TOKEN:
        try:
            from api.github_integration import initialize_github_client
            results["github"] = initialize_github_client()
        except Exception as e:
            logger.error(f"Error testing GitHub integration: {str(e)}")
            results["github"] = False
            
    if config.SENTRY_API_KEY:
        try:
            from api.sentry_integration import initialize_sentry_client
            results["sentry"] = initialize_sentry_client()
        except Exception as e:
            logger.error(f"Error testing Sentry integration: {str(e)}")
            results["sentry"] = False
            
    if config.MODJO_API_KEY:
        try:
            from api.modjo_integration import initialize_modjo_client
            results["modjo"] = initialize_modjo_client()
        except Exception as e:
            logger.error(f"Error testing Modjo integration: {str(e)}")
            results["modjo"] = False
    
    # Calculate success rate
    success_count = sum(1 for result in results.values() if result)
    total_count = len(results)
    success_rate = (success_count / total_count * 100) if total_count > 0 else 0
    
    flash(f"Integration tests completed: {success_count}/{total_count} successful ({success_rate:.1f}%)", "info")
    return redirect(url_for('monitoring'))

@app.route('/clear_cache', methods=['POST'])
@login_required
def clear_cache():
    """Clear the application data cache"""
    global data_cache
    data_cache = {
        "last_updated": None,
        "data": None
    }
    flash("System cache cleared successfully", "success")
    return redirect(url_for('monitoring'))

@app.route('/download_logs')
@login_required
def download_logs():
    """Download system logs as a text file"""
    logs = get_recent_logs(1000)  # Get a larger number of logs for download
    
    # Format logs as text
    log_text = ""
    for log in logs:
        log_text += f"{log['timestamp']} [{log['level']}] {log['message']}\n"
    
    # Create response with text file
    response = Response(
        log_text,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename=ceo_assistant_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"}
    )
    
    return response

def get_recent_logs(limit=50):
    """Get recent system logs"""
    # This is a mock implementation - in a real app, you'd fetch from a log store
    # For this example, we're generating some sample logs
    logs = []
    now = datetime.now()
    
    # Sample log messages
    log_messages = [
        {"level": "INFO", "message": "Application started successfully"},
        {"level": "INFO", "message": "User logged in: " + (current_user.email if current_user.is_authenticated else "unknown")},
        {"level": "INFO", "message": "Data cache refreshed"},
        {"level": "INFO", "message": "Daily digest generated"},
        {"level": "WARNING", "message": "Slow API response from HubSpot (2.3s)"},
        {"level": "ERROR", "message": "Failed to connect to Chargebee API: timeout"},
        {"level": "INFO", "message": "Integration test completed for GitHub"},
        {"level": "INFO", "message": "User viewed dashboard"},
        {"level": "WARNING", "message": "High memory usage detected (85%)"},
        {"level": "INFO", "message": "Cache cleared by user"},
        {"level": "ERROR", "message": "Exception in data processor: KeyError"},
        {"level": "INFO", "message": "System monitoring page accessed"}
    ]
    
    # Generate random logs with timestamps
    for i in range(min(limit, 50)):  # Limit to 50 for this example
        log_entry = log_messages[i % len(log_messages)]
        timestamp = now - timedelta(minutes=i*5)  # Logs every 5 minutes
        logs.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "level": log_entry["level"],
            "message": log_entry["message"]
        })
    
    return logs

@app.route('/debug/session')
def debug_session():
    """Debug route to check session state - only available in development mode"""
    if os.environ.get("FLASK_ENV", "production").lower() != "development":
        return redirect(url_for('index'))
        
    debug_info = {
        "session": dict(session),
        "current_user": {
            "is_authenticated": current_user.is_authenticated,
            "id": current_user.id if current_user.is_authenticated else None,
            "email": current_user.email if current_user.is_authenticated else None
        },
        "users_db": {k: {"email": v.email, "name": v.name} for k, v in auth.users_db.items()}
    }
    
    return jsonify(debug_info)

@app.route('/api/okr_alignment')
@login_required
def okr_alignment_api():
    """API endpoint for OKR alignment analysis"""
    try:
        # Get cached data
        data = get_cached_data()
        if not data:
            return jsonify({"error": "No data available"}), 400
        
        # Generate OKR alignment analysis
        alignment = analyze_okr_alignment(data)
        
        return jsonify(alignment)
    except Exception as e:
        logger.error(f"Error in OKR alignment API: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/okr_alignment')
@login_required
def okr_alignment():
    """OKR alignment analysis page"""
    try:
        data = get_cached_data()
        if not data:
            flash("No data available. Please check your integrations.", "warning")
            return redirect(url_for('integrations'))
        
        # Generate OKR alignment analysis
        alignment = analyze_okr_alignment(data)
        
        return render_template(
            'okr_alignment.html',
            alignment=alignment,
            page_title="OKR Alignment Analysis"
        )
    except Exception as e:
        logger.error(f"Error in OKR alignment page: {str(e)}")
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/api/metrics')
@login_required
@restricted_access_required  # Only allow access to authorized emails
@audit_access_decorator      # Add audit logging
def metrics_api():
    """API endpoint for sensitive metrics data"""
    try:
        # Get cached data
        data = get_cached_data()
        if not data:
            return jsonify({"error": "No data available"}), 400
        
        # Generate metrics
        metrics = generate_key_metrics(data)
        
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Error in metrics API: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/insights')
@login_required
@restricted_access_required  # Only allow access to authorized emails
@audit_access_decorator      # Add audit logging
def insights_api():
    """API endpoint for sensitive business insights"""
    try:
        # Get cached data
        data = get_cached_data()
        if not data:
            return jsonify({"error": "No data available"}), 400
        
        # Generate insights
        insights = generate_insights(data)
        
        return jsonify(insights)
    except Exception as e:
        logger.error(f"Error in insights API: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/admin/audit-logs')
@login_required
@restricted_access_required  # Only authorized emails can access this
def admin_audit_logs():
    """Administrative endpoint to view audit logs"""
    from utils.audit_viewer import load_audit_logs, generate_summary
    import json
    from flask import render_template_string
    
    # Get parameters
    email_filter = request.args.get('email', '')
    endpoint_filter = request.args.get('endpoint', '')
    status_filter = request.args.get('status', '')
    
    # Load all logs
    logs = load_audit_logs()
    
    # Filter logs based on request parameters
    filtered_logs = []
    for log in logs:
        if log.get('is_summary', False):
            continue
            
        # Email filter
        if email_filter and not (log.get('user_email') and email_filter.lower() in log.get('user_email', '').lower()):
            continue
            
        # Endpoint filter
        if endpoint_filter and not (log.get('endpoint') and endpoint_filter.lower() in log.get('endpoint', '').lower()):
            continue
            
        # Status filter
        if status_filter == 'granted' and not log.get('access_granted'):
            continue
        elif status_filter == 'denied' and log.get('access_granted'):
            continue
            
        filtered_logs.append(log)
    
    # Generate summary
    summary = generate_summary(filtered_logs)
    
    # Limit to most recent 100 logs for display
    display_logs = sorted(filtered_logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:100]
    
    # Format logs for display
    formatted_logs = []
    for log in display_logs:
        timestamp = log.get('timestamp', '').replace('T', ' ').split('.')[0]
        status = "GRANTED" if log.get('access_granted') else "DENIED"
        user = log.get('user_email', 'Unknown')
        endpoint = log.get('endpoint', 'Unknown')
        ip = log.get('ip_address', 'Unknown')
        
        formatted_logs.append({
            'timestamp': timestamp,
            'status': status,
            'user': user,
            'endpoint': endpoint,
            'ip': ip,
            'details': json.dumps(log, indent=2)
        })
    
    # Simple HTML template for displaying logs
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Audit Logs</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">
        <style>
            .log-row { cursor: pointer; }
            .log-details { display: none; font-family: monospace; white-space: pre-wrap; }
            .denied { background-color: #ffebee; }
        </style>
    </head>
    <body>
        <div class="container mt-4">
            <h1>Audit Logs</h1>
            
            <div class="card mb-4">
                <div class="card-header">
                    <h4>Summary</h4>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-3">
                            <div class="card text-white bg-primary">
                                <div class="card-body">
                                    <h5 class="card-title">Total Attempts</h5>
                                    <p class="card-text display-4">{{ summary.total_attempts }}</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-success">
                                <div class="card-body">
                                    <h5 class="card-title">Access Granted</h5>
                                    <p class="card-text display-4">{{ summary.granted }}</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-danger">
                                <div class="card-body">
                                    <h5 class="card-title">Access Denied</h5>
                                    <p class="card-text display-4">{{ summary.denied }}</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card text-white bg-info">
                                <div class="card-body">
                                    <h5 class="card-title">Unique Users</h5>
                                    <p class="card-text display-4">{{ summary.unique_users }}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card mb-4">
                <div class="card-header">
                    <h4>Filters</h4>
                </div>
                <div class="card-body">
                    <form method="get" class="row">
                        <div class="col-md-4 mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="text" class="form-control" id="email" name="email" value="{{ email_filter }}">
                        </div>
                        <div class="col-md-4 mb-3">
                            <label for="endpoint" class="form-label">Endpoint</label>
                            <input type="text" class="form-control" id="endpoint" name="endpoint" value="{{ endpoint_filter }}">
                        </div>
                        <div class="col-md-4 mb-3">
                            <label for="status" class="form-label">Status</label>
                            <select class="form-control" id="status" name="status">
                                <option value="" {% if not status_filter %}selected{% endif %}>All</option>
                                <option value="granted" {% if status_filter == 'granted' %}selected{% endif %}>Granted</option>
                                <option value="denied" {% if status_filter == 'denied' %}selected{% endif %}>Denied</option>
                            </select>
                        </div>
                        <div class="col-12 text-end">
                            <button type="submit" class="btn btn-primary">Apply Filters</button>
                            <a href="/admin/audit-logs" class="btn btn-secondary">Clear Filters</a>
                        </div>
                    </form>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h4>Log Entries (Most Recent 100)</h4>
                </div>
                <div class="card-body p-0">
                    <table class="table table-hover mb-0">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Status</th>
                                <th>User</th>
                                <th>Endpoint</th>
                                <th>IP Address</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in logs %}
                            <tr class="log-row {% if log.status == 'DENIED' %}denied{% endif %}" onclick="toggleDetails('{{ loop.index }}')">
                                <td>{{ log.timestamp }}</td>
                                <td>{{ log.status }}</td>
                                <td>{{ log.user }}</td>
                                <td>{{ log.endpoint }}</td>
                                <td>{{ log.ip }}</td>
                            </tr>
                            <tr>
                                <td colspan="5" class="log-details" id="details-{{ loop.index }}">{{ log.details }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            
            {% if not logs %}
            <div class="alert alert-info mt-4">
                No logs matching the selected filters.
            </div>
            {% endif %}
        </div>
        
        <script>
            function toggleDetails(id) {
                const detailsRow = document.getElementById('details-' + id);
                if (detailsRow.style.display === 'table-cell') {
                    detailsRow.style.display = 'none';
                } else {
                    detailsRow.style.display = 'table-cell';
                }
            }
        </script>
    </body>
    </html>
    """
    
    return render_template_string(
        template, 
        logs=formatted_logs, 
        summary=summary,
        email_filter=email_filter,
        endpoint_filter=endpoint_filter,
        status_filter=status_filter
    )

# Add custom filters to Jinja environment
@app.template_filter('format_datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object or timestamp string."""
    if isinstance(value, str):
        # Try to parse from ISO 8601 format
        try:
            # Handle format like "2023-04-06T14:30:45.123456Z"
            if "." in value:
                # Split at the decimal point and keep only the first part
                value = value.split(".")[0]
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    
    return value.strftime(format)

# Add now function to Jinja template context
@app.context_processor
def utility_processor():
    """Add utility functions to Jinja templates"""
    return {
        'now': datetime.now
    }

import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from datetime import datetime, timedelta
import json
from pathlib import Path
from flask_login import LoginManager, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import config
from services.daily_digest import generate_daily_digest
from services.integrations import get_all_platform_data
from api.slack_integration import post_message
from utils.insights_generator import generate_insights, generate_action_items
from utils.data_processor import consolidate_data
from api.ooti import OOTIAPI
from models.user import User

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

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

# Add CSRF protection
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
def index():
    """Main dashboard page or simple landing page"""
    # If already authenticated, show the dashboard
    if current_user.is_authenticated:
        # Check for missing API keys
        if missing_keys:
            return render_template('dashboard.html', 
                                missing_keys=missing_keys,
                                error_message="Missing required API keys")
        
        try:
            platform_data = get_cached_data()
            if not platform_data:
                flash("Could not retrieve platform data. Please check your API credentials.", "danger")
                return render_template('dashboard.html', error=True)
            
            # Generate insights from the data
            insights = generate_insights(platform_data)
            action_items = generate_action_items(platform_data)
            
            # Get latest digest if it exists
            latest_digest = None
            digest_files = list(config.DIGESTS_DIR.glob("*.json"))
            if digest_files:
                latest_digest_file = max(digest_files, key=lambda x: x.stat().st_mtime)
                with open(latest_digest_file, 'r') as f:
                    latest_digest = json.load(f)
            
            return render_template('dashboard.html', 
                                insights=insights,
                                action_items=action_items,
                                platform_data=platform_data,
                                latest_digest=latest_digest,
                                last_updated=data_cache["last_updated"])
        except Exception as e:
            logger.error(f"Error in dashboard: {str(e)}")
            flash(f"An error occurred: {str(e)}", "danger")
            return render_template('dashboard.html', error=True)
    else:
        # Not authenticated, show the landing page
        return render_template('landing.html')

@app.route('/integrations')
@login_required
def integrations():
    """Shows the status of various integrations"""
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
    return render_template('integrations.html', integration_status=integration_status)

@app.route('/digests')
@login_required
def digests():
    """View all generated daily digests"""
    digest_files = sorted(config.DIGESTS_DIR.glob("*.json"), 
                          key=lambda x: x.stat().st_mtime, 
                          reverse=True)
    digests = []
    
    for digest_file in digest_files:
        try:
            with open(digest_file, 'r') as f:
                digest_data = json.load(f)
                digest_data['filename'] = digest_file.name
                digests.append(digest_data)
        except Exception as e:
            logger.error(f"Error reading digest file {digest_file}: {str(e)}")
    
    return render_template('digests.html', digests=digests)

@app.route('/digest/<filename>')
@login_required
def view_digest(filename):
    """View a specific digest"""
    digest_path = config.DIGESTS_DIR / filename
    
    if not digest_path.exists():
        flash("Digest not found", "danger")
        return redirect(url_for('digests'))
    
    try:
        with open(digest_path, 'r') as f:
            digest = json.load(f)
        return render_template('digest_view.html', digest=digest)
    except Exception as e:
        logger.error(f"Error reading digest file {filename}: {str(e)}")
        flash(f"Error reading digest: {str(e)}", "danger")
        return redirect(url_for('digests'))

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
        digest = generate_daily_digest(platform_data)
        
        # Save to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        digest_path = config.DIGESTS_DIR / f"digest_{timestamp}.json"
        with open(digest_path, 'w') as f:
            json.dump(digest, f, indent=2)
        
        # Send to Slack if enabled
        if config.ENABLE_SLACK_NOTIFICATIONS:
            # Format digest for Slack
            slack_message = f"*Daily CEO Digest - {datetime.now().strftime('%Y-%m-%d')}*\n\n"
            slack_message += f"*Executive Summary*\n{digest['executive_summary']}\n\n"
            slack_message += f"*Key Metrics*\n"
            for metric, value in digest['key_metrics'].items():
                slack_message += f"• {metric}: {value}\n"
            slack_message += f"\n*Top Priorities*\n"
            for i, item in enumerate(digest['action_items'][:3], 1):
                slack_message += f"{i}. {item}\n"
            
            # Send to Slack
            post_message(slack_message)
            flash("Digest generated and sent to Slack", "success")
        else:
            flash("Digest generated successfully", "success")
        
        return redirect(url_for('digests'))
    except Exception as e:
        logger.error(f"Error generating digest: {str(e)}")
        flash(f"Error generating digest: {str(e)}", "danger")
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
        logger.error(f"Error refreshing data: {str(e)}")
        flash(f"Error refreshing data: {str(e)}", "danger")
    
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

# Register CSRF error handler
@app.errorhandler(400)
def csrf_error(e):
    if 'CSRF' in str(e):
        logger.warning(f"CSRF error: {str(e)}")
        return render_template('403.html', error_message="CSRF token validation failed. Please try again."), 403
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
        logger.error(f"Error accessing Gmail: {str(e)}")
        flash(f"Error accessing Gmail: {str(e)}", "danger")
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
        query = request.form.get('query', '')
        
        try:
            # Search emails
            results = search_emails(query, max_results=20)
            
            return render_template('gmail_search.html', 
                                  query=query,
                                  results=results)
        except Exception as e:
            logger.error(f"Error searching Gmail: {str(e)}")
            flash(f"Error searching Gmail: {str(e)}", "danger")
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
        query = request.form.get('query', '')
        
        try:
            # Search files
            results = search_files(query, max_results=30)
            
            return render_template('drive_search.html', 
                                  query=query,
                                  results=results)
        except Exception as e:
            logger.error(f"Error searching Google Drive: {str(e)}")
            flash(f"Error searching Google Drive: {str(e)}", "danger")
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
        folder_name = request.form.get('name', '')
        parent_id = request.form.get('parent_id', None)
        
        if not folder_name:
            flash("Folder name is required", "danger")
            return render_template('folder_create.html', parent_id=parent_id)
        
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
            logger.error(f"Error creating folder: {str(e)}")
            flash(f"Error creating folder: {str(e)}", "danger")
        
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
        
        try:
            # Save the file temporarily
            temp_path = os.path.join(config.DATA_DIR, file.filename)
            file.save(temp_path)
            
            # Upload the file to Google Drive
            uploaded_file = upload_file(temp_path, parent_id, description)
            
            # Remove the temporary file
            os.remove(temp_path)
            
            if uploaded_file:
                flash(f"File '{file.filename}' uploaded successfully", "success")
                return redirect(url_for('drive_files', folder=parent_id))
            else:
                flash("Failed to upload file", "danger")
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            flash(f"Error uploading file: {str(e)}", "danger")
        
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
            email = request.form.get('email', '')
            role = request.form.get('role', 'reader')
            
            if not email:
                flash("Email address is required", "danger")
                return render_template('file_share.html', file=file_data)
            
            try:
                # Share the file
                success = share_file(file_id, email, role)
                
                if success:
                    flash(f"File shared with {email} successfully", "success")
                    return redirect(url_for('view_drive_file', file_id=file_id))
                else:
                    flash("Failed to share file", "danger")
            except Exception as e:
                logger.error(f"Error sharing file: {str(e)}")
                flash(f"Error sharing file: {str(e)}", "danger")
            
            return render_template('file_share.html', file=file_data)
        else:
            return render_template('file_share.html', file=file_data)
    except Exception as e:
        logger.error(f"Error accessing file for sharing: {str(e)}")
        flash(f"Error accessing file for sharing: {str(e)}", "danger")
        return redirect(url_for('drive_files'))

@app.route('/digest/upload_to_drive/<filename>', methods=['POST'])
@login_required
def upload_digest_to_drive_route(filename):
    """Upload a digest to Google Drive"""
    if not config.GDRIVE_ENABLED or 'upload_digest_to_drive' not in globals():
        flash("Google Drive integration is not enabled or properly configured.", "warning")
        return redirect(url_for('digests'))
    
    digest_path = config.DIGESTS_DIR / filename
    
    if not digest_path.exists():
        flash("Digest not found", "danger")
        return redirect(url_for('digests'))
    
    try:
        # Load the digest
        with open(digest_path, 'r') as f:
            digest = json.load(f)
        
        # Upload to Google Drive
        result = upload_digest_to_drive(digest)
        
        if result:
            flash("Digest uploaded to Google Drive successfully", "success")
        else:
            flash("Failed to upload digest to Google Drive", "danger")
    except Exception as e:
        logger.error(f"Error uploading digest to Google Drive: {str(e)}")
        flash(f"Error uploading digest to Google Drive: {str(e)}", "danger")
    
    return redirect(url_for('view_digest', filename=filename))

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
    """OOTI KPI scorecard page"""
    if not config.OOTI_API_KEY:
        flash("OOTI integration is not enabled or properly configured.", "warning")
        return redirect(url_for('integrations'))
    
    try:
        # Initialize OOTI API
        ooti_api = OOTIAPI()
        
        # Get scorecard data
        scorecard_data = ooti_api.get_all_ooti_data()
        
        return render_template('scorecard.html', scorecard_data=scorecard_data)
    except Exception as e:
        logger.error(f"Error accessing OOTI for scorecard: {str(e)}")
        flash(f"Error accessing OOTI data: {str(e)}", "danger")
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
    """Landing page that automatically redirects to Google OAuth"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # Directly redirect to Google authentication
    return redirect(url_for('auth.login'))

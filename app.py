import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from datetime import datetime, timedelta
import json
from pathlib import Path

import config
from services.daily_digest import generate_daily_digest
from services.integrations import get_all_platform_data
from api.slack_integration import post_message
from utils.insights_generator import generate_insights, generate_action_items
from utils.data_processor import consolidate_data

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")

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
    """Main dashboard page"""
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

@app.route('/integrations')
def integrations():
    """Shows the status of various integrations"""
    integration_status = {
        "hubspot": bool(config.HUBSPOT_API_KEY),
        "chargebee": bool(config.CHARGEBEE_API_KEY and config.CHARGEBEE_SITE),
        "ooti": bool(config.OOTI_API_KEY),
        "slack": bool(config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL_ID),
        "openai": bool(config.OPENAI_API_KEY)
    }
    return render_template('integrations.html', integration_status=integration_status)

@app.route('/digests')
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
def settings():
    """Settings page"""
    return render_template('settings.html')

@app.route('/refresh_data', methods=['POST'])
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

# Create necessary directories
os.makedirs(config.DATA_DIR, exist_ok=True)
os.makedirs(config.DIGESTS_DIR, exist_ok=True)

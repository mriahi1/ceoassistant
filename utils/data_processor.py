import logging
from datetime import datetime
import json
import config
from api.hubspot import HubSpotAPI
from api.chargebee import ChargebeeAPI
from api.ooti import OOTIAPI

logger = logging.getLogger(__name__)

def fetch_hubspot_data():
    """Fetch data from HubSpot"""
    try:
        hubspot_api = HubSpotAPI()
        return hubspot_api.get_all_hubspot_data()
    except Exception as e:
        logger.error(f"Error fetching HubSpot data: {str(e)}")
        return {
            "deals": [],
            "contacts": [],
            "activities": [],
            "pipelines": [],
            "metrics": {
                "total_deal_value": 0,
                "deals_by_stage": {},
                "recent_deals_count": 0,
                "contacts_count": 0
            },
            "error": str(e)
        }

def fetch_chargebee_data():
    """Fetch data from Chargebee"""
    try:
        chargebee_api = ChargebeeAPI()
        return chargebee_api.get_all_chargebee_data()
    except Exception as e:
        logger.error(f"Error fetching Chargebee data: {str(e)}")
        return {
            "subscriptions": [],
            "customers": [],
            "invoices": [],
            "mrr": 0,
            "metrics": {
                "active_subscriptions_count": 0,
                "canceled_subscriptions_count": 0,
                "recent_invoices_count": 0,
                "recent_revenue": 0
            },
            "error": str(e)
        }

def fetch_ooti_data():
    """Fetch data from OOTI"""
    try:
        ooti_api = OOTIAPI()
        return ooti_api.get_all_ooti_data()
    except Exception as e:
        logger.error(f"Error fetching OOTI data: {str(e)}")
        return {
            "projects": [],
            "finance_summary": {},
            "resources": [],
            "indicators": {},
            "metrics": {
                "active_projects_count": 0,
                "at_risk_projects_count": 0,
                "total_budget": 0,
                "total_spent": 0,
                "total_remaining": 0,
                "budget_utilization": 0,
                "overall_resource_utilization": 0
            },
            "error": str(e)
        }

def fetch_calendar_data():
    """Fetch data from Google Calendar"""
    if not config.CALENDAR_ENABLED:
        return {}
    
    try:
        from api.calendar_integration import get_all_calendar_data
        return get_all_calendar_data()
    except Exception as e:
        logger.error(f"Error fetching Calendar data: {str(e)}")
        return {"error": str(e)}

def fetch_gmail_data():
    """Fetch data from Gmail"""
    if not config.GMAIL_ENABLED:
        return {}
    
    try:
        from api.gmail_integration import get_unread_emails, get_recent_emails
        
        unread = get_unread_emails(max_results=10)
        recent = get_recent_emails(max_results=20)
        
        return {
            "unread_emails": unread,
            "recent_emails": recent,
            "metrics": {
                "unread_count": len(unread),
                "recent_count": len(recent)
            }
        }
    except Exception as e:
        logger.error(f"Error fetching Gmail data: {str(e)}")
        return {"error": str(e)}

def fetch_jira_data():
    """Fetch data from Jira"""
    if not config.JIRA_ENABLED:
        return {}
    
    try:
        from api.jira_integration import get_all_jira_data
        return get_all_jira_data()
    except Exception as e:
        logger.error(f"Error fetching Jira data: {str(e)}")
        return {"error": str(e)}

def fetch_github_data():
    """Fetch data from GitHub"""
    if not config.GITHUB_ENABLED:
        return {}
    
    try:
        from api.github_integration import get_all_github_data
        return get_all_github_data()
    except Exception as e:
        logger.error(f"Error fetching GitHub data: {str(e)}")
        return {"error": str(e)}

def fetch_sentry_data():
    """Fetch data from Sentry"""
    if not config.SENTRY_ENABLED:
        return {}
    
    try:
        from api.sentry_integration import get_all_sentry_data
        return get_all_sentry_data()
    except Exception as e:
        logger.error(f"Error fetching Sentry data: {str(e)}")
        return {"error": str(e)}

def fetch_modjo_data():
    """Fetch data from Modjo"""
    if not config.MODJO_ENABLED:
        return {}
    
    try:
        from api.modjo_integration import get_all_modjo_data
        return get_all_modjo_data()
    except Exception as e:
        logger.error(f"Error fetching Modjo data: {str(e)}")
        return {"error": str(e)}

def consolidate_data():
    """Consolidate data from all platforms"""
    hubspot_data = fetch_hubspot_data()
    chargebee_data = fetch_chargebee_data()
    ooti_data = fetch_ooti_data()
    calendar_data = fetch_calendar_data()
    gmail_data = fetch_gmail_data()
    jira_data = fetch_jira_data()
    github_data = fetch_github_data()
    sentry_data = fetch_sentry_data()
    modjo_data = fetch_modjo_data()
    
    # Check for errors
    errors = []
    if "error" in hubspot_data:
        errors.append(f"HubSpot error: {hubspot_data['error']}")
    if "error" in chargebee_data:
        errors.append(f"Chargebee error: {chargebee_data['error']}")
    if "error" in ooti_data:
        errors.append(f"OOTI error: {ooti_data['error']}")
    if "error" in calendar_data:
        errors.append(f"Calendar error: {calendar_data['error']}")
    if "error" in gmail_data:
        errors.append(f"Gmail error: {gmail_data['error']}")
    if "error" in jira_data:
        errors.append(f"Jira error: {jira_data['error']}")
    if "error" in github_data:
        errors.append(f"GitHub error: {github_data['error']}")
    if "error" in sentry_data:
        errors.append(f"Sentry error: {sentry_data['error']}")
    if "error" in modjo_data:
        errors.append(f"Modjo error: {modjo_data['error']}")
    
    # Create consolidated data structure
    consolidated_data = {
        "hubspot": hubspot_data,
        "chargebee": chargebee_data,
        "ooti": ooti_data,
        "calendar": calendar_data,
        "gmail": gmail_data,
        "jira": jira_data,
        "github": github_data,
        "sentry": sentry_data,
        "modjo": modjo_data,
        "timestamp": datetime.now().isoformat(),
        "errors": errors if errors else None
    }
    
    return consolidated_data

def save_data_snapshot(data, filename=None):
    """Save a snapshot of the data to a file"""
    try:
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"data_snapshot_{timestamp}.json"
        
        filepath = config.DATA_DIR / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.debug(f"Data snapshot saved to {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Error saving data snapshot: {str(e)}")
        return None

def load_data_snapshot(filename):
    """Load a data snapshot from a file"""
    try:
        filepath = config.DATA_DIR / filename
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return data
    except Exception as e:
        logger.error(f"Error loading data snapshot: {str(e)}")
        return None

def enrich_customer_data(data):
    """
    Enrich customer data by combining HubSpot and Chargebee data
    
    This creates a unified view of customers across platforms
    """
    try:
        # Get HubSpot contacts and Chargebee customers
        hubspot_contacts = data.get('hubspot', {}).get('contacts', [])
        chargebee_customers = data.get('chargebee', {}).get('customers', [])
        
        # Create a map of emails to contacts
        email_to_contact = {}
        for contact in hubspot_contacts:
            email = contact.get('email')
            if email:
                email_to_contact[email.lower()] = contact
        
        # Enrich Chargebee customers with HubSpot data
        enriched_customers = []
        for customer in chargebee_customers:
            email = customer.get('email')
            enriched_customer = customer.copy()
            
            if email and email.lower() in email_to_contact:
                contact = email_to_contact[email.lower()]
                enriched_customer['hubspot_data'] = {
                    'id': contact.get('id'),
                    'lead_status': contact.get('lead_status'),
                    'lifecycle_stage': contact.get('lifecycle_stage')
                }
            
            enriched_customers.append(enriched_customer)
        
        return enriched_customers
    except Exception as e:
        logger.error(f"Error enriching customer data: {str(e)}")
        return []

def analyze_revenue_streams(data):
    """
    Analyze revenue streams across platforms
    
    Combines HubSpot deals and Chargebee subscriptions to provide a revenue overview
    """
    try:
        # Get HubSpot deals and Chargebee subscriptions
        hubspot_deals = data.get('hubspot', {}).get('deals', [])
        chargebee_subs = data.get('chargebee', {}).get('subscriptions', [])
        mrr = data.get('chargebee', {}).get('mrr', 0)
        
        # Calculate total deal values
        total_deal_value = sum(deal.get('amount', 0) for deal in hubspot_deals)
        
        # Get active subscriptions value
        active_subs = [sub for sub in chargebee_subs if sub.get('status') == 'active']
        active_subs_value = sum(sub.get('amount', 0) for sub in active_subs)
        
        return {
            "pipeline_value": total_deal_value,
            "active_subscriptions_value": active_subs_value,
            "mrr": mrr,
            "arr": mrr * 12 if mrr else 0
        }
    except Exception as e:
        logger.error(f"Error analyzing revenue streams: {str(e)}")
        return {
            "pipeline_value": 0,
            "active_subscriptions_value": 0,
            "mrr": 0,
            "arr": 0,
            "error": str(e)
        }

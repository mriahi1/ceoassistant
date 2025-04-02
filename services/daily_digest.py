import logging
from datetime import datetime
import json
from pathlib import Path
import config
from api.openai_integration import summarize_data, generate_action_items, generate_key_metrics
from utils.data_processor import save_data_snapshot
from api.slack_integration import post_digest_to_slack

logger = logging.getLogger(__name__)

def generate_daily_digest(data):
    """
    Generate a daily digest from platform data
    
    Args:
        data (dict): Consolidated platform data
    
    Returns:
        dict: The generated digest
    """
    try:
        logger.info("Generating daily digest")
        
        # Generate executive summary using OpenAI
        executive_summary = summarize_data(data)
        
        # Generate action items
        action_items = generate_action_items(data)
        
        # Generate key metrics
        key_metrics = generate_key_metrics(data)
        
        # Create the digest structure
        digest = {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "timestamp": datetime.now().isoformat(),
            "executive_summary": executive_summary,
            "key_metrics": key_metrics,
            "action_items": action_items,
            "platform_stats": {
                "hubspot": {
                    "deals_count": len(data.get("hubspot", {}).get("deals", [])),
                    "contacts_count": len(data.get("hubspot", {}).get("contacts", [])),
                    "total_deal_value": sum(deal.get("amount", 0) for deal in data.get("hubspot", {}).get("deals", []))
                },
                "chargebee": {
                    "active_subscriptions": len([s for s in data.get("chargebee", {}).get("subscriptions", []) if s.get("status") == "active"]),
                    "mrr": data.get("chargebee", {}).get("mrr", 0),
                    "recent_invoices": len(data.get("chargebee", {}).get("invoices", []))
                },
                "ooti": {
                    "active_projects": len([p for p in data.get("ooti", {}).get("projects", []) if p.get("status") == "active"]),
                    "at_risk_projects": len([p for p in data.get("ooti", {}).get("projects", []) if p.get("status") == "at_risk"]),
                    "resource_utilization": data.get("ooti", {}).get("metrics", {}).get("overall_resource_utilization", 0)
                }
            }
        }
        
        # Save the digest
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        digest_path = config.DIGESTS_DIR / f"digest_{timestamp}.json"
        with open(digest_path, 'w') as f:
            json.dump(digest, f, indent=2)
        
        logger.info(f"Daily digest saved to {digest_path}")
        
        # Save a snapshot of the data that generated this digest
        snapshot_path = config.DATA_DIR / f"data_snapshot_{timestamp}.json"
        with open(snapshot_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        # If Slack is configured, send the digest
        if config.ENABLE_SLACK_NOTIFICATIONS and config.SLACK_BOT_TOKEN and config.SLACK_CHANNEL_ID:
            post_digest_to_slack(digest)
        
        return digest
    except Exception as e:
        logger.error(f"Error generating daily digest: {str(e)}")
        return {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "executive_summary": "Error generating daily digest. Please check the logs.",
            "key_metrics": {},
            "action_items": [f"Investigate digest generation error: {str(e)}"]
        }

def get_digest_history():
    """
    Get the history of generated digests
    
    Returns:
        list: List of digest metadata
    """
    try:
        digest_files = sorted(list(config.DIGESTS_DIR.glob("*.json")), 
                             key=lambda x: x.stat().st_mtime, 
                             reverse=True)
        
        digests = []
        for file in digest_files:
            try:
                with open(file, 'r') as f:
                    digest = json.load(f)
                
                digests.append({
                    "filename": file.name,
                    "date": digest.get("date"),
                    "timestamp": digest.get("timestamp")
                })
            except Exception as e:
                logger.error(f"Error reading digest file {file}: {str(e)}")
        
        return digests
    except Exception as e:
        logger.error(f"Error getting digest history: {str(e)}")
        return []

def get_digest(filename):
    """
    Get a specific digest by filename
    
    Args:
        filename (str): The filename of the digest
    
    Returns:
        dict: The digest or None if not found
    """
    try:
        file_path = config.DIGESTS_DIR / filename
        if not file_path.exists():
            return None
        
        with open(file_path, 'r') as f:
            digest = json.load(f)
        
        return digest
    except Exception as e:
        logger.error(f"Error getting digest {filename}: {str(e)}")
        return None

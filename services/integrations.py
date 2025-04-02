import logging
from utils.data_processor import fetch_hubspot_data, fetch_chargebee_data, fetch_ooti_data, consolidate_data

logger = logging.getLogger(__name__)

def get_all_platform_data():
    """
    Get data from all integrated platforms
    
    Returns:
        dict: Consolidated data from all platforms
    """
    try:
        logger.info("Fetching data from all platforms")
        return consolidate_data()
    except Exception as e:
        logger.error(f"Error getting platform data: {str(e)}")
        return {
            "hubspot": {},
            "chargebee": {},
            "ooti": {},
            "error": str(e)
        }

def get_platform_status():
    """
    Check the status of all platform integrations
    
    Returns:
        dict: Status of each platform integration
    """
    status = {}
    
    # Check HubSpot
    try:
        hubspot_data = fetch_hubspot_data()
        if "error" in hubspot_data:
            status["hubspot"] = {
                "connected": False,
                "error": hubspot_data["error"]
            }
        else:
            status["hubspot"] = {
                "connected": True,
                "deals_count": len(hubspot_data.get("deals", [])),
                "contacts_count": len(hubspot_data.get("contacts", []))
            }
    except Exception as e:
        status["hubspot"] = {
            "connected": False,
            "error": str(e)
        }
    
    # Check Chargebee
    try:
        chargebee_data = fetch_chargebee_data()
        if "error" in chargebee_data:
            status["chargebee"] = {
                "connected": False,
                "error": chargebee_data["error"]
            }
        else:
            status["chargebee"] = {
                "connected": True,
                "subscriptions_count": len(chargebee_data.get("subscriptions", [])),
                "customers_count": len(chargebee_data.get("customers", []))
            }
    except Exception as e:
        status["chargebee"] = {
            "connected": False,
            "error": str(e)
        }
    
    # Check OOTI
    try:
        ooti_data = fetch_ooti_data()
        if "error" in ooti_data:
            status["ooti"] = {
                "connected": False,
                "error": ooti_data["error"]
            }
        else:
            status["ooti"] = {
                "connected": True,
                "projects_count": len(ooti_data.get("projects", [])),
                "has_finance_data": bool(ooti_data.get("finance_summary"))
            }
    except Exception as e:
        status["ooti"] = {
            "connected": False,
            "error": str(e)
        }
    
    return status

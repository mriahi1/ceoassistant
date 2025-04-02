import os
import json
import logging
from openai import OpenAI
import config

logger = logging.getLogger(__name__)

# Initialize OpenAI client
openai_api_key = config.OPENAI_API_KEY
openai_client = None

if openai_api_key:
    try:
        openai_client = OpenAI(api_key=openai_api_key)
        logger.debug("OpenAI client initialized")
    except Exception as e:
        logger.error(f"Error initializing OpenAI client: {str(e)}")

def summarize_data(data, max_tokens=1000):
    """
    Summarize platform data using OpenAI
    
    Args:
        data (dict): The data to summarize
        max_tokens (int, optional): Maximum tokens for the response. Defaults to 1000.
    
    Returns:
        str: The summary text
    """
    if not openai_client:
        logger.error("OpenAI client not initialized. Cannot generate summary.")
        return "Unable to generate summary: OpenAI client not initialized."
    
    try:
        # Prepare a concise version of the data for the prompt
        hubspot_summary = data.get('hubspot', {}).get('metrics', {})
        chargebee_summary = data.get('chargebee', {}).get('metrics', {})
        ooti_summary = data.get('ooti', {}).get('metrics', {})
        
        # Format the data for the prompt
        data_summary = {
            "hubspot": hubspot_summary,
            "chargebee": chargebee_summary,
            "ooti": ooti_summary
        }
        
        prompt = (
            "As a CEO's AI assistant, analyze this data from our core platforms "
            "and provide a concise executive summary highlighting key insights, "
            "trends, opportunities, and risks. Focus on business impact and actionable insights.\n\n"
            f"DATA: {json.dumps(data_summary, indent=2)}\n\n"
            "Your executive summary (3-4 paragraphs):"
        )
        
        response = openai_client.chat.completions.create(
            model=config.OPENAI_MODEL,  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
                                         # do not change this unless explicitly requested by the user
            messages=[
                {"role": "system", "content": "You are an executive assistant AI that provides concise, insightful business analysis for a CEO."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Error generating summary with OpenAI: {str(e)}")
        return f"Unable to generate summary: {str(e)}"

def generate_strategic_insights(data, max_tokens=800):
    """
    Generate strategic insights from platform data
    
    Args:
        data (dict): The platform data
        max_tokens (int, optional): Maximum tokens for the response. Defaults to 800.
    
    Returns:
        list: List of strategic insights
    """
    if not openai_client:
        logger.error("OpenAI client not initialized. Cannot generate insights.")
        return ["Unable to generate insights: OpenAI client not initialized."]
    
    try:
        # Extract relevant data points for the prompt
        hubspot_deals = data.get('hubspot', {}).get('deals', [])[:5]  # Limit to 5 for the prompt
        chargebee_subs = data.get('chargebee', {}).get('subscriptions', [])[:5]
        ooti_projects = data.get('ooti', {}).get('projects', [])[:5]
        
        metrics = {
            "hubspot": data.get('hubspot', {}).get('metrics', {}),
            "chargebee": data.get('chargebee', {}).get('metrics', {}),
            "ooti": data.get('ooti', {}).get('metrics', {})
        }
        
        prompt = (
            "Based on this business data, identify 5 strategic insights that would be valuable "
            "for a CEO to know. Focus on sales pipeline risks/opportunities, revenue trends, "
            "operational gaps, and highlight priority areas. Each insight should be specific, "
            "actionable, and include business impact.\n\n"
            f"METRICS: {json.dumps(metrics, indent=2)}\n\n"
            f"SAMPLE DEALS: {json.dumps(hubspot_deals, indent=2)}\n\n"
            f"SAMPLE SUBSCRIPTIONS: {json.dumps(chargebee_subs, indent=2)}\n\n"
            f"SAMPLE PROJECTS: {json.dumps(ooti_projects, indent=2)}\n\n"
            "Return 5 strategic insights in this JSON format: "
            "{ \"insights\": [\"insight 1\", \"insight 2\", ...] }"
        )
        
        response = openai_client.chat.completions.create(
            model=config.OPENAI_MODEL,  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
                                         # do not change this unless explicitly requested by the user
            messages=[
                {"role": "system", "content": "You are a strategic business analyst that identifies key insights from business data."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.7,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        return result.get("insights", [])
    except Exception as e:
        logger.error(f"Error generating insights with OpenAI: {str(e)}")
        return [f"Unable to generate insights: {str(e)}"]

def generate_action_items(data, max_tokens=800):
    """
    Generate action items based on platform data
    
    Args:
        data (dict): The platform data
        max_tokens (int, optional): Maximum tokens for the response. Defaults to 800.
    
    Returns:
        list: List of action items
    """
    if not openai_client:
        logger.error("OpenAI client not initialized. Cannot generate action items.")
        return ["Unable to generate action items: OpenAI client not initialized."]
    
    try:
        # Create a summarized version of the data for the prompt
        hubspot_metrics = data.get('hubspot', {}).get('metrics', {})
        chargebee_metrics = data.get('chargebee', {}).get('metrics', {})
        ooti_metrics = data.get('ooti', {}).get('metrics', {})
        ooti_indicators = data.get('ooti', {}).get('indicators', {})
        
        # Get at-risk deals
        hubspot_deals = data.get('hubspot', {}).get('deals', [])
        at_risk_deals = [d for d in hubspot_deals if d.get('amount', 0) > 100000][:3]  # High-value deals
        
        # Get at-risk projects
        ooti_projects = data.get('ooti', {}).get('projects', [])
        at_risk_projects = [p for p in ooti_projects if p.get('status') == 'at_risk']
        
        # Format the data for the prompt
        data_summary = {
            "hubspot_metrics": hubspot_metrics,
            "chargebee_metrics": chargebee_metrics,
            "ooti_metrics": ooti_metrics,
            "ooti_indicators": ooti_indicators,
            "at_risk_deals": at_risk_deals,
            "at_risk_projects": at_risk_projects
        }
        
        prompt = (
            "As a CEO's AI assistant, based on this business data, generate a prioritized list of "
            "action items the CEO should focus on this week. Each action item should be specific, "
            "actionable, and directly tied to business impact. Focus on sales pipeline risks, revenue "
            "opportunities, operational gaps, and strategic priorities.\n\n"
            f"DATA: {json.dumps(data_summary, indent=2)}\n\n"
            "Return 7 prioritized action items in this JSON format: "
            "{ \"action_items\": [\"action 1\", \"action 2\", ...] }"
        )
        
        response = openai_client.chat.completions.create(
            model=config.OPENAI_MODEL,  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
                                         # do not change this unless explicitly requested by the user
            messages=[
                {"role": "system", "content": "You are a strategic executive assistant that creates focused, actionable to-do lists for CEOs."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.7,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        return result.get("action_items", [])
    except Exception as e:
        logger.error(f"Error generating action items with OpenAI: {str(e)}")
        return [f"Unable to generate action items: {str(e)}"]

def generate_key_metrics(data, max_tokens=500):
    """
    Generate key metrics summary from platform data
    
    Args:
        data (dict): The platform data
        max_tokens (int, optional): Maximum tokens for the response. Defaults to 500.
    
    Returns:
        dict: Dictionary of key metrics with values
    """
    if not openai_client:
        logger.error("OpenAI client not initialized. Cannot generate key metrics.")
        return {"Error": "OpenAI client not initialized"}
    
    try:
        # Extract relevant metrics from each platform
        hubspot_metrics = data.get('hubspot', {}).get('metrics', {})
        chargebee_metrics = data.get('chargebee', {}).get('metrics', {})
        ooti_metrics = data.get('ooti', {}).get('metrics', {})
        ooti_indicators = data.get('ooti', {}).get('indicators', {})
        
        metrics_data = {
            "hubspot": hubspot_metrics,
            "chargebee": chargebee_metrics,
            "ooti": {
                **ooti_metrics,
                "indicators": ooti_indicators
            }
        }
        
        prompt = (
            "As a CEO's AI assistant, identify the 8 most important business metrics "
            "from this data that the CEO should track. Calculate derived metrics when "
            "useful, and format the values to be CEO-friendly (round numbers, add $ "
            "signs for currency, % signs for percentages, etc.).\n\n"
            f"DATA: {json.dumps(metrics_data, indent=2)}\n\n"
            "Return 8 key metrics in this JSON format: "
            "{ \"metric_name1\": \"value1\", \"metric_name2\": \"value2\", ... }"
        )
        
        response = openai_client.chat.completions.create(
            model=config.OPENAI_MODEL,  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
                                         # do not change this unless explicitly requested by the user
            messages=[
                {"role": "system", "content": "You are a business metrics analyst that identifies and formats key metrics for executives."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.5,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
    except Exception as e:
        logger.error(f"Error generating key metrics with OpenAI: {str(e)}")
        return {"Error": str(e)}

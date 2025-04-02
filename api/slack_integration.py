import os
import logging
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import config

logger = logging.getLogger(__name__)

# Initialize Slack client
slack_token = config.SLACK_BOT_TOKEN
slack_channel_id = config.SLACK_CHANNEL_ID
slack_client = None

if slack_token and slack_channel_id:
    try:
        slack_client = WebClient(token=slack_token)
        logger.debug("Slack client initialized")
    except Exception as e:
        logger.error(f"Error initializing Slack client: {str(e)}")

def post_message(message: str, blocks=None, channel=None) -> bool:
    """
    Post a message to Slack
    
    Args:
        message (str): The message to post
        blocks (list, optional): Slack blocks for rich formatting. Defaults to None.
        channel (str, optional): Channel ID to post to. Defaults to configured channel.
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not slack_client:
        logger.error("Slack client not initialized. Cannot post message.")
        return False
    
    target_channel = channel or slack_channel_id
    
    try:
        response = slack_client.chat_postMessage(
            channel=target_channel,
            text=message,
            blocks=blocks
        )
        logger.debug(f"Message posted to Slack: {response.data.get('ts')}")
        return True
    except SlackApiError as e:
        logger.error(f"Error posting message to Slack: {str(e)}")
        return False

def format_digest_for_slack(digest):
    """
    Format a digest for posting to Slack
    
    Args:
        digest (dict): The digest to format
    
    Returns:
        dict: Slack blocks for the formatted digest
    """
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"CEO Daily Digest - {digest.get('date', 'Today')}",
                "emoji": True
            }
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Executive Summary*"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": digest.get('executive_summary', 'No summary available')
            }
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Key Metrics*"
            }
        }
    ]
    
    # Add key metrics
    metrics_text = ""
    for key, value in digest.get('key_metrics', {}).items():
        metrics_text += f"• *{key}*: {value}\n"
    
    if metrics_text:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": metrics_text
            }
        })
    
    # Add action items
    blocks.extend([
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Top Priorities*"
            }
        }
    ])
    
    action_items = digest.get('action_items', [])
    if action_items:
        action_items_text = ""
        for i, item in enumerate(action_items[:5], 1):
            action_items_text += f"{i}. {item}\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": action_items_text
            }
        })
    
    # Add footer
    blocks.extend([
        {
            "type": "divider"
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Generated by CEO AI Assistant"
                }
            ]
        }
    ])
    
    return blocks

def post_digest_to_slack(digest):
    """
    Post a digest to Slack
    
    Args:
        digest (dict): The digest to post
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not slack_client:
        logger.error("Slack client not initialized. Cannot post digest.")
        return False
    
    try:
        blocks = format_digest_for_slack(digest)
        summary = f"CEO Daily Digest - {digest.get('date', 'Today')}\n\n{digest.get('executive_summary', 'No summary available')}"
        
        response = slack_client.chat_postMessage(
            channel=slack_channel_id,
            text=summary,
            blocks=blocks
        )
        logger.debug(f"Digest posted to Slack: {response.data.get('ts')}")
        return True
    except SlackApiError as e:
        logger.error(f"Error posting digest to Slack: {str(e)}")
        return False

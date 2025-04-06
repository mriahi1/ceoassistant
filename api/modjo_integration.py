import requests
import logging
import config
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ================================================================
# SECURITY NOTICE: This integration operates in READ-ONLY mode
# No modifications will be made to Modjo
# All write operations are disabled for security reasons
# ================================================================

class ModjoAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key or config.MODJO_API_KEY
        self.base_url = "https://api.modjo.ai/v1"
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
    def get_conversations(self, start_date=None, end_date=None, max_results=50):
        """Get conversations from Modjo"""
        url = f"{self.base_url}/conversations"
        
        # Default to last 30 days if no dates provided
        if not start_date:
            start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        if not end_date:
            end_date = datetime.now().strftime("%Y-%m-%d")
        
        params = {
            'start_date': start_date,
            'end_date': end_date,
            'limit': max_results
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            return response.json().get('conversations', [])
        except Exception as e:
            logger.error(f"Error fetching Modjo conversations: {str(e)}")
            return []
        
    def get_conversation_details(self, conversation_id):
        """Get details for a specific conversation"""
        url = f"{self.base_url}/conversations/{conversation_id}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching Modjo conversation details for {conversation_id}: {str(e)}")
            return {}
    
    def get_conversation_summary(self, conversation_id):
        """Get summary for a specific conversation"""
        url = f"{self.base_url}/conversations/{conversation_id}/summary"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching Modjo conversation summary for {conversation_id}: {str(e)}")
            return {}
    
    def get_demo_recordings(self, max_results=20):
        """Get demo recordings"""
        # Specifically filter for demo conversations
        conversations = self.get_conversations(max_results=max_results*2)  # Get more to filter
        
        demo_conversations = []
        for conversation in conversations:
            # Look for conversations that are likely demos (based on tags or content)
            tags = conversation.get('tags', [])
            name = conversation.get('name', '').lower()
            
            if any(tag.lower() in ['demo', 'product demo', 'sales demo'] for tag in tags) or \
               any(keyword in name for keyword in ['demo', 'presentation', 'walkthrough']):
                demo_conversations.append(conversation)
                
                # Get additional details if needed
                if len(demo_conversations) <= max_results:
                    conversation_id = conversation.get('id')
                    if conversation_id:
                        details = self.get_conversation_details(conversation_id)
                        summary = self.get_conversation_summary(conversation_id)
                        
                        conversation['details'] = details
                        conversation['summary'] = summary
        
        return demo_conversations[:max_results]
    
    def get_analytics(self):
        """Get analytics from Modjo"""
        url = f"{self.base_url}/analytics"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching Modjo analytics: {str(e)}")
            return {}
    
    def get_topics(self):
        """Get trending topics from conversations"""
        url = f"{self.base_url}/topics"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json().get('topics', [])
        except Exception as e:
            logger.error(f"Error fetching Modjo topics: {str(e)}")
            return []
    
    def get_agents(self):
        """Get agent information"""
        url = f"{self.base_url}/agents"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json().get('agents', [])
        except Exception as e:
            logger.error(f"Error fetching Modjo agents: {str(e)}")
            return []
    
    def get_modjo_summary(self):
        """Get Modjo summary for dashboard"""
        conversations = self.get_conversations()
        demo_recordings = self.get_demo_recordings()
        analytics = self.get_analytics()
        topics = self.get_topics()
        agents = self.get_agents()
        
        # Process demo recordings
        demo_insights = []
        for demo in demo_recordings:
            if 'summary' in demo and demo['summary']:
                # Extract key insights from the summary
                summary = demo['summary']
                insight = {
                    'id': demo.get('id'),
                    'name': demo.get('name'),
                    'date': demo.get('date'),
                    'agent': demo.get('agent', {}).get('name'),
                    'duration': demo.get('duration'),
                    'summary': summary.get('summary'),
                    'key_points': summary.get('key_points', []),
                    'action_items': summary.get('action_items', []),
                    'sentiment': summary.get('sentiment')
                }
                demo_insights.append(insight)
        
        # Calculate statistics
        conversation_count = len(conversations)
        demo_count = len(demo_recordings)
        
        # Get average sentiment if available
        sentiment_scores = []
        for conversation in conversations:
            if 'sentiment_score' in conversation:
                sentiment_scores.append(conversation['sentiment_score'])
        
        avg_sentiment = sum(sentiment_scores) / len(sentiment_scores) if sentiment_scores else None
        
        # Extract top topics
        top_topics = topics[:10] if topics else []
        
        return {
            'conversations': conversations,
            'demo_recordings': demo_recordings,
            'demo_insights': demo_insights,
            'analytics': analytics,
            'topics': topics,
            'agents': agents,
            'metrics': {
                'conversation_count': conversation_count,
                'demo_count': demo_count,
                'avg_sentiment': avg_sentiment,
                'top_topics': top_topics
            }
        }

# Initialize Modjo client
modjo_client = None

def initialize_modjo_client():
    """Initialize the Modjo client"""
    global modjo_client
    try:
        modjo_client = ModjoAPI()
        logger.debug("Modjo client initialized")
        return True
    except Exception as e:
        logger.error(f"Error initializing Modjo client: {str(e)}")
        return False

def get_all_modjo_data():
    """Get all Modjo data for the application"""
    if not modjo_client:
        if not initialize_modjo_client():
            logger.error("Failed to initialize Modjo client.")
            return {
                "error": "Failed to initialize Modjo client. Check MODJO_API_KEY settings."
            }
    
    try:
        return modjo_client.get_modjo_summary()
    except Exception as e:
        logger.error(f"Error getting Modjo data: {str(e)}")
        return {
            "error": str(e)
        } 
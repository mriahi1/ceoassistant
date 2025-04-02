import requests
import logging
from datetime import datetime, timedelta
import time
import config
from api.mock_data import generate_hubspot_mock_data

logger = logging.getLogger(__name__)

class HubSpotAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key or config.HUBSPOT_API_KEY
        self.base_url = config.HUBSPOT_BASE_URL
        self.use_mock = not self.api_key
        
        if not self.use_mock:
            self.headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
        else:
            logger.info("No HubSpot API key provided. Using mock data.")
            self.headers = {}
        
    def _make_request(self, endpoint, method='GET', params=None, data=None):
        """Make a request to the HubSpot API"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=self.headers, params=params)
            elif method == 'POST':
                response = requests.post(url, headers=self.headers, params=params, json=data)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"HubSpot API error: {str(e)}")
            # Just log the error without trying to access response details
            raise
    
    def get_deals(self, limit=100, after=0):
        """Get deals from HubSpot"""
        endpoint = "/crm/v3/objects/deals"
        params = {
            'limit': limit,
            'properties': 'dealname,amount,closedate,pipeline,dealstage,hs_lastmodifieddate',
            'after': after
        }
        
        deals = []
        try:
            while True:
                response = self._make_request(endpoint, params=params)
                deals.extend(response.get('results', []))
                
                if 'paging' in response and 'next' in response['paging']:
                    params['after'] = response['paging']['next']['after']
                else:
                    break
                
                # Respect rate limits
                time.sleep(0.1)
                
                # For the initial version, limit to the first page
                if len(deals) >= limit:
                    break
            
            # Process and format the deals data
            formatted_deals = []
            for deal in deals:
                formatted_deal = {
                    'id': deal.get('id'),
                    'name': deal.get('properties', {}).get('dealname'),
                    'amount': float(deal.get('properties', {}).get('amount', 0) or 0),
                    'close_date': deal.get('properties', {}).get('closedate'),
                    'pipeline': deal.get('properties', {}).get('pipeline'),
                    'stage': deal.get('properties', {}).get('dealstage'),
                    'last_modified': deal.get('properties', {}).get('hs_lastmodifieddate')
                }
                formatted_deals.append(formatted_deal)
            
            return formatted_deals
        except Exception as e:
            logger.error(f"Error fetching HubSpot deals: {str(e)}")
            return []
    
    def get_contacts(self, limit=100, after=0):
        """Get contacts from HubSpot"""
        endpoint = "/crm/v3/objects/contacts"
        params = {
            'limit': limit,
            'properties': 'firstname,lastname,email,phone,company,hs_lead_status,lifecyclestage',
            'after': after
        }
        
        contacts = []
        try:
            while True:
                response = self._make_request(endpoint, params=params)
                contacts.extend(response.get('results', []))
                
                if 'paging' in response and 'next' in response['paging']:
                    params['after'] = response['paging']['next']['after']
                else:
                    break
                
                # Respect rate limits
                time.sleep(0.1)
                
                # For the initial version, limit to the first page
                if len(contacts) >= limit:
                    break
            
            # Process and format the contacts data
            formatted_contacts = []
            for contact in contacts:
                formatted_contact = {
                    'id': contact.get('id'),
                    'first_name': contact.get('properties', {}).get('firstname'),
                    'last_name': contact.get('properties', {}).get('lastname'),
                    'email': contact.get('properties', {}).get('email'),
                    'phone': contact.get('properties', {}).get('phone'),
                    'company': contact.get('properties', {}).get('company'),
                    'lead_status': contact.get('properties', {}).get('hs_lead_status'),
                    'lifecycle_stage': contact.get('properties', {}).get('lifecyclestage')
                }
                formatted_contacts.append(formatted_contact)
            
            return formatted_contacts
        except Exception as e:
            logger.error(f"Error fetching HubSpot contacts: {str(e)}")
            return []
    
    def get_activities(self, limit=50, after=0):
        """Get recent activities from HubSpot"""
        endpoint = "/crm/v3/objects/engagements"
        params = {
            'limit': limit,
            'after': after
        }
        
        try:
            activities = []
            response = self._make_request(endpoint, params=params)
            activities.extend(response.get('results', []))
            
            # Process and format the activities data
            formatted_activities = []
            for activity in activities:
                formatted_activity = {
                    'id': activity.get('id'),
                    'type': activity.get('properties', {}).get('hs_activity_type'),
                    'timestamp': activity.get('properties', {}).get('hs_timestamp'),
                    'title': activity.get('properties', {}).get('hs_title'),
                    'description': activity.get('properties', {}).get('hs_note_body')
                }
                formatted_activities.append(formatted_activity)
            
            return formatted_activities
        except Exception as e:
            logger.error(f"Error fetching HubSpot activities: {str(e)}")
            return []
    
    def get_pipelines(self):
        """Get deal pipelines from HubSpot"""
        endpoint = "/crm/v3/pipelines/deals"
        
        try:
            response = self._make_request(endpoint)
            return response.get('results', [])
        except Exception as e:
            logger.error(f"Error fetching HubSpot pipelines: {str(e)}")
            return []
    
    def get_all_hubspot_data(self):
        """Get all relevant HubSpot data for the dashboard"""
        try:
            # If using mock data, return generated mock data
            if self.use_mock:
                logger.info("Using mock HubSpot data")
                return generate_hubspot_mock_data()
            
            # Otherwise, use the real API
            deals = self.get_deals()
            contacts = self.get_contacts()
            activities = self.get_activities()
            pipelines = self.get_pipelines()
            
            # Calculate some basic metrics
            total_deal_value = sum(deal.get('amount', 0) for deal in deals)
            deals_by_stage = {}
            for deal in deals:
                stage = deal.get('stage', 'unknown')
                if stage not in deals_by_stage:
                    deals_by_stage[stage] = 0
                deals_by_stage[stage] += 1
            
            # Get deals updated in the last 7 days
            one_week_ago = int((datetime.now() - timedelta(days=7)).timestamp() * 1000)
            recent_deals = [
                deal for deal in deals
                if deal.get('last_modified') and int(deal.get('last_modified', 0)) > one_week_ago
            ]
            
            return {
                "deals": deals,
                "contacts": contacts,
                "activities": activities,
                "pipelines": pipelines,
                "metrics": {
                    "total_deal_value": total_deal_value,
                    "deals_by_stage": deals_by_stage,
                    "recent_deals_count": len(recent_deals),
                    "contacts_count": len(contacts)
                }
            }
        except Exception as e:
            logger.error(f"Error gathering HubSpot data: {str(e)}")
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

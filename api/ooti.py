import requests
import logging
from datetime import datetime, timedelta
import config
from api.mock_data import generate_ooti_mock_data

logger = logging.getLogger(__name__)

class OOTIAPI:
    def __init__(self, api_key=None, base_url=None):
        self.api_key = api_key or config.OOTI_API_KEY
        self.base_url = base_url or config.OOTI_BASE_URL
        self.use_mock = not self.api_key
        
        if not self.use_mock:
            self.headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
        else:
            logger.info("No OOTI API key provided. Will return empty data.")
            self.headers = {}
    
    def _make_request(self, endpoint, method='GET', params=None, data=None):
        """Make a request to the OOTI API"""
        # If we're using mock data, don't actually make API requests
        if self.use_mock:
            logger.info(f"No API key - not making actual request to {endpoint}")
            return {"data": []}
            
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
            logger.error(f"OOTI API error: {str(e)}")
            # Just log the error without trying to access response details
            raise
    
    def get_projects(self):
        """Get projects from OOTI"""
        endpoint = "/api/projects"
        
        try:
            response = self._make_request(endpoint)
            return response.get('data', [])
        except Exception as e:
            logger.error(f"Error fetching OOTI projects: {str(e)}")
            return []
    
    def get_finances(self):
        """Get finance data from OOTI"""
        endpoint = "/api/finances"
        
        try:
            response = self._make_request(endpoint)
            return response.get('data', {})
        except Exception as e:
            logger.error(f"Error fetching OOTI finances: {str(e)}")
            return {}
    
    def get_resources(self):
        """Get resource planning data from OOTI"""
        endpoint = "/api/resources"
        
        try:
            response = self._make_request(endpoint)
            return response.get('data', [])
        except Exception as e:
            logger.error(f"Error fetching OOTI resources: {str(e)}")
            return []
    
    def get_indicators(self):
        """Get KPI and indicators from OOTI"""
        endpoint = "/api/indicators"
        
        try:
            response = self._make_request(endpoint)
            return response.get('data', {})
        except Exception as e:
            logger.error(f"Error fetching OOTI indicators: {str(e)}")
            return {}
    
    def get_all_ooti_data(self):
        """Get all relevant OOTI data for the dashboard"""
        try:
            # If no API key, return empty data
            if self.use_mock:
                logger.info("No OOTI API key. Returning empty data.")
                return {
                    "projects": [],
                    "resources": [],
                    "finance_summary": {},
                    "indicators": {},
                    "metrics": {
                        "active_projects": 0,
                        "at_risk_projects": 0,
                        "total_budget": 0,
                        "resource_utilization": 0
                    }
                }
            
            # Otherwise, use the real API
            projects = self.get_projects()
            finances = self.get_finances()
            resources = self.get_resources()
            indicators = self.get_indicators()
            
            # Calculate metrics
            active_projects = len([p for p in projects if p.get('status') == 'active'])
            at_risk_projects = len([p for p in projects if p.get('status') == 'at_risk'])
            total_budget = sum(p.get('budget', 0) for p in projects)
            
            # Calculate resource utilization
            total_staff = sum(r.get('total_staff', 0) for r in resources) if resources else 0
            total_allocated = sum(r.get('allocated', 0) for r in resources) if resources else 0
            resource_utilization = (total_allocated / total_staff * 100) if total_staff > 0 else 0
            
            return {
                "projects": projects,
                "finance_summary": finances,
                "resources": resources,
                "indicators": indicators,
                "metrics": {
                    "active_projects": active_projects,
                    "at_risk_projects": at_risk_projects,
                    "total_budget": total_budget,
                    "resource_utilization": resource_utilization
                }
            }
        except Exception as e:
            logger.error(f"Error gathering OOTI data: {str(e)}")
            return {
                "projects": [],
                "finance_summary": {},
                "resources": [],
                "indicators": {},
                "metrics": {
                    "active_projects": 0,
                    "at_risk_projects": 0,
                    "total_budget": 0,
                    "resource_utilization": 0
                },
                "error": str(e)
            }

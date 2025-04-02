import requests
import logging
from datetime import datetime, timedelta
import config

logger = logging.getLogger(__name__)

class OOTIAPI:
    def __init__(self, api_key=None, base_url=None):
        self.api_key = api_key or config.OOTI_API_KEY
        self.base_url = base_url or config.OOTI_BASE_URL
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
    
    def _make_request(self, endpoint, method='GET', params=None, data=None):
        """Make a request to the OOTI API"""
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
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                logger.error(f"Response: {e.response.text}")
            raise
    
    def get_projects(self):
        """Get projects from OOTI"""
        endpoint = "/api/projects"
        
        try:
            response = self._make_request(endpoint)
            return response.get('data', [])
        except Exception as e:
            logger.error(f"Error fetching OOTI projects: {str(e)}")
            # For now, return a mock response since we don't have actual OOTI API specs
            # This should be updated once we have actual API documentation
            return [
                {
                    "id": "proj-001",
                    "name": "Digital Transformation Initiative",
                    "status": "active",
                    "client": "Acme Inc.",
                    "start_date": "2023-01-01",
                    "end_date": "2023-12-31",
                    "budget": 250000,
                    "spent": 120000,
                    "remaining": 130000,
                    "progress": 48,
                    "team_members": 8
                },
                {
                    "id": "proj-002",
                    "name": "Cloud Migration Project",
                    "status": "at_risk",
                    "client": "TechCorp",
                    "start_date": "2023-02-15",
                    "end_date": "2023-08-30",
                    "budget": 180000,
                    "spent": 100000,
                    "remaining": 80000,
                    "progress": 55,
                    "team_members": 6
                },
                {
                    "id": "proj-003",
                    "name": "Mobile App Development",
                    "status": "completed",
                    "client": "FinanceApp Ltd.",
                    "start_date": "2022-11-01",
                    "end_date": "2023-04-15",
                    "budget": 120000,
                    "spent": 115000,
                    "remaining": 5000,
                    "progress": 100,
                    "team_members": 5
                }
            ]
    
    def get_finances(self):
        """Get finance data from OOTI"""
        endpoint = "/api/finances"
        
        try:
            response = self._make_request(endpoint)
            return response.get('data', {})
        except Exception as e:
            logger.error(f"Error fetching OOTI finances: {str(e)}")
            # For now, return a mock response
            return {
                "monthly_revenue": 350000,
                "quarterly_profit": 180000,
                "ytd_revenue": 1250000,
                "ytd_profit": 420000,
                "operating_expenses": 170000,
                "accounts_receivable": 280000,
                "accounts_payable": 95000,
                "cash_flow": 85000
            }
    
    def get_resources(self):
        """Get resource planning data from OOTI"""
        endpoint = "/api/resources"
        
        try:
            response = self._make_request(endpoint)
            return response.get('data', [])
        except Exception as e:
            logger.error(f"Error fetching OOTI resources: {str(e)}")
            # For now, return a mock response
            return [
                {
                    "department": "Development",
                    "total_staff": 24,
                    "allocated": 22,
                    "available": 2,
                    "utilization": 92,
                    "planned_hires": 3
                },
                {
                    "department": "Design",
                    "total_staff": 8,
                    "allocated": 7,
                    "available": 1,
                    "utilization": 88,
                    "planned_hires": 1
                },
                {
                    "department": "Project Management",
                    "total_staff": 6,
                    "allocated": 6,
                    "available": 0,
                    "utilization": 100,
                    "planned_hires": 2
                },
                {
                    "department": "QA",
                    "total_staff": 10,
                    "allocated": 8,
                    "available": 2,
                    "utilization": 80,
                    "planned_hires": 0
                }
            ]
    
    def get_indicators(self):
        """Get KPI and indicators from OOTI"""
        endpoint = "/api/indicators"
        
        try:
            response = self._make_request(endpoint)
            return response.get('data', {})
        except Exception as e:
            logger.error(f"Error fetching OOTI indicators: {str(e)}")
            # For now, return a mock response
            return {
                "delivery_on_time": 86,
                "client_satisfaction": 92,
                "employee_satisfaction": 79,
                "project_profitability": 24.5,
                "resource_utilization": 90,
                "sales_pipeline_value": 2800000,
                "win_rate": 35,
                "average_deal_size": 210000
            }
    
    def get_all_ooti_data(self):
        """Get all relevant OOTI data for the dashboard"""
        try:
            projects = self.get_projects()
            finances = self.get_finances()
            resources = self.get_resources()
            indicators = self.get_indicators()
            
            # Calculate some project metrics
            active_projects = [p for p in projects if p.get('status') == 'active']
            at_risk_projects = [p for p in projects if p.get('status') == 'at_risk']
            
            total_budget = sum(p.get('budget', 0) for p in projects)
            total_spent = sum(p.get('spent', 0) for p in projects)
            total_remaining = sum(p.get('remaining', 0) for p in projects)
            
            # Format finance summary
            finance_summary = {
                "monthly_revenue": finances.get('monthly_revenue', 0),
                "ytd_revenue": finances.get('ytd_revenue', 0),
                "quarterly_profit": finances.get('quarterly_profit', 0),
                "cash_flow": finances.get('cash_flow', 0)
            }
            
            # Resource utilization
            total_staff = sum(r.get('total_staff', 0) for r in resources)
            total_allocated = sum(r.get('allocated', 0) for r in resources)
            overall_utilization = (total_allocated / total_staff * 100) if total_staff > 0 else 0
            
            return {
                "projects": projects,
                "finance_summary": finance_summary,
                "resources": resources,
                "indicators": indicators,
                "metrics": {
                    "active_projects_count": len(active_projects),
                    "at_risk_projects_count": len(at_risk_projects),
                    "total_budget": total_budget,
                    "total_spent": total_spent,
                    "total_remaining": total_remaining,
                    "budget_utilization": (total_spent / total_budget * 100) if total_budget > 0 else 0,
                    "overall_resource_utilization": overall_utilization
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

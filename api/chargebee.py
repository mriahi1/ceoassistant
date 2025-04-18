import requests
import logging
import base64
from datetime import datetime, timedelta
import config
from api.mock_data import generate_chargebee_mock_data

logger = logging.getLogger(__name__)

class ChargebeeAPI:
    def __init__(self, api_key=None, site=None):
        self.api_key = api_key or config.CHARGEBEE_API_KEY
        self.site = site or config.CHARGEBEE_SITE
        self.use_mock = not (self.api_key and self.site)
        
        if not self.use_mock:
            self.base_url = f"https://{self.site}.chargebee.com/api/v2"
            self.auth = base64.b64encode(f"{self.api_key}:".encode()).decode()
            self.headers = {
                'Authorization': f'Basic {self.auth}',
                'Content-Type': 'application/json'
            }
        else:
            logger.info("No Chargebee API key or site provided. Will return empty data.")
            self.base_url = ""
            self.headers = {}
    
    def _make_request(self, endpoint, method='GET', params=None, data=None):
        """Make a request to the Chargebee API"""
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
            logger.error(f"Chargebee API error: {str(e)}")
            # Just log the error without trying to access response details
            raise
    
    def get_subscriptions(self, limit=100, offset="start"):
        """Get subscriptions from Chargebee"""
        endpoint = "/subscriptions"
        params = {
            'limit': limit,
            'offset': offset,
            'sort_by[desc]': 'created_at'
        }
        
        subscriptions = []
        try:
            while True:
                response = self._make_request(endpoint, params=params)
                subscriptions.extend([item.get('subscription', {}) for item in response.get('list', [])])
                
                if response.get('next_offset'):
                    params['offset'] = response.get('next_offset')
                else:
                    break
                
                # For the initial version, limit to the first page
                if len(subscriptions) >= limit:
                    break
            
            # Process and format the subscriptions data
            formatted_subscriptions = []
            for subscription in subscriptions:
                formatted_subscription = {
                    'id': subscription.get('id'),
                    'customer_id': subscription.get('customer_id'),
                    'plan_id': subscription.get('plan_id'),
                    'status': subscription.get('status'),
                    'amount': subscription.get('plan_amount') / 100 if subscription.get('plan_amount') else 0,
                    'currency_code': subscription.get('currency_code'),
                    'created_at': datetime.fromtimestamp(subscription.get('created_at', 0)).isoformat() if subscription.get('created_at') else None,
                    'current_term_start': datetime.fromtimestamp(subscription.get('current_term_start', 0)).isoformat() if subscription.get('current_term_start') else None,
                    'current_term_end': datetime.fromtimestamp(subscription.get('current_term_end', 0)).isoformat() if subscription.get('current_term_end') else None,
                    'billing_period': subscription.get('billing_period'),
                    'billing_period_unit': subscription.get('billing_period_unit')
                }
                formatted_subscriptions.append(formatted_subscription)
            
            return formatted_subscriptions
        except Exception as e:
            logger.error(f"Error fetching Chargebee subscriptions: {str(e)}")
            return []
    
    def get_customers(self, limit=100, offset="start"):
        """Get customers from Chargebee"""
        endpoint = "/customers"
        params = {
            'limit': limit,
            'offset': offset,
            'sort_by[desc]': 'created_at'
        }
        
        customers = []
        try:
            while True:
                response = self._make_request(endpoint, params=params)
                customers.extend([item.get('customer', {}) for item in response.get('list', [])])
                
                if response.get('next_offset'):
                    params['offset'] = response.get('next_offset')
                else:
                    break
                
                # For the initial version, limit to the first page
                if len(customers) >= limit:
                    break
            
            # Process and format the customers data
            formatted_customers = []
            for customer in customers:
                formatted_customer = {
                    'id': customer.get('id'),
                    'first_name': customer.get('first_name'),
                    'last_name': customer.get('last_name'),
                    'email': customer.get('email'),
                    'company': customer.get('company'),
                    'created_at': datetime.fromtimestamp(customer.get('created_at', 0)).isoformat() if customer.get('created_at') else None
                }
                formatted_customers.append(formatted_customer)
            
            return formatted_customers
        except Exception as e:
            logger.error(f"Error fetching Chargebee customers: {str(e)}")
            return []
    
    def get_invoices(self, limit=100, offset="start"):
        """Get invoices from Chargebee"""
        endpoint = "/invoices"
        params = {
            'limit': limit,
            'offset': offset,
            'sort_by[desc]': 'date'
        }
        
        invoices = []
        try:
            while True:
                response = self._make_request(endpoint, params=params)
                invoices.extend([item.get('invoice', {}) for item in response.get('list', [])])
                
                if response.get('next_offset'):
                    params['offset'] = response.get('next_offset')
                else:
                    break
                
                # For the initial version, limit to the first page
                if len(invoices) >= limit:
                    break
            
            # Process and format the invoices data
            formatted_invoices = []
            for invoice in invoices:
                formatted_invoice = {
                    'id': invoice.get('id'),
                    'customer_id': invoice.get('customer_id'),
                    'subscription_id': invoice.get('subscription_id'),
                    'status': invoice.get('status'),
                    'amount': invoice.get('total') / 100 if invoice.get('total') else 0,
                    'amount_paid': invoice.get('amount_paid') / 100 if invoice.get('amount_paid') else 0,
                    'amount_due': invoice.get('amount_due') / 100 if invoice.get('amount_due') else 0,
                    'currency_code': invoice.get('currency_code'),
                    'date': datetime.fromtimestamp(invoice.get('date', 0)).isoformat() if invoice.get('date') else None,
                    'due_date': datetime.fromtimestamp(invoice.get('due_date', 0)).isoformat() if invoice.get('due_date') else None
                }
                formatted_invoices.append(formatted_invoice)
            
            return formatted_invoices
        except Exception as e:
            logger.error(f"Error fetching Chargebee invoices: {str(e)}")
            return []
    
    def get_mrr(self):
        """Get MRR from Chargebee"""
        endpoint = "/subscriptions"
        params = {
            'limit': 100,
            'status[is]': 'active'
        }
        
        try:
            active_subscriptions = []
            response = self._make_request(endpoint, params=params)
            active_subscriptions.extend([item.get('subscription', {}) for item in response.get('list', [])])
            
            # Calculate MRR
            mrr = 0
            for subscription in active_subscriptions:
                # Convert to monthly value regardless of billing frequency
                if subscription.get('billing_period_unit') == 'month':
                    mrr += (subscription.get('plan_amount', 0) / 100)
                elif subscription.get('billing_period_unit') == 'year':
                    mrr += (subscription.get('plan_amount', 0) / 100) / 12
            
            return mrr
        except Exception as e:
            logger.error(f"Error calculating Chargebee MRR: {str(e)}")
            return 0
    
    def get_all_chargebee_data(self):
        """Get all relevant Chargebee data for the dashboard"""
        try:
            # If no API key, return empty data
            if self.use_mock:
                logger.info("No Chargebee API key. Returning empty data.")
                return {
                    "subscriptions": [],
                    "customers": [],
                    "invoices": [],
                    "mrr": 0,
                    "metrics": {
                        "active_subscriptions": 0,
                        "total_customers": 0,
                        "recent_invoices": 0,
                        "mrr_by_plan": {}
                    }
                }
            
            # Otherwise, use the real API
            subscriptions = self.get_subscriptions()
            customers = self.get_customers()
            invoices = self.get_invoices()
            mrr = self.get_mrr()
            
            # Calculate metrics
            active_subscriptions = len([s for s in subscriptions if s.get('status') == 'active'])
            
            # Get invoices created in the last 30 days
            thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
            recent_invoices = [
                inv for inv in invoices
                if inv.get('date') and inv.get('date') > thirty_days_ago
            ]
            
            # Calculate MRR by plan
            mrr_by_plan = {}
            for subscription in subscriptions:
                if subscription.get('status') == 'active':
                    plan_id = subscription.get('plan_id', 'unknown')
                    if plan_id not in mrr_by_plan:
                        mrr_by_plan[plan_id] = 0
                    mrr_by_plan[plan_id] += subscription.get('amount', 0)
            
            return {
                "subscriptions": subscriptions,
                "customers": customers,
                "invoices": invoices,
                "mrr": mrr,
                "metrics": {
                    "active_subscriptions": active_subscriptions,
                    "total_customers": len(customers),
                    "recent_invoices": len(recent_invoices),
                    "mrr_by_plan": mrr_by_plan
                }
            }
        except Exception as e:
            logger.error(f"Error gathering Chargebee data: {str(e)}")
            return {
                "subscriptions": [],
                "customers": [],
                "invoices": [],
                "mrr": 0,
                "metrics": {
                    "active_subscriptions": 0,
                    "total_customers": 0,
                    "recent_invoices": 0,
                    "mrr_by_plan": {}
                },
                "error": str(e)
            }

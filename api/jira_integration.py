import requests
import logging
import config
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ================================================================
# SECURITY NOTICE: This integration operates in READ-ONLY mode
# No modifications will be made to Jira
# All write operations are disabled for security reasons
# ================================================================

class JiraAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key or config.JIRA_API_KEY
        self.domain = "ooti.atlassian.net"  # Ooti's Jira domain
        self.email = "mriahi@ooti.co"  # Associated email address
        self.auth = (self.email, self.api_key)
        
    def get_tickets(self, max_results=50):
        """Get Jira tickets"""
        url = f"https://{self.domain}/rest/api/3/search"
        
        # Query for tickets updated in the last 30 days
        jql = "updated >= -30d ORDER BY updated DESC"
        
        params = {
            'jql': jql,
            'maxResults': max_results
        }
        
        try:
            response = requests.get(url, auth=self.auth, params=params)
            response.raise_for_status()
            
            tickets = []
            for issue in response.json().get('issues', []):
                tickets.append({
                    'id': issue.get('key'),
                    'summary': issue.get('fields', {}).get('summary'),
                    'status': issue.get('fields', {}).get('status', {}).get('name'),
                    'priority': issue.get('fields', {}).get('priority', {}).get('name'),
                    'assignee': issue.get('fields', {}).get('assignee', {}).get('displayName'),
                    'updated': issue.get('fields', {}).get('updated')
                })
            
            return tickets
        except Exception as e:
            logger.error(f"Error fetching Jira tickets: {str(e)}")
            return []

    def get_sprint_info(self, board_id=1):
        """Get current sprint information"""
        url = f"https://{self.domain}/rest/agile/1.0/board/{board_id}/sprint"
        
        params = {
            'state': 'active'
        }
        
        try:
            response = requests.get(url, auth=self.auth, params=params)
            response.raise_for_status()
            
            sprints = response.json().get('values', [])
            if not sprints:
                return None
            
            current_sprint = sprints[0]
            
            # Get sprint issues
            sprint_id = current_sprint.get('id')
            issues_url = f"https://{self.domain}/rest/agile/1.0/sprint/{sprint_id}/issue"
            
            issues_response = requests.get(issues_url, auth=self.auth)
            issues_response.raise_for_status()
            
            issues = issues_response.json().get('issues', [])
            
            # Categorize issues by status
            todo = []
            in_progress = []
            done = []
            
            for issue in issues:
                status = issue.get('fields', {}).get('status', {}).get('name', '')
                
                issue_data = {
                    'id': issue.get('key'),
                    'summary': issue.get('fields', {}).get('summary'),
                    'priority': issue.get('fields', {}).get('priority', {}).get('name'),
                    'assignee': issue.get('fields', {}).get('assignee', {}).get('displayName')
                }
                
                if status.lower() in ['to do', 'open', 'new']:
                    todo.append(issue_data)
                elif status.lower() in ['in progress', 'in development', 'review']:
                    in_progress.append(issue_data)
                elif status.lower() in ['done', 'closed', 'resolved']:
                    done.append(issue_data)
            
            return {
                'id': sprint_id,
                'name': current_sprint.get('name'),
                'start_date': current_sprint.get('startDate'),
                'end_date': current_sprint.get('endDate'),
                'issues': {
                    'todo': todo,
                    'in_progress': in_progress,
                    'done': done
                },
                'metrics': {
                    'total_issues': len(issues),
                    'todo_count': len(todo),
                    'in_progress_count': len(in_progress),
                    'done_count': len(done),
                    'completion_percentage': round(len(done) / len(issues) * 100, 1) if issues else 0
                }
            }
        except Exception as e:
            logger.error(f"Error fetching sprint info: {str(e)}")
            return None

    def get_support_tickets(self, max_results=30):
        """Get support-related tickets"""
        url = f"https://{self.domain}/rest/api/3/search"
        
        # Query for support tickets
        jql = "project = 'Support' ORDER BY created DESC"
        
        params = {
            'jql': jql,
            'maxResults': max_results
        }
        
        try:
            response = requests.get(url, auth=self.auth, params=params)
            response.raise_for_status()
            
            tickets = []
            for issue in response.json().get('issues', []):
                tickets.append({
                    'id': issue.get('key'),
                    'summary': issue.get('fields', {}).get('summary'),
                    'status': issue.get('fields', {}).get('status', {}).get('name'),
                    'priority': issue.get('fields', {}).get('priority', {}).get('name'),
                    'reporter': issue.get('fields', {}).get('reporter', {}).get('displayName'),
                    'created': issue.get('fields', {}).get('created'),
                    'customer': issue.get('fields', {}).get('customfield_10024')  # Adjust field ID as needed
                })
            
            return tickets
        except Exception as e:
            logger.error(f"Error fetching support tickets: {str(e)}")
            return []

    def get_jira_summary(self):
        """Get summary of Jira data for dashboard"""
        # Get all needed data
        tickets = self.get_tickets()
        sprint_info = self.get_sprint_info()
        support_tickets = self.get_support_tickets()
        
        # Calculate statistics
        statuses = {}
        priorities = {}
        
        for ticket in tickets:
            status = ticket.get('status')
            priority = ticket.get('priority')
            
            if status:
                statuses[status] = statuses.get(status, 0) + 1
            
            if priority:
                priorities[priority] = priorities.get(priority, 0) + 1
        
        # Calculate support statistics
        open_support = len([t for t in support_tickets if t.get('status') not in ['Done', 'Closed', 'Resolved']])
        high_priority_support = len([t for t in support_tickets if t.get('priority') in ['High', 'Highest', 'Critical']])
        
        return {
            'tickets': tickets,
            'sprint': sprint_info,
            'support_tickets': support_tickets,
            'metrics': {
                'total_tickets': len(tickets),
                'by_status': statuses,
                'by_priority': priorities,
                'support': {
                    'total': len(support_tickets),
                    'open': open_support,
                    'high_priority': high_priority_support
                }
            }
        }

# Initialize Jira client
jira_client = None

def initialize_jira_client():
    """Initialize the Jira client"""
    global jira_client
    try:
        jira_client = JiraAPI()
        logger.debug("Jira client initialized")
        return True
    except Exception as e:
        logger.error(f"Error initializing Jira client: {str(e)}")
        return False

def get_all_jira_data():
    """Get all Jira data for the application"""
    if not jira_client:
        if not initialize_jira_client():
            logger.error("Failed to initialize Jira client.")
            return {
                "error": "Failed to initialize Jira client. Check JIRA_API_KEY settings."
            }
    
    try:
        return jira_client.get_jira_summary()
    except Exception as e:
        logger.error(f"Error getting Jira data: {str(e)}")
        return {
            "error": str(e)
        } 
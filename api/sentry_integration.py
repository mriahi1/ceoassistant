import requests
import logging
import config
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ================================================================
# SECURITY NOTICE: This integration operates in READ-ONLY mode
# No modifications will be made to Sentry
# All write operations are disabled for security reasons
# ================================================================

class SentryAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key or config.SENTRY_API_KEY
        self.org_slug = "ooti"  # Sentry organization slug
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
    def get_projects(self):
        """Get Sentry projects"""
        url = f"https://sentry.io/api/0/organizations/{self.org_slug}/projects/"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            projects = []
            for project in response.json():
                projects.append({
                    'id': project.get('id'),
                    'slug': project.get('slug'),
                    'name': project.get('name'),
                    'platform': project.get('platform'),
                    'status': project.get('status'),
                    'team': project.get('team', {}).get('name')
                })
            
            return projects
        except Exception as e:
            logger.error(f"Error fetching Sentry projects: {str(e)}")
            return []
        
    def get_issues(self, project_slug=None, max_results=50):
        """Get Sentry issues"""
        url = f"https://sentry.io/api/0/organizations/{self.org_slug}/issues/"
        
        params = {
            'limit': max_results
        }
        
        if project_slug:
            params['project'] = project_slug
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            issues = []
            for issue in response.json():
                issues.append({
                    'id': issue.get('id'),
                    'title': issue.get('title'),
                    'project': issue.get('project', {}).get('slug'),
                    'level': issue.get('level'),
                    'count': issue.get('count'),
                    'users_count': issue.get('userCount'),
                    'last_seen': issue.get('lastSeen'),
                    'first_seen': issue.get('firstSeen'),
                    'status': issue.get('status'),
                    'permalink': issue.get('permalink')
                })
            
            return issues
        except Exception as e:
            logger.error(f"Error fetching Sentry issues: {str(e)}")
            return []
    
    def get_issue_details(self, issue_id):
        """Get details for a specific issue"""
        url = f"https://sentry.io/api/0/issues/{issue_id}/"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            issue = response.json()
            
            # Get the events for this issue
            events_url = f"https://sentry.io/api/0/issues/{issue_id}/events/"
            events_response = requests.get(events_url, headers=self.headers)
            events_response.raise_for_status()
            
            events = events_response.json()
            
            return {
                'issue': issue,
                'events': events
            }
        except Exception as e:
            logger.error(f"Error fetching issue details for {issue_id}: {str(e)}")
            return {}
    
    def get_stats(self, project_slug=None):
        """Get statistics for issues"""
        url = f"https://sentry.io/api/0/organizations/{self.org_slug}/stats/"
        
        params = {}
        if project_slug:
            params['project'] = project_slug
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching Sentry stats: {str(e)}")
            return {}
    
    def get_sentry_summary(self):
        """Get Sentry summary for dashboard"""
        projects = self.get_projects()
        issues = self.get_issues()
        
        # Get project-specific issues for active projects
        project_issues = {}
        for project in projects[:5]:  # Limit to first 5 projects
            slug = project.get('slug')
            if slug:
                project_issues[slug] = self.get_issues(project_slug=slug, max_results=10)
        
        # Calculate statistics
        by_level = {}
        by_project = {}
        by_status = {}
        
        for issue in issues:
            level = issue.get('level')
            project = issue.get('project')
            status = issue.get('status')
            
            if level:
                by_level[level] = by_level.get(level, 0) + 1
            
            if project:
                by_project[project] = by_project.get(project, 0) + 1
            
            if status:
                by_status[status] = by_status.get(status, 0) + 1
        
        # Get stats
        stats = self.get_stats()
        
        # Get detailed info for top issues
        top_issues = []
        for issue in issues[:5]:  # Limit to first 5 issues
            issue_id = issue.get('id')
            if issue_id:
                details = self.get_issue_details(issue_id)
                if details:
                    top_issues.append({
                        'issue': issue,
                        'details': details
                    })
        
        return {
            'projects': projects,
            'issues': issues,
            'project_issues': project_issues,
            'top_issues': top_issues,
            'stats': stats,
            'metrics': {
                'total_issues': len(issues),
                'by_level': by_level,
                'by_project': by_project,
                'by_status': by_status,
                'project_count': len(projects)
            }
        }

# Initialize Sentry client
sentry_client = None

def initialize_sentry_client():
    """Initialize the Sentry client"""
    global sentry_client
    try:
        sentry_client = SentryAPI()
        logger.debug("Sentry client initialized")
        return True
    except Exception as e:
        logger.error(f"Error initializing Sentry client: {str(e)}")
        return False

def get_all_sentry_data():
    """Get all Sentry data for the application"""
    if not sentry_client:
        if not initialize_sentry_client():
            logger.error("Failed to initialize Sentry client.")
            return {
                "error": "Failed to initialize Sentry client. Check SENTRY_API_KEY settings."
            }
    
    try:
        return sentry_client.get_sentry_summary()
    except Exception as e:
        logger.error(f"Error getting Sentry data: {str(e)}")
        return {
            "error": str(e)
        } 
import requests
import logging
import config
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ================================================================
# SECURITY NOTICE: This integration operates in READ-ONLY mode
# No modifications will be made to GitHub
# All write operations are disabled for security reasons
# ================================================================

class GitHubAPI:
    def __init__(self, token=None):
        self.token = token or config.GITHUB_TOKEN
        self.headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.org = "ooti-co"  # GitHub organization
        
    def get_repositories(self, max_results=30):
        """Get repositories from GitHub"""
        url = f"https://api.github.com/orgs/{self.org}/repos"
        
        params = {
            'sort': 'updated',
            'direction': 'desc',
            'per_page': max_results
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            repos = []
            for repo in response.json():
                repos.append({
                    'id': repo.get('id'),
                    'name': repo.get('name'),
                    'full_name': repo.get('full_name'),
                    'description': repo.get('description'),
                    'language': repo.get('language'),
                    'url': repo.get('html_url'),
                    'created_at': repo.get('created_at'),
                    'updated_at': repo.get('updated_at'),
                    'stars': repo.get('stargazers_count'),
                    'forks': repo.get('forks_count')
                })
            
            return repos
        except Exception as e:
            logger.error(f"Error fetching GitHub repositories: {str(e)}")
            return []
        
    def get_pull_requests(self, state="all", max_results=30):
        """Get pull requests from GitHub across repositories"""
        repos = self.get_repositories(max_results=max_results)
        
        prs = []
        for repo in repos[:10]:  # Limit to 10 repos to avoid too many API calls
            repo_name = repo.get('name')
            url = f"https://api.github.com/repos/{self.org}/{repo_name}/pulls"
            
            params = {
                'state': state,
                'sort': 'updated',
                'direction': 'desc',
                'per_page': 5  # Limit PRs per repo
            }
            
            try:
                response = requests.get(url, headers=self.headers, params=params)
                if response.status_code == 404:
                    continue  # Skip repos with no PRs
                
                response.raise_for_status()
                
                for pr in response.json():
                    prs.append({
                        'id': pr.get('number'),
                        'title': pr.get('title'),
                        'repo': repo_name,
                        'author': pr.get('user', {}).get('login'),
                        'state': pr.get('state'),
                        'created_at': pr.get('created_at'),
                        'updated_at': pr.get('updated_at'),
                        'url': pr.get('html_url'),
                        'labels': [label.get('name') for label in pr.get('labels', [])]
                    })
            except Exception as e:
                logger.error(f"Error fetching GitHub PRs for {repo_name}: {str(e)}")
                continue
        
        # Sort by updated_at
        prs.sort(key=lambda x: x.get('updated_at', ''), reverse=True)
        return prs[:max_results]
    
    def get_commits(self, repo_name, max_results=20):
        """Get recent commits for a repository"""
        url = f"https://api.github.com/repos/{self.org}/{repo_name}/commits"
        
        params = {
            'per_page': max_results
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            commits = []
            for commit in response.json():
                commits.append({
                    'sha': commit.get('sha'),
                    'message': commit.get('commit', {}).get('message'),
                    'author': commit.get('commit', {}).get('author', {}).get('name'),
                    'date': commit.get('commit', {}).get('author', {}).get('date'),
                    'url': commit.get('html_url')
                })
            
            return commits
        except Exception as e:
            logger.error(f"Error fetching GitHub commits for {repo_name}: {str(e)}")
            return []
    
    def get_deployments(self, repo_name, max_results=10):
        """Get recent deployments for a repository"""
        url = f"https://api.github.com/repos/{self.org}/{repo_name}/deployments"
        
        params = {
            'per_page': max_results
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            deployments = []
            for deployment in response.json():
                # Get deployment status
                status_url = deployment.get('statuses_url')
                status_response = requests.get(status_url, headers=self.headers)
                status_response.raise_for_status()
                
                statuses = status_response.json()
                latest_status = statuses[0] if statuses else {}
                
                deployments.append({
                    'id': deployment.get('id'),
                    'environment': deployment.get('environment'),
                    'ref': deployment.get('ref'),
                    'sha': deployment.get('sha'),
                    'created_at': deployment.get('created_at'),
                    'creator': deployment.get('creator', {}).get('login'),
                    'status': latest_status.get('state', 'unknown'),
                    'status_description': latest_status.get('description')
                })
            
            return deployments
        except Exception as e:
            logger.error(f"Error fetching GitHub deployments for {repo_name}: {str(e)}")
            return []
    
    def get_all_deployments(self, max_results=20):
        """Get deployments across repositories"""
        repos = self.get_repositories(max_results=10)
        
        all_deployments = []
        for repo in repos:
            repo_name = repo.get('name')
            deployments = self.get_deployments(repo_name, max_results=5)
            
            for deployment in deployments:
                deployment['repo'] = repo_name
                all_deployments.append(deployment)
        
        # Sort by created_at
        all_deployments.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return all_deployments[:max_results]
    
    def get_github_summary(self):
        """Get GitHub summary for dashboard"""
        repos = self.get_repositories()
        prs = self.get_pull_requests()
        deployments = self.get_all_deployments()
        
        # Get commits for most recently updated repo
        recent_commits = []
        if repos:
            recent_repo = repos[0].get('name')
            recent_commits = self.get_commits(recent_repo)
        
        # Calculate statistics
        open_prs = [pr for pr in prs if pr.get('state') == 'open']
        deployment_environments = {}
        
        for deployment in deployments:
            env = deployment.get('environment')
            if env:
                deployment_environments[env] = deployment_environments.get(env, 0) + 1
        
        return {
            'repositories': repos,
            'pull_requests': prs,
            'open_pull_requests': open_prs,
            'deployments': deployments,
            'recent_commits': recent_commits,
            'metrics': {
                'repo_count': len(repos),
                'open_prs': len(open_prs),
                'recent_deployments': len(deployments),
                'environments': deployment_environments
            }
        }

# Initialize GitHub client
github_client = None

def initialize_github_client():
    """Initialize the GitHub client"""
    global github_client
    try:
        github_client = GitHubAPI()
        logger.debug("GitHub client initialized")
        return True
    except Exception as e:
        logger.error(f"Error initializing GitHub client: {str(e)}")
        return False

def get_all_github_data():
    """Get all GitHub data for the application"""
    if not github_client:
        if not initialize_github_client():
            logger.error("Failed to initialize GitHub client.")
            return {
                "error": "Failed to initialize GitHub client. Check GITHUB_TOKEN settings."
            }
    
    try:
        return github_client.get_github_summary()
    except Exception as e:
        logger.error(f"Error getting GitHub data: {str(e)}")
        return {
            "error": str(e)
        } 
import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import Flask app only after patching environment
os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
os.environ['SESSION_SECRET'] = 'test_secret_key'
os.environ['TESTING'] = 'True'

from flask import Flask, current_app, request_started, request_finished
from app import app as flask_app

@pytest.fixture
def app():
    """Create a Flask application for testing."""
    # Configure app for testing
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['SERVER_NAME'] = 'localhost'
    
    # Return the Flask app from app.py
    return flask_app

@pytest.fixture
def client(app):
    """Create a test client for the app."""
    with app.test_client() as client:
        with app.app_context():
            # Create tables in the in-memory database
            try:
                from app import db
                db.create_all()
            except Exception as e:
                print(f"Error creating database tables: {e}")
            
            yield client

@pytest.fixture
def authenticated_client(client):
    """Create an authenticated client session."""
    with patch('flask_login.utils._get_user') as mock_get_user:
        # Create a mock authenticated user
        mock_user = MagicMock()
        mock_user.is_authenticated = True
        mock_user.id = 'test_user_id'
        mock_user.email = 'test@example.com'
        mock_user.name = 'Test User'
        mock_user.picture = None
        mock_user.login_time = 12345
        mock_user.last_active = 12345
        mock_get_user.return_value = mock_user
        
        with client.session_transaction() as sess:
            sess['user_id'] = 'test_user_id'
        
        yield client

@pytest.fixture
def mock_auth_users_db():
    """Mock the auth.users_db dictionary."""
    with patch('auth.users_db') as mock_users_db:
        # Create a dictionary-like mock
        mock_dict = {}
        mock_users_db.__getitem__.side_effect = mock_dict.__getitem__
        mock_users_db.__setitem__.side_effect = mock_dict.__setitem__
        mock_users_db.__contains__.side_effect = mock_dict.__contains__
        mock_users_db.get.side_effect = mock_dict.get
        mock_users_db.pop.side_effect = mock_dict.pop
        
        # Add a test user
        test_user = MagicMock()
        test_user.id = 'test_user_id'
        test_user.email = 'test@example.com'
        test_user.name = 'Test User'
        test_user.picture = None
        test_user.login_time = 12345
        test_user.last_active = 12345
        
        mock_dict['test_user_id'] = test_user
        yield mock_users_db

@pytest.fixture
def temp_digest_dir():
    """Create a temporary directory for storing digests during tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test digest file
        test_digest = {
            "id": 123,
            "date": "2023-01-01",
            "content": "Test digest content"
        }
        
        with open(temp_path / "digest_2023-01-01.json", "w") as f:
            import json
            json.dump(test_digest, f)
        
        # Patch the config.DIGESTS_DIR
        with patch('app.config.DIGESTS_DIR', temp_path):
            with patch('config.DIGESTS_DIR', temp_path):
                yield temp_path

@pytest.fixture
def mock_platform_data():
    """Mock platform data for testing."""
    return {
        'hubspot': {
            'deals': [
                {'id': 1, 'name': 'Deal 1', 'amount': 10000, 'stage': 'proposal'},
                {'id': 2, 'name': 'Deal 2', 'amount': 20000, 'stage': 'closed_won'}
            ],
            'contacts': [
                {'id': 1, 'name': 'Contact 1', 'email': 'contact1@example.com'},
                {'id': 2, 'name': 'Contact 2', 'email': 'contact2@example.com'}
            ],
            'companies': [
                {'id': 1, 'name': 'Company 1'},
                {'id': 2, 'name': 'Company 2'}
            ],
            'metrics': {
                'total_deals': 2,
                'pipeline_value': 30000,
                'closed_deals': 1
            }
        },
        'chargebee': {
            'subscriptions': [
                {'id': 'sub_1', 'plan_id': 'plan_basic', 'status': 'active'},
                {'id': 'sub_2', 'plan_id': 'plan_premium', 'status': 'active'}
            ],
            'mrr': 5000,
            'invoices': [
                {'id': 'inv_1', 'amount': 1000, 'status': 'paid'},
                {'id': 'inv_2', 'amount': 2000, 'status': 'pending'}
            ],
            'metrics': {
                'active_subscriptions': 2,
                'mrr': 5000,
                'annual_revenue': 60000
            }
        },
        'ooti': {
            'projects': [
                {'id': 1, 'name': 'Project 1', 'status': 'active'},
                {'id': 2, 'name': 'Project 2', 'status': 'completed'},
                {'id': 3, 'name': 'Project 3', 'status': 'active'}
            ],
            'finance_summary': {
                'revenue': 150000,
                'expenses': 100000,
                'profit': 50000
            },
            'employees': [
                {'id': 1, 'name': 'Employee 1'},
                {'id': 2, 'name': 'Employee 2'}
            ],
            'metrics': {
                'active_projects': 2,
                'completed_projects': 1,
                'avg_project_value': 50000
            },
            'indicators': {
                'on_time_delivery': 85,
                'client_satisfaction': 92,
                'resource_utilization': 78
            }
        }
    }

@pytest.fixture
def mock_integrations():
    """Mock integration configuration."""
    patches = [
        patch('app.config.HUBSPOT_API_KEY', 'test_hubspot_key'),
        patch('app.config.CHARGEBEE_API_KEY', 'test_chargebee_key'),
        patch('app.config.CHARGEBEE_SITE', 'test_chargebee_site'),
        patch('app.config.OOTI_API_KEY', 'test_ooti_key'),
        patch('app.config.OPENAI_API_KEY', 'test_openai_key'),
        patch('app.config.SLACK_BOT_TOKEN', 'test_slack_token'),
        patch('app.config.SLACK_CHANNEL_ID', 'test_slack_channel'),
        patch('app.config.GOOGLE_CREDENTIALS_PATH', 'test_google_path'),
        patch('app.config.GMAIL_ENABLED', True),
        patch('app.config.GDRIVE_ENABLED', True),
        patch('app.config.CALENDAR_ENABLED', True),
        patch('app.config.PENNYLANE_ENABLED', True),
        patch('app.config.PENNYLANE_API_KEY', 'test_pennylane_key')
    ]
    
    for p in patches:
        p.start()
    
    yield
    
    for p in patches:
        p.stop() 
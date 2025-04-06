import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from flask import session, url_for
from app import app, get_cached_data

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    with app.test_client() as client:
        with app.app_context():
            yield client

@pytest.fixture
def authenticated_client(client):
    """Fixture for an authenticated client session"""
    with patch('flask_login.utils._get_user') as mock_get_user:
        # Create a mock authenticated user
        mock_user = MagicMock()
        mock_user.is_authenticated = True
        mock_user.id = 'test_user_id'
        mock_user.email = 'test@example.com'
        mock_get_user.return_value = mock_user
        
        with client.session_transaction() as sess:
            sess['user_id'] = 'test_user_id'
        
        yield client

class TestRoutes:
    def test_index_route(self, client):
        """Test that the index route returns the landing page when not authenticated"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'landing' in response.data.lower()
    
    def test_authenticated_index(self, authenticated_client):
        """Test that the index route shows dashboard for authenticated users"""
        with patch('app.get_cached_data', return_value={'hubspot': {}, 'chargebee': {}, 'ooti': {}}):
            with patch('app.generate_insights', return_value=[]):
                with patch('app.generate_action_items', return_value=[]):
                    response = authenticated_client.get('/')
                    assert response.status_code == 200
                    assert b'dashboard' in response.data.lower()
    
    def test_error_pages(self, client):
        """Test that error pages work correctly"""
        # Test 404 page
        response = client.get('/non_existent_route')
        assert response.status_code == 404
        
        # Test route that would trigger a 500 error
        with patch('app.get_cached_data', side_effect=Exception("Test error")):
            with authenticated_client.session_transaction() as sess:
                sess['user_id'] = 'test_user_id'
            
            response = authenticated_client.get('/')
            assert b'error' in response.data.lower()
    
    def test_forbidden_access(self, client):
        """Test access to forbidden resources"""
        # Mock a 403 response
        @app.route('/test_forbidden')
        def test_forbidden():
            from flask import abort
            abort(403)
        
        response = client.get('/test_forbidden')
        assert response.status_code == 403
        assert b'403' in response.data

class TestIntegrations:
    def test_integrations_page(self, authenticated_client):
        """Test the integrations status page"""
        response = authenticated_client.get('/integrations')
        assert response.status_code == 200
        assert b'integration' in response.data.lower()
    
    @patch('app.config.HUBSPOT_API_KEY', 'test_key')
    @patch('app.config.CHARGEBEE_API_KEY', 'test_key')
    @patch('app.config.CHARGEBEE_SITE', 'test_site')
    @patch('app.config.OOTI_API_KEY', 'test_key')
    def test_integration_status(self, authenticated_client):
        """Test that integration status is correctly reported"""
        response = authenticated_client.get('/integrations')
        assert response.status_code == 200
        # Check that the page shows the integrations as configured
        assert b'hubspot' in response.data.lower()
        assert b'chargebee' in response.data.lower()
        assert b'ooti' in response.data.lower()
    
    @patch('app.HubSpotAPI')
    def test_integration_testing(self, mock_hubspot, authenticated_client):
        """Test the integration testing functionality"""
        # Mock the test_connection method
        mock_instance = MagicMock()
        mock_instance.test_connection.return_value = True
        mock_hubspot.return_value = mock_instance
        
        # Mock CSRF validation
        with patch('app.csrf._validate_token', return_value=True):
            response = authenticated_client.post('/test_integration/hubspot',
                                              headers={'X-CSRFToken': 'test_token'},
                                              data={'csrf_token': 'test_token'})
            
            # Parse the JSON response
            data = json.loads(response.data)
            assert data['success'] is True

class TestDigestGeneration:
    @patch('app.get_cached_data')
    @patch('app.generate_daily_digest')
    def test_digest_generation(self, mock_generate_digest, mock_get_data, authenticated_client):
        """Test the digest generation functionality"""
        # Mock the necessary functions
        mock_get_data.return_value = {'test': 'data'}
        mock_generate_digest.return_value = {'id': 123, 'date': '2023-01-01', 'content': 'Test digest'}
        
        # Test the digest generation endpoint
        response = authenticated_client.post('/generate_digest', follow_redirects=True)
        
        # Check that the functions were called with correct parameters
        mock_get_data.assert_called_once()
        mock_generate_digest.assert_called_once_with({'test': 'data'}, user_id='test_user_id')
        
        # Check the response
        assert response.status_code == 200
        assert b'digest' in response.data.lower()

class TestMonitoring:
    def test_monitoring_page(self, authenticated_client):
        """Test the system monitoring page"""
        response = authenticated_client.get('/monitoring')
        assert response.status_code == 200
        assert b'monitoring' in response.data.lower()
        
        # Check for specific monitoring sections
        assert b'integration' in response.data.lower()
        assert b'environment' in response.data.lower()
        assert b'log' in response.data.lower()
    
    def test_test_all_integrations(self, authenticated_client):
        """Test the 'test all integrations' functionality"""
        with patch('app.HubSpotAPI') as mock_hubspot, \
             patch('app.ChargebeeAPI') as mock_chargebee, \
             patch('app.OOTIAPI') as mock_ooti:
            
            # Set up mocks
            mock_hubspot_instance = MagicMock()
            mock_hubspot_instance.test_connection.return_value = True
            mock_hubspot.return_value = mock_hubspot_instance
            
            mock_chargebee_instance = MagicMock()
            mock_chargebee_instance.test_connection.return_value = True
            mock_chargebee.return_value = mock_chargebee_instance
            
            mock_ooti_instance = MagicMock()
            mock_ooti_instance.test_connection.return_value = False  # One failure
            mock_ooti.return_value = mock_ooti_instance
            
            # Test the endpoint
            response = authenticated_client.post('/test_all_integrations', follow_redirects=True)
            
            # Check response
            assert response.status_code == 200
            assert b'monitoring' in response.data.lower()
            assert b'integration test' in response.data.lower()
    
    def test_clear_cache(self, authenticated_client):
        """Test the cache clearing functionality"""
        # First make a request to populate the cache
        with patch('app.get_all_platform_data', return_value={'test': 'data'}):
            authenticated_client.get('/')
        
        # Now clear the cache
        response = authenticated_client.post('/clear_cache', follow_redirects=True)
        
        # Check response
        assert response.status_code == 200
        assert b'cache cleared' in response.data.lower()
        
        # Check that data_cache was actually reset
        from app import data_cache
        assert data_cache["last_updated"] is None
        assert data_cache["data"] is None

class TestScorecard:
    @patch('app.OOTIAPI')
    def test_scorecard_view(self, mock_ooti, authenticated_client):
        """Test the scorecard view"""
        # Mock the OOTI API
        mock_instance = MagicMock()
        mock_instance.get_all_ooti_data.return_value = {
            'project_delivery': {
                'status': 'green',
                'metric': 'On-time delivery',
                'value': '95%'
            },
            'customer_satisfaction': {
                'status': 'yellow',
                'metric': 'Customer NPS',
                'value': '45'
            },
            'financial_performance': {
                'status': 'green',
                'metric': 'Revenue',
                'value': '€120,000'
            }
        }
        mock_ooti.return_value = mock_instance
        
        # Test the scorecard endpoint
        response = authenticated_client.get('/scorecard')
        
        # Check response
        assert response.status_code == 200
        assert b'scorecard' in response.data.lower()
        
        # Check for scorecard data
        assert b'project_delivery' in response.data.lower()
        assert b'customer_satisfaction' in response.data.lower()
        assert b'financial_performance' in response.data.lower()

class TestAPIEndpoints:
    @patch('app.get_cached_data')
    def test_platform_summary_api(self, mock_get_data, authenticated_client):
        """Test the platform summary API endpoint"""
        # Mock the data
        mock_get_data.return_value = {
            'hubspot': {
                'deals': [{'id': 1, 'amount': 1000}, {'id': 2, 'amount': 2000}],
                'contacts': [{'id': 1}, {'id': 2}, {'id': 3}]
            },
            'chargebee': {
                'subscriptions': [{'id': 1}, {'id': 2}],
                'mrr': 3000,
                'invoices': [{'id': 1}]
            },
            'ooti': {
                'projects': [{'id': 1}, {'id': 2}, {'id': 3}],
                'finance_summary': {'revenue': 100000}
            }
        }
        
        # Test the API endpoint
        response = authenticated_client.get('/api/platform_summary')
        
        # Check response
        assert response.status_code == 200
        
        # Parse the JSON response
        data = json.loads(response.data)
        
        # Check the data structure
        assert 'hubspot' in data
        assert 'chargebee' in data
        assert 'ooti' in data
        
        # Check specific values
        assert data['hubspot']['deals_count'] == 2
        assert data['hubspot']['total_deal_value'] == 3000
        assert data['chargebee']['active_subscriptions'] == 2
        assert data['ooti']['active_projects'] == 3 
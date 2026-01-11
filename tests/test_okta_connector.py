"""
Unit tests for OktaConnector module
Tests API connectivity, log retrieval, and filtering functionality
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from okta_connector import OktaConnector


class TestOktaConnectorInit:
    """Test OktaConnector initialization"""
    
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_init_with_valid_credentials(self):
        """Test successful initialization with valid credentials"""
        connector = OktaConnector()
        assert connector.domain == 'test.okta.com'
        assert connector.api_token == 'test_token'
        assert connector.base_url == 'https://test.okta.com/api/v1'
    
    @patch.dict(os.environ, {'OKTA_DOMAIN': '', 'OKTA_API_TOKEN': ''}, clear=True)
    def test_init_with_missing_credentials(self):
        """Test initialization fails with missing credentials"""
        with pytest.raises(ValueError):
            OktaConnector()
    
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com'}, clear=True)
    def test_init_with_missing_token(self):
        """Test initialization fails with missing API token"""
        with pytest.raises(ValueError):
            OktaConnector()


class TestOktaConnectorConnection:
    """Test OktaConnector connection methods"""
    
    @patch('okta_connector.requests.get')
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_test_connection_success(self, mock_get):
        """Test successful API connection test"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        connector = OktaConnector()
        result = connector.test_connection()
        
        assert result is True
        mock_get.assert_called_once()
    
    @patch('okta_connector.requests.get')
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_test_connection_failure_auth(self, mock_get):
        """Test failed API connection due to authentication error"""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_get.return_value = mock_response
        
        connector = OktaConnector()
        result = connector.test_connection()
        
        assert result is False
    
    @patch('okta_connector.requests.get')
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_test_connection_request_exception(self, mock_get):
        """Test connection failure due to request exception"""
        import requests.exceptions
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        connector = OktaConnector()
        result = connector.test_connection()
        
        assert result is False


class TestOktaConnectorLogs:
    """Test OktaConnector log retrieval"""
    
    @patch('okta_connector.requests.get')
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_get_logs_success(self, mock_get):
        """Test successful log retrieval"""
        mock_logs = [
            {'eventType': 'user.authentication.auth_success', 'published': '2026-01-11T10:00:00Z'},
            {'eventType': 'user.session.start', 'published': '2026-01-11T10:01:00Z'}
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_logs
        mock_get.return_value = mock_response
        
        connector = OktaConnector()
        logs = connector.get_logs(hours_ago=24, limit=100)
        
        assert len(logs) == 2
        assert logs[0]['eventType'] == 'user.authentication.auth_success'
    
    @patch('okta_connector.requests.get')
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_get_logs_failure(self, mock_get):
        """Test failed log retrieval"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        connector = OktaConnector()
        logs = connector.get_logs()
        
        assert logs == []
    
    @patch('okta_connector.requests.get')
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_get_logs_timeout(self, mock_get):
        """Test log retrieval timeout"""
        import requests.exceptions
        mock_get.side_effect = requests.exceptions.Timeout("Request timeout")
        
        connector = OktaConnector()
        logs = connector.get_logs()
        
        assert logs == []


class TestOktaConnectorAuthLogs:
    """Test OktaConnector authentication log filtering"""
    
    @patch('okta_connector.requests.get')
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_get_authentication_logs_filtering(self, mock_get):
        """Test authentication event filtering"""
        mock_logs = [
            {'eventType': 'user.authentication.auth_success', 'eventTypeDescription': 'Authentication Success'},
            {'eventType': 'user.session.start', 'eventTypeDescription': 'User session started'},
            {'eventType': 'user.mfa.factor_enroll_success', 'eventTypeDescription': 'MFA Enroll Success'},
            {'eventType': 'app.generic.unclassified.event', 'eventTypeDescription': 'Some app event'}
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_logs
        mock_get.return_value = mock_response
        
        connector = OktaConnector()
        auth_logs = connector.get_authentication_logs()
        
        # Should filter to only auth-related events
        assert len(auth_logs) == 3
        assert all('authentication' in log['eventType'].lower() or 
                   'login' in log['eventType'].lower() or 
                   'session' in log['eventType'].lower() or 
                   'mfa' in log['eventType'].lower() or 
                   'verify' in log['eventType'].lower() 
                   for log in auth_logs)
    
    @patch('okta_connector.requests.get')
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token'})
    def test_get_authentication_logs_empty(self, mock_get):
        """Test authentication log retrieval with no results"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response
        
        connector = OktaConnector()
        auth_logs = connector.get_authentication_logs()
        
        assert auth_logs == []


class TestOktaConnectorHeaders:
    """Test OktaConnector header configuration"""
    
    @patch.dict(os.environ, {'OKTA_DOMAIN': 'test.okta.com', 'OKTA_API_TOKEN': 'test_token_123'})
    def test_ssws_authentication_header(self):
        """Test SSWS authentication header format"""
        connector = OktaConnector()
        
        assert 'Authorization' in connector.headers
        assert connector.headers['Authorization'] == 'SSWS test_token_123'
        assert connector.headers['Accept'] == 'application/json'
        assert connector.headers['Content-Type'] == 'application/json'

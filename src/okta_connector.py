"""
Okta API Connector
This module handles authentication and communication with Okta's System Log API
"""

import os
import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any
from dotenv import load_dotenv
import requests.exceptions

from config import DEFAULT_LOG_HOURS_BACK, DEFAULT_LOG_LIMIT, API_TIMEOUT, AUTH_EVENT_KEYWORDS

load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)


class OktaConnector:
    """Handles Okta API authentication and log retrieval"""
    
    def __init__(self) -> None:
        """Initialize Okta connector with credentials from environment variables
        
        Raises:
            ValueError: If OKTA_DOMAIN or OKTA_API_TOKEN environment variables are missing
        """
        self.domain = os.getenv('OKTA_DOMAIN')
        self.api_token = os.getenv('OKTA_API_TOKEN')
        
        if not self.domain or not self.api_token:
            error_msg = "Missing Okta credentials. Check your .env file for OKTA_DOMAIN and OKTA_API_TOKEN"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        self.base_url = f"https://{self.domain}/api/v1"
        self.timeout = API_TIMEOUT
        
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'SSWS {self.api_token}'
        }
        
        logger.info(f"Connected to Okta domain: {self.domain}")
    
    def test_connection(self) -> bool:
        """Test connectivity to Okta API
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            url = f"{self.base_url}/logs"
            params = {'limit': 1}
            
            response = requests.get(url, headers=self.headers, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                logger.info("API connection successful!")
                return True
            else:
                logger.error(f"API connection failed. Status: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error(f"API request timed out after {self.timeout} seconds")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error testing connection: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error testing connection: {str(e)}")
            return False
    
    def get_logs(self, hours_ago: int = DEFAULT_LOG_HOURS_BACK, limit: int = DEFAULT_LOG_LIMIT) -> List[Dict[str, Any]]:
        """Fetch raw logs from Okta API
        
        Args:
            hours_ago: Number of hours back to fetch logs from (default: 24)
            limit: Maximum number of logs to retrieve (default: 1000)
            
        Returns:
            List[Dict]: List of log events from Okta API, or empty list if failed
        """
        try:
            since = datetime.utcnow() - timedelta(hours=hours_ago)
            since_str = since.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            url = f"{self.base_url}/logs"
            params = {
                'since': since_str,
                'limit': limit,
                'sortOrder': 'DESCENDING'
            }
            
            logger.info(f"Fetching logs from last {hours_ago} hours...")
            
            response = requests.get(url, headers=self.headers, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                logs = response.json()
                logger.info(f"Retrieved {len(logs)} log events")
                return logs
            else:
                logger.error(f"Failed to retrieve logs. Status: {response.status_code}")
                return []
                
        except requests.exceptions.Timeout:
            logger.error(f"API request timed out after {self.timeout} seconds")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error retrieving logs: {str(e)}")
            return []
        except ValueError as e:
            logger.error(f"JSON parsing error: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving logs: {str(e)}")
            return []
    
    def get_authentication_logs(self, hours_ago: int = DEFAULT_LOG_HOURS_BACK) -> List[Dict[str, Any]]:
        """Fetch and filter authentication-related logs
        
        Args:
            hours_ago: Number of hours back to fetch logs from (default: 24)
            
        Returns:
            List[Dict]: Filtered list of authentication events
        """
        all_logs = self.get_logs(hours_ago=hours_ago, limit=DEFAULT_LOG_LIMIT)
        
        auth_logs = []
        for log in all_logs:
            event_type = log.get('eventType', '').lower()
            if any(keyword in event_type for keyword in AUTH_EVENT_KEYWORDS):
                auth_logs.append(log)
        
        logger.info(f"Filtered to {len(auth_logs)} authentication events")
        return auth_logs


if __name__ == "__main__":
    # Configure logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Testing Okta Connector...\n")
    
    connector = OktaConnector()
    
    if connector.test_connection():
        logger.info("=" * 50)
        
        logs = connector.get_authentication_logs(hours_ago=1)
        
        if logs:
            logger.info(f"\nSample of first 3 events:\n")
            for i, log in enumerate(logs[:3], 1):
                logger.info(f"Event {i}:")
                logger.info(f"  Type: {log.get('eventType')}")
                logger.info(f"  Time: {log.get('published')}")
                logger.info(f"  User: {log.get('actor', {}).get('alternateId', 'N/A')}")
                logger.info(f"  Outcome: {log.get('outcome', {}).get('result', 'N/A')}")
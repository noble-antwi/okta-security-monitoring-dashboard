"""
Okta API Connector
This module handles authentication and communication with Okta's System Log API
"""

import os
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

class OktaConnector:
    
    def __init__(self):
        self.domain = os.getenv('OKTA_DOMAIN')
        self.api_token = os.getenv('OKTA_API_TOKEN')
        
        if not self.domain or not self.api_token:
            raise ValueError("Missing Okta credentials. Check your .env file")
        
        self.base_url = f"https://{self.domain}/api/v1"
        
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'SSWS {self.api_token}'
        }
        
        print(f"Connected to Okta domain: {self.domain}")
    
    def test_connection(self):
        try:
            url = f"{self.base_url}/logs"
            params = {'limit': 1}
            
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                print("API connection successful!")
                return True
            else:
                print(f"API connection failed. Status: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error testing connection: {str(e)}")
            return False
    
    def get_logs(self, hours_ago=24, limit=100):
        try:
            since = datetime.utcnow() - timedelta(hours=hours_ago)
            since_str = since.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            url = f"{self.base_url}/logs"
            params = {
                'since': since_str,
                'limit': limit,
                'sortOrder': 'DESCENDING'
            }
            
            print(f"Fetching logs from last {hours_ago} hours...")
            
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                logs = response.json()
                print(f"Retrieved {len(logs)} log events")
                return logs
            else:
                print(f"Failed to retrieve logs. Status: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"Error retrieving logs: {str(e)}")
            return []
    
    def get_authentication_logs(self, hours_ago=24):
        all_logs = self.get_logs(hours_ago=hours_ago, limit=1000)
        
        auth_keywords = ['authentication', 'login', 'session', 'mfa', 'verify']
        
        auth_logs = []
        for log in all_logs:
            event_type = log.get('eventType', '').lower()
            if any(keyword in event_type for keyword in auth_keywords):
                auth_logs.append(log)
        
        print(f"Filtered to {len(auth_logs)} authentication events")
        return auth_logs


if __name__ == "__main__":
    print("Testing Okta Connector...\n")
    
    connector = OktaConnector()
    
    if connector.test_connection():
        print("\n" + "="*50)
        
        logs = connector.get_authentication_logs(hours_ago=1)
        
        if logs:
            print(f"\nSample of first 3 events:\n")
            for i, log in enumerate(logs[:3], 1):
                print(f"Event {i}:")
                print(f"  Type: {log.get('eventType')}")
                print(f"  Time: {log.get('published')}")
                print(f"  User: {log.get('actor', {}).get('alternateId', 'N/A')}")
                print(f"  Outcome: {log.get('outcome', {}).get('result', 'N/A')}")
                print()
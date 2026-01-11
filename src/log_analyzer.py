"""
Okta Log Analyzer
Analyzes authentication logs to detect security threats
"""

import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any
import json

from config import (
    FAILED_LOGIN_THRESHOLD,
    MFA_FAILURE_THRESHOLD,
    RISK_LEVEL_CRITICAL,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_MEDIUM
)

# Configure logging
logger = logging.getLogger(__name__)


class LogAnalyzer:
    """Analyzes Okta logs for security threats and anomalies"""
    
    def __init__(self) -> None:
        """Initialize the analyzer with threat detection thresholds"""
        
        self.failed_login_threshold = FAILED_LOGIN_THRESHOLD
        self.mfa_failure_threshold = MFA_FAILURE_THRESHOLD
        
        logger.info("Log Analyzer initialized")
    
    def analyze_failed_logins(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect users/IPs with excessive failed login attempts
        
        Args:
            logs: List of log events
            
        Returns:
            dict: Users and IPs with suspicious failed login patterns
        """
        logger.info("Analyzing failed login patterns...")
        
        # Track failures by user and IP
        user_failures: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        ip_failures: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        # Process each log event
        for log in logs:
            event_type = log.get('eventType', '')
            outcome = log.get('outcome', {}).get('result', '')
            
            # Check if this is a failed authentication
            if 'authentication' in event_type.lower() and outcome == 'FAILURE':
                # Get user email
                user = log.get('actor', {}).get('alternateId', 'Unknown')
                
                # Get IP address
                ip = log.get('client', {}).get('ipAddress', 'Unknown')
                
                # Get timestamp
                timestamp = log.get('published', '')
                
                # Store failure info
                failure_info = {
                    'time': timestamp,
                    'ip': ip,
                    'reason': log.get('outcome', {}).get('reason', 'Unknown')
                }
                
                user_failures[user].append(failure_info)
                ip_failures[ip].append(failure_info)
        
        # Identify suspicious patterns
        suspicious_users = {}
        suspicious_ips = {}
        
        # Check users with multiple failures
        for user, failures in user_failures.items():
            if len(failures) >= self.failed_login_threshold:
                suspicious_users[user] = {
                    'failure_count': len(failures),
                    'failures': failures,
                    'risk_level': self._calculate_risk_level(len(failures))
                }
        
        # Check IPs with multiple failures
        for ip, failures in ip_failures.items():
            if len(failures) >= self.failed_login_threshold:
                suspicious_ips[ip] = {
                    'failure_count': len(failures),
                    'failures': failures,
                    'risk_level': self._calculate_risk_level(len(failures))
                }
        
        logger.info(f"   Found {len(suspicious_users)} suspicious users")
        logger.info(f"   Found {len(suspicious_ips)} suspicious IPs")
        
        return {
            'suspicious_users': suspicious_users,
            'suspicious_ips': suspicious_ips
        }
    
    def analyze_mfa_events(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze MFA usage and detect issues
        
        Args:
            logs: List of log events
            
        Returns:
            dict: MFA statistics and issues
        """
        logger.info("Analyzing MFA events...")
        
        mfa_stats: Dict[str, Any] = {
            'total_challenges': 0,
            'successful': 0,
            'failed': 0,
            'denied': 0,
            'users_with_failures': defaultdict(int)
        }
        
        for log in logs:
            event_type = log.get('eventType', '')
            
            # Check for MFA events
            if 'mfa' in event_type.lower():
                outcome = log.get('outcome', {}).get('result', '')
                user = log.get('actor', {}).get('alternateId', 'Unknown')
                
                mfa_stats['total_challenges'] += 1
                
                if outcome == 'SUCCESS':
                    mfa_stats['successful'] += 1
                elif outcome == 'FAILURE':
                    mfa_stats['failed'] += 1
                    mfa_stats['users_with_failures'][user] += 1
                elif 'deny' in event_type.lower():
                    mfa_stats['denied'] += 1
                    mfa_stats['users_with_failures'][user] += 1
        
        # Calculate MFA success rate
        if mfa_stats['total_challenges'] > 0:
            success_rate = (mfa_stats['successful'] / mfa_stats['total_challenges']) * 100
            mfa_stats['success_rate'] = round(success_rate, 2)
        else:
            mfa_stats['success_rate'] = 0
        
        # Find users with multiple MFA failures
        suspicious_mfa_users = {
            user: count 
            for user, count in mfa_stats['users_with_failures'].items() 
            if count >= self.mfa_failure_threshold
        }
        
        mfa_stats['suspicious_users'] = suspicious_mfa_users
        
        logger.info(f"   Total MFA challenges: {mfa_stats['total_challenges']}")
        logger.info(f"   Success rate: {mfa_stats['success_rate']}%")
        logger.info(f"   Users with multiple failures: {len(suspicious_mfa_users)}")
        
        return mfa_stats
    
    def analyze_geographic_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect logins from unusual locations
        
        Args:
            logs: List of log events
            
        Returns:
            dict: Geographic distribution of logins
        """
        logger.info("Analyzing geographic patterns...")
        
        location_data: Dict[str, Dict[str, Any]] = defaultdict(lambda: {'count': 0, 'users': set()})
        
        for log in logs:
            event_type = log.get('eventType', '')
            
            # Check for authentication events
            if 'authentication' in event_type.lower():
                # Get location info
                location = log.get('client', {}).get('geographicalContext', {})
                city = location.get('city', 'Unknown')
                country = location.get('country', 'Unknown')
                
                # Get user
                user = log.get('actor', {}).get('alternateId', 'Unknown')
                
                # Track location
                location_key = f"{city}, {country}"
                location_data[location_key]['count'] += 1
                location_data[location_key]['users'].add(user)
        
        # Convert sets to lists for JSON serialization
        for location in location_data:
            location_data[location]['users'] = list(location_data[location]['users'])
        
        logger.info(f"   Logins from {len(location_data)} different locations")
        
        return dict(location_data)
    
    def generate_summary(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate overall security summary
        
        Args:
            logs: List of log events
            
        Returns:
            dict: Summary statistics
        """
        logger.info("Generating security summary...")
        
        summary: Dict[str, Any] = {
            'total_events': len(logs),
            'total_authentications': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'unique_users': set(),
            'unique_ips': set()
        }
        
        for log in logs:
            event_type = log.get('eventType', '')
            outcome = log.get('outcome', {}).get('result', '')
            
            # Count authentication events
            if 'authentication' in event_type.lower():
                summary['total_authentications'] += 1
                
                user = log.get('actor', {}).get('alternateId')
                ip = log.get('client', {}).get('ipAddress')
                
                if user:
                    summary['unique_users'].add(user)
                if ip:
                    summary['unique_ips'].add(ip)
                
                if outcome == 'SUCCESS':
                    summary['successful_logins'] += 1
                elif outcome == 'FAILURE':
                    summary['failed_logins'] += 1
        
        # Convert sets to counts
        summary['unique_users'] = len(summary['unique_users'])
        summary['unique_ips'] = len(summary['unique_ips'])
        
        # Calculate success rate
        if summary['total_authentications'] > 0:
            success_rate = (summary['successful_logins'] / summary['total_authentications']) * 100
            summary['login_success_rate'] = round(success_rate, 2)
        else:
            summary['login_success_rate'] = 0
        
        return summary
    
    def _calculate_risk_level(self, failure_count: int) -> str:
        """Calculate risk level based on failure count
        
        Args:
            failure_count: Number of failures
            
        Returns:
            str: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if failure_count >= RISK_LEVEL_CRITICAL:
            return 'CRITICAL'
        elif failure_count >= RISK_LEVEL_HIGH:
            return 'HIGH'
        elif failure_count >= RISK_LEVEL_MEDIUM:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def run_full_analysis(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run complete security analysis on logs
        
        Args:
            logs: List of log events
            
        Returns:
            dict: Complete analysis results
        """
        logger.info("=" * 60)
        logger.info("STARTING SECURITY ANALYSIS")
        logger.info("=" * 60)
        
        results = {
            'summary': self.generate_summary(logs),
            'failed_logins': self.analyze_failed_logins(logs),
            'mfa_analysis': self.analyze_mfa_events(logs),
            'geographic_patterns': self.analyze_geographic_patterns(logs)
        }
        
        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETE")
        logger.info("=" * 60)
        
        return results


# Test the analyzer if running directly
if __name__ == "__main__":
    # Configure logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Testing Log Analyzer...\n")
    
    # This is just for testing the analyzer structure
    logger.info("Analyzer module loaded successfully!")
    logger.info("Run the main script to perform actual analysis.")

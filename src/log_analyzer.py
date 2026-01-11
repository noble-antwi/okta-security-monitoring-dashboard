"""
Okta Log Analyzer
Analyzes authentication logs to detect security threats
"""

from datetime import datetime
from collections import defaultdict
import json

class LogAnalyzer:
    
    def __init__(self):
        """Initialize the analyzer with threat detection thresholds"""
        
        # Thresholds for detecting threats
        self.FAILED_LOGIN_THRESHOLD = 5  # 5+ failures = suspicious
        self.TIME_WINDOW_MINUTES = 15     # Within 15 minutes
        self.MFA_FAILURE_THRESHOLD = 3    # 3+ MFA failures = suspicious
        
        print("Log Analyzer initialized")
    
    def analyze_failed_logins(self, logs):
        """
        Detect users/IPs with excessive failed login attempts
        
        Args:
            logs: List of log events
            
        Returns:
            dict: Users and IPs with suspicious failed login patterns
        """
        print("\n🔍 Analyzing failed login patterns...")
        
        # Track failures by user and IP
        user_failures = defaultdict(list)
        ip_failures = defaultdict(list)
        
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
            if len(failures) >= self.FAILED_LOGIN_THRESHOLD:
                suspicious_users[user] = {
                    'failure_count': len(failures),
                    'failures': failures,
                    'risk_level': self._calculate_risk_level(len(failures))
                }
        
        # Check IPs with multiple failures
        for ip, failures in ip_failures.items():
            if len(failures) >= self.FAILED_LOGIN_THRESHOLD:
                suspicious_ips[ip] = {
                    'failure_count': len(failures),
                    'failures': failures,
                    'risk_level': self._calculate_risk_level(len(failures))
                }
        
        print(f"   Found {len(suspicious_users)} suspicious users")
        print(f"   Found {len(suspicious_ips)} suspicious IPs")
        
        return {
            'suspicious_users': suspicious_users,
            'suspicious_ips': suspicious_ips
        }
    
    def analyze_mfa_events(self, logs):
        """
        Analyze MFA usage and detect issues
        
        Args:
            logs: List of log events
            
        Returns:
            dict: MFA statistics and issues
        """
        print("\n🔐 Analyzing MFA events...")
        
        mfa_stats = {
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
            if count >= self.MFA_FAILURE_THRESHOLD
        }
        
        mfa_stats['suspicious_users'] = suspicious_mfa_users
        
        print(f"   Total MFA challenges: {mfa_stats['total_challenges']}")
        print(f"   Success rate: {mfa_stats['success_rate']}%")
        print(f"   Users with multiple failures: {len(suspicious_mfa_users)}")
        
        return mfa_stats
    
    def analyze_geographic_patterns(self, logs):
        """
        Detect logins from unusual locations
        
        Args:
            logs: List of log events
            
        Returns:
            dict: Geographic distribution of logins
        """
        print("\n🌍 Analyzing geographic patterns...")
        
        location_data = defaultdict(lambda: {'count': 0, 'users': set()})
        
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
        
        print(f"   Logins from {len(location_data)} different locations")
        
        return dict(location_data)
    
    def generate_summary(self, logs):
        """
        Generate overall security summary
        
        Args:
            logs: List of log events
            
        Returns:
            dict: Summary statistics
        """
        print("\n📊 Generating security summary...")
        
        summary = {
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
    
    def _calculate_risk_level(self, failure_count):
        """
        Calculate risk level based on failure count
        
        Args:
            failure_count: Number of failures
            
        Returns:
            str: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if failure_count >= 20:
            return 'CRITICAL'
        elif failure_count >= 10:
            return 'HIGH'
        elif failure_count >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def run_full_analysis(self, logs):
        """
        Run complete security analysis on logs
        
        Args:
            logs: List of log events
            
        Returns:
            dict: Complete analysis results
        """
        print("\n" + "="*60)
        print("🔬 STARTING SECURITY ANALYSIS")
        print("="*60)
        
        results = {
            'summary': self.generate_summary(logs),
            'failed_logins': self.analyze_failed_logins(logs),
            'mfa_analysis': self.analyze_mfa_events(logs),
            'geographic_patterns': self.analyze_geographic_patterns(logs)
        }
        
        print("\n" + "="*60)
        print("✅ ANALYSIS COMPLETE")
        print("="*60)
        
        return results


# Test the analyzer if running directly
if __name__ == "__main__":
    print("Testing Log Analyzer...\n")
    
    # This is just for testing the analyzer structure
    print("Analyzer module loaded successfully!")
    print("Run the main script to perform actual analysis.")

"""
Unit tests for LogAnalyzer module
Tests threat detection, analysis, and reporting functionality
"""

import pytest
import sys
import os
from unittest.mock import MagicMock

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from log_analyzer import LogAnalyzer


class TestLogAnalyzerInit:
    """Test LogAnalyzer initialization"""
    
    def test_analyzer_init(self):
        """Test LogAnalyzer initializes with correct thresholds"""
        analyzer = LogAnalyzer()
        assert analyzer.failed_login_threshold == 5
        assert analyzer.mfa_failure_threshold == 3


class TestFailedLoginAnalysis:
    """Test failed login detection"""
    
    def test_analyze_failed_logins_suspicious_user(self):
        """Test detection of user with multiple failed logins"""
        analyzer = LogAnalyzer()
        
        # Create logs with 5 failed logins for a user
        logs = [
            {
                'eventType': 'user.authentication.auth_failed',
                'outcome': {'result': 'FAILURE'},
                'actor': {'alternateId': 'user@example.com'},
                'client': {'ipAddress': '192.168.1.1'},
                'published': '2026-01-11T10:00:00Z'
            }
            for _ in range(5)
        ]
        
        result = analyzer.analyze_failed_logins(logs)
        
        assert 'user@example.com' in result['suspicious_users']
        assert result['suspicious_users']['user@example.com']['failure_count'] == 5
        assert result['suspicious_users']['user@example.com']['risk_level'] == 'MEDIUM'
    
    def test_analyze_failed_logins_suspicious_ip(self):
        """Test detection of IP with multiple failed logins"""
        analyzer = LogAnalyzer()
        
        # Create logs with 5 failed logins from same IP
        logs = [
            {
                'eventType': 'user.authentication.auth_failed',
                'outcome': {'result': 'FAILURE'},
                'actor': {'alternateId': f'user{i}@example.com'},
                'client': {'ipAddress': '192.168.1.1'},
                'published': '2026-01-11T10:00:00Z'
            }
            for i in range(5)
        ]
        
        result = analyzer.analyze_failed_logins(logs)
        
        assert '192.168.1.1' in result['suspicious_ips']
        assert result['suspicious_ips']['192.168.1.1']['failure_count'] == 5
    
    def test_analyze_failed_logins_below_threshold(self):
        """Test that minimal failures don't trigger alerts"""
        analyzer = LogAnalyzer()
        
        # Create logs with only 2 failed logins
        logs = [
            {
                'eventType': 'user.authentication.auth_failed',
                'outcome': {'result': 'FAILURE'},
                'actor': {'alternateId': 'user@example.com'},
                'client': {'ipAddress': '192.168.1.1'},
                'published': '2026-01-11T10:00:00Z'
            }
            for _ in range(2)
        ]
        
        result = analyzer.analyze_failed_logins(logs)
        
        assert len(result['suspicious_users']) == 0
        assert len(result['suspicious_ips']) == 0
    
    def test_analyze_failed_logins_empty_logs(self):
        """Test with empty log list"""
        analyzer = LogAnalyzer()
        
        result = analyzer.analyze_failed_logins([])
        
        assert len(result['suspicious_users']) == 0
        assert len(result['suspicious_ips']) == 0


class TestMFAAnalysis:
    """Test MFA event analysis"""
    
    def test_analyze_mfa_events_success_rate(self):
        """Test MFA success rate calculation"""
        analyzer = LogAnalyzer()
        
        # Create MFA logs: 8 successful, 2 failed
        logs = [
            {
                'eventType': 'user.mfa.factor_challenge_success',
                'outcome': {'result': 'SUCCESS'},
                'actor': {'alternateId': 'user@example.com'}
            }
            for _ in range(8)
        ] + [
            {
                'eventType': 'user.mfa.factor_challenge_failed',
                'outcome': {'result': 'FAILURE'},
                'actor': {'alternateId': 'user@example.com'}
            }
            for _ in range(2)
        ]
        
        result = analyzer.analyze_mfa_events(logs)
        
        assert result['total_challenges'] == 10
        assert result['successful'] == 8
        assert result['failed'] == 2
        assert result['success_rate'] == 80.0
    
    def test_analyze_mfa_events_suspicious_users(self):
        """Test detection of users with multiple MFA failures"""
        analyzer = LogAnalyzer()
        
        # Create logs with 3 MFA failures for a user
        logs = [
            {
                'eventType': 'user.mfa.factor_challenge_failed',
                'outcome': {'result': 'FAILURE'},
                'actor': {'alternateId': 'user@example.com'}
            }
            for _ in range(3)
        ]
        
        result = analyzer.analyze_mfa_events(logs)
        
        assert 'user@example.com' in result['suspicious_users']
        assert result['suspicious_users']['user@example.com'] == 3
    
    def test_analyze_mfa_events_no_mfa_events(self):
        """Test with logs that have no MFA events"""
        analyzer = LogAnalyzer()
        
        logs = [
            {
                'eventType': 'user.authentication.auth_success',
                'outcome': {'result': 'SUCCESS'},
                'actor': {'alternateId': 'user@example.com'}
            }
        ]
        
        result = analyzer.analyze_mfa_events(logs)
        
        assert result['total_challenges'] == 0
        assert result['success_rate'] == 0


class TestGeographicAnalysis:
    """Test geographic pattern analysis"""
    
    def test_analyze_geographic_patterns(self):
        """Test geographic pattern detection"""
        analyzer = LogAnalyzer()
        
        logs = [
            {
                'eventType': 'user.authentication.auth_success',
                'actor': {'alternateId': 'user1@example.com'},
                'client': {
                    'geographicalContext': {
                        'city': 'San Francisco',
                        'country': 'United States'
                    }
                }
            },
            {
                'eventType': 'user.authentication.auth_success',
                'actor': {'alternateId': 'user2@example.com'},
                'client': {
                    'geographicalContext': {
                        'city': 'San Francisco',
                        'country': 'United States'
                    }
                }
            },
            {
                'eventType': 'user.authentication.auth_success',
                'actor': {'alternateId': 'user1@example.com'},
                'client': {
                    'geographicalContext': {
                        'city': 'London',
                        'country': 'United Kingdom'
                    }
                }
            }
        ]
        
        result = analyzer.analyze_geographic_patterns(logs)
        
        assert 'San Francisco, United States' in result
        assert result['San Francisco, United States']['count'] == 2
        assert set(result['San Francisco, United States']['users']) == {'user1@example.com', 'user2@example.com'}
    
    def test_analyze_geographic_patterns_unknown_location(self):
        """Test handling of unknown locations"""
        analyzer = LogAnalyzer()
        
        logs = [
            {
                'eventType': 'user.authentication.auth_success',
                'actor': {'alternateId': 'user@example.com'},
                'client': {
                    'geographicalContext': {}
                }
            }
        ]
        
        result = analyzer.analyze_geographic_patterns(logs)
        
        assert 'Unknown, Unknown' in result
        assert result['Unknown, Unknown']['count'] == 1


class TestSecuritySummary:
    """Test security summary generation"""
    
    def test_generate_summary_basic_stats(self):
        """Test basic summary statistics"""
        analyzer = LogAnalyzer()
        
        logs = [
            {
                'eventType': 'user.authentication.auth_success',
                'outcome': {'result': 'SUCCESS'},
                'actor': {'alternateId': 'user@example.com'},
                'client': {'ipAddress': '192.168.1.1'}
            },
            {
                'eventType': 'user.authentication.auth_failed',
                'outcome': {'result': 'FAILURE'},
                'actor': {'alternateId': 'user@example.com'},
                'client': {'ipAddress': '192.168.1.1'}
            }
        ]
        
        result = analyzer.generate_summary(logs)
        
        assert result['total_events'] == 2
        assert result['total_authentications'] == 2
        assert result['successful_logins'] == 1
        assert result['failed_logins'] == 1
        assert result['unique_users'] == 1
        assert result['unique_ips'] == 1
        assert result['login_success_rate'] == 50.0
    
    def test_generate_summary_empty_logs(self):
        """Test summary with empty logs"""
        analyzer = LogAnalyzer()
        
        result = analyzer.generate_summary([])
        
        assert result['total_events'] == 0
        assert result['total_authentications'] == 0
        assert result['login_success_rate'] == 0


class TestRiskLevelCalculation:
    """Test risk level calculation"""
    
    def test_risk_level_critical(self):
        """Test CRITICAL risk level"""
        analyzer = LogAnalyzer()
        risk = analyzer._calculate_risk_level(25)
        assert risk == 'CRITICAL'
    
    def test_risk_level_high(self):
        """Test HIGH risk level"""
        analyzer = LogAnalyzer()
        risk = analyzer._calculate_risk_level(15)
        assert risk == 'HIGH'
    
    def test_risk_level_medium(self):
        """Test MEDIUM risk level"""
        analyzer = LogAnalyzer()
        risk = analyzer._calculate_risk_level(5)
        assert risk == 'MEDIUM'
    
    def test_risk_level_low(self):
        """Test LOW risk level"""
        analyzer = LogAnalyzer()
        risk = analyzer._calculate_risk_level(2)
        assert risk == 'LOW'


class TestFullAnalysis:
    """Test complete analysis pipeline"""
    
    def test_run_full_analysis(self):
        """Test running full analysis"""
        analyzer = LogAnalyzer()
        
        logs = [
            {
                'eventType': 'user.authentication.auth_success',
                'outcome': {'result': 'SUCCESS'},
                'actor': {'alternateId': 'user@example.com'},
                'client': {
                    'ipAddress': '192.168.1.1',
                    'geographicalContext': {'city': 'San Francisco', 'country': 'United States'}
                },
                'published': '2026-01-11T10:00:00Z'
            },
            {
                'eventType': 'user.mfa.factor_challenge_success',
                'outcome': {'result': 'SUCCESS'},
                'actor': {'alternateId': 'user@example.com'},
                'client': {'ipAddress': '192.168.1.1'}
            }
        ]
        
        result = analyzer.run_full_analysis(logs)
        
        assert 'summary' in result
        assert 'failed_logins' in result
        assert 'mfa_analysis' in result
        assert 'geographic_patterns' in result
        
        # Verify summary data
        assert result['summary']['total_events'] == 2
        assert result['summary']['successful_logins'] == 1

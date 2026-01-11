"""
Main script for Okta Security Monitoring Dashboard
Combines data collection and analysis
"""
import sys
import os
import logging
from datetime import datetime
from typing import Dict, Any
import json

sys.path.insert(0, os.path.dirname(__file__))

from okta_connector import OktaConnector
from log_analyzer import LogAnalyzer
from config import RESULTS_FILE_PREFIX, RESULTS_FILE_FORMAT, TIMESTAMP_FORMAT, LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT

# Configure logging
logging.basicConfig(
    level=LOG_LEVEL,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT
)
logger = logging.getLogger(__name__)


def main() -> None:
    """Main execution function"""
    
    print("=" * 70)
    print("    OKTA SECURITY MONITORING DASHBOARD")
    print("=" * 70)
    print()
    
    try:
        # Step 1: Connect to Okta and fetch logs
        logger.info("STEP 1: Connecting to Okta API...")
        connector = OktaConnector()
        
        if not connector.test_connection():
            logger.error("❌ Failed to connect to Okta. Check your credentials.")
            return
        
        logger.info("STEP 2: Fetching authentication logs...")
        logs = connector.get_authentication_logs(hours_ago=24)
        
        if not logs:
            logger.error("❌ No logs retrieved. Check your Okta configuration.")
            return
        
        # Step 2: Analyze the logs
        logger.info("STEP 3: Analyzing logs for security threats...")
        analyzer = LogAnalyzer()
        results = analyzer.run_full_analysis(logs)
        
        # Step 3: Display results
        print("\n" + "=" * 70)
        print("📋 SECURITY SUMMARY")
        print("=" * 70)
        
        summary = results['summary']
        print(f"\n📊 Overall Statistics:")
        print(f"   Total Events: {summary['total_events']}")
        print(f"   Total Authentications: {summary['total_authentications']}")
        print(f"   Successful Logins: {summary['successful_logins']}")
        print(f"   Failed Logins: {summary['failed_logins']}")
        print(f"   Login Success Rate: {summary['login_success_rate']}%")
        print(f"   Unique Users: {summary['unique_users']}")
        print(f"   Unique IPs: {summary['unique_ips']}")
        
        # Display suspicious activity
        failed_logins = results['failed_logins']
        if failed_logins['suspicious_users']:
            print(f"\n🚨 SUSPICIOUS USERS ({len(failed_logins['suspicious_users'])} found):")
            for user, data in failed_logins['suspicious_users'].items():
                print(f"   - {user}")
                print(f"     Failures: {data['failure_count']}")
                print(f"     Risk Level: {data['risk_level']}")
        else:
            print(f"\n✅ No suspicious user activity detected")
        
        if failed_logins['suspicious_ips']:
            print(f"\n🚨 SUSPICIOUS IPS ({len(failed_logins['suspicious_ips'])} found):")
            for ip, data in failed_logins['suspicious_ips'].items():
                print(f"   - {ip}")
                print(f"     Failures: {data['failure_count']}")
                print(f"     Risk Level: {data['risk_level']}")
        else:
            print(f"\n✅ No suspicious IP activity detected")
        
        # Display MFA analysis
        mfa = results['mfa_analysis']
        print(f"\n🔐 MFA ANALYSIS:")
        print(f"   Total Challenges: {mfa['total_challenges']}")
        print(f"   Success Rate: {mfa['success_rate']}%")
        if mfa['suspicious_users']:
            print(f"   ⚠️  Users with multiple MFA failures: {len(mfa['suspicious_users'])}")
        
        # Save results to file
        print("\n" + "=" * 70)
        logger.info("Saving results...")
        
        timestamp = datetime.now().strftime(TIMESTAMP_FORMAT)
        filename = RESULTS_FILE_FORMAT.format(prefix=RESULTS_FILE_PREFIX, timestamp=timestamp)
        
        # Save to src/ directory
        src_dir = os.path.dirname(__file__)
        filepath = os.path.join(src_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"✅ Results saved to: {filepath}")
        print("\n" + "=" * 70)
        print("🎉 Analysis Complete!")
        print("=" * 70)
        
    except ValueError as e:
        logger.error(f"Configuration error: {str(e)}")
    except KeyboardInterrupt:
        logger.info("\nAnalysis interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Generate synthetic historical analysis data for the past 30 days.
This helps test and demonstrate the dashboard trends functionality.
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

def generate_analysis_data(timestamp):
    """Generate synthetic analysis data for a given timestamp."""
    
    # Simulate variation in metrics over time
    # Morning (6-9am): Lower activity
    # Midday (10am-4pm): Peak activity
    # Evening (5-11pm): Moderate activity
    hour = timestamp.hour
    
    if 6 <= hour < 9:
        base_events = random.randint(40, 60)
        failure_rate = random.uniform(0.15, 0.25)
    elif 10 <= hour < 17:
        base_events = random.randint(80, 120)
        failure_rate = random.uniform(0.20, 0.35)
    else:
        base_events = random.randint(50, 80)
        failure_rate = random.uniform(0.25, 0.40)
    
    total_events = base_events + random.randint(-5, 10)
    failed_logins = int(total_events * failure_rate) + random.randint(-2, 2)
    successful_logins = total_events - failed_logins
    
    # MFA analysis
    mfa_total = int(total_events * 0.3)
    mfa_success = int(mfa_total * random.uniform(0.85, 0.98))
    mfa_failed = mfa_total - mfa_success
    
    # Unique users and IPs
    unique_users = random.randint(3, 12)
    unique_ips = random.randint(2, 8)
    
    # Geographic patterns
    locations = [
        {"location": "United States", "count": int(total_events * 0.7), "users": []},
        {"location": "Canada", "count": int(total_events * 0.15), "users": []},
        {"location": "United Kingdom", "count": int(total_events * 0.1), "users": []},
        {"location": "India", "count": int(total_events * 0.05), "users": []},
    ]
    
    # Suspicious users (5-10% of attempts)
    suspicious_users = []
    if random.random() < 0.6:
        suspicious_count = random.randint(1, 3)
        for i in range(suspicious_count):
            suspicious_users.append({
                "user": f"user_{random.randint(100, 999)}@company.com",
                "failure_count": random.randint(3, 8),
                "risk_level": random.choice(["low", "medium", "high"])
            })
    
    # Suspicious IPs (2-5%)
    suspicious_ips = []
    if random.random() < 0.4:
        ip_count = random.randint(1, 2)
        for i in range(ip_count):
            suspicious_ips.append({
                "ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "failure_count": random.randint(2, 6),
                "risk_level": random.choice(["low", "medium"])
            })
    
    # MFA suspicious users
    mfa_suspicious_users = []
    if random.random() < 0.3:
        mfa_count = random.randint(1, 2)
        for i in range(mfa_count):
            mfa_suspicious_users.append({
                "user": f"user_{random.randint(100, 999)}@company.com",
                "failure_count": random.randint(2, 4)
            })
    
    return {
        "summary": {
            "total_events": total_events,
            "total_authentications": total_events,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "login_success_rate": round((successful_logins / total_events * 100) if total_events > 0 else 0, 2),
            "unique_users": unique_users,
            "unique_ips": unique_ips
        },
        "mfa_analysis": {
            "successful": mfa_success,
            "failed": mfa_failed,
            "denied": 0,
            "success_rate": round((mfa_success / mfa_total * 100) if mfa_total > 0 else 0, 2)
        },
        "mfa_suspicious_users": mfa_suspicious_users,
        "suspicious_users": suspicious_users,
        "suspicious_ips": suspicious_ips,
        "geographic_patterns": locations,
        "last_updated": timestamp.isoformat()
    }


def generate_historical_data(days=30, files_per_day=4):
    """Generate historical analysis files for the past N days."""
    
    src_dir = Path(__file__).parent.parent / 'src'
    src_dir.mkdir(exist_ok=True)
    
    generated_count = 0
    now = datetime.now()
    
    # Start from 30 days ago
    start_date = now - timedelta(days=days)
    
    # Generate files for each day
    current = start_date
    while current <= now:
        # Generate multiple files per day at different times
        for file_idx in range(files_per_day):
            hour = (file_idx * 24) // files_per_day + random.randint(0, 2)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            timestamp = current.replace(hour=hour, minute=minute, second=second)
            
            # Skip if in the future
            if timestamp > now:
                continue
            
            # Generate data
            data = generate_analysis_data(timestamp)
            
            # Create filename
            filename = f"analysis_results_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
            filepath = src_dir / filename
            
            # Skip if already exists
            if filepath.exists():
                continue
            
            # Write file
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            generated_count += 1
            print(f"✅ Generated {filename}")
        
        current += timedelta(days=1)
    
    print(f"\n✅ Generated {generated_count} historical analysis files")
    print(f"📁 Files saved to: {src_dir}")
    
    return generated_count


if __name__ == '__main__':
    print("🔄 Generating synthetic historical data...")
    print("=" * 60)
    
    try:
        count = generate_historical_data(days=30, files_per_day=4)
        print("=" * 60)
        print(f"✅ Success! Generated {count} analysis files")
        print("\nNow restart the Flask server for changes to take effect:")
        print("   $ python dashboard.py")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

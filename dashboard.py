"""
Flask dashboard server for Okta Security Monitoring
Serves interactive web dashboard and provides API endpoints for analysis data
"""

import os
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from typing import Dict, Any, List

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configuration
ANALYSIS_RESULTS_DIR = os.path.dirname(os.path.abspath(__file__))


def get_latest_analysis() -> Dict[str, Any]:
    """Get the most recent analysis results JSON file
    
    Returns:
        dict: Analysis results or empty dict if no files found
    """
    try:
        # Find all analysis_results_*.json files
        json_files = list(Path(ANALYSIS_RESULTS_DIR).glob('analysis_results_*.json'))
        
        if not json_files:
            logger.warning("No analysis results found. Run main.py to generate analysis data.")
            return {}
        
        # Get the most recently modified file
        latest_file = max(json_files, key=lambda p: p.stat().st_mtime)
        
        logger.info(f"Loading analysis from: {latest_file}")
        
        with open(latest_file, 'r') as f:
            return json.load(f)
            
    except Exception as e:
        logger.error(f"Error loading analysis results: {str(e)}")
        return {}


def transform_analysis_for_dashboard(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Transform raw analysis data into dashboard-friendly format
    
    Args:
        analysis: Raw analysis results from main.py
        
    Returns:
        dict: Transformed data for dashboard consumption
    """
    if not analysis:
        return {}
    
    summary = analysis.get('summary', {})
    failed_logins = analysis.get('failed_logins', {})
    mfa_analysis = analysis.get('mfa_analysis', {})
    geographic = analysis.get('geographic_patterns', {})
    
    # Transform suspicious data for dashboard
    suspicious_users_list = []
    for user, data in failed_logins.get('suspicious_users', {}).items():
        suspicious_users_list.append({
            'user': user,
            'failure_count': data.get('failure_count', 0),
            'risk_level': data.get('risk_level', 'LOW')
        })
    
    suspicious_ips_list = []
    for ip, data in failed_logins.get('suspicious_ips', {}).items():
        suspicious_ips_list.append({
            'ip': ip,
            'failure_count': data.get('failure_count', 0),
            'risk_level': data.get('risk_level', 'LOW')
        })
    
    mfa_suspicious_users = []
    for user, count in mfa_analysis.get('suspicious_users', {}).items():
        mfa_suspicious_users.append({
            'user': user,
            'failure_count': count
        })
    
    # Transform geographic data
    geographic_list = []
    for location, data in geographic.items():
        geographic_list.append({
            'location': location,
            'count': data.get('count', 0),
            'users': data.get('users', [])
        })
    
    return {
        'summary': summary,
        'suspicious_users': suspicious_users_list,
        'suspicious_ips': suspicious_ips_list,
        'mfa_analysis': mfa_analysis,
        'mfa_suspicious_users': mfa_suspicious_users,
        'geographic_patterns': geographic_list,
        'last_updated': datetime.now().isoformat()
    }


@app.route('/')
def dashboard():
    """Serve the main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/analysis')
def get_analysis():
    """API endpoint to get current analysis data
    
    Query Parameters:
        hours: Number of hours to look back (default: 24)
        
    Returns:
        json: Dashboard-formatted analysis results
    """
    # Get hours parameter from query string (default 24)
    hours = request.args.get('hours', 24, type=int)
    
    # If requesting different time range, run fresh analysis
    if hours != 24:
        logger.info(f"Fetching analysis for last {hours} hours...")
        try:
            from okta_connector import OktaConnector
            from log_analyzer import LogAnalyzer
            
            # Connect to Okta and fetch logs
            connector = OktaConnector()
            logs = connector.get_logs(hours_ago=hours)
            
            if not logs:
                return jsonify({'error': f'No logs found in last {hours} hours'}), 404
            
            # Analyze logs
            analyzer = LogAnalyzer()
            analysis = analyzer.run_full_analysis(logs)
            
            transformed = transform_analysis_for_dashboard(analysis)
            return jsonify(transformed)
            
        except Exception as e:
            logger.error(f"Error fetching analysis for {hours} hours: {str(e)}")
            return jsonify({'error': f'Failed to analyze logs: {str(e)}'}), 500
    
    # Default: return latest saved analysis
    analysis = get_latest_analysis()
    transformed = transform_analysis_for_dashboard(analysis)
    return jsonify(transformed)


@app.route('/api/summary')
def get_summary():
    """API endpoint to get summary statistics only
    
    Returns:
        json: Summary data
    """
    analysis = get_latest_analysis()
    return jsonify(analysis.get('summary', {}))


@app.route('/api/threats')
def get_threats():
    """API endpoint to get threat data
    
    Returns:
        json: Suspicious users and IPs
    """
    analysis = get_latest_analysis()
    
    return jsonify({
        'suspicious_users': analysis.get('failed_logins', {}).get('suspicious_users', {}),
        'suspicious_ips': analysis.get('failed_logins', {}).get('suspicious_ips', {})
    })


@app.route('/api/mfa')
def get_mfa():
    """API endpoint to get MFA analysis
    
    Returns:
        json: MFA statistics and suspicious users
    """
    analysis = get_latest_analysis()
    return jsonify(analysis.get('mfa_analysis', {}))


@app.route('/api/geography')
def get_geography():
    """API endpoint to get geographic patterns
    
    Returns:
        json: Login locations and distribution
    """
    analysis = get_latest_analysis()
    return jsonify(analysis.get('geographic_patterns', {}))


@app.route('/api/status')
def get_status():
    """API endpoint to get dashboard status
    
    Returns:
        json: Status information including last update time
    """
    analysis = get_latest_analysis()
    
    return jsonify({
        'status': 'ok' if analysis else 'no_data',
        'has_data': bool(analysis),
        'message': 'Analysis data loaded successfully' if analysis else 'No analysis data available. Run main.py to generate analysis.',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/fetch-fresh-data', methods=['POST'])
def fetch_fresh_data():
    """API endpoint to trigger fresh data fetch from Okta
    
    Runs main.py as a subprocess to fetch latest logs and analysis
    
    Returns:
        json: Status of the fetch operation
    """
    try:
        logger.info("Starting fresh data fetch from Okta...")
        
        # Get the directory where main.py is located
        src_dir = Path(__file__).parent / 'src'
        main_script = src_dir / 'main.py'
        
        if not main_script.exists():
            return jsonify({
                'status': 'error',
                'message': f'main.py not found at {main_script}'
            }), 500
        
        # Get the Python executable from the current environment
        import sys
        python_exe = sys.executable
        
        # Run main.py as subprocess
        result = subprocess.run(
            [python_exe, str(main_script)],
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout
        )
        
        if result.returncode != 0:
            logger.error(f"Error running main.py: {result.stderr}")
            return jsonify({
                'status': 'error',
                'message': f'Failed to fetch data: {result.stderr}',
                'returncode': result.returncode
            }), 500
        
        # After successful fetch, reload and return new data
        analysis = get_latest_analysis()
        transformed = transform_analysis_for_dashboard(analysis)
        
        logger.info("Fresh data fetch completed successfully")
        
        return jsonify({
            'status': 'success',
            'message': 'Fresh data fetched from Okta successfully',
            'data': transformed,
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except subprocess.TimeoutExpired:
        logger.error("Timeout: main.py took too long to complete")
        return jsonify({
            'status': 'error',
            'message': 'Data fetch timed out. The process took too long.'
        }), 504
        
    except Exception as e:
        logger.error(f"Exception during fetch-fresh-data: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error fetching data: {str(e)}'
        }), 500


@app.route('/api/trends/7d')
def get_7day_trends():
    """Get 7-day trend analysis"""
    try:
        from trends_analyzer import TrendsAnalyzer
        analyzer = TrendsAnalyzer(ANALYSIS_RESULTS_DIR)
        trends = analyzer.get_7day_trends()
        return jsonify(trends), 200
    except Exception as e:
        logger.error(f"Error getting 7-day trends: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/trends/30d')
def get_30day_trends():
    """Get 30-day trend analysis"""
    try:
        from trends_analyzer import TrendsAnalyzer
        analyzer = TrendsAnalyzer(ANALYSIS_RESULTS_DIR)
        trends = analyzer.get_30day_trends()
        return jsonify(trends), 200
    except Exception as e:
        logger.error(f"Error getting 30-day trends: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/trends/custom')
def get_custom_trends():
    """Get trends for custom hours parameter"""
    try:
        hours = request.args.get('hours', 24, type=int)
        
        # Validate hours
        if hours < 1 or hours > 8760:
            return jsonify({'error': 'Hours must be between 1 and 8760'}), 400
        
        from trends_analyzer import TrendsAnalyzer
        analyzer = TrendsAnalyzer(ANALYSIS_RESULTS_DIR)
        trends = analyzer.get_trend_data(hours)
        return jsonify(trends), 200
    except Exception as e:
        logger.error(f"Error getting custom trends: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/trends/week-over-week')
def get_week_over_week():
    """Get week-over-week comparison"""
    try:
        from trends_analyzer import TrendsAnalyzer
        analyzer = TrendsAnalyzer(ANALYSIS_RESULTS_DIR)
        comparison = analyzer.get_week_over_week()
        return jsonify(comparison), 200
    except Exception as e:
        logger.error(f"Error getting week-over-week comparison: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Page not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Starting Okta Security Monitoring Dashboard...")
    logger.info("Dashboard available at: http://localhost:5000")
    logger.info("Press Ctrl+C to stop the server")
    
    # Check if analysis data exists
    analysis = get_latest_analysis()
    if not analysis:
        logger.warning("⚠️  No analysis data found!")
        logger.warning("Run 'python src/main.py' first to generate analysis data")
    else:
        logger.info(f"✅ Analysis data loaded: {analysis.get('summary', {}).get('total_events', 0)} events")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

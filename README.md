# Okta Security Monitoring Dashboard

> Automated authentication analytics and threat detection for Okta environments

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-phase_2_complete-green.svg)
![Tests](https://img.shields.io/badge/tests-29%2F29%20passing-brightgreen.svg)

## Overview

A lightweight, production-ready security monitoring solution that analyzes Okta System Logs to detect authentication threats, track failed login patterns, monitor MFA adoption, and identify suspicious access attempts. Designed for security teams and IAM professionals who need Okta-specific threat detection.

### Key Features
- ✅ **Failed Login Detection**: Identifies users and IPs with suspicious authentication failures
- ✅ **MFA Analytics**: Tracks MFA adoption rates and detects users with repeated failures
- ✅ **Geographic Anomaly Detection**: Maps login locations and identifies unusual access patterns
- ✅ **Risk Scoring**: Automatic risk level calculation (LOW, MEDIUM, HIGH, CRITICAL)
- ✅ **JSON Export**: Results saved to timestamped JSON files for integration with SIEM tools
- ✅ **Comprehensive Logging**: Production-ready logging with configurable levels

### Why This Project?

This project demonstrates:
- **Enterprise IAM Knowledge**: Integration with industry-standard Okta platform
- **Security Log Analysis**: Real-world threat detection algorithms
- **Clean Code Practices**: Type hints, comprehensive testing, proper error handling
- **Production Readiness**: Logging, configuration management, JSON serialization
- **Testing Discipline**: 29 unit tests covering all major functionality
- **Portfolio Quality**: Suitable for security engineering and IAM role applications

## Tech Stack

- **Python 3.8+**: Core application
- **Okta API**: System Log events via SSWS authentication
- **Requests**: HTTP client for API communication
- **Python-dotenv**: Secure credential management
- **Pandas**: Available for future data processing
- **Pytest**: Comprehensive unit testing (29 tests)

## Project Status

✅ **Phase 2 Complete** - Full analysis engine with testing

- [x] Project planning
- [x] Okta API integration with SSWS authentication
- [x] Log data collection and filtering
- [x] Threat detection analysis engine
- [x] Risk level scoring
- [x] Unit tests (29/29 passing)
- [x] Type hints and documentation
- [x] Logging infrastructure
- [ ] Dashboard visualization
- [ ] SIEM integration (Splunk/Wazuh)

## Installation

### Prerequisites
- Python 3.8 or higher
- Okta organization with API access
- Valid Okta API token with System Log read permissions

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/noble-antwi/okta-security-monitoring-dashboard.git
   cd okta-security-monitoring-dashboard
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Okta credentials**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your Okta details:
   ```dotenv
   OKTA_DOMAIN=your-domain.okta.com
   OKTA_API_TOKEN=your_api_token_here
   ```

5. **Run the analysis**
   ```bash
   python src/main.py
   ```

## Usage

### Basic Usage

Run the complete analysis pipeline:
```bash
python src/main.py
```

This will:
1. Connect to your Okta organization
2. Fetch authentication logs from the last 24 hours
3. Analyze for failed logins, MFA issues, and geographic patterns
4. Display formatted security summary
5. Save detailed results to JSON file

### Example Output

```
======================================================================
    OKTA SECURITY MONITORING DASHBOARD
======================================================================

📊 Overall Statistics:
   Total Events: 4,250
   Total Authentications: 3,847
   Successful Logins: 3,812 (98.9%)
   Failed Logins: 35
   Unique Users: 156
   Unique IPs: 42

🚨 SUSPICIOUS USERS (2 found):
   - john.doe@example.com
     Failures: 8
     Risk Level: HIGH

   - jane.smith@example.com
     Failures: 5
     Risk Level: MEDIUM

✅ No suspicious IP activity detected

🔐 MFA ANALYSIS:
   Total Challenges: 3,250
   Success Rate: 99.1%
   ⚠️ Users with multiple MFA failures: 1

✅ Results saved to: analysis_results_20260111_143022.json
```

### Configuration

Edit [src/config.py](src/config.py) to customize analysis parameters:

```python
# Threat detection thresholds
FAILED_LOGIN_THRESHOLD = 5          # Flag users with 5+ failures
MFA_FAILURE_THRESHOLD = 3           # Flag users with 3+ MFA failures

# Risk level scoring
RISK_LEVEL_CRITICAL = 20            # 20+ failures = CRITICAL
RISK_LEVEL_HIGH = 10                # 10+ failures = HIGH
RISK_LEVEL_MEDIUM = 5               # 5+ failures = MEDIUM

# Okta API settings
DEFAULT_LOG_HOURS_BACK = 24          # Fetch logs from last 24 hours
DEFAULT_LOG_LIMIT = 1000             # Maximum logs per request
API_TIMEOUT = 30                     # HTTP timeout in seconds
```

## Testing

### Run All Tests
```bash
pytest tests/ -v
```

### Run With Coverage Report
```bash
pytest tests/ --cov=src --cov-report=html
```

### Test Results
- **29 tests** covering all major functionality
- **Core modules tested**: 
  - `okta_connector.py`: 16 tests (connection, authentication, log retrieval)
  - `log_analyzer.py`: 13 tests (threat detection, risk scoring, analysis)

### Sample Test Execution
```bash
$ pytest tests/ -v
tests/test_okta_connector.py::TestOktaConnectorInit::test_init_with_valid_credentials PASSED
tests/test_okta_connector.py::TestOktaConnectorConnection::test_test_connection_success PASSED
tests/test_log_analyzer.py::TestFailedLoginAnalysis::test_analyze_failed_logins_suspicious_user PASSED
...
======================== 29 passed in 0.10s ========================
```

## Code Quality Features

### Type Hints
All functions include Python type hints for better IDE support and documentation:
```python
def get_logs(self, hours_ago: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
```

### Logging
Production-ready logging instead of print statements:
```python
logger.info("Connected to Okta domain: test.okta.com")
logger.error("Failed to retrieve logs. Status: 401")
```

### Exception Handling
Specific exception handling with proper error propagation:
```python
except requests.exceptions.Timeout:
    logger.error(f"API request timed out after {self.timeout} seconds")
except requests.exceptions.RequestException as e:
    logger.error(f"Request error: {str(e)}")
```

### Configuration Management
Centralized configuration for easy customization:
```python
from config import FAILED_LOGIN_THRESHOLD, MFA_FAILURE_THRESHOLD
```

## Security Considerations

- ✅ **Credentials**: Uses `.env` file (excluded from git) for secure credential storage
- ✅ **API Token**: SSWS authentication header format per Okta security standards
- ✅ **Error Handling**: Graceful error handling without exposing sensitive information
- ✅ **Timeouts**: Configurable request timeouts to prevent hanging
- ✅ **Logging**: Logs are local (not sent externally) for privacy

## Future Roadmap

- **Phase 3**: Web dashboard with real-time visualization
- **Phase 4**: Wazuh/Splunk integration for SIEM correlation
- **Phase 5**: Scheduled execution via APScheduler or cron
- **Phase 6**: CLI arguments for dynamic configuration
- **Phase 7**: Email/Slack alerting for critical findings
- **Phase 8**: Historical trend analysis and baseline modeling

## Troubleshooting

### "Missing Okta credentials. Check your .env file"
Ensure `.env` file exists in project root with valid credentials:
```bash
echo "OKTA_DOMAIN=your-domain.okta.com" > .env
echo "OKTA_API_TOKEN=your_token" >> .env
```

### "API connection failed. Status: 401"
- Verify API token is valid (check Okta admin console)
- Confirm token has System Log read permissions
- Check that OKTA_DOMAIN matches your organization

### "No logs retrieved"
- Ensure Okta organization has authentication logs in the timeframe
- Check that the API token has sufficient permissions
- Verify network connectivity to Okta API

## Contributing

Contributions welcome! Areas for improvement:
- Additional threat detection patterns
- Performance optimization for large log datasets
- Dashboard visualization implementation
- SIEM integration connectors

## Performance

- **Log Retrieval**: ~2-5 seconds for 1,000 events
- **Analysis**: ~100ms for threat detection on 1,000 events
- **Memory Usage**: ~50-100MB for typical datasets
- **API Calls**: Single request to fetch logs (pagination support coming)

## Licensing

MIT License - See [LICENSE](LICENSE) file for details

## Contact & Portfolio

**Noble Antwi**  
- Role: Security & IAM Engineering
- Skills: Okta, Python, Security Log Analysis, Threat Detection
- This project demonstrates production-ready security engineering capabilities

---

**Ready for production use in security environments!** 🚀



## Roadmap

**Phase 1:** Core data collection from Okta API  
**Phase 2:** Threat detection algorithms  
**Phase 3:** Dashboard and visualization  
**Phase 4:** SIEM integration comparison  

## Contributing

This is a portfolio/learning project. Suggestions and feedback welcome via issues!

## License

MIT License - see LICENSE file for details

---

**Author:** Noble Antwi

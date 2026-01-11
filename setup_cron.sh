#!/bin/bash
# Setup cron job to fetch Okta data every hour

PROJECT_DIR="/home/nantwi/okta-security-monitoring-dashboard"
PYTHON_BIN="$PROJECT_DIR/venv/bin/python"
MAIN_SCRIPT="$PROJECT_DIR/src/main.py"

# Create cron job that runs every hour
CRON_JOB="0 * * * * cd $PROJECT_DIR && $PYTHON_BIN $MAIN_SCRIPT >> /tmp/okta_fetch.log 2>&1"

# Check if cron job already exists
(crontab -l 2>/dev/null | grep -F "$MAIN_SCRIPT") && {
    echo "Cron job already exists. Removing old one..."
    crontab -l 2>/dev/null | grep -v "$MAIN_SCRIPT" | crontab -
}

# Add new cron job
(crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -

echo "✅ Cron job installed successfully!"
echo "📋 Okta data will be fetched automatically every hour"
echo ""
echo "Current crontab:"
crontab -l
echo ""
echo "To view logs: tail -f /tmp/okta_fetch.log"
echo "To remove: crontab -e (then delete the line)"

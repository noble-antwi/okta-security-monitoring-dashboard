# DASHBOARD - QUICK START GUIDE

## Phase 3: Web Dashboard for Okta Security Monitoring

### ⚡ Quick Start (2 Minutes)

```bash
# 1. Generate analysis data
python src/main.py

# 2. Start the dashboard
python dashboard.py

# 3. Open in browser
# http://localhost:5000
```

---

## 📊 Dashboard Overview

The web dashboard visualizes your Okta security analysis with:

### 🎯 KPI Cards (Top Section)
- Total Events, Success Rate, Failed Logins, MFA Rate, Unique Users, Unique IPs

### 📈 Charts & Graphs
- **Login Status**: Pie chart (Success vs Failure)
- **MFA Analysis**: Bar chart (Successful, Failed, Denied)
- **Geographic Distribution**: Top 10 login locations

### 🚨 Security Alerts
- **Suspicious Users**: Users with excessive failed logins (5+)
- **Suspicious IPs**: IP addresses with suspicious activity
- **MFA Anomalies**: Users with repeated MFA failures

### 📋 Data Tables
- Top Login Locations (with user counts)
- Risk Assessment Summary (key metrics and status)

### 🔄 Features
- **Auto-refresh**: Updates every 5 minutes
- **Manual refresh**: Button in header
- **Responsive design**: Works on mobile, tablet, desktop
- **Dark mode support**: Adapts to system preferences
- **Professional styling**: Portfolio-ready design

---

## 📁 File Structure

```
okta-security-monitoring-dashboard/
├── dashboard.py                 ← Flask server (run this!)
├── DASHBOARD.md                 ← Full documentation
├── templates/
│   └── dashboard.html           ← Main dashboard page
└── static/
    ├── css/
    │   └── style.css            ← Professional styling
    └── js/
        └── dashboard.js         ← Charts & interactivity
```

---

## 🚀 Running the Dashboard

### Prerequisite: Generate Analysis Data

The dashboard reads from JSON files created by the analysis engine:

```bash
python src/main.py
```

This creates: `analysis_results_20260111_143022.json`

### Start Dashboard Server

```bash
python dashboard.py
```

Output:
```
Running on http://127.0.0.1:5000
```

### Access Dashboard

Open browser: **http://localhost:5000**

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| "No analysis found" | Run `python src/main.py` first |
| Port 5000 in use | Change port in `dashboard.py` (line ~200) |
| Templates not found | Run from project root directory |
| Charts not showing | Check browser console (F12 → Console) |

---

## 📊 What Data Is Displayed?

The dashboard displays all analysis results from `main.py`:

- ✅ **Authentication Summary**: Total events, success rate, failures
- ✅ **Failed Logins**: By user and IP address
- ✅ **MFA Statistics**: Challenge rates and anomalies
- ✅ **Geographic Patterns**: Login locations worldwide
- ✅ **Risk Assessment**: Overall security posture

---

## 🎨 Design Features

- **Color Scheme**: Professional security theme (blues, dark grays)
- **Dark Mode**: Automatically adapts to system settings
- **Responsive**: Optimized for 320px - 4K displays
- **Fast**: Charts load in <500ms
- **Professional**: Portfolio-ready quality

---

## 🔌 API Endpoints

Use these for custom integrations:

```bash
GET  /api/analysis      - Complete dashboard data
GET  /api/summary       - Summary statistics only
GET  /api/threats       - Suspicious users & IPs
GET  /api/mfa           - MFA analysis data
GET  /api/geography     - Geographic patterns
GET  /api/status        - Server status
```

Example:
```bash
curl http://localhost:5000/api/summary
```

---

## 💡 Pro Tips

1. **Bookmarks**: Save http://localhost:5000 to bookmarks
2. **Auto-refresh**: Dashboard updates every 5 minutes automatically
3. **Manual refresh**: Click the refresh button anytime
4. **Full screen**: Dashboard works great in full-screen mode
5. **Mobile**: Works great on phones/tablets too
6. **Screenshots**: Perfect for security reports or presentations

---

## 📚 Full Documentation

For detailed information, see: [DASHBOARD.md](DASHBOARD.md)

Topics covered:
- Installation & setup
- Feature descriptions
- API endpoints
- Deployment options
- Customization guide
- Troubleshooting
- Production deployment

---

## ✨ Next Steps

- [ ] Generate analysis data: `python src/main.py`
- [ ] Start dashboard: `python dashboard.py`
- [ ] View at: http://localhost:5000
- [ ] Take screenshots for portfolio
- [ ] Customize colors (optional): `static/css/style.css`
- [ ] Deploy to production (optional): See DASHBOARD.md

---

## 🎓 Portfolio Impact

This dashboard demonstrates:

✅ **Full Stack Development**
- Python backend (Flask)
- Frontend (HTML/CSS/JavaScript)
- API design
- Responsive design

✅ **Data Visualization**
- Chart.js integration
- Real-time updates
- Professional styling

✅ **Security Domain Knowledge**
- Okta integration
- Threat detection
- Authentication analysis
- Risk assessment

✅ **Production Quality**
- Error handling
- Performance optimization
- Security best practices
- Professional documentation

---

**Happy dashboarding! 📊🚀**

---

*Built as Phase 3 of the Okta Security Monitoring Dashboard project*
*Perfect for security engineer and IAM role interviews*

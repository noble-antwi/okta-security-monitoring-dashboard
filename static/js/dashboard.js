/**
 * Okta Security Monitoring Dashboard - JavaScript
 * Handles data loading, chart rendering, and interactivity
 */

// Global state
let dashboardData = {};
let charts = {};
let currentFilter = 'all';
let currentHours = 24;
let syncCountdown = 300; // 5 minutes in seconds
let syncInterval = null;
let allData = {}; // Store unfiltered data for filtering

// DOM Elements
const loadingState = document.getElementById('loadingState');
const errorState = document.getElementById('errorState');
const dashboardContent = document.getElementById('dashboardContent');
const refreshBtn = document.getElementById('refreshBtn');
const fetchFreshBtn = document.getElementById('fetchFreshBtn');
const lastUpdatedSpan = document.getElementById('lastUpdated');
const securityScoreBadge = document.getElementById('securityScore');
const scoreValue = document.getElementById('scoreValue');
const connectionStatus = document.getElementById('connectionStatus');
const syncTimer = document.getElementById('syncTimer');
const filterBtns = document.querySelectorAll('.filter-btn');
const exportPdfBtn = document.getElementById('exportPdfBtn');
const exportCsvBtn = document.getElementById('exportCsvBtn');
const printBtn = document.getElementById('printBtn');
const timeRangeSelect = document.getElementById('timeRangeSelect');
const customHoursDiv = document.getElementById('customHoursDiv');
const applyCustomBtn = document.getElementById('applyCustomBtn');
const customHoursInput = document.getElementById('customHours');
const dateInfo = document.getElementById('dateInfo');
const filterInfo = document.getElementById('filterInfo');

/**
 * Load analysis data from API
 */
async function loadAnalysisData(hours = 24) {
    try {
        const url = hours === 24 ? '/api/analysis' : `/api/analysis?hours=${hours}`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error('Error loading analysis data:', error);
        return null;
    }
}

/**
 * Update KPI cards with summary data
 */
function updateKPICards(data) {
    const summary = data.summary || {};
    
    document.getElementById('kpiTotalEvents').textContent = 
        (summary.total_events || 0).toLocaleString();
    
    document.getElementById('kpiSuccessRate').textContent = 
        `${(summary.login_success_rate || 0).toFixed(1)}%`;
    
    document.getElementById('kpiFailedLogins').textContent = 
        (summary.failed_logins || 0).toLocaleString();
    
    const mfaRate = data.mfa_analysis?.success_rate || 0;
    document.getElementById('kpiMFARate').textContent = 
        `${mfaRate.toFixed(1)}%`;
    
    document.getElementById('kpiUniqueUsers').textContent = 
        (summary.unique_users || 0).toLocaleString();
    
    document.getElementById('kpiUniqueIPs').textContent = 
        (summary.unique_ips || 0).toLocaleString();
}

/**
 * Calculate and update security risk score
 */
function updateSecurityScore(data) {
    const summary = data.summary || {};
    const suspiciousUsers = (data.suspicious_users || []).length;
    const suspiciousIPs = (data.suspicious_ips || []).length;
    const mfaRate = data.mfa_analysis?.success_rate || 0;
    const successRate = summary.login_success_rate || 0;
    
    // Calculate risk score (0-100)
    let riskScore = 0;
    
    // Factor 1: Suspicious users (0-40 points)
    riskScore += Math.min(suspiciousUsers * 20, 40);
    
    // Factor 2: Suspicious IPs (0-30 points)
    riskScore += Math.min(suspiciousIPs * 15, 30);
    
    // Factor 3: Low MFA success rate (0-20 points)
    if (mfaRate < 50) riskScore += 20;
    else if (mfaRate < 80) riskScore += 10;
    
    // Factor 4: Low login success rate (0-10 points)
    if (successRate < 30) riskScore += 10;
    else if (successRate < 50) riskScore += 5;
    
    // Determine status
    let status = 'safe';
    if (riskScore >= 70) status = 'critical';
    else if (riskScore >= 40) status = 'caution';
    
    // Update badge
    securityScoreBadge.className = `security-score-badge ${status}`;
    scoreValue.textContent = Math.min(riskScore, 99);
    
    return status;
}

/**
 * Start auto-refresh countdown timer
 */
function startSyncCountdown() {
    syncCountdown = 300; // Reset to 5 minutes
    
    if (syncInterval) clearInterval(syncInterval);
    
    syncInterval = setInterval(() => {
        syncCountdown--;
        
        const minutes = Math.floor(syncCountdown / 60);
        const seconds = syncCountdown % 60;
        syncTimer.textContent = `Auto-refresh in ${minutes}:${seconds.toString().padStart(2, '0')}`;
        
        if (syncCountdown <= 0) {
            clearInterval(syncInterval);
            refreshDashboard();
            startSyncCountdown();
        }
    }, 1000);
}

/**
 * Update connection status
 */
function updateConnectionStatus(connected = true) {
    if (connected) {
        connectionStatus.classList.remove('error');
        document.getElementById('connectionText').textContent = 'Connected';
    } else {
        connectionStatus.classList.add('error');
        document.getElementById('connectionText').textContent = 'Disconnected';
    }
}

/**
 * Handle filter button clicks
 */
function handleFilterClick(e) {
    if (!e.target.closest('.filter-btn')) return;
    
    const btn = e.target.closest('.filter-btn');
    const filter = btn.getAttribute('data-filter');
    
    // Update active button
    filterBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    // Apply filter
    currentFilter = filter;
    applyDataFilter(filter);
}

/**
 * Apply data filter to dashboard
 */
function applyDataFilter(filter) {
    const kpiSection = document.querySelector('.kpi-section');
    const alerts = document.querySelectorAll('.alert-card');
    const tables = document.querySelectorAll('.data-table');
    
    if (filter === 'all') {
        // Show all sections
        kpiSection.style.display = 'grid';
        alerts.forEach(alert => alert.style.display = 'block');
        tables.forEach(table => table.style.display = 'block');
    } else if (filter === 'suspicious') {
        // Hide other sections, show alerts
        kpiSection.style.display = 'none';
        alerts.forEach(alert => alert.style.display = 'block');
        tables.forEach(table => table.style.display = 'none');
    } else if (filter === 'mfa') {
        // Show MFA specific data
        kpiSection.style.display = 'none';
        alerts.forEach(alert => {
            if (alert.textContent.includes('MFA')) alert.style.display = 'block';
            else alert.style.display = 'none';
        });
        tables.forEach(table => table.style.display = 'none');
    }
}

/**
 * Handle custom hours input
 */
async function handleCustomHours() {
    const hours = parseInt(customHoursInput.value);
    
    if (!hours || hours < 1 || hours > 8760) {
        showNotification('Please enter hours between 1 and 8760 (1 year)', 'error');
        return;
    }
    
    // Reset dropdown to custom
    timeRangeSelect.value = 'custom';
    
    // Update date info
    const days = Math.floor(hours / 24);
    if (days > 1) {
        dateInfo.textContent = `Showing last ${days} days (${hours} hours)`;
    } else {
        dateInfo.textContent = `Showing last ${hours} hours`;
    }
    
    currentHours = hours;
    await loadInsights(hours);
}

/**
 * Load analysis data for specific date range
 */
async function loadDataWithDateRange(hours) {
    console.log(`⏱️ loadDataWithDateRange called with hours=${hours}`);
    
    loadingState.style.display = 'flex';
    errorState.style.display = 'none';
    dashboardContent.style.display = 'none';
    
    const data = await loadAnalysisData(hours);
    
    if (!data || Object.keys(data).length === 0) {
        loadingState.style.display = 'none';
        errorState.style.display = 'block';
        return;
    }
    
    // Store full data
    allData = data;
    dashboardData = JSON.parse(JSON.stringify(data));
    
    // Apply current filter
    applyDataFilter(currentFilter);
    
    loadingState.style.display = 'none';
    errorState.style.display = 'none';
    dashboardContent.style.display = 'block';
    
    // Re-render everything
    renderDashboard(dashboardData);
    
    // Also update trends chart with the new time range
    updateTrendForTimeRange(hours);
    
    // Update period-over-period comparison with current time range
    loadWeekOverWeekData(hours);
}

/**
 * Apply filter to actual data
 */
function applyDataFilter(filter) {
    currentFilter = filter;
    
    // Create filtered copy
    dashboardData = JSON.parse(JSON.stringify(allData));
    
    if (filter === 'all') {
        filterInfo.textContent = '';
    } else if (filter === 'suspicious') {
        // Keep only suspicious data
        if (dashboardData.suspicious_users) {
            const filtered = dashboardData.suspicious_users.filter(u => u.failure_count >= 5);
            filterInfo.textContent = `Showing ${filtered.length} suspicious users`;
        }
        if (dashboardData.suspicious_ips) {
            dashboardData.suspicious_ips = dashboardData.suspicious_ips.filter(ip => ip.failure_count >= 5);
        }
    } else if (filter === 'mfa') {
        // Keep only MFA failures
        if (dashboardData.mfa_suspicious_users) {
            filterInfo.textContent = `Showing ${dashboardData.mfa_suspicious_users.length} users with MFA failures`;
        }
        // Filter to show only MFA-related data
        if (dashboardData.suspicious_users) {
            dashboardData.suspicious_users = [];
        }
        if (dashboardData.suspicious_ips) {
            dashboardData.suspicious_ips = [];
        }
    }
    
    // Re-render with filtered data
    if (dashboardContent.style.display !== 'none') {
        renderDashboard(dashboardData);
    }
}

/**
 * Export dashboard to PDF
 */
function exportToPDF() {
    const timestamp = new Date().toLocaleString();
    const title = 'Okta Security Monitoring Dashboard Report';
    
    showNotification('PDF export feature coming soon!', 'info');
    console.log('PDF Export - ', title, timestamp);
}

/**
 * Export data to CSV
 */
function exportToCSV() {
    if (!dashboardData.summary) {
        showNotification('No data available to export', 'error');
        return;
    }
    
    const csv = [
        ['Metric', 'Value'],
        ['Total Events', dashboardData.summary.total_events],
        ['Success Rate', dashboardData.summary.login_success_rate + '%'],
        ['Failed Logins', dashboardData.summary.failed_logins],
        ['MFA Success Rate', dashboardData.mfa_analysis?.success_rate + '%'],
        ['Unique Users', dashboardData.summary.unique_users],
        ['Unique IPs', dashboardData.summary.unique_ips],
        [''],
        ['Suspicious Users'],
        ...dashboardData.suspicious_users.map(u => [u.user, u.failure_count, u.risk_level]),
        [''],
        ['Suspicious IPs'],
        ...dashboardData.suspicious_ips.map(ip => [ip.ip, ip.failure_count, ip.risk_level])
    ].map(row => row.join(',')).join('\n');
    
    downloadFile(csv, 'okta-security-report.csv', 'text/csv');
    showNotification('CSV exported successfully!', 'success');
}

/**
 * Download file helper
 */
function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
}

/**
 * Print dashboard
 */
function printDashboard() {
    window.print();
    showNotification('Opening print dialog...', 'info');
}

/**
 * Render login status pie chart
 */
function renderLoginStatusChart(data) {
    const summary = data.summary || {};
    const successful = summary.successful_logins || 0;
    const failed = summary.failed_logins || 0;
    const total = successful + failed;
    
    const ctx = document.getElementById('loginStatusChart');
    
    // Destroy existing chart if it exists
    if (charts.loginStatus) {
        charts.loginStatus.destroy();
    }
    
    charts.loginStatus = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Successful', 'Failed'],
            datasets: [{
                data: [successful, failed],
                backgroundColor: ['#10b981', '#ef4444'],
                borderColor: ['#059669', '#dc2626'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { padding: 15, font: { size: 12, weight: 'bold' } }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const value = context.parsed;
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${context.label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Render MFA statistics bar chart
 */
function renderMFAChart(data) {
    const mfaData = data.mfa_analysis || {};
    const successful = mfaData.successful || 0;
    const failed = mfaData.failed || 0;
    const denied = mfaData.denied || 0;
    
    const ctx = document.getElementById('mfaChart');
    
    // Destroy existing chart if it exists
    if (charts.mfa) {
        charts.mfa.destroy();
    }
    
    charts.mfa = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Successful', 'Failed', 'Denied'],
            datasets: [{
                label: 'MFA Challenges',
                data: [successful, failed, denied],
                backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
                borderColor: ['#059669', '#dc2626', '#d97706'],
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true, labels: { font: { size: 12, weight: 'bold' } } },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.parsed.x} challenges`;
                        }
                    }
                }
            },
            scales: {
                x: { beginAtZero: true, ticks: { font: { size: 12 } } },
                y: { ticks: { font: { size: 12 } } }
            }
        }
    });
}

/**
 * Render geographic distribution chart
 */
function renderGeographicChart(data) {
    const geographic = data.geographic_patterns || [];
    
    // Sort by count and take top 10
    const topLocations = geographic
        .sort((a, b) => (b.count || 0) - (a.count || 0))
        .slice(0, 10);
    
    const labels = topLocations.map(loc => loc.location);
    const counts = topLocations.map(loc => loc.count);
    
    const ctx = document.getElementById('geographicChart');
    
    // Destroy existing chart if it exists
    if (charts.geographic) {
        charts.geographic.destroy();
    }
    
    charts.geographic = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Login Count',
                data: counts,
                backgroundColor: '#0ea5e9',
                borderColor: '#0284c7',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true, labels: { font: { size: 12, weight: 'bold' } } },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.parsed.x} logins`;
                        }
                    }
                }
            },
            scales: {
                x: { beginAtZero: true, ticks: { font: { size: 12 } } },
                y: { ticks: { font: { size: 12 } } }
            }
        }
    });
}

/**
 * Create risk badge HTML
 */
function createRiskBadge(riskLevel) {
    const levelLower = (riskLevel || 'low').toLowerCase();
    return `<span class="risk-badge ${levelLower}">${riskLevel}</span>`;
}

/**
 * Update suspicious users section
 */
function updateSuspiciousUsers(data) {
    const users = data.suspicious_users || [];
    const container = document.getElementById('suspiciousUsersContainer');
    const countBadge = document.getElementById('suspiciousUserCount');
    
    countBadge.textContent = users.length;
    
    if (users.length === 0) {
        container.innerHTML = '<p class="no-threats">✅ No suspicious user activity detected</p>';
        return;
    }
    
    container.innerHTML = users.map(user => `
        <div class="threat-item ${user.risk_level.toLowerCase()}">
            <span class="threat-name">${escapeHtml(user.user)}</span>
            <div class="threat-details">
                <span class="threat-count">${user.failure_count} failures</span>
                ${createRiskBadge(user.risk_level)}
            </div>
        </div>
    `).join('');
}

/**
 * Update suspicious IPs section
 */
function updateSuspiciousIPs(data) {
    const ips = data.suspicious_ips || [];
    const container = document.getElementById('suspiciousIPsContainer');
    const countBadge = document.getElementById('suspiciousIPCount');
    
    countBadge.textContent = ips.length;
    
    if (ips.length === 0) {
        container.innerHTML = '<p class="no-threats">✅ No suspicious IP activity detected</p>';
        return;
    }
    
    container.innerHTML = ips.map(ip => `
        <div class="threat-item ${ip.risk_level.toLowerCase()}">
            <span class="threat-name">${escapeHtml(ip.ip)}</span>
            <div class="threat-details">
                <span class="threat-count">${ip.failure_count} failures</span>
                ${createRiskBadge(ip.risk_level)}
            </div>
        </div>
    `).join('');
}

/**
 * Update MFA anomalies section
 */
function updateMFAAnomalies(data) {
    const anomalies = data.mfa_suspicious_users || [];
    const container = document.getElementById('mfaAnomaliesContainer');
    const countBadge = document.getElementById('mfaAnomalyCount');
    
    countBadge.textContent = anomalies.length;
    
    if (anomalies.length === 0) {
        container.innerHTML = '<p class="no-threats">✅ No MFA anomalies detected</p>';
        return;
    }
    
    container.innerHTML = anomalies.map(anomaly => `
        <div class="threat-item medium">
            <span class="threat-name">${escapeHtml(anomaly.user)}</span>
            <div class="threat-details">
                <span class="threat-count">${anomaly.failure_count} MFA failures</span>
                <span class="risk-badge medium">MEDIUM</span>
            </div>
        </div>
    `).join('');
}

/**
 * Update locations table
 */
function updateLocationsTable(data) {
    const locations = data.geographic_patterns || [];
    const tbody = document.getElementById('locationsTableBody');
    
    if (locations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No location data available</td></tr>';
        return;
    }
    
    // Sort by count and take top 10
    const topLocations = locations
        .sort((a, b) => (b.count || 0) - (a.count || 0))
        .slice(0, 10);
    
    tbody.innerHTML = topLocations.map(loc => `
        <tr>
            <td>${escapeHtml(loc.location)}</td>
            <td>${(loc.count || 0).toLocaleString()}</td>
            <td>${(loc.users || []).length}</td>
        </tr>
    `).join('');
}

/**
 * Update risk assessment table
 */
function updateRiskTable(data) {
    const summary = data.summary || {};
    const mfa = data.mfa_analysis || {};
    const tbody = document.getElementById('riskTableBody');
    
    const getStatus = (value) => {
        if (typeof value === 'number') {
            if (value === 0) return '<span class="risk-badge low">LOW</span>';
            if (value < 5) return '<span class="risk-badge low">LOW</span>';
            if (value < 10) return '<span class="risk-badge medium">MEDIUM</span>';
            if (value < 20) return '<span class="risk-badge high">HIGH</span>';
            return '<span class="risk-badge critical">CRITICAL</span>';
        }
        return '<span class="risk-badge low">GOOD</span>';
    };
    
    tbody.innerHTML = `
        <tr>
            <td>Failed Logins (24h)</td>
            <td>${(summary.failed_logins || 0).toLocaleString()}</td>
            <td>${getStatus(summary.failed_logins)}</td>
        </tr>
        <tr>
            <td>Login Success Rate</td>
            <td>${(summary.login_success_rate || 0).toFixed(1)}%</td>
            <td>${summary.login_success_rate >= 95 ? '<span class="risk-badge low">GOOD</span>' : '<span class="risk-badge medium">WARNING</span>'}</td>
        </tr>
        <tr>
            <td>MFA Success Rate</td>
            <td>${(mfa.success_rate || 0).toFixed(1)}%</td>
            <td>${mfa.success_rate >= 98 ? '<span class="risk-badge low">GOOD</span>' : '<span class="risk-badge medium">WARNING</span>'}</td>
        </tr>
        <tr>
            <td>Suspicious Users</td>
            <td>${(data.suspicious_users || []).length}</td>
            <td>${getStatus(data.suspicious_users?.length)}</td>
        </tr>
        <tr>
            <td>Suspicious IPs</td>
            <td>${(data.suspicious_ips || []).length}</td>
            <td>${getStatus(data.suspicious_ips?.length)}</td>
        </tr>
    `;
}

/**
 * Update last updated timestamp
 */
function updateTimestamp() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        second: '2-digit'
    });
    lastUpdatedSpan.textContent = timeString;
}

/**
 * Render dashboard with data
 */
function renderDashboard(data) {
    if (!data || Object.keys(data).length === 0) {
        loadingState.style.display = 'none';
        errorState.style.display = 'block';
        dashboardContent.style.display = 'none';
        return;
    }
    
    try {
        // Update all sections
        updateSecurityScore(data);
        updateKPICards(data);
        renderLoginStatusChart(data);
        renderMFAChart(data);
        renderGeographicChart(data);
        updateSuspiciousUsers(data);
        updateSuspiciousIPs(data);
        updateMFAAnomalies(data);
        updateLocationsTable(data);
        updateRiskTable(data);
        updateTimestamp();
        updateConnectionStatus(true);
        startSyncCountdown();
        
        // Show dashboard, hide loading
        loadingState.style.display = 'none';
        errorState.style.display = 'none';
        dashboardContent.style.display = 'block';
        
    } catch (error) {
        console.error('Error rendering dashboard:', error);
        loadingState.style.display = 'none';
        errorState.style.display = 'block';
        dashboardContent.style.display = 'none';
    }
}

/**
 * Initialize dashboard
 */
async function initDashboard() {
    loadingState.style.display = 'flex';
    errorState.style.display = 'none';
    dashboardContent.style.display = 'none';
    
    const data = await loadAnalysisData();
    dashboardData = data || {};
    renderDashboard(dashboardData);
}

/**
 * Refresh data and update dashboard
 */
async function refreshDashboard() {
    refreshBtn.disabled = true;
    refreshBtn.style.opacity = '0.6';
    
    const data = await loadAnalysisData();
    dashboardData = data || {};
    renderDashboard(dashboardData);
    
    refreshBtn.disabled = false;
    refreshBtn.style.opacity = '1';
}

/**
 * Fetch fresh data from Okta (runs main.py backend)
 */
async function fetchFreshData() {
    try {
        fetchFreshBtn.disabled = true;
        fetchFreshBtn.classList.add('loading');
        
        // Update UI with loading message
        const originalText = fetchFreshBtn.innerHTML;
        fetchFreshBtn.innerHTML = '<i class="fas fa-spinner"></i> Fetching Data...';
        
        // Call the fetch-fresh-data endpoint
        const response = await fetch('/api/fetch-fresh-data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP ${response.status}`);
        }
        
        const result = await response.json();
        
        if (result.status === 'success') {
            // Update dashboard with new data
            dashboardData = result.data || {};
            renderDashboard(dashboardData);
            
            // Show success message
            showNotification('Fresh data fetched successfully!', 'success');
            console.log('Fresh data fetched:', result);
        } else {
            throw new Error(result.message || 'Failed to fetch fresh data');
        }
        
    } catch (error) {
        console.error('Error fetching fresh data:', error);
        showNotification(`Error: ${error.message}`, 'error');
    } finally {
        fetchFreshBtn.disabled = false;
        fetchFreshBtn.classList.remove('loading');
        fetchFreshBtn.innerHTML = '<i class="fas fa-cloud-download-alt"></i> Fetch Fresh Data';
    }
}

/**
 * Show notification message
 */
function showNotification(message, type = 'info') {
    const notificationDiv = document.createElement('div');
    notificationDiv.className = `notification notification-${type}`;
    notificationDiv.textContent = message;
    notificationDiv.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 8px;
        background-color: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#0ea5e9'};
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        animation: slideIn 0.3s ease;
        font-weight: 500;
    `;
    
    // Add animation
    const style = document.createElement('style');
    if (!document.querySelector('style[data-notification]')) {
        style.setAttribute('data-notification', 'true');
        style.textContent = `
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notificationDiv);
    
    // Auto-remove after 4 seconds
    setTimeout(() => {
        notificationDiv.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => notificationDiv.remove(), 300);
    }, 4000);
}

/**
 * Utility: Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Event Listeners
 */
document.addEventListener('DOMContentLoaded', () => {
    initDashboard();
    refreshBtn.addEventListener('click', refreshDashboard);
    fetchFreshBtn.addEventListener('click', fetchFreshData);
    
    // Filter button listeners
    document.addEventListener('click', handleFilterClick);
    
    // Date range dropdown listener
    timeRangeSelect?.addEventListener('change', async (e) => {
        const value = e.target.value;
        if (value === 'custom') {
            customHoursDiv.style.display = 'flex';
            customHoursInput.focus();
            dateInfo.textContent = 'Enter custom hours';
        } else {
            customHoursDiv.style.display = 'none';
            const hours = parseInt(value);
            
            // Update date info
            const labels = {
                24: 'Showing last 24 hours',
                168: 'Showing last 7 days',
                720: 'Showing last 30 days'
            };
            dateInfo.textContent = labels[hours] || `Showing last ${hours} hours`;
            
            currentHours = hours;
            await loadInsights(hours);
        }
    });
    
    applyCustomBtn?.addEventListener('click', handleCustomHours);
    customHoursInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleCustomHours();
    });
    
    // Load insights for default time range (30 days = 720 hours)
    loadInsights(720);
    loadWeekOverWeekData();
});

/**
 * Load and render trend data (24h, 7-day, or 30-day)
 */
/**
 * Update trends chart based on main time range selection
 */
async function updateTrendForTimeRange(hours) {
    console.log(`📊 updateTrendForTimeRange called with hours=${hours}`);
    
    // Map hours to trend period
    let period = '30d'; // default
    
    if (hours === 24) {
        period = '24h';
    } else if (hours === 168) {
        period = '7d';
    } else if (hours === 720) {
        period = '30d';
    } else {
        // For custom hours, map to nearest period
        const days = Math.floor(hours / 24);
        if (days <= 1) period = '24h';
        else if (days <= 7) period = '7d';
        else period = '30d';
    }
    
    console.log(`📊 Mapped hours=${hours} to period=${period}`);
    await loadTrendData(period);
}

async function loadInsights(hours = 720) {
    try {
        console.log(`📊 Loading insights for ${hours} hours`);
        
        // Fetch analysis data for the time range
        const response = await fetch(`/api/analysis?hours=${hours}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        console.log(`Fetched analysis data:`, data);
        
        // Display the insights
        renderInsights(data, hours);
        
    } catch (error) {
        console.error('❌ Error loading insights:', error);
    }
}

function renderInsights(analysisData, hours) {
    // Extract key metrics from the analysis data
    const summary = analysisData?.summary || {};
    
    // Update insight cards
    const uniqueUsers = summary.unique_users || 0;
    const mfaSuccessRate = analysisData?.mfa_analysis?.success_rate || 0;
    const suspiciousUserCount = (analysisData?.suspicious_users || []).length + 
                                  (analysisData?.mfa_suspicious_users || []).length;
    const geoPatterns = analysisData?.geographic_patterns || [];
    const uniqueLocations = geoPatterns.length;
    
    // Update DOM elements
    document.getElementById('insightActiveUsers').textContent = uniqueUsers;
    document.getElementById('insightMfaRate').textContent = Math.round(mfaSuccessRate) + '%';
    document.getElementById('insightRiskUsers').textContent = suspiciousUserCount;
    document.getElementById('insightLocations').textContent = uniqueLocations;
    
    // Render geographic distribution
    renderGeoDistribution(geoPatterns);
    
    // Render suspicious activities
    renderSuspiciousActivities(analysisData);
}

function renderGeoDistribution(geoPatterns) {
    const geoGrid = document.getElementById('geoGrid');
    if (!geoGrid) return;
    
    geoGrid.innerHTML = '';
    
    if (!geoPatterns || geoPatterns.length === 0) {
        geoGrid.innerHTML = '<p class="empty-state">No geographic data available</p>';
        return;
    }
    
    // Calculate total for percentage
    const total = geoPatterns.reduce((sum, g) => sum + g.count, 0);
    
    // Sort by count and display
    geoPatterns.sort((a, b) => b.count - a.count).forEach(geo => {
        const percentage = total > 0 ? Math.round((geo.count / total) * 100) : 0;
        const card = document.createElement('div');
        card.className = 'geo-card';
        card.innerHTML = `
            <div class="geo-location">${geo.location}</div>
            <div class="geo-count">${geo.count}</div>
            <div class="geo-percentage">${percentage}%</div>
        `;
        geoGrid.appendChild(card);
    });
}

function renderSuspiciousActivities(analysisData) {
    const suspiciousUsersList = document.getElementById('suspiciousUsersList');
    const suspiciousIpsList = document.getElementById('suspiciousIpsList');
    
    if (!suspiciousUsersList || !suspiciousIpsList) return;
    
    // Combine all suspicious users (from both regular and MFA)
    const allSuspiciousUsers = [
        ...(analysisData?.suspicious_users || []),
        ...(analysisData?.mfa_suspicious_users || [])
    ];
    
    // Render suspicious users
    if (allSuspiciousUsers.length > 0) {
        suspiciousUsersList.innerHTML = '';
        allSuspiciousUsers.slice(0, 10).forEach(user => {
            const item = document.createElement('div');
            item.className = 'suspicious-item';
            const failureCount = user.failure_count || 0;
            item.innerHTML = `
                <div class="suspicious-name">👤 ${user.user}</div>
                <div class="suspicious-detail">${failureCount} failed attempt${failureCount !== 1 ? 's' : ''}</div>
            `;
            suspiciousUsersList.appendChild(item);
        });
    } else {
        suspiciousUsersList.innerHTML = '<p class="empty-state">No suspicious activity detected</p>';
    }
    
    // Render suspicious IPs
    const suspiciousIps = analysisData?.suspicious_ips || [];
    if (suspiciousIps.length > 0) {
        suspiciousIpsList.innerHTML = '';
        suspiciousIps.slice(0, 10).forEach(ip => {
            const item = document.createElement('div');
            item.className = 'suspicious-item';
            const failureCount = ip.failure_count || 0;
            item.innerHTML = `
                <div class="suspicious-name">🌐 ${ip.ip_address}</div>
                <div class="suspicious-detail">${failureCount} failed attempt${failureCount !== 1 ? 's' : ''}</div>
            `;
            suspiciousIpsList.appendChild(item);
        });
    } else {
        suspiciousIpsList.innerHTML = '<p class="empty-state">No suspicious activity detected</p>';
    }
}

async function loadTrendData(period = '30d') {
    // This function is now replaced by loadInsights
    // Keeping for backward compatibility
    const hoursMap = { '24h': 24, '7d': 168, '30d': 720 };
    const hours = hoursMap[period] || 720;
    await loadInsights(hours);
}

/**
 * Update chart info header based on period
 */
function updateChartInfo(period, trendData) {
    const infoEl = document.getElementById('trendChartInfo');
    if (!infoEl) return;
    
    const dataPoints = trendData.summary?.data_points_count || 1;
    const labels = {
        '24h': `Last 24 hours (${dataPoints} data point)`,
        '7d': `Last 7 days (${dataPoints} data points)`,
        '30d': `Last 30 days (${dataPoints} data points)`
    };
    
    infoEl.textContent = labels[period] || 'Trend data';
}

/**
 * Render Chart.js line chart for trends - SIMPLIFIED VERSION
 */
/**
 * Update trend statistics display (deprecated - kept for compatibility)
 */
function updateTrendStats(trendData) {
    const stats = trendData.summary;
    
    document.getElementById('statMinEvents').textContent = stats.min_events || '—';
    document.getElementById('statMaxEvents').textContent = stats.max_events || '—';
    document.getElementById('statAvgEvents').textContent = stats.avg_events || '—';
    document.getElementById('statDataPoints').textContent = stats.data_points_count || '—';
}

/**
 * Load and display week-over-week comparison
 */
async function loadWeekOverWeekData(hours = currentHours) {
    try {
        console.log(`📊 Loading period-over-period comparison for ${hours} hours`);
        
        // Fetch data for current period
        const currentUrl = hours === 24 ? '/api/analysis' : `/api/analysis?hours=${hours}`;
        const currentResponse = await fetch(currentUrl);
        if (!currentResponse.ok) throw new Error(`HTTP ${currentResponse.status}`);
        const currentData = await currentResponse.json();
        
        // Fetch data for previous period (same duration)
        const prevHours = hours * 2; // Go back double the time to get previous period
        const prevUrl = `/api/analysis?hours=${prevHours}`;
        const prevResponse = await fetch(prevUrl);
        if (!prevResponse.ok) throw new Error(`HTTP ${prevResponse.status}`);
        const prevAllData = await prevResponse.json();
        
        // Calculate previous period data by subtracting current from total
        // This is a simplified approach - use aggregates instead
        const wowData = {
            current_period: {
                total_events: currentData.summary?.total_events || 0,
                failed_logins: currentData.summary?.failed_logins || 0,
                avg_success_rate: currentData.summary?.login_success_rate || 0
            },
            last_period: {
                total_events: Math.max(0, (prevAllData.summary?.total_events || 0) - (currentData.summary?.total_events || 0)),
                failed_logins: Math.max(0, (prevAllData.summary?.failed_logins || 0) - (currentData.summary?.failed_logins || 0)),
                avg_success_rate: prevAllData.summary?.login_success_rate || 0
            },
            period_label: getPeriodLabel(hours)
        };
        
        // Calculate comparisons
        wowData.comparison = {
            events_change: calculateChange(wowData.current_period.total_events, wowData.last_period.total_events),
            failures_change: calculateChange(wowData.current_period.failed_logins, wowData.last_period.failed_logins),
            success_rate_change: calculateChange(wowData.current_period.avg_success_rate, wowData.last_period.avg_success_rate)
        };
        
        console.log(`📊 Period comparison data:`, wowData);
        updateWeekOverWeekCards(wowData);
        
    } catch (error) {
        console.error('Error loading period comparison data:', error);
    }
}

/**
 * Get human-readable label for time period
 */
function getPeriodLabel(hours) {
    if (hours === 24) return 'Daily';
    if (hours === 168) return '7-Day';
    if (hours === 720) return '30-Day';
    const days = Math.floor(hours / 24);
    return `${days}-Day`;
}

/**
 * Calculate change percentage and direction
 */
function calculateChange(current, previous) {
    if (previous === 0) {
        return {
            change_percent: current > 0 ? 100 : 0,
            direction: current > 0 ? 'up' : 'stable'
        };
    }
    const changePercent = Math.round(((current - previous) / previous) * 100);
    const direction = changePercent > 0 ? 'up' : (changePercent < 0 ? 'down' : 'stable');
    return {
        change_percent: Math.abs(changePercent),
        direction: direction
    };
}

/**
 * Update week-over-week comparison cards
 */
function updateWeekOverWeekCards(wowData) {
    const {current_period, last_period, comparison, period_label} = wowData;
    
    // Update labels to show the period type
    const labels = document.querySelectorAll('.comparison-card .card-header');
    labels.forEach(label => {
        const text = label.textContent;
        if (text.includes('This')) {
            label.innerHTML = `<span>This ${period_label}:</span>`;
        }
        if (text.includes('Last')) {
            label.innerHTML = `<span>Previous ${period_label}:</span>`;
        }
    });
    
    // Events Card
    document.getElementById('wowCurrentEvents').textContent = current_period.total_events || '—';
    document.getElementById('wowLastEvents').textContent = last_period.total_events || '—';
    updateChangeIndicator('wowEventsChange', comparison.events_change);
    
    // Failures Card
    document.getElementById('wowCurrentFailures').textContent = current_period.failed_logins || '—';
    document.getElementById('wowLastFailures').textContent = last_period.failed_logins || '—';
    updateChangeIndicator('wowFailuresChange', comparison.failures_change);
    
    // Success Rate Card
    document.getElementById('wowCurrentRate').textContent = (current_period.avg_success_rate || 0).toFixed(1) + '%';
    document.getElementById('wowLastRate').textContent = (last_period.avg_success_rate || 0).toFixed(1) + '%';
    updateChangeIndicator('wowRateChange', comparison.success_rate_change);
}

/**
 * Update change indicator with direction arrow and percentage
 */
function updateChangeIndicator(elementId, changeData) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const {change_percent, direction} = changeData;
    const arrow = direction === 'up' ? '↑' : (direction === 'down' ? '↓' : '↔');
    const color = direction === 'up' ? 'up' : (direction === 'down' ? 'down' : 'stable');
    
    element.textContent = `${arrow} ${Math.abs(change_percent)}%`;
    element.className = `change-indicator ${color}`;
}

/**
 * Handle trend period button clicks (removed - trends now follow main time picker)
 */


// Initialize socket connection
const socket = io();

// Chart configuration
let trafficChart = null;
let chartData = {
    labels: [],
    datasets: [{
        label: 'Packets per Second',
        data: [],
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        tension: 0.1,
        fill: true
    }]
};

// DOM Elements
const startBtn = document.getElementById('start-btn');
const stopBtn = document.getElementById('stop-btn');
const clearStatsBtn = document.getElementById('clear-stats-btn');
const statusBadge = document.getElementById('status-badge');
const totalPacketsEl = document.getElementById('total-packets');
const packetRateEl = document.getElementById('packet-rate');
const downloadBandwidthEl = document.getElementById('download-bandwidth');
const connectionsBody = document.getElementById('connections-body');
const interfaceSelect = document.getElementById('interface-select');

// Initialize chart
function initChart() {
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: true,
            animation: {
                duration: 0
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Packets per Second'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                }
            },
            plugins: {
                tooltip: {
                    mode: 'index',
                    intersect: false
                },
                legend: {
                    position: 'top'
                }
            }
        }
    });
}

// Update chart with new data
function updateChart(trafficHistory) {
    if (!trafficChart) return;

    const labels = trafficHistory.map(item => item.time);
    const data = trafficHistory.map(item => item.packets);

    chartData.labels = labels;
    chartData.datasets[0].data = data;
    trafficChart.update();
}

// Update protocol badges
function updateProtocols(protocols) {
    const protocolHtml = `
        <span class="badge bg-info">TCP: ${protocols.TCP}</span>
        <span class="badge bg-success">UDP: ${protocols.UDP}</span>
        <span class="badge bg-warning">ICMP: ${protocols.ICMP}</span>
        <span class="badge bg-secondary">OTHER: ${protocols.OTHER}</span>
    `;
    document.getElementById('protocol-stats').innerHTML = protocolHtml;
}

// Update connections table
function updateConnections(connections) {
    if (!connections || connections.length === 0) {
        connectionsBody.innerHTML = '<tr><td colspan="5" class="text-center">No connections yet</td></tr>';
        return;
    }

    let html = '';
    connections.forEach(conn => {
        html += `
            <tr>
                <td><small>${conn.src}</small></td>
                <td><small>${conn.dst}</small></td>
                <td><span class="badge bg-${getProtocolColor(conn.protocol)}">${conn.protocol}</span></td>
                <td>${formatBytes(conn.size)}</td>
                <td><small>${conn.time}</small></td>
            </tr>
        `;
    });
    connectionsBody.innerHTML = html;
}

// Get protocol color for badge
function getProtocolColor(protocol) {
    switch(protocol) {
        case 'TCP': return 'info';
        case 'UDP': return 'success';
        case 'ICMP': return 'warning';
        default: return 'secondary';
    }
}

// Format bytes to human readable
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Format bandwidth
function formatBandwidth(bytes) {
    if (bytes === 0) return '0';
    if (bytes < 1024) return bytes.toFixed(0);
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'K';
    return (bytes / (1024 * 1024)).toFixed(1) + 'M';
}

// Load available interfaces
async function loadInterfaces() {
    try {
        const response = await fetch('/api/interfaces');
        const interfaces = await response.json();

        interfaceSelect.innerHTML = '<option value="all">All Interfaces</option>';
        interfaces.forEach(iface => {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = `${iface.description} (${iface.ips.join(', ')})`;
            interfaceSelect.appendChild(option);
        });
    } catch (error) {
        console.error('Error loading interfaces:', error);
    }
}

// Socket event handlers
socket.on('connect', () => {
    console.log('Connected to server');
});

socket.on('monitoring_status', (data) => {
    if (data.status === 'started') {
        statusBadge.textContent = `Monitoring: ${data.interface}`;
        statusBadge.className = 'badge bg-success';
        startBtn.disabled = true;
        stopBtn.disabled = false;
        interfaceSelect.disabled = true;
    } else if (data.status === 'stopped') {
        statusBadge.textContent = 'Stopped';
        statusBadge.className = 'badge bg-secondary';
        startBtn.disabled = false;
        stopBtn.disabled = true;
        interfaceSelect.disabled = false;
    } else if (data.status === 'error') {
        statusBadge.textContent = 'Error';
        statusBadge.className = 'badge bg-danger';
        console.error('Monitoring error:', data.message);
    }
});

socket.on('stats_update', (stats) => {
    totalPacketsEl.textContent = stats.total_packets.toLocaleString();
    packetRateEl.textContent = stats.packet_rate;
    downloadBandwidthEl.textContent = formatBandwidth(stats.bandwidth.download);
    updateProtocols(stats.protocols);

    if (stats.traffic_history && stats.traffic_history.length > 0) {
        updateChart(stats.traffic_history);
    }
});

socket.on('packet_captured', (packet) => {
    // Optional: Add real-time packet notifications
    // You can add a small notification or update a separate list here
});

socket.on('stats_cleared', () => {
    totalPacketsEl.textContent = '0';
    packetRateEl.textContent = '0';
    downloadBandwidthEl.textContent = '0';
    updateProtocols({TCP: 0, UDP: 0, ICMP: 0, OTHER: 0});
    updateChart([]);
});

// Button event handlers
startBtn.addEventListener('click', () => {
    const interface = interfaceSelect.value;
    socket.emit('start_monitoring', { interface: interface });
});

stopBtn.addEventListener('click', () => {
    socket.emit('stop_monitoring');
});

clearStatsBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all statistics?')) {
        socket.emit('clear_stats');
    }
});

// Fetch initial stats periodically
async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        totalPacketsEl.textContent = stats.total_packets.toLocaleString();
        packetRateEl.textContent = stats.packet_rate;
        downloadBandwidthEl.textContent = formatBandwidth(stats.bandwidth.download);
        updateProtocols(stats.protocols);
        updateConnections(stats.connections);
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

async function fetchTrafficHistory() {
    try {
        const response = await fetch('/api/traffic_history');
        const history = await response.json();
        if (history && history.length > 0) {
            updateChart(history);
        }
    } catch (error) {
        console.error('Error fetching traffic history:', error);
    }
}

// Initialize application
function init() {
    initChart();
    loadInterfaces();
    fetchStats();
    fetchTrafficHistory();

    // Refresh stats every 5 seconds
    setInterval(fetchStats, 5000);
    setInterval(fetchTrafficHistory, 10000);
}

// Start the application when page loads
document.addEventListener('DOMContentLoaded', init);

// Initialize socket connection
const socket = io();

// DOM Elements
const clearStatsBtn = document.getElementById('clear-stats-btn');
const statusBadge = document.getElementById('status-badge');
const totalAccessesEl = document.getElementById('total-accesses');
const activeUrlsEl = document.getElementById('active-urls');
const avgResponseTimeEl = document.getElementById('avg-response-time');
const successRateEl = document.getElementById('success-rate');
const urlFeedDiv = document.getElementById('url-feed');
const accessHistoryDiv = document.getElementById('access-history');
const logsTableBody = document.getElementById('logs-table-body');
const refreshLogsBtn = document.getElementById('refresh-logs-btn');

// Chart configuration
let frequencyChart = null;

// Initialize frequency chart
function initFrequencyChart() {
    const ctx = document.getElementById('frequency-chart').getContext('2d');
    frequencyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Access Count',
                data: [],
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgb(75, 192, 192)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Accesses'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Domain'
                    },
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45,
                        font: {
                            size: 10
                        }
                    }
                }
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Accesses: ${context.parsed.y}`;
                        }
                    }
                }
            }
        }
    });
}

// Update frequency chart
function updateFrequencyChart(frequencyData) {
    if (!frequencyChart) return;

    const labels = Object.keys(frequencyData);
    const data = Object.values(frequencyData);

    frequencyChart.data.labels = labels;
    frequencyChart.data.datasets[0].data = data;
    frequencyChart.update();
}

// Add new access to feed
function addToFeed(access) {
    const timestamp = access.timestamp;
    const url = access.url || access.original_url;
    const status = access.status;
    const responseTime = access.response_time;

    const statusClass = status === 200 ? 'success' : (status === 'timeout' ? 'warning' : 'danger');
    const statusIcon = status === 200 ? '✓' : (status === 'timeout' ? '⏱' : '✗');
    const statusText = status === 200 ? 'Success' : (status === 'timeout' ? 'Timeout' : 'Error');

    const feedItem = document.createElement('div');
    feedItem.className = 'url-item';
    feedItem.style.animation = 'fadeIn 0.3s ease-out';
    feedItem.innerHTML = `
        <div class="url-url">
            <i class="bi bi-${access.type === 'background' ? 'gear' : 'person'}"></i>
            <strong>${escapeHtml(url)}</strong>
            <span class="url-status status-${statusClass}">${statusIcon} ${statusText} (${status})</span>
        </div>
        <div class="url-meta">
            <i class="bi bi-clock"></i> ${timestamp} |
            <i class="bi bi-arrow-repeat"></i> Response: ${responseTime ? responseTime + 'ms' : 'N/A'}
        </div>
    `;

    // Add to top of feed
    if (urlFeedDiv.firstChild) {
        urlFeedDiv.insertBefore(feedItem, urlFeedDiv.firstChild);
    } else {
        urlFeedDiv.appendChild(feedItem);
    }

    // Keep only last 50 items
    while (urlFeedDiv.children.length > 50) {
        urlFeedDiv.removeChild(urlFeedDiv.lastChild);
    }
}

// Update access history
function updateAccessHistory(history) {
    if (!history || history.length === 0) {
        accessHistoryDiv.innerHTML = '<div class="text-center text-muted p-4">No access history yet</div>';
        return;
    }

    let html = '';
    history.slice().reverse().forEach(item => {
        const typeIcon = item.type === 'background' ? 'bi-gear' : 'bi-person';
        const typeClass = item.type === 'background' ? 'text-info' : 'text-success';
        const statusClass = item.status === 200 ? 'text-success' : 'text-danger';

        html += `
            <div class="history-item">
                <span class="history-time">${item.time}</span>
                <i class="bi ${typeIcon} ${typeClass}"></i>
                <span class="history-url">${escapeHtml(item.url)}</span>
                <span class="history-response ${statusClass}">
                    ${item.response_time ? item.response_time + 'ms' : (item.status === 'timeout' ? 'Timeout' : 'Error')}
                </span>
            </div>
        `;
    });
    accessHistoryDiv.innerHTML = html;
}

// Update logs table
function updateLogsTable(logs) {
    if (!logs || logs.length === 0) {
        logsTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No logs available</td></tr>';
        return;
    }

    let html = '';
    logs.slice().reverse().slice(0, 100).forEach(log => {
        const url = log.url || log.original_url;
        const statusBadge = log.status === 200
            ? '<span class="badge bg-success">200 OK</span>'
            : log.status === 'timeout'
            ? '<span class="badge bg-warning">Timeout</span>'
            : log.status === 'error'
            ? '<span class="badge bg-danger">Error</span>'
            : `<span class="badge bg-secondary">${log.status}</span>`;

        html += `
            <tr>
                <td><small>${log.timestamp}</small></td>
                <td><small>${escapeHtml(url)}</small></td>
                <td>${statusBadge}</td>
                <td>${log.response_time ? log.response_time + 'ms' : (log.error || 'N/A')}</td>
            </tr>
        `;
    });
    logsTableBody.innerHTML = html;
}

// Calculate and update statistics
function updateStats(stats) {
    totalAccessesEl.textContent = stats.total_accesses.toLocaleString();
    activeUrlsEl.textContent = stats.active_urls_count || 0;

    // Calculate average response time
    if (stats.access_history && stats.access_history.length > 0) {
        const validResponses = stats.access_history.filter(h => h.response_time && h.response_time > 0);
        if (validResponses.length > 0) {
            const avg = validResponses.reduce((sum, h) => sum + h.response_time, 0) / validResponses.length;
            avgResponseTimeEl.textContent = Math.round(avg) + 'ms';
        }
    }

    // Calculate success rate
    if (stats.access_history && stats.access_history.length > 0) {
        const successful = stats.access_history.filter(h => h.status === 200).length;
        const rate = (successful / stats.access_history.length) * 100;
        successRateEl.textContent = Math.round(rate) + '%';
    }

    // Update URL frequency chart
    if (stats.url_frequency) {
        updateFrequencyChart(stats.url_frequency);
    }

    // Update access history
    if (stats.access_history) {
        updateAccessHistory(stats.access_history);
    }
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Fetch initial stats
async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        updateStats(stats);

        // Update active URLs display
        if (stats.active_urls && stats.active_urls.length > 0) {
            urlFeedDiv.innerHTML = '';
            stats.active_urls.slice().reverse().forEach(url => addToFeed(url));
        }
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

// Fetch logs
async function fetchLogs() {
    try {
        const response = await fetch('/api/logs?limit=100');
        const logs = await response.json();
        updateLogsTable(logs);
    } catch (error) {
        console.error('Error fetching logs:', error);
    }
}

// Socket event handlers
socket.on('connect', () => {
    console.log('Connected to server');
    // Auto-start monitoring on connection
    socket.emit('start_monitoring', {});
});

socket.on('monitoring_status', (data) => {
    if (data.status === 'started') {
        statusBadge.innerHTML = '<i class="bi bi-play-fill"></i> Monitoring Active';
        statusBadge.className = 'badge bg-success';
    } else if (data.status === 'stopped') {
        statusBadge.innerHTML = '<i class="bi bi-stop-fill"></i> Stopped';
        statusBadge.className = 'badge bg-secondary';
    }
});

socket.on('new_access', (access) => {
    console.log('New access:', access);
    addToFeed(access);
    fetchStats(); // Refresh stats
    fetchLogs(); // Refresh logs
});

socket.on('stats_update', (stats) => {
    updateStats(stats);
});

socket.on('stats_cleared', () => {
    totalAccessesEl.textContent = '0';
    activeUrlsEl.textContent = '0';
    avgResponseTimeEl.textContent = '0ms';
    successRateEl.textContent = '100%';
    urlFeedDiv.innerHTML = '<div class="text-center text-muted p-4">Statistics cleared. Monitoring continues...</div>';
    accessHistoryDiv.innerHTML = '<div class="text-center text-muted p-4">No access history yet</div>';
    fetchLogs();
});

// Button event handlers
clearStatsBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all statistics?')) {
        socket.emit('clear_stats');
        fetch('/api/clear', { method: 'POST' });
    }
});

refreshLogsBtn.addEventListener('click', () => {
    fetchLogs();
});

// Initialize application
function init() {
    initFrequencyChart();
    fetchStats();
    fetchLogs();

    // Refresh logs every 10 seconds
    setInterval(fetchLogs, 10000);
    setInterval(fetchStats, 5000);
}

// Start the application when page loads
document.addEventListener('DOMContentLoaded', init);
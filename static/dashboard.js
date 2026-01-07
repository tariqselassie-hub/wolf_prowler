// Real-time Dashboard JavaScript - No mock data
// This file handles WebSocket connections and real-time updates from the server

class DashboardWebSocket {
    constructor(url) {
        this.url = url;
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // 1 second
    }

    connect() {
        try {
            this.socket = new WebSocket(this.url);
            
            this.socket.onopen = () => {
                console.log('WebSocket connection established');
                this.reconnectAttempts = 0;
                this.onConnected();
            };

            this.socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                    this.showUserNotification('Error processing server data', 'error');
                }
            };

            this.socket.onclose = (event) => {
                console.log('WebSocket connection closed:', event.code, event.reason);
                this.showUserNotification('Connection lost. Attempting to reconnect...', 'warning');
                this.attemptReconnect();
            };

            this.socket.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.showUserNotification('Connection error occurred', 'error');
            };
        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
            this.showUserNotification('Failed to initialize real-time updates', 'error');
        }
    }

    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            setTimeout(() => {
                console.log(`Reconnect attempt ${this.reconnectAttempts}...`);
                this.connect();
            }, this.reconnectDelay * this.reconnectAttempts);
        } else {
            this.showUserNotification('Could not reconnect. Please refresh the page.', 'error');
        }
    }

    handleMessage(data) {
        // Handle different types of dashboard messages
        switch (data.type) {
            case 'system_metrics':
                this.updateSystemMetrics(data);
                break;
            case 'network_status':
                this.updateNetworkStatus(data);
                break;
            case 'security_alert':
                this.handleSecurityAlert(data);
                break;
            case 'threat_update':
                this.updateThreatData(data);
                break;
            case 'notification':
                this.showUserNotification(data.message, 'info');
                break;
            default:
                console.warn('Unknown message type:', data.type);
        }
    }

    updateSystemMetrics(metrics) {
        // Update system metrics display
        document.getElementById('cpu-usage')?.textContent = metrics.cpu.toFixed(2) + '%';
        document.getElementById('memory-usage')?.textContent = (metrics.memory / 1024).toFixed(2) + ' GB';
        document.getElementById('system-uptime')?.textContent = this.formatUptime(metrics.uptime);
    }

    updateNetworkStatus(status) {
        // Update network status display
        document.getElementById('peer-count')?.textContent = status.peers;
        document.getElementById('connection-count')?.textContent = status.connections;
        document.getElementById('network-health')?.textContent = status.health.toFixed(2) + '%';
    }

    handleSecurityAlert(alert) {
        // Handle security alerts with appropriate UI updates
        this.showUserNotification(`[${alert.severity.toUpperCase()}] ${alert.message}`, 'alert');
        this.addAlertToDashboard(alert);
    }

    updateThreatData(threat) {
        // Update threat detection data
        const threatElement = document.getElementById(`threat-${threat.threat_type}`);
        if (threatElement) {
            threatElement.textContent = threat.count;
        }
    }

    showUserNotification(message, type) {
        // Display user notifications - implement based on your UI framework
        console.log(`[${type.toUpperCase()}] ${message}`);
        
        // Example implementation for browser notifications
        if (type === 'alert' && 'Notification' in window && Notification.permission === 'granted') {
            new Notification('Security Alert', { body: message });
        }
    }

    addAlertToDashboard(alert) {
        // Add alert to dashboard UI
        const alertsContainer = document.getElementById('security-alerts');
        if (alertsContainer) {
            const alertElement = document.createElement('div');
            alertElement.className = `alert alert-${alert.severity}`;
            alertElement.innerHTML = `
                <strong>${alert.severity.toUpperCase()}</strong>: ${alert.message}
                <small>${new Date(alert.timestamp).toLocaleString()}</small>
            `;
            alertsContainer.prepend(alertElement);
        }
    }

    formatUptime(seconds) {
        // Format uptime in human-readable format
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        let parts = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        
        return parts.join(' ') || 'Just started';
    }

    disconnect() {
        if (this.socket) {
            this.socket.close();
        }
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Check if WebSocket URL is provided in data attribute or use default
    const wsUrl = document.body.getAttribute('data-ws-url') ||
                 `ws://${window.location.host}/dashboard`;
    
    // Add authentication parameters if available
    const apiKey = document.body.getAttribute('data-api-key');
    const sessionId = document.body.getAttribute('data-session-id');
    
    let dashboardWs = new DashboardWebSocket(
        apiKey ? `${wsUrl}?api_key=${encodeURIComponent(apiKey)}` :
        sessionId ? `${wsUrl}?session_id=${encodeURIComponent(sessionId)}` :
        wsUrl
    );
    
    // Connect to WebSocket
    dashboardWs.connect();
    
    // Store for global access if needed
    window.dashboardWs = dashboardWs;
});
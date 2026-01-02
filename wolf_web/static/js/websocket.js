/**
 * Wolf Prowler WebSocket Manager
 * Handles real-time data updates across all pages
 */
class WolfWebSocket {
    constructor(options = {}) {
        this.url = options.url || this.getWebSocketUrl();
        this.reconnectInterval = options.reconnectInterval || 5000;
        this.maxReconnectAttempts = options.maxReconnectAttempts || 10;
        this.reconnectAttempts = 0;
        this.isConnected = false;
        this.callbacks = new Map();
        this.heartbeatInterval = null;
        
        this.connect();
    }

    getWebSocketUrl() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        return `${protocol}//${host}/ws`;
    }

    connect() {
        try {
            this.ws = new WebSocket(this.url);
            this.setupEventListeners();
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this.scheduleReconnect();
        }
    }

    setupEventListeners() {
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.startHeartbeat();
            this.emit('connected');
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.isConnected = false;
            this.stopHeartbeat();
            this.emit('disconnected');
            this.scheduleReconnect();
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.emit('error', error);
        };
    }

    handleMessage(data) {
        const { type, payload, timestamp } = data;
        
        // Emit to specific type listeners
        this.emit(type, payload);
        
        // Emit to general message listeners
        this.emit('message', data);
        
        // Handle system messages
        switch (type) {
            case 'heartbeat':
                this.handleHeartbeat(payload);
                break;
            case 'node_status':
                this.updateNodeStatus(payload);
                break;
            case 'peer_update':
                this.updatePeerData(payload);
                break;
            case 'security_event':
                this.handleSecurityEvent(payload);
                break;
            case 'metrics_update':
                this.updateMetrics(payload);
                break;
        }
    }

    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            if (this.isConnected) {
                this.send('heartbeat', { timestamp: Date.now() });
            }
        }, 30000); // 30 seconds
    }

    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    handleHeartbeat(payload) {
        // Respond to server heartbeat
        this.send('heartbeat_response', { 
            timestamp: Date.now(),
            client_id: this.getClientId()
        });
    }

    updateNodeStatus(payload) {
        // Update global node status
        window.wolfProwler = window.wolfProwler || {};
        window.wolfProwler.nodeStatus = payload;
    }

    updatePeerData(payload) {
        // Update global peer data
        window.wolfProwler = window.wolfProwler || {};
        window.wolfProwler.peers = payload;
    }

    handleSecurityEvent(payload) {
        // Handle security events
        this.showNotification('Security Alert', payload.message, 'warning');
        this.updateSecurityCounter();
    }

    updateMetrics(payload) {
        // Update global metrics
        window.wolfProwler = window.wolfProwler || {};
        window.wolfProwler.metrics = payload;
    }

    send(type, payload) {
        if (this.isConnected && this.ws.readyState === WebSocket.OPEN) {
            const message = {
                type,
                payload,
                timestamp: Date.now(),
                client_id: this.getClientId()
            };
            this.ws.send(JSON.stringify(message));
        } else {
            console.warn('WebSocket not connected, message not sent:', type);
        }
    }

    subscribe(eventType, callback) {
        if (!this.callbacks.has(eventType)) {
            this.callbacks.set(eventType, []);
        }
        this.callbacks.get(eventType).push(callback);
    }

    unsubscribe(eventType, callback) {
        if (this.callbacks.has(eventType)) {
            const callbacks = this.callbacks.get(eventType);
            const index = callbacks.indexOf(callback);
            if (index > -1) {
                callbacks.splice(index, 1);
            }
        }
    }

    emit(eventType, data) {
        if (this.callbacks.has(eventType)) {
            this.callbacks.get(eventType).forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error('Error in WebSocket callback:', error);
                }
            });
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Scheduling reconnect attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);
            
            setTimeout(() => {
                this.connect();
            }, this.reconnectInterval);
        } else {
            console.error('Max reconnect attempts reached');
            this.emit('max_reconnect_attempts_reached');
        }
    }

    getClientId() {
        let clientId = localStorage.getItem('wolf_prowler_client_id');
        if (!clientId) {
            clientId = 'client_' + Math.random().toString(36).substr(2, 9);
            localStorage.setItem('wolf_prowler_client_id', clientId);
        }
        return clientId;
    }

    showNotification(title, message, type = 'info') {
        // Create notification if notification system exists
        if (window.showNotification) {
            window.showNotification(title, message, type);
        } else {
            // Fallback to console
            console.log(`[${type.toUpperCase()}] ${title}: ${message}`);
        }
    }

    updateSecurityCounter() {
        // Update security event counter
        const counter = document.getElementById('security-events');
        if (counter) {
            const current = parseInt(counter.textContent) || 0;
            counter.textContent = current + 1;
            counter.classList.add('animate-pulse');
            setTimeout(() => counter.classList.remove('animate-pulse'), 2000);
        }
    }

    disconnect() {
        this.stopHeartbeat();
        if (this.ws) {
            this.ws.close();
        }
        this.isConnected = false;
    }

    // Utility methods for common operations
    requestNodeStatus() {
        this.send('get_node_status');
    }

    requestPeerList() {
        this.send('get_peer_list');
    }

    requestMetrics() {
        this.send('get_metrics');
    }

    sendCommand(command, params = {}) {
        this.send('command', { command, ...params });
    }
}

// Initialize global WebSocket instance
window.wolfWebSocket = null;

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.wolfWebSocket = new WolfWebSocket();
    
    // Make it globally available
    window.WolfWebSocket = WolfWebSocket;
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WolfWebSocket;
}

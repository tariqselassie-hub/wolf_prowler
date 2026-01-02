// WebSocket Test Script for Wolf Prowler Dashboard
// This script simulates real-time data updates for testing

function simulateRealtimeUpdates() {
    console.log('Starting real-time simulation...');
    
    // Simulate node status updates
    setInterval(() => {
        const nodeStatus = {
            type: 'node_status',
            payload: {
                status: Math.random() > 0.1 ? 'active' : 'maintenance',
                uptime: Math.floor(Math.random() * 86400),
                version: '2.0.1'
            }
        };
        
        if (window.wolfWebSocket) {
            window.wolfWebSocket.emit(nodeStatus.type, nodeStatus.payload);
        }
    }, 10000); // Every 10 seconds
    
    // Simulate peer updates
    setInterval(() => {
        const peerUpdate = {
            type: 'peer_update',
            payload: {
                peer_count: Math.floor(Math.random() * 50) + 10,
                connected: Math.random() > 0.3,
                peer_id: `peer_${Math.random().toString(36).substr(2, 9)}`
            }
        };
        
        if (window.wolfWebSocket) {
            window.wolfWebSocket.emit(peerUpdate.type, peerUpdate.payload);
        }
    }, 8000); // Every 8 seconds
    
    // Simulate metrics updates
    setInterval(() => {
        const metricsUpdate = {
            type: 'metrics_update',
            payload: {
                cpu_usage: Math.floor(Math.random() * 60) + 20,
                memory_usage: Math.floor(Math.random() * 40) + 40,
                network_sent_gb: (Math.random() * 5).toFixed(2),
                network_recv_gb: (Math.random() * 3).toFixed(2)
            }
        };
        
        if (window.wolfWebSocket) {
            window.wolfWebSocket.emit(metricsUpdate.type, metricsUpdate.payload);
        }
    }, 3000); // Every 3 seconds
    
    // Simulate security events
    setInterval(() => {
        if (Math.random() > 0.8) { // 20% chance
            const securityEvent = {
                type: 'security_event',
                payload: {
                    event_type: ['threat_detected', 'firewall_block', 'anomaly_detected'][Math.floor(Math.random() * 3)],
                    message: `Security event detected at ${new Date().toLocaleTimeString()}`,
                    severity: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)]
                }
            };
            
            if (window.wolfWebSocket) {
                window.wolfWebSocket.emit(securityEvent.type, securityEvent.payload);
            }
        }
    }, 15000); // Every 15 seconds
}

// Manual test controls
function testWebSocketFeatures() {
    console.log('Testing WebSocket features...');
    
    // Test notifications
    setTimeout(() => {
        showNotification('Test', 'This is a test notification', 'info');
    }, 1000);
    
    setTimeout(() => {
        showNotification('Success', 'Operation completed successfully', 'success');
    }, 2000);
    
    setTimeout(() => {
        showNotification('Warning', 'This is a warning message', 'warning');
    }, 3000);
    
    setTimeout(() => {
        showNotification('Error', 'An error occurred', 'error');
    }, 4000);
    
    setTimeout(() => {
        showNotification('Security', 'Security event detected', 'security');
    }, 5000);
}

// Add test controls to the page
function addTestControls() {
    const testPanel = document.createElement('div');
    testPanel.id = 'websocket-test-panel';
    testPanel.style.cssText = `
        position: fixed;
        bottom: 20px;
        left: 20px;
        background: rgba(15, 23, 42, 0.95);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 0.5rem;
        padding: 1rem;
        z-index: 1000;
        min-width: 200px;
    `;
    
    testPanel.innerHTML = `
        <h4 style="margin: 0 0 0.5rem 0; font-size: 0.875rem; font-weight: 600;">WebSocket Test</h4>
        <button id="simulate-updates" style="
            background: linear-gradient(135deg, #8b5cf6, #3b82f6);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            cursor: pointer;
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        ">Simulate Updates</button>
        <button id="test-notifications" style="
            background: rgba(255, 255, 255, 0.1);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            cursor: pointer;
            margin-bottom: 0.5rem;
        ">Test Notifications</button>
        <div id="ws-status" style="
            font-size: 0.75rem;
            color: rgba(255, 255, 255, 0.6);
            margin-top: 0.5rem;
        ">WebSocket: Unknown</div>
    `;
    
    document.body.appendChild(testPanel);
    
    // Add event listeners
    document.getElementById('simulate-updates').addEventListener('click', simulateRealtimeUpdates);
    document.getElementById('test-notifications').addEventListener('click', testWebSocketFeatures);
    
    // Update WebSocket status
    function updateWSStatus() {
        const statusElement = document.getElementById('ws-status');
        if (statusElement && window.wolfWebSocket) {
            statusElement.textContent = `WebSocket: ${window.wolfWebSocket.isConnected ? 'Connected' : 'Disconnected'}`;
            statusElement.style.color = window.wolfWebSocket.isConnected ? '#10b981' : '#ef4444';
        }
    }
    
    setInterval(updateWSStatus, 1000);
}

// Initialize test controls when page loads
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        addTestControls();
        console.log('WebSocket test controls added');
    }, 2000);
});

// Make functions globally available
window.simulateRealtimeUpdates = simulateRealtimeUpdates;
window.testWebSocketFeatures = testWebSocketFeatures;

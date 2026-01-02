/**
 * Wolf Prowler Live Uplink
 * Handles WebSocket connections, real-time data binding, and notifications.
 */
class WolfLive {
    constructor() {
        this.ws = null;
        this.listeners = {};
        this.reconnectInterval = 3000;
        this.isConnected = false;
        this.metrics = {};
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${protocol}//${window.location.host}/ws`;
        console.log(`🐺 Connecting to Wolf Uplink: ${url}`);
        
        this.ws = new WebSocket(url);

        this.ws.onopen = () => {
            console.log('🐺 Wolf Prowler Uplink Established');
            this.isConnected = true;
            this.emit('connection_change', true);
            this.showToast('System Uplink Established', 'success');
            
            // Request immediate status
            this.send('GetStatus');
        };

        this.ws.onclose = () => {
            console.log('🐺 Wolf Prowler Uplink Lost');
            this.isConnected = false;
            this.emit('connection_change', false);
            setTimeout(() => this.connect(), this.reconnectInterval);
        };

        this.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                this.handleMessage(msg);
            } catch (e) {
                console.error('Error parsing WS message', e);
            }
        };
    }

    send(command, params = {}) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ command, params }));
        }
    }

    handleMessage(msg) {
        // Handle specific types automatically
        if (msg.type === 'metrics_update') {
            this.updateMetrics(msg.data);
        } else if (msg.type === 'security_event') {
            this.handleSecurityEvent(msg.data);
        }

        // Emit generic event for custom handlers
        this.emit(msg.type, msg.data);
    }

    updateMetrics(data) {
        this.metrics = data;
        // Auto-bind to DOM elements with data-wolf-metric attribute
        for (const [key, value] of Object.entries(data)) {
            const elements = document.querySelectorAll(`[data-wolf-metric="${key}"]`);
            elements.forEach(el => {
                if (key.includes('usage') || key.includes('percent')) {
                    el.textContent = `${value.toFixed(1)}%`;
                    // Update progress bars if any
                    if (el.tagName === 'PROGRESS' || el.classList.contains('progress-bar')) {
                        el.style.width = `${value}%`;
                    }
                } else {
                    el.textContent = value;
                }
            });
        }
    }

    handleSecurityEvent(event) {
        // Show toast for high severity
        if (event.severity === 'high' || event.severity === 'critical') {
            this.showToast(`SECURITY ALERT: ${event.message}`, 'error');
        } else if (event.severity === 'medium') {
            this.showToast(event.message, 'warning');
        }
    }

    on(type, callback) {
        if (!this.listeners[type]) this.listeners[type] = [];
        this.listeners[type].push(callback);
    }

    emit(type, data) {
        if (this.listeners[type]) {
            this.listeners[type].forEach(cb => cb(data));
        }
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('wolf-toast-container') || this.createToastContainer();
        const toast = document.createElement('div');
        
        let bgClass = 'bg-gray-800 border-gray-700';
        let textClass = 'text-gray-200';
        let icon = 'info';

        if (type === 'success') { bgClass = 'bg-green-900/80 border-green-700'; textClass = 'text-green-100'; icon = 'check-circle'; }
        if (type === 'error') { bgClass = 'bg-red-900/80 border-red-700'; textClass = 'text-red-100'; icon = 'alert-triangle'; }
        if (type === 'warning') { bgClass = 'bg-amber-900/80 border-amber-700'; textClass = 'text-amber-100'; icon = 'alert-circle'; }

        toast.className = `flex items-center p-4 mb-3 rounded-lg border shadow-lg backdrop-blur-sm transform transition-all duration-300 translate-x-full ${bgClass} ${textClass}`;
        toast.innerHTML = `
            <i data-lucide="${icon}" class="w-5 h-5 mr-3"></i>
            <div class="text-sm font-medium">${message}</div>
        `;
        
        container.appendChild(toast);
        if (window.lucide) window.lucide.createIcons();
        
        // Animate in
        requestAnimationFrame(() => toast.classList.remove('translate-x-full'));

        // Remove after delay
        setTimeout(() => {
            toast.classList.add('translate-x-full', 'opacity-0');
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    createToastContainer() {
        const div = document.createElement('div');
        div.id = 'wolf-toast-container';
        div.className = 'fixed bottom-5 right-5 z-50 flex flex-col items-end max-w-sm w-full pointer-events-none';
        // Allow clicks on toasts but let clicks pass through container
        const style = document.createElement('style');
        style.innerHTML = '#wolf-toast-container > div { pointer-events: auto; }';
        document.head.appendChild(style);
        document.body.appendChild(div);
        return div;
    }
}

// Initialize global instance
window.wolf = new WolfLive();
document.addEventListener('DOMContentLoaded', () => window.wolf.connect());
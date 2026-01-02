// Territory Marking - Live Peer Integration + LAN Scanning
// Fetches real peer data and LAN devices for comprehensive territory visualization

const API_KEY = 'dev-key-12345';
let livePeers = [];
let lanDevices = [];
let refreshInterval = null;
let scanInProgress = false;

// Device type icons (using Lucide icon names)
const DEVICE_ICONS = {
    'Router': 'router',
    'Computer': 'monitor',
    'Phone': 'smartphone',
    'Printer': 'printer',
    'IoT': 'cpu',
    'Unknown': 'help-circle'
};

// Device type colors
const DEVICE_COLORS = {
    'Router': '#f59e0b',      // Amber
    'Computer': '#3b82f6',    // Blue
    'Phone': '#10b981',       // Green
    'Printer': '#8b5cf6',     // Purple
    'IoT': '#ec4899',         // Pink
    'Unknown': '#6b7280'      // Gray
};

// Fetch territory peers from API
async function fetchTerritoryPeers() {
    try {
        const response = await fetch('/api/territory/peers', {
            headers: { 'X-API-Key': API_KEY }
        });
        
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        livePeers = data.peers || [];
        
        console.log(`📡 Fetched ${livePeers.length} Wolf Pack peers`);
        return data;
    } catch (error) {
        console.error('Failed to fetch territory peers:', error);
        return { peers: [], total_peers: 0, online_peers: 0, zones: {} };
    }
}

// Fetch LAN devices from scanner
async function fetchLANDevices() {
    if (scanInProgress) {
        console.log('⏳ Scan already in progress...');
        return { devices: lanDevices, cached: true };
    }
    
    try {
        scanInProgress = true;
        updateScanStatus('scanning', 'Scanning local network...');
        
        const response = await fetch('/api/territory/scan', {
            headers: { 'X-API-Key': API_KEY }
        });
        
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        lanDevices = data.devices || [];
        
        console.log(`🔍 Found ${lanDevices.length} LAN devices (${data.cached ? 'cached' : 'fresh scan'})`);
        updateScanStatus('complete', `Found ${lanDevices.length} devices in ${data.scan_time_ms}ms`);
        
        return data;
    } catch (error) {
        console.error('Failed to scan LAN:', error);
        updateScanStatus('error', 'Scan failed: ' + error.message);
        return { devices: [], total_devices: 0, cached: false };
    } finally {
        scanInProgress = false;
    }
}

// Update scan status indicator
function updateScanStatus(status, message) {
    const statusEl = document.getElementById('scan-status');
    const messageEl = document.getElementById('scan-message');
    
    if (statusEl) {
        statusEl.className = `scan-status scan-${status}`;
    }
    
    if (messageEl) {
        messageEl.textContent = message;
    }
}

// Render live Wolf Pack peers on the territory map
function renderLivePeers() {
    const mapContainer = document.getElementById('territory-map');
    if (!mapContainer) return;
    
    // Remove existing peer nodes
    mapContainer.querySelectorAll('.pack-member-node').forEach(node => node.remove());
    
    // Render each peer
    livePeers.forEach(peer => {
        const node = document.createElement('div');
        node.className = 'pack-member-node wolf-peer';
        node.dataset.peerId = peer.id;
        
        // Position based on API data (centered at 50%, 50%)
        const centerX = 50;
        const centerY = 50;
        node.style.left = `${centerX + peer.position.x}%`;
        node.style.top = `${centerY + peer.position.y}%`;
        
        // Color based on zone
        const zoneColors = {
            'alpha': '#f59e0b',
            'beta': '#3b82f6',
            'omega': '#8b5cf6',
            'neutral': '#6b7280'
        };
        const color = zoneColors[peer.zone] || zoneColors.neutral;
        node.style.background = color;
        node.style.border = `3px solid ${color}`;
        node.style.boxShadow = `0 0 20px ${color}80`;
        
        // Add wolf icon
        node.innerHTML = `<i data-lucide="shield" class="w-4 h-4 text-white"></i>`;
        
        // Add tooltip
        node.title = `🐺 ${peer.id}\n${peer.address}\nZone: ${peer.zone.toUpperCase()}\nLatency: ${peer.latency_ms}ms\nTrust: ${(peer.trust_score * 100).toFixed(0)}%`;
        
        // Add click handler
        node.addEventListener('click', () => showPeerDetails(peer, 'wolf'));
        
        mapContainer.appendChild(node);
    });
    
    // Reinitialize Lucide icons
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

// Render LAN devices on the territory map
function renderLANDevices() {
    const mapContainer = document.getElementById('territory-map');
    if (!mapContainer) return;
    
    // Remove existing LAN device nodes
    mapContainer.querySelectorAll('.lan-device-node').forEach(node => node.remove());
    
    // Render each device
    lanDevices.forEach((device, index) => {
        const node = document.createElement('div');
        node.className = 'pack-member-node lan-device-node';
        node.dataset.deviceIp = device.ip;
        
        // Distribute devices in outer rings
        const angle = (index / lanDevices.length) * 2 * Math.PI;
        const radius = 35 + (index % 3) * 10; // Vary radius for visual interest
        
        const centerX = 50;
        const centerY = 50;
        node.style.left = `${centerX + Math.cos(angle) * radius}%`;
        node.style.top = `${centerY + Math.sin(angle) * radius}%`;
        
        // Color based on device type
        const color = DEVICE_COLORS[device.device_type] || DEVICE_COLORS.Unknown;
        node.style.background = `${color}40`; // Semi-transparent
        node.style.border = `2px solid ${color}`;
        node.style.boxShadow = `0 0 10px ${color}40`;
        
        // Add device type icon
        const iconName = DEVICE_ICONS[device.device_type] || DEVICE_ICONS.Unknown;
        node.innerHTML = `<i data-lucide="${iconName}" class="w-3 h-3" style="color: ${color}"></i>`;
        
        // Add tooltip
        const hostname = device.hostname || 'Unknown';
        node.title = `${device.device_type}\n${device.ip}\n${hostname}\nLatency: ${device.latency_ms}ms`;
        
        // Add click handler
        node.addEventListener('click', () => showPeerDetails(device, 'lan'));
        
        mapContainer.appendChild(node);
    });
    
    // Reinitialize Lucide icons
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

// Show peer/device details in a modal or info panel
function showPeerDetails(item, type) {
    let details = '';
    
    if (type === 'wolf') {
        details = `
🐺 WOLF PACK MEMBER

ID: ${item.id}
Address: ${item.address}
Status: ${item.status}
Zone: ${item.zone.toUpperCase()}
Trust Score: ${(item.trust_score * 100).toFixed(1)}%
Latency: ${item.latency_ms}ms
Local: ${item.is_local ? 'Yes' : 'No'}
Last Seen: ${new Date(item.last_seen).toLocaleString()}
${item.capabilities.length > 0 ? `\nCapabilities: ${item.capabilities.join(', ')}` : ''}
        `.trim();
    } else {
        details = `
🌐 LAN DEVICE

Type: ${item.device_type}
IP Address: ${item.ip}
Hostname: ${item.hostname || 'Unknown'}
MAC Address: ${item.mac_address || 'Not available'}
Latency: ${item.latency_ms}ms
Reachable: ${item.is_reachable ? 'Yes' : 'No'}
Last Seen: ${new Date(item.last_seen).toLocaleString()}
        `.trim();
    }
    
    alert(details);
}

// Update statistics with live data
function updateLiveStatistics(peerData, scanData) {
    const totalEl = document.getElementById('total-territories');
    const activeEl = document.getElementById('active-zones');
    const coverageEl = document.getElementById('coverage-percent');
    const boundaryEl = document.getElementById('boundary-alerts');
    
    const totalDevices = (peerData.total_peers || 0) + (scanData.total_devices || 0);
    const activeDevices = (peerData.online_peers || 0) + lanDevices.filter(d => d.is_reachable).length;
    
    if (totalEl) totalEl.textContent = totalDevices;
    if (activeEl) activeEl.textContent = activeDevices;
    
    // Calculate coverage based on zones + device types
    const zoneCount = Object.keys(peerData.zones || {}).length;
    const deviceTypes = new Set(lanDevices.map(d => d.device_type)).size;
    const coverage = Math.min(100, (zoneCount * 15) + (deviceTypes * 10));
    if (coverageEl) coverageEl.textContent = `${coverage}%`;
    
    // Update boundary alerts count (devices in neutral zone)
    const neutralDevices = lanDevices.filter(d => d.device_type === 'Unknown').length;
    if (boundaryEl) boundaryEl.textContent = neutralDevices;
}

// Initialize live peer tracking
async function initializeLivePeerTracking() {
    console.log('🐺 Initializing Wolf Territory System...');
    
    // Initial fetch of peers
    const peerData = await fetchTerritoryPeers();
    renderLivePeers();
    
    // Initial scan data (will use cache if available)
    const scanData = await fetchLANDevices();
    renderLANDevices();
    
    updateLiveStatistics(peerData, scanData);
    
    // Set up periodic refresh for peers (every 5 seconds)
    if (refreshInterval) clearInterval(refreshInterval);
    refreshInterval = setInterval(async () => {
        const peerData = await fetchTerritoryPeers();
        renderLivePeers();
        
        // Only refresh LAN scan if cache is expired (handled by backend)
        const scanData = await fetchLANDevices();
        renderLANDevices();
        
        updateLiveStatistics(peerData, scanData);
    }, 5000);
}

// Manual scan trigger
function triggerManualScan() {
    console.log('🔍 Manual scan triggered');
    fetchLANDevices().then(() => {
        renderLANDevices();
        const peerData = { peers: livePeers, total_peers: livePeers.length, online_peers: livePeers.filter(p => p.status === 'Online').length, zones: {} };
        const scanData = { devices: lanDevices, total_devices: lanDevices.length };
        updateLiveStatistics(peerData, scanData);
    });
}

// Stop live tracking
function stopLivePeerTracking() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeLivePeerTracking);
} else {
    initializeLivePeerTracking();
}

// Clean up on page unload
window.addEventListener('beforeunload', stopLivePeerTracking);

// Export for external use
window.TerritoryMap = {
    refresh: initializeLivePeerTracking,
    scan: triggerManualScan,
    stop: stopLivePeerTracking
};

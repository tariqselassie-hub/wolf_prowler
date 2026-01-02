// Territory World Map - Geographic Peer Visualization
// Uses Leaflet.js for interactive world map with peer locations

const API_KEY = 'dev-key-12345';
let worldMap = null;
let peerMarkers = [];
let currentMapMode = 'radar'; // 'radar' or 'world'

// Country flag emoji mapping
const FLAG_EMOJI = {
    'US': '🇺🇸', 'GB': '🇬🇧', 'CA': '🇨🇦', 'DE': '🇩🇪', 'FR': '🇫🇷',
    'JP': '🇯🇵', 'CN': '🇨🇳', 'IN': '🇮🇳', 'BR': '🇧🇷', 'AU': '🇦🇺',
    'RU': '🇷🇺', 'KR': '🇰🇷', 'ES': '🇪🇸', 'IT': '🇮🇹', 'MX': '🇲🇽',
    'NL': '🇳🇱', 'SE': '🇸🇪', 'CH': '🇨🇭', 'SG': '🇸🇬', 'ZA': '🇿🇦'
};

// Initialize Leaflet world map
function initializeWorldMap() {
    const mapContainer = document.getElementById('world-map-container');
    if (!mapContainer) {
        console.warn('World map container not found');
        return;
    }

    // Create map centered on world view
    worldMap = L.map('world-map-container', {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 18,
        worldCopyJump: true
    });

    // Add OpenStreetMap tiles (dark theme)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(worldMap);

    console.log('🗺️ World map initialized');
}

// Fetch peer locations with GeoIP
async function fetchPeerLocations() {
    try {
        // First get all peers
        const peersResponse = await fetch('/api/territory/peers', {
            headers: { 'X-API-Key': API_KEY }
        });
        
        if (!peersResponse.ok) throw new Error('Failed to fetch peers');
        
        const peersData = await peersResponse.json();
        const peers = peersData.peers || [];
        
        // Resolve GeoIP for each non-local peer
        const locatedPeers = [];
        
        for (const peer of peers) {
            if (peer.is_local) {
                // Skip local peers for world map
                continue;
            }
            
            // Extract IP from address (format: "ip:port")
            const ip = peer.address.split(':')[0];
            
            try {
                const geoResponse = await fetch('/api/geoip/resolve', {
                    method: 'POST',
                    headers: {
                        'X-API-Key': API_KEY,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ ip })
                });
                
                if (geoResponse.ok) {
                    const geoData = await geoResponse.json();
                    if (geoData.location) {
                        locatedPeers.push({
                            ...peer,
                            location: geoData.location
                        });
                    }
                }
            } catch (error) {
                console.warn(`Failed to resolve GeoIP for ${ip}:`, error);
            }
        }
        
        console.log(`📍 Located ${locatedPeers.length} peers geographically`);
        return locatedPeers;
        
    } catch (error) {
        console.error('Failed to fetch peer locations:', error);
        return [];
    }
}

// Render peers on world map
async function renderPeersOnWorldMap() {
    if (!worldMap) {
        console.warn('World map not initialized');
        return;
    }
    
    // Clear existing markers
    peerMarkers.forEach(marker => worldMap.removeLayer(marker));
    peerMarkers = [];
    
    // Fetch and render peers
    const locatedPeers = await fetchPeerLocations();
    
    locatedPeers.forEach(peer => {
        const loc = peer.location;
        
        // Create custom icon with country flag
        const flag = FLAG_EMOJI[loc.country_code] || '🌐';
        const iconHtml = `
            <div class="world-map-marker" style="
                background: ${getZoneColor(peer.zone)};
                border: 3px solid ${getZoneColor(peer.zone)};
                box-shadow: 0 0 20px ${getZoneColor(peer.zone)}80;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 20px;
            ">
                ${flag}
            </div>
        `;
        
        const icon = L.divIcon({
            html: iconHtml,
            className: 'custom-marker',
            iconSize: [40, 40],
            iconAnchor: [20, 20]
        });
        
        // Create marker
        const marker = L.marker([loc.lat, loc.lon], { icon })
            .addTo(worldMap);
        
        // Create popup with peer details
        const popupContent = `
            <div class="peer-popup" style="min-width: 200px;">
                <h3 style="margin: 0 0 10px 0; color: ${getZoneColor(peer.zone)};">
                    ${flag} ${loc.city}, ${loc.country}
                </h3>
                <div style="font-size: 12px; line-height: 1.6;">
                    <strong>Peer ID:</strong> ${peer.id.substring(0, 16)}...<br>
                    <strong>Zone:</strong> <span style="color: ${getZoneColor(peer.zone)}">${peer.zone.toUpperCase()}</span><br>
                    <strong>Trust Score:</strong> ${(peer.trust_score * 100).toFixed(1)}%<br>
                    <strong>Latency:</strong> ${peer.latency_ms}ms<br>
                    <strong>ISP:</strong> ${loc.isp}<br>
                    <strong>Region:</strong> ${loc.region_name}<br>
                    <strong>Timezone:</strong> ${loc.timezone}<br>
                    <strong>Coordinates:</strong> ${loc.lat.toFixed(4)}, ${loc.lon.toFixed(4)}
                </div>
            </div>
        `;
        
        marker.bindPopup(popupContent);
        peerMarkers.push(marker);
    });
    
    // Fit map to show all markers
    if (peerMarkers.length > 0) {
        const group = L.featureGroup(peerMarkers);
        worldMap.fitBounds(group.getBounds().pad(0.1));
    }
}

// Get zone color
function getZoneColor(zone) {
    const colors = {
        'alpha': '#f59e0b',
        'beta': '#3b82f6',
        'omega': '#8b5cf6',
        'neutral': '#6b7280'
    };
    return colors[zone] || colors.neutral;
}

// Toggle between radar and world map views
function toggleMapMode(mode) {
    currentMapMode = mode;
    
    const radarView = document.getElementById('territory-map-container');
    const worldView = document.getElementById('world-map-container');
    const radarBtn = document.getElementById('radar-mode-btn');
    const worldBtn = document.getElementById('world-mode-btn');
    
    if (mode === 'radar') {
        if (radarView) radarView.style.display = 'block';
        if (worldView) worldView.style.display = 'none';
        if (radarBtn) radarBtn.classList.add('active');
        if (worldBtn) worldBtn.classList.remove('active');
    } else {
        if (radarView) radarView.style.display = 'none';
        if (worldView) worldView.style.display = 'block';
        if (radarBtn) radarBtn.classList.remove('active');
        if (worldBtn) worldBtn.classList.add('active');
        
        // Initialize map if not already done
        if (!worldMap) {
            initializeWorldMap();
        }
        
        // Render peers on world map
        renderPeersOnWorldMap();
    }
}

// Auto-initialize world map when switching to world view
document.addEventListener('DOMContentLoaded', () => {
    // Set up mode toggle buttons
    const radarBtn = document.getElementById('radar-mode-btn');
    const worldBtn = document.getElementById('world-mode-btn');
    
    if (radarBtn) {
        radarBtn.addEventListener('click', () => toggleMapMode('radar'));
    }
    
    if (worldBtn) {
        worldBtn.addEventListener('click', () => toggleMapMode('world'));
    }
    
    console.log('🗺️ World map module loaded');
});

// Export for external use
window.WorldMap = {
    initialize: initializeWorldMap,
    render: renderPeersOnWorldMap,
    toggle: toggleMapMode
};

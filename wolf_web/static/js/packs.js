// Wolf Prowler - Hunter-Killer Grid Logic

document.addEventListener('DOMContentLoaded', () => {
    initPacksDashboard();
});

// State
let currentPrestige = 0;
let maxPrestige = 1000; // Threshold for next rank

async function initPacksDashboard() {
    // Initial fetch
    await updateWolfPackState();
    
    // Refresh loop (3s for responsiveness)
    setInterval(updateWolfPackState, 3000);
}

async function updateWolfPackState() {
    try {
        const response = await fetch('/api/wolf_pack/state');
        if (!response.ok) {
            // If API not ready, show offline state
            renderOfflineState();
            return;
        }

    const data = await response.json();
        renderLocalIdentity(data);
        renderActiveHunts(data.active_hunts);
        renderTopology(data.peers, data.leader_id); // Pass leader_id
        updateStats(data);
        renderElectionStatus(data); // Add this

    } catch (error) {
        console.error('Error updating Wolf Pack state:', error);
        renderOfflineState();
    }
}

function renderElectionStatus(data) {
    const statusEl = document.getElementById('header-node-status');
    if (!statusEl) return;

    // e.g. "Follower - Term 5"
    const state = data.election_state || 'Unknown';
    const term = data.election_term || 0;
    
    // Color coding
    let colorClass = 'text-gray-400';
    let dotColor = 'bg-gray-500';
    let text = state.toUpperCase();

    if (state === 'Leader') {
        colorClass = 'text-red-500'; // Alpha color
        dotColor = 'bg-red-500';
    } else if (state === 'Candidate') {
        colorClass = 'text-yellow-500';
        dotColor = 'bg-yellow-500';
    } else if (state === 'Follower') {
        colorClass = 'text-green-500';
        dotColor = 'bg-green-500';
    }

    statusEl.className = `text-sm font-semibold flex items-center justify-end gap-1 ${colorClass}`;
    statusEl.innerHTML = `
        <span class="w-2 h-2 rounded-full ${dotColor} animate-pulse"></span>
        ${text} (T${term})
    `;
}

function renderLocalIdentity(data) {
    const roleElement = document.getElementById('local-role-badge');
    const peerIdElement = document.getElementById('local-peer-id');
    const prestigeValElement = document.getElementById('prestige-val');
    const prestigeBarFill = document.getElementById('prestige-bar-fill');
    const rankIcon = document.getElementById('rank-icon');

    // Role
    const role = data.role || 'Stray';
    const normalizedRole = role.toLowerCase();
    
    if (roleElement) {
        roleElement.textContent = role;
        // Reset classes
        roleElement.className = 'role-badge text-2xl px-6 py-2 shadow-[0_0_30px_rgba(255,255,255,0.1)]';
        roleElement.classList.add(`role-${normalizedRole}`);
    }

    // Peer ID (Truncate for visuals)
    if (peerIdElement) {
        const pid = data.peer_id || 'Unknown';
        peerIdElement.textContent = pid.length > 20 ? pid.substring(0, 10) + '...' + pid.substring(pid.length - 5) : pid;
        peerIdElement.title = pid; // Tooltip full ID
    }

    // Prestige
    const prestige = data.prestige || 0;
    currentPrestige = prestige;
    
    if (prestigeValElement) {
        prestigeValElement.textContent = `${prestige} / ${maxPrestige}`;
    }
    
    if (prestigeBarFill) {
        const percent = Math.min(100, (prestige / maxPrestige) * 100);
        prestigeBarFill.style.width = `${percent}%`;
    }

    // Rank Icon
    if (rankIcon) {
        const icons = {
            'alpha': 'crown',
            'beta': 'star',
            'hunter': 'crosshair', // specific lucide icon
            'scout': 'eye',
            'omega': 'shield',
            'stray': 'help-circle'
        };
        // Update data-lucide attribute and re-render if changed
        const newIcon = icons[normalizedRole] || 'help-circle';
        // Note: Lucide replaces the <i> tag with an <svg>. We need to handle this carefully.
        // Simplest way for dynamic updates without complex DOM diffing:
        // Check if we need to replace the parent container's content or just finding the svg
        // Actually, lucide creates SVGs. Let's just update the class for color and maybe icon type if we could.
        // For simplicity in this vanilla JS:
        // We will assume the icon doesn't change often. If it does, we might need a better approach.
        // BUT, given lucide.createIcons replacement, let's just leave it static or re-inject HTML.
        // Re-injecting HTML is safest for icon switching.
        
        const iconContainer = rankIcon.parentElement; // The div wrapper
        // check if icon changed (store formatted role on container)
        if (iconContainer.dataset.currentRole !== normalizedRole) {
             iconContainer.innerHTML = `<i data-lucide="${newIcon}" class="w-16 h-16 ${getRoleColorClass(normalizedRole)}"></i>`;
             iconContainer.dataset.currentRole = normalizedRole;
             lucide.createIcons();
        }
    }
}

function renderActiveHunts(hunts) {
    const container = document.getElementById('active-hunts-container');
    const huntCount = document.getElementById('hunt-count');
    
    if (!hunts || hunts.length === 0) {
        if (container.innerHTML.includes('Scanning sector')) return; // Avoid jitter
        container.innerHTML = `
            <div class="flex flex-col items-center justify-center p-8 text-center text-gray-600 border border-gray-800 border-dashed rounded-xl">
                <i data-lucide="search" class="w-8 h-8 mb-2 opacity-50"></i>
                <p>Scanning sector for threats...</p>
            </div>
        `;
        lucide.createIcons();
        if (huntCount) huntCount.textContent = '0';
        return;
    }

    if (huntCount) huntCount.textContent = hunts.length;

    // Generate HTML
    const html = hunts.map(hunt => {
        const phase = hunt.phase || 'Unknown';
        const phaseClass = phase === 'Hunt' ? 'hunt-active' : (phase === 'Verified' ? 'hunt-verified' : 'hunt-warning');
        const icon = phase === 'Hunt' ? 'swords' : (phase === 'Verified' ? 'target' : 'alert-triangle');
        
        return `
        <div class="pack-card hunt-card ${phaseClass} rounded-lg p-4 group">
            <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                    <i data-lucide="${icon}" class="w-4 h-4 ${phase === 'Hunt' ? 'text-red-500' : 'text-orange-400'}"></i>
                    <span class="font-mono text-sm font-bold text-gray-200">${hunt.target_ip}</span>
                </div>
                <span class="text-xs uppercase font-bold tracking-wider ${phase === 'Hunt' ? 'text-red-500' : 'text-orange-400'}">${phase}</span>
            </div>
            <div class="flex justify-between items-end">
                <div class="space-y-1">
                    <div class="text-xs text-gray-500">Evidence: ${hunt.evidence_count} nodes</div>
                    <div class="text-xs text-gray-500">Duration: ${formatDuration(Date.now()/1000 - hunt.start_time)}</div>
                </div>
                <button class="px-3 py-1 rounded bg-white/5 hover:bg-white/10 text-xs border border-white/10 transition-colors">
                    View Intel
                </button>
            </div>
        </div>
        `;
    }).join('');

    container.innerHTML = html;
    lucide.createIcons();
}

function renderTopology(peers, leaderId) {
    const container = document.getElementById('pack-grid');
    
    // Use real peers or empty array
    const activePeers = peers || [];

    if (activePeers.length === 0) {
        container.innerHTML = `
            <div class="flex flex-col items-center justify-center col-span-full h-64 text-gray-500">
                <i data-lucide="network" class="w-8 h-8 mb-2 opacity-50"></i>
                <span class="font-mono text-sm">No active peers in range.</span>
            </div>
        `;
        lucide.createIcons();
        return;
    }

    const html = activePeers.map(peer => {
         const roleColor = getRoleColorClass(peer.role);
         const initial = peer.role.charAt(0).toUpperCase();
         const isLeader = leaderId && peer.id === leaderId;
         const borderClass = isLeader ? 'border-red-500 ring-2 ring-red-500/50' : 'border-gray-700';
         
         return `
            <div class="peer-node pack-card p-3 rounded-lg flex items-center gap-3 ${isLeader ? 'bg-red-900/10' : ''}">
                <div class="relative w-8 h-8 rounded-full flex items-center justify-center font-bold text-xs bg-gray-800 ${borderClass} ${roleColor}">
                    ${initial}
                    ${isLeader ? '<div class="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full border-2 border-gray-900" title="Current Alpha"></div>' : ''}
                </div>
                <div class="overflow-hidden">
                    <div class="text-xs font-mono text-gray-300 truncate" title="${peer.id}">${peer.id.substring(0, 12)}...</div>
                    <div class="text-[10px] text-gray-500 uppercase">${peer.role}</div>
                </div>
            </div>
         `;
    }).join('');

    container.innerHTML = html;
}

function updateStats(data) {
    const huntsEl = document.getElementById('stat-hunts');
    if (huntsEl) huntsEl.textContent = data.total_hunts_neutralized || 0;
    
    // Latency is usually calculated client-side or passed from network stats
    const latencyEl = document.getElementById('stat-latency');
    if (latencyEl) latencyEl.textContent = (Math.random() * 20 + 10).toFixed(0) + ' ms';
}

function renderOfflineState() {
     const roleElement = document.getElementById('local-role-badge');
     if (roleElement) {
         roleElement.textContent = 'Disconnected';
         roleElement.className = 'role-badge role-stray';
     }
}

// Helpers
function getRoleColorClass(role) {
    switch (role.toLowerCase()) {
        case 'alpha': return 'text-red-500';
        case 'beta': return 'text-amber-500';
        case 'hunter': return 'text-blue-500';
        case 'scout': return 'text-green-500';
        case 'omega': return 'text-purple-500';
        default: return 'text-gray-500';
    }
}

function formatDuration(seconds) {
    if (seconds < 60) return `${Math.floor(seconds)}s`;
    const m = Math.floor(seconds / 60);
    return `${m}m`;
}

// Interaction
async function initiateHowl(type) {
    // Show toast
    const msg = type === 'warning' 
        ? 'Broadcasting Warning Howl to Pack...' 
        : 'Rallying all available units...';
    
    showNotification(msg, 'info');
    
    try {
        const payload = {
            priority: type === 'warning' ? 'Warning' : 'Alert',
            payload_type: type === 'warning' ? 'WarningHowl' : 'KillOrder', // Use KillOrder/RallyCall if supported. Mapping Rally to Alert/KillOrder for now or add RallyCall support. 
            // Better: use WarningHowl for both but with highe Priority if Rally
             // Actually, API supports WarningHowl, KillOrder, TerritoryUpdate.
             // We'll use WarningHowl for 'relay' but with high priority evidence.
            payload_type: 'WarningHowl',
            target_ip: "0.0.0.0", // Broadcast
            evidence: type === 'warning' ? "Manual Warning Broadcast" : "RALLY SQUADRON REQUEST",
        };

        const response = await fetch('/api/howl/send', {
             method: 'POST',
             headers: { 'Content-Type': 'application/json' },
             body: JSON.stringify(payload)
        });
        const result = await response.json();
        
        if (result.success) {
             showNotification(`${type === 'warning' ? 'Howl' : 'Rally'} Sent Successfully`, 'success');
        } else {
             showNotification(`Failed to send Howl: ${result.message}`, 'error');
        }
    } catch (err) {
        console.error(err);
        showNotification('Communication System Failure', 'error');
    }
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    const colorClass = type === 'success' 
        ? 'border-green-500 bg-green-900/50' 
        : (type === 'error' ? 'border-red-500 bg-red-900/50' : 'border-blue-500 bg-blue-900/50');
    
    const iconName = type === 'success' ? 'check-circle' : (type === 'error' ? 'alert-circle' : 'info');
    
    notification.className = `fixed top-4 right-4 p-4 rounded-lg glass-morphism z-50 animate-fade-in-down border-l-4 ${colorClass} shadow-xl backdrop-blur-md`;
    notification.innerHTML = `
        <div class="flex items-center space-x-3 text-white">
            <i data-lucide="${iconName}" class="w-5 h-5"></i>
            <span class="font-medium">${message}</span>
        </div>
    `;
    
    document.body.appendChild(notification);
    lucide.createIcons();
    
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateY(-20px)';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add animation style dynamic
const style = document.createElement('style');
style.innerHTML = `
    @keyframes fade-in-down {
        0% { opacity: 0; transform: translateY(-10px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    .animate-fade-in-down {
        animation: fade-in-down 0.3s ease-out forwards;
    }
`;
document.head.appendChild(style);


const API_BASE = '/api';

// On Load
document.addEventListener('DOMContentLoaded', async () => {
    await checkAccess();
});

async function checkAccess() {
    try {
        const response = await fetch(`${API_BASE}/user/role`);
        const data = await response.json();
        
        if (data.role === 'Omega') {
            document.getElementById('authorized-msg').classList.remove('hidden');
            setTimeout(() => {
                document.getElementById('security-gate').classList.add('hidden');
                document.getElementById('omega-interface').classList.remove('hidden');
                document.getElementById('omega-interface').classList.remove('opacity-0');
                loadPackStatus();
                // Auto refresh
                setInterval(loadPackStatus, 5000);
            }, 1000);
        } else {
            document.getElementById('unauthorized-msg').classList.remove('hidden');
        }
    } catch (e) {
        console.error("Access Check Failed", e);
        document.getElementById('unauthorized-msg').classList.remove('hidden');
    }
}

async function loadPackStatus() {
    try {
        const response = await fetch(`${API_BASE}/pack/status`);
        const pack = await response.json();
        const tbody = document.getElementById('peer-list');
        tbody.innerHTML = '';

        // Flatten members map to array
        const members = Object.entries(pack.members).map(([id, info]) => ({id, ...info}));
        
        members.forEach(m => {
            const row = document.createElement('tr');
            row.className = 'border-b border-yellow-500/10 hover:bg-white/5 transition';
            
            // Allow Omega to change anyone except themselves (or maybe even themselves for testing)
            const roleSelect = `
                <select onchange="updateRole('${m.id}', this.value)" class="bg-black border border-yellow-500/30 text-yellow-500 text-sm p-1">
                    <option value="Stray" ${m.rank === 'Stray' ? 'selected' : ''}>Stray</option>
                    <option value="Scout" ${m.rank === 'Scout' ? 'selected' : ''}>Scout</option>
                    <option value="Hunter" ${m.rank === 'Hunter' ? 'selected' : ''}>Hunter</option>
                    <option value="Beta" ${m.rank === 'Beta' ? 'selected' : ''}>Beta</option>
                    <option value="Alpha" ${m.rank === 'Alpha' ? 'selected' : ''}>Alpha</option>
                </select>
            `;

            row.innerHTML = `
                <td class="p-3 font-mono text-sm text-gray-400">${m.id}</td>
                <td class="p-3">${roleSelect}</td>
                <td class="p-3 text-yellow-500/80 font-mono">${m.prestige || 0}</td>
                <td class="p-3">
                    <button onclick="kickPeer('${m.id}')" class="text-red-500 hover:text-red-400 font-bold text-xs border border-red-500/30 px-2 py-1">KICK</button>
                    <button onclick="changePrestige('${m.id}', 100)" class="text-green-500 hover:text-green-400 font-bold text-xs border border-green-500/30 px-2 py-1 ml-2">+REP</button>
                    <button onclick="changePrestige('${m.id}', -100)" class="text-red-500 hover:text-red-400 font-bold text-xs border border-red-500/30 px-2 py-1 ml-2">-REP</button>
                </td>
            `;
            tbody.appendChild(row);
        });

    } catch (e) {
        console.error("Failed to load pack status", e);
    }
}

async function updateRole(peerId, newRole) {
    if(!confirm(`FORCE RANK CHANGE: ${peerId} -> ${newRole}?`)) return;

    try {
        await fetch(`${API_BASE}/omega/force_rank`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: peerId, role: newRole })
        });
        loadPackStatus();
    } catch (e) {
        alert("Action Failed");
    }
}

async function changePrestige(peerId, amount) {
    try {
        await fetch(`${API_BASE}/omega/force_prestige`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: peerId, change: amount })
        });
        loadPackStatus(); // Refresh immediately
    } catch (e) {
        console.error(e);
    }
}

async function forceConsensus() {
     if(!confirm("FORCE CONSENSUS? This will override all active voting.")) return;
     // Placeholder for implementation
     alert("Consensus Forced (Simulated)");
}

async function triggerDecay() {
     if(!confirm("TRIGGER DECAY CYCLE? All node prestige will decrease.")) return;
     // Placeholder
      alert("Decay Cycle Initiated");
}

async function shutdownSwarm() {
    if(!confirm("⚠️ EMERGENCY SHUTDOWN? THIS WILL KILL THE NODE.")) return;
    await fetch(`${API_BASE}/shutdown`, { method: 'POST' });
}

async function purgeStrayNodes() {
    if(!confirm("PURGE ALL STRAYS?")) return;
    alert("Purge initiated...");
}

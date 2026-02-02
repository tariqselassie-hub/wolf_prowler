// Lock Prowler Simulation Engine
const terminal = document.getElementById('terminal-screen');
const progressBar = id('main-progress');
const progressPercent = id('progress-percent');
const startBtn = id('start-btn');
const keyDisplay = id('key-display');
const canvas = id('neural-net');
const ctx = canvas.getContext('2d');

function id(name) { return document.getElementById(name); }

// Matrix-like background effect
let particles = [];
function initCanvas() {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    for (let i = 0; i < 50; i++) {
        particles.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            vx: (Math.random() - 0.5) * 1.5,
            vy: (Math.random() - 0.5) * 1.5,
            size: Math.random() * 2
        });
    }
}

function drawCanvas() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(0, 242, 255, 0.5)';
    ctx.strokeStyle = 'rgba(0, 242, 255, 0.1)';
    
    particles.forEach((p, i) => {
        p.x += p.vx;
        p.y += p.vy;
        
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
        
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
        
        for (let j = i + 1; j < particles.length; j++) {
            let p2 = particles[j];
            let dist = Math.sqrt((p.x - p2.x)**2 + (p.y - p2.y)**2);
            if (dist < 80) {
                ctx.beginPath();
                ctx.moveTo(p.x, p.y);
                ctx.lineTo(p2.x, p2.y);
                ctx.stroke();
            }
        }
    });
    requestAnimationFrame(drawCanvas);
}

// Log simulation
const logs = [
    "ANALYZING_FVE_HEADER...",
    "DETECTED_METADATA_VERSION: 1.0",
    "SEARCHING_FOR_KEY_PROTECTORS...",
    "FOUND_DRA_PROTECTOR: {LP-RSA-882}",
    "INITIATING_HEURISTIC_ANALYSIS...",
    "RECONSTRUCTING_POLYNOMIAL_H...",
    "ATTEMPTING_SUBKEY_RECOVERY...",
    "SUCCESS: AUTHENTICATION_SUBKEY_RECOVERED",
    "DECRYPTING_VMK_FRAGMENTS...",
    "BRUTEFORCING_WEAK_RSA_PARAMETERS...",
    "PRIME_FACTORIZATION_COMPLETE",
    "REASSEMBLING_VERY_SECURE_RANDOM_KEY..."
];

async function addLog(text, delay = 1000) {
    return new Promise(resolve => {
        setTimeout(() => {
            const p = document.createElement('p');
            p.textContent = `> ${text}`;
            terminal.appendChild(p);
            terminal.scrollTop = terminal.scrollHeight;
            resolve();
        }, delay);
    });
}

const secureRandomKeyParts = [
    "LP8A", "F92B", "C1D0", "E477", 
    "A932", "BE55", "FF01", "88CC",
    "22A1", "33B4", "99DD", "EE22"
];

function generateSecureKey() {
    return secureRandomKeyParts.sort(() => Math.random() - 0.5).join("-");
}

async function startRecovery() {
    startBtn.disabled = true;
    startBtn.textContent = "PROCESSING...";
    
    let currentLog = 0;
    for (let i = 0; i <= 100; i += 2) {
        progressBar.style.width = `${i}%`;
        progressPercent.textContent = `${i}%`;
        
        if (i % 8 === 0 && currentLog < logs.length) {
            await addLog(logs[currentLog], 200);
            currentLog++;
        }
        
        // Random secure bits flicker
        if (i > 80) {
            keyDisplay.textContent = Math.random().toString(16).substr(2, 24).toUpperCase();
        }
        
        await new Promise(r => setTimeout(r, 80));
    }
    
    const finalKey = generateSecureKey();
    keyDisplay.innerHTML = `<span class="success-text">${finalKey}</span>`;
    await addLog("SYSTEM_RECOVERY_COMPLETE. KEY_SECURED.", 500);
    
    startBtn.textContent = "SYSTEM_RESTORED";
    startBtn.style.color = "#00ff88";
    startBtn.style.borderColor = "#00ff88";
}

initCanvas();
drawCanvas();

startBtn.addEventListener('click', startRecovery);

// Auto-adjust canvas
window.addEventListener('resize', () => {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
});

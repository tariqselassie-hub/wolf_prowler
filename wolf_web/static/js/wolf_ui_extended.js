// wolf_ui_extended.js - Shared UI utilities for Wolf Prowler Dashboard
// Supersedes wolf_ui.js with additional features

// --- API Fetch Wrapper ---
async function apiFetch(endpoint, options = {}) {
  const defaultHeaders = {
    'Content-Type': 'application/json',
  };
  const fetchOptions = {
    headers: { ...defaultHeaders, ...(options.headers || {}) },
    ...options,
  };
  const response = await fetch(endpoint, fetchOptions);
  if (!response.ok) {
    const err = await response.json().catch(() => ({ message: 'Unknown error' }));
    throw err;
  }
  // If no content (204) return null
  if (response.status === 204) return null;
  return response.json();
}

// --- Toast Notifications ---
function showToast(message, type = 'info') {
    // Remove existing toasts to prevent stacking overload
    const existingNotifications = document.querySelectorAll('.wolf-toast');
    existingNotifications.forEach(n => n.remove());

    const notification = document.createElement('div');
    // Using Wolf Theme colors by default, but keeping flexibility
    const colors = {
        'success': 'border-green-500 text-green-400 bg-black/90',
        'error': 'border-red-500 text-red-400 bg-black/90',
        'info': 'border-blue-500 text-blue-400 bg-black/90',
        'warning': 'border-yellow-500 text-yellow-400 bg-black/90'
    };

    const icons = {
        'success': 'check-circle',
        'error': 'alert-circle',
        'info': 'info',
        'warning': 'alert-triangle'
    };

    const colorClass = colors[type] || colors['info'];
    const iconName = icons[type] || icons['info'];

    notification.className = `wolf-toast fixed top-20 right-8 p-4 rounded-lg backdrop-blur-md border border-l-4 flex items-center space-x-3 shadow-lg z-50 animate-bounce ${colorClass}`;
    notification.style.animation = 'slideIn 0.3s ease-out forwards';

    // Add slide-in animation style if not present
    if (!document.getElementById('wolf-toast-style')) {
        const style = document.createElement('style');
        style.id = 'wolf-toast-style';
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);
    }

    notification.innerHTML = `
        <i data-lucide="${iconName}" class="w-5 h-5"></i>
        <span class="text-white font-medium">${message}</span>
    `;

    document.body.appendChild(notification);

    if (window.lucide) {
        lucide.createIcons();
    }

    setTimeout(() => {
        notification.style.transition = 'opacity 0.3s ease-out, transform 0.3s ease-out';
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// --- Sidebar Logic ---
function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebarStateKey = 'wolf_prowler_sidebar_collapsed';

    if (!sidebar) return; // Not all pages have a sidebar element with this ID

    // Restore state
    if (localStorage.getItem(sidebarStateKey) === 'true') {
        sidebar.classList.add('collapsed');
        if (mainContent) mainContent.classList.add('expanded');
    }

    if (sidebarToggle) {
        // Clone to remove old event listeners if re-initializing
        const newToggle = sidebarToggle.cloneNode(true);
        sidebarToggle.parentNode.replaceChild(newToggle, sidebarToggle);

        newToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            if (mainContent) mainContent.classList.toggle('expanded');
            localStorage.setItem(sidebarStateKey, sidebar.classList.contains('collapsed'));
            window.dispatchEvent(new Event('sidebar-toggle'));
        });

        if (!newToggle.getAttribute('aria-label')) {
            newToggle.setAttribute('aria-label', 'Toggle Sidebar');
        }
    }
}

// --- Icon Initialization ---
function initIcons() {
  if (window.lucide) {
    lucide.createIcons();
  }
}

// --- WebSocket Helper ---
let ws = null;
function initWebSocket(url, onMessage) {
  if (ws) ws.close();
  ws = new WebSocket(url);
  ws.onopen = () => console.log('WebSocket connected');
  ws.onmessage = (ev) => {
    try {
      const data = JSON.parse(ev.data);
      onMessage(data);
    } catch (e) {
      console.error('Invalid WS message', e);
    }
  };
  ws.onclose = () => console.log('WebSocket closed');
  ws.onerror = (err) => console.error('WebSocket error', err);
}

// Export utilities globally (Backward Compatibility + Namespace)
window.WolfUI = {
  apiFetch,
  showToast,
  initIcons,
  initWebSocket,
  initSidebar
};

// Global shorthands
window.apiFetch = apiFetch;
window.showToast = showToast;
window.initIcons = initIcons;
window.initSidebar = initSidebar;
window.initWebSocket = initWebSocket;

// Auto-initialize
document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initIcons();
});

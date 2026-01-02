/**
 * Wolf Prowler - Shared UI Logic
 * Handles Toasts, Sidebar Toggling, and Common Utilities
 */

// --- Toast Notifications ---
function showToast(message, type = 'info') {
    // Remove existing toasts to prevent stacking overload
    const existingNotifications = document.querySelectorAll('.wolf-toast');
    existingNotifications.forEach(n => n.remove());

    const notification = document.createElement('div');
    notification.className = `wolf-toast fixed top-20 right-8 p-4 rounded-lg glass-morphism z-50 animate-bounce border-l-4 flex items-center space-x-3 shadow-lg`;
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

    const colors = {
        'success': 'border-green-500 text-green-400',
        'error': 'border-red-500 text-red-400',
        'info': 'border-blue-500 text-blue-400',
        'warning': 'border-yellow-500 text-yellow-400'
    };

    const icons = {
        'success': 'check-circle',
        'error': 'alert-circle',
        'info': 'info',
        'warning': 'alert-triangle'
    };

    const colorClass = colors[type] || colors['info'];
    const iconName = icons[type] || icons['info'];

    notification.classList.add(colorClass.split(' ')[0]); // Add border color

    notification.innerHTML = `
        <i data-lucide="${iconName}" class="w-5 h-5 ${colorClass.split(' ')[1]}"></i>
        <span class="text-white font-medium">${message}</span>
    `;

    document.body.appendChild(notification);

    // Initialize icons for this new element
    if (window.lucide) {
        lucide.createIcons();
    }

    setTimeout(() => {
        notification.style.transition = 'opacity 0.3s ease-out, transform 0.3s ease-out';
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => notification.remove(), 300);
    }, 5000); // 5 seconds display
}

// --- Sidebar Logic ---
function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebarStateKey = 'wolf_prowler_sidebar_collapsed';

    if (!sidebar || !mainContent) return;

    // Restore state
    if (localStorage.getItem(sidebarStateKey) === 'true') {
        sidebar.classList.add('collapsed');
        mainContent.classList.add('expanded');
    }

    if (sidebarToggle) {
        // Clone to remove old event listeners if re-initializing
        const newToggle = sidebarToggle.cloneNode(true);
        sidebarToggle.parentNode.replaceChild(newToggle, sidebarToggle);

        newToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            mainContent.classList.toggle('expanded');
            localStorage.setItem(sidebarStateKey, sidebar.classList.contains('collapsed'));

            // Dispatch custom event for pages that need to react (e.g. D3 resize)
            window.dispatchEvent(new Event('sidebar-toggle'));
        });

        // Add aria-label if missing
        if (!newToggle.getAttribute('aria-label')) {
            newToggle.setAttribute('aria-label', 'Toggle Sidebar');
        }
    }
}

// Auto-initialize on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    if (window.lucide) {
        lucide.createIcons();
    }
});

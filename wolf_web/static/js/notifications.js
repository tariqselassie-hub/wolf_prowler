/**
 * Wolf Prowler Notification System
 * Real-time notifications for events and updates
 */
class NotificationSystem {
    constructor(options = {}) {
        this.maxNotifications = options.maxNotifications || 5;
        this.defaultDuration = options.defaultDuration || 5000;
        this.position = options.position || 'top-right';
        this.container = null;
        this.notifications = [];
        
        this.init();
    }

    init() {
        this.createContainer();
        this.setupStyles();
    }

    createContainer() {
        this.container = document.createElement('div');
        this.container.id = 'wolf-notification-container';
        this.container.className = `wolf-notification-container wolf-notification-${this.position}`;
        document.body.appendChild(this.container);
    }

    setupStyles() {
        const styles = `
            .wolf-notification-container {
                position: fixed;
                z-index: 9999;
                pointer-events: none;
                display: flex;
                flex-direction: column;
                gap: 0.5rem;
                max-width: 400px;
            }
            
            .wolf-notification-top-right {
                top: 1rem;
                right: 1rem;
            }
            
            .wolf-notification-top-left {
                top: 1rem;
                left: 1rem;
            }
            
            .wolf-notification-bottom-right {
                bottom: 1rem;
                right: 1rem;
            }
            
            .wolf-notification-bottom-left {
                bottom: 1rem;
                left: 1rem;
            }
            
            .wolf-notification {
                pointer-events: auto;
                background: rgba(15, 23, 42, 0.95);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 0.5rem;
                padding: 1rem;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
                transform: translateX(100%);
                opacity: 0;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                max-width: 100%;
            }
            
            .wolf-notification.show {
                transform: translateX(0);
                opacity: 1;
            }
            
            .wolf-notification.hide {
                transform: translateX(100%);
                opacity: 0;
            }
            
            .wolf-notification-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 0.5rem;
            }
            
            .wolf-notification-title {
                font-weight: 600;
                font-size: 0.875rem;
                margin: 0;
            }
            
            .wolf-notification-close {
                background: none;
                border: none;
                color: rgba(255, 255, 255, 0.6);
                cursor: pointer;
                padding: 0.25rem;
                border-radius: 0.25rem;
                transition: all 0.2s;
            }
            
            .wolf-notification-close:hover {
                background: rgba(255, 255, 255, 0.1);
                color: rgba(255, 255, 255, 0.8);
            }
            
            .wolf-notification-message {
                color: rgba(255, 255, 255, 0.8);
                font-size: 0.875rem;
                line-height: 1.4;
                margin: 0;
            }
            
            .wolf-notification-icon {
                width: 1.25rem;
                height: 1.25rem;
                margin-right: 0.5rem;
                flex-shrink: 0;
            }
            
            .wolf-notification-title-wrapper {
                display: flex;
                align-items: center;
                flex: 1;
            }
            
            /* Type-specific styles */
            .wolf-notification.info {
                border-left: 4px solid #3b82f6;
            }
            
            .wolf-notification.info .wolf-notification-icon {
                color: #3b82f6;
            }
            
            .wolf-notification.success {
                border-left: 4px solid #10b981;
            }
            
            .wolf-notification.success .wolf-notification-icon {
                color: #10b981;
            }
            
            .wolf-notification.warning {
                border-left: 4px solid #f59e0b;
            }
            
            .wolf-notification.warning .wolf-notification-icon {
                color: #f59e0b;
            }
            
            .wolf-notification.error {
                border-left: 4px solid #ef4444;
            }
            
            .wolf-notification.error .wolf-notification-icon {
                color: #ef4444;
            }
            
            .wolf-notification.security {
                border-left: 4px solid #8b5cf6;
            }
            
            .wolf-notification.security .wolf-notification-icon {
                color: #8b5cf6;
            }
            
            /* Progress bar */
            .wolf-notification-progress {
                position: absolute;
                bottom: 0;
                left: 0;
                height: 2px;
                background: linear-gradient(90deg, #8b5cf6, #3b82f6);
                transition: width linear;
            }
            
            /* Mobile responsive */
            @media (max-width: 640px) {
                .wolf-notification-container {
                    left: 0.5rem !important;
                    right: 0.5rem !important;
                    max-width: none;
                }
            }
        `;
        
        const styleSheet = document.createElement('style');
        styleSheet.textContent = styles;
        document.head.appendChild(styleSheet);
    }

    show(title, message, type = 'info', options = {}) {
        const notification = this.createNotification(title, message, type, options);
        this.addNotification(notification);
        return notification;
    }

    createNotification(title, message, type, options) {
        const notification = document.createElement('div');
        notification.className = `wolf-notification ${type}`;
        
        const iconMap = {
            info: 'info',
            success: 'check-circle',
            warning: 'alert-triangle',
            error: 'x-circle',
            security: 'shield'
        };
        
        const icon = iconMap[type] || 'info';
        
        notification.innerHTML = `
            <div class="wolf-notification-header">
                <div class="wolf-notification-title-wrapper">
                    <i data-lucide="${icon}" class="wolf-notification-icon"></i>
                    <h4 class="wolf-notification-title">${title}</h4>
                </div>
                <button class="wolf-notification-close" aria-label="Close notification">
                    <i data-lucide="x" class="w-4 h-4"></i>
                </button>
            </div>
            <p class="wolf-notification-message">${message}</p>
            ${options.duration !== 0 ? '<div class="wolf-notification-progress"></div>' : ''}
        `;
        
        // Initialize Lucide icons
        if (window.lucide) {
            window.lucide.createIcons();
        }
        
        const notificationObj = {
            element: notification,
            title,
            message,
            type,
            duration: options.duration !== undefined ? options.duration : this.defaultDuration,
            persistent: options.persistent || false,
            actions: options.actions || []
        };
        
        this.setupNotificationEvents(notificationObj);
        
        return notificationObj;
    }

    setupNotificationEvents(notificationObj) {
        const { element } = notificationObj;
        
        // Close button
        const closeBtn = element.querySelector('.wolf-notification-close');
        closeBtn.addEventListener('click', () => {
            this.removeNotification(notificationObj);
        });
        
        // Auto-hide
        if (notificationObj.duration > 0 && !notificationObj.persistent) {
            notificationObj.timeout = setTimeout(() => {
                this.removeNotification(notificationObj);
            }, notificationObj.duration);
            
            // Progress bar animation
            const progressBar = element.querySelector('.wolf-notification-progress');
            if (progressBar) {
                progressBar.style.width = '100%';
                progressBar.style.transitionDuration = `${notificationObj.duration}ms`;
                
                // Start animation after element is shown
                setTimeout(() => {
                    progressBar.style.width = '0%';
                }, 100);
            }
        }
        
        // Actions
        notificationObj.actions.forEach(action => {
            const button = document.createElement('button');
            button.className = 'wolf-notification-action';
            button.textContent = action.label;
            button.style.cssText = `
                background: ${action.primary ? 'linear-gradient(135deg, #8b5cf6, #3b82f6)' : 'rgba(255, 255, 255, 0.1)'};
                color: white;
                border: none;
                padding: 0.5rem 1rem;
                border-radius: 0.25rem;
                font-size: 0.75rem;
                cursor: pointer;
                margin-top: 0.5rem;
                margin-right: 0.5rem;
                transition: all 0.2s;
            `;
            
            button.addEventListener('click', () => {
                if (action.handler) {
                    action.handler();
                }
                this.removeNotification(notificationObj);
            });
            
            element.appendChild(button);
        });
    }

    addNotification(notificationObj) {
        // Remove oldest notifications if we exceed max
        while (this.notifications.length >= this.maxNotifications) {
            this.removeNotification(this.notifications[0]);
        }
        
        this.notifications.push(notificationObj);
        this.container.appendChild(notificationObj.element);
        
        // Trigger show animation
        requestAnimationFrame(() => {
            notificationObj.element.classList.add('show');
        });
    }

    removeNotification(notificationObj) {
        const index = this.notifications.indexOf(notificationObj);
        if (index > -1) {
            this.notifications.splice(index, 1);
        }
        
        // Clear timeout
        if (notificationObj.timeout) {
            clearTimeout(notificationObj.timeout);
        }
        
        // Trigger hide animation
        notificationObj.element.classList.add('hide');
        
        // Remove element after animation
        setTimeout(() => {
            if (notificationObj.element.parentNode) {
                notificationObj.element.parentNode.removeChild(notificationObj.element);
            }
        }, 300);
    }

    clear() {
        this.notifications.forEach(notification => {
            this.removeNotification(notification);
        });
    }

    // Convenience methods
    info(title, message, options = {}) {
        return this.show(title, message, 'info', options);
    }

    success(title, message, options = {}) {
        return this.show(title, message, 'success', options);
    }

    warning(title, message, options = {}) {
        return this.show(title, message, 'warning', options);
    }

    error(title, message, options = {}) {
        return this.show(title, message, 'error', options);
    }

    security(title, message, options = {}) {
        return this.show(title, message, 'security', options);
    }
}

// Initialize global notification system
window.notificationSystem = null;

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.notificationSystem = new NotificationSystem();
    
    // Make it globally available
    window.showNotification = (title, message, type, options) => {
        return window.notificationSystem.show(title, message, type, options);
    };
    
    // Export for module systems
    window.NotificationSystem = NotificationSystem;
});

if (typeof module !== 'undefined' && module.exports) {
    module.exports = NotificationSystem;
}

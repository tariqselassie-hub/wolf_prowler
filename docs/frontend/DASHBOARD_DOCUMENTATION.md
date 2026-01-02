# Wolf Prowler Dashboard Documentation

## 🎯 **Overview**

The Wolf Prowler Dashboard is a modern, real-time monitoring and control center for the P2P security network system. This documentation provides comprehensive information about the dashboard architecture, features, API integration, and development guidelines.

## 📋 **Table of Contents**

1. [Architecture](#architecture)
2. [Core Features](#core-features)
3. [API Integration](#api-integration)
4. [Security Implementation](#security-implementation)
5. [File Structure](#file-structure)
6. [Development Guidelines](#development-guidelines)
7. [Authentication System](#authentication-system)
8. [Real-time Data Flow](#real-time-data-flow)
9. [Component Library](#component-library)
10. [Troubleshooting](#troubleshooting)

---

## 🏗️ **Architecture**

### **Technology Stack**
- **Frontend**: HTML5, Tailwind CSS, Vanilla JavaScript
- **Icons**: Lucide Icon Library
- **Charts**: Chart.js
- **Backend**: Python HTTP Server with API endpoints
- **Security**: API Key Authentication, Rate Limiting, CORS

### **Design System**
- **Theme**: Dark mode with glass morphism effects
- **Colors**: Purple (#8b5cf6), Blue (#3b82f6), Green (#22c55e), Orange (#f97316)
- **Typography**: Inter font family, JetBrains Mono for code
- **Layout**: Sidebar navigation with main content area

### **Component Architecture**
```
Dashboard Components
├── Navigation System
│   ├── Sidebar Menu
│   ├── Header Actions
│   └── Breadcrumb Navigation
├── Data Display
│   ├── Metric Cards
│   ├── Charts & Graphs
│   ├── Activity Feeds
│   └── Status Indicators
├── Interactive Elements
│   ├── Forms & Inputs
│   ├── Modals & Overlays
│   ├── Tooltips & Popovers
│   └── Action Buttons
└── Real-time Updates
    ├── Auto-refresh System
    ├── WebSocket Connections
    └── Event Handlers
```

---

## 🌟 **Core Features**

### **1. Real-time System Monitoring**
- **CPU Usage**: Live percentage with visual progress bars
- **Memory Usage**: Dynamic memory allocation tracking
- **Network I/O**: Real-time data transfer metrics
- **Process Count**: Active system processes monitoring

### **2. Network Management**
- **Peer Discovery**: Active connection tracking
- **Node Status**: Online/offline status indicators
- **Network Health**: Overall network performance metrics
- **Latency Monitoring**: Connection response times

### **3. Security Operations**
- **Threat Detection**: Real-time security event monitoring
- **Firewall Status**: Windows firewall integration
- **Connection Tracking**: Active network connections
- **Security Scoring**: Dynamic security assessment

### **4. P2P Communication**
- **Peer Chat**: Real-time messaging system
- **File Sharing**: Secure file transfer capabilities
- **Network Discovery**: mDNS and network scanning
- **Trust Management**: Peer reputation system

### **5. Cryptographic Services**
- **Hash Generation**: Multiple algorithm support
- **Key Derivation**: PBKDF2, Argon2 integration
- **MAC Generation**: HMAC implementations
- **Encryption**: AES-256 operations

---

## 🔌 **API Integration**

### **Authentication**
```javascript
// API Key Authentication
const headers = {
    'X-API-Key': 'your-api-key-here',
    'Content-Type': 'application/json'
};

// Session Authentication
const sessionHeaders = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
};
```

### **Core API Endpoints**

#### **System Metrics**
```javascript
// GET /api/system/metrics
{
    "cpu_usage": 42.5,
    "memory_usage": 78.3,
    "network_sent_gb": 1.2,
    "network_recv_gb": 0.8,
    "process_count": 127,
    "timestamp": "2025-12-03T14:30:00Z"
}
```

#### **Network Status**
```javascript
// GET /api/network/status
{
    "active_nodes": 247,
    "connected_peers": 1847,
    "network_health": 98.7,
    "avg_latency": 23,
    "total_peers": 2100,
    "timestamp": "2025-12-03T14:30:00Z"
}
```

#### **Security Events**
```javascript
// GET /api/security/events
{
    "events": [
        {
            "type": "System Event",
            "message": "Recent security events retrieved",
            "severity": "info",
            "timestamp": "2025-12-03T14:30:00Z"
        }
    ],
    "total_events": 1,
    "timestamp": "2025-12-03T14:30:00Z"
}
```

#### **Peer Information**
```javascript
// GET /api/peers
{
    "peers": [
        {
            "id": "Node-STUDENT-PC",
            "address": "192.168.1.100:8080",
            "status": "online",
            "latency": 0,
            "connections": 15,
            "local": true,
            "hostname": "STUDENT-PC"
        }
    ],
    "total_peers": 1,
    "timestamp": "2025-12-03T14:30:00Z"
}
```

#### **NEW: AI Threat Intelligence** ✨
```javascript
// GET /api/threat/intelligence
{
    "ml_model_status": "active",
    "anomaly_score": 0.15,
    "threat_predictions": [
        {
            "type": "APT Simulation",
            "confidence": 0.85,
            "tactic": "Initial Access",
            "technique": "T1078 - Valid Accounts"
        }
    ],
    "ueba_alerts": [
        {
            "user": "admin",
            "behavior": "Unusual login pattern detected",
            "risk_score": 7.5
        }
    ],
    "mitre_coverage": {
        "tactics_detected": ["Initial Access", "Execution", "Persistence"],
        "techniques_covered": 12,
        "total_techniques": 14
    },
    "timestamp": "2025-12-03T14:30:00Z"
}
```

#### **NEW: CVE Intelligence Feed** ✨
```javascript
// GET /api/cve/feed
{
    "cves": [
        {
            "id": "CVE-2025-0001",
            "severity": "Critical",
            "cvss": 9.8,
            "description": "Remote code execution vulnerability in system service",
            "affected_systems": ["Windows", "Linux"],
            "published": "2025-12-03T14:30:00Z"
        }
    ],
    "total_critical": 1,
    "total_high": 1,
    "timestamp": "2025-12-03T14:30:00Z"
}
```

#### **NEW: Zero Trust Status** ✨
```javascript
// GET /api/zero/trust
{
    "network_segments": {
        "total": 8,
        "active": 6,
        "compliant": 5
    },
    "device_trust": {
        "total_devices": 24,
        "trusted_devices": 18,
        "high_risk_devices": 3,
        "medium_risk_devices": 3
    },
    "continuous_auth": {
        "biometric_confidence": 98.5,
        "behavioral_score": "High",
        "auth_risk_level": "Low",
        "active_sessions": 12
    },
    "policy_enforcement": {
        "total_policies": 15,
        "enforced_policies": 13,
        "violations": 2
    },
    "timestamp": "2025-12-03T14:30:00Z"
}
```

#### **NEW: SIEM Analytics** ✨
```javascript
// GET /api/siem/analytics
{
    "log_processing": {
        "logs_per_second": 1200,
        "total_events_today": 85000,
        "correlated_events": 47,
        "false_positive_rate": 2.1
    },
    "incident_response": {
        "active_incidents": 3,
        "critical_incidents": 1,
        "automated_responses": 27,
        "manual_responses": 5,
        "avg_response_time": "4.2 minutes"
    },
    "soar_automation": {
        "active_playbooks": 8,
        "executed_today": 42,
        "success_rate": 94.5,
        "avg_execution_time": "2.1 minutes"
    },
    "threat_hunting": {
        "active_hunts": 5,
        "threats_detected": 12,
        "investigations_open": 7,
        "resolved_threats": 28
    },
    "timestamp": "2025-12-03T14:30:00Z"
}
```

### **Error Handling**
```javascript
async function fetchWithAuth(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'X-API-Key': getApiKey(),
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}
```

---

## 🔐 **Security Implementation**

### **Rate Limiting**
- **Limit**: 60 requests per minute per IP
- **Enforcement**: Server-side tracking
- **Response**: HTTP 429 when exceeded

### **CORS Policy**
- **Allowed Origins**: `http://localhost:8080`, `http://127.0.0.1:8080`
- **Allowed Methods**: GET, POST, OPTIONS
- **Allowed Headers**: X-API-Key, Content-Type

### **API Key Management**
```python
# Server-side API key validation
API_KEY = os.environ.get('WOLF_PROWLER_API_KEY', 'dev-key-12345')

def check_api_key(self):
    api_key = self.headers.get('X-API-Key')
    return secrets.compare_digest(api_key, self.API_KEY)
```

### **Session Management**
- **Token Type**: JWT-like tokens
- **Expiration**: 1 hour
- **Storage**: LocalStorage
- **Auto-renewal**: On successful activity

---

## 📁 **File Structure**

```
static/
├── dashboard_modern.html      # Main dashboard (REPLACES dashboard.html)
├── auth.html                  # Authentication portal
├── p2p.html                   # P2P communication interface
├── network.html               # Network monitoring
├── security.html              # Security operations
├── crypto.html                # Cryptographic services
├── howl.html                 # Network discovery
├── packs.html                 # Pack activity (TO BE UPDATED)
├── monitoring.html            # System monitoring
├── logs.html                  # System logs
├── settings.html              # Configuration
├── index.html                 # Entry point (redirects to dashboard)
├── server.py                  # Backend server with security
├── startup_check.py           # Server validation script
└── api/                       # API documentation pages
    ├── index.html
    ├── cryptography/
    ├── network/
    └── security/
```

### **Deprecated Files**
```
├── dashboard.html            # ❌ OLD - TO BE REMOVED
├── dashboard.css              # ❌ OLD - TO BE REMOVED
└── dashboard.js               # ❌ OLD - TO BE REMOVED
```

---

## 🛠️ **Development Guidelines**

### **Code Standards**
1. **HTML**: Semantic HTML5 structure
2. **CSS**: Tailwind utility classes with custom styles
3. **JavaScript**: ES6+ features, async/await patterns
4. **API**: RESTful endpoints with JSON responses

### **Component Patterns**
```javascript
// Metric Card Component
function createMetricCard(title, value, unit, color, icon) {
    return `
        <div class="metric-card rounded-xl p-6">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-semibold">${title}</h3>
                <i data-lucide="${icon}" class="w-5 h-5 text-${color}-400"></i>
            </div>
            <div class="text-2xl font-bold text-${color}-400">
                ${value}${unit}
            </div>
        </div>
    `;
}
```

### **Data Loading Pattern**
```javascript
// Standard API data loading
async function loadDashboardData() {
    try {
        const [systemData, networkData, securityData] = await Promise.all([
            fetchWithAuth('/api/system/metrics'),
            fetchWithAuth('/api/network/status'),
            fetchWithAuth('/api/security/status')
        ]);
        
        updateUI(systemData, networkData, securityData);
    } catch (error) {
        showError('Failed to load dashboard data');
    }
}
```

### **Auto-refresh Implementation**
```javascript
// 30-second auto-refresh
setInterval(() => {
    loadDashboardData();
}, 30000);

// Manual refresh
function refreshDashboard() {
    loadDashboardData();
    showNotification('Dashboard refreshed');
}
```

---

## 🔑 **Authentication System**

### **Authentication Flow**
1. **User Access**: Visit `/auth.html` or automatic redirect
2. **Method Selection**: API Key or Session authentication
3. **Validation**: Server-side verification
4. **Token Generation**: JWT-like token creation
5. **Storage**: LocalStorage with expiration
6. **Auto-refresh**: Dashboard access with valid token

### **API Key Authentication**
```javascript
// Generate and store API key
const apiKey = generateSecureKey();
localStorage.setItem('wolf_prowler_api_key', apiKey);

// Use in requests
fetch('/api/system/metrics', {
    headers: { 'X-API-Key': apiKey }
});
```

### **Session Authentication**
```javascript
// Login flow
async function login(username, password) {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    
    const { token } = await response.json();
    localStorage.setItem('wolf_prowler_token', token);
}
```

---

## 📊 **Real-time Data Flow**

### **Data Update Cycle**
```
1. Dashboard Load
   ↓
2. Authentication Check
   ↓
3. Initial API Calls (parallel)
   ├── System Metrics
   ├── Network Status
   ├── Security Events
   └── Peer Information
   ↓
4. UI Updates
   ↓
5. Auto-refresh (30s interval)
   ↓
6. Repeat cycle
```

### **Error Recovery**
```javascript
// Retry mechanism with exponential backoff
async function fetchWithRetry(url, maxRetries = 3) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            return await fetchWithAuth(url);
        } catch (error) {
            if (i === maxRetries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        }
    }
}
```

---

## 🎨 **Component Library**

### **Metric Cards**
```html
<div class="metric-card rounded-xl p-6">
    <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold">Metric Title</h3>
        <i data-lucide="icon-name" class="w-5 h-5 text-color-400"></i>
    </div>
    <div class="space-y-4">
        <!-- Content here -->
    </div>
</div>
```

### **Status Indicators**
```html
<div class="flex items-center space-x-2">
    <div class="w-3 h-3 bg-green-500 rounded-full status-online"></div>
    <span class="text-sm">Status Text</span>
</div>
```

### **Activity Feed**
```html
<div class="space-y-3 max-h-80 overflow-y-auto">
    <div class="flex items-start space-x-3 p-2 hover:bg-gray-800/30 rounded">
        <div class="w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
        <div class="flex-1">
            <p class="text-sm">Activity message</p>
            <p class="text-xs text-gray-500">Timestamp</p>
        </div>
    </div>
</div>
```

---

## 🔧 **Troubleshooting**

### **Common Issues**

#### **API Authentication Errors**
```javascript
// Check API key validity
function validateApiKey() {
    const apiKey = localStorage.getItem('wolf_prowler_api_key');
    return apiKey && apiKey.length > 0;
}

// Redirect to auth if invalid
if (!validateApiKey()) {
    window.location.href = '/auth.html';
}
```

#### **CORS Issues**
- **Solution**: Ensure server allows correct origins
- **Check**: Browser developer tools network tab
- **Fix**: Update `ALLOWED_ORIGINS` in server.py

#### **Rate Limiting**
- **Symptom**: HTTP 429 responses
- **Solution**: Implement request throttling
- **Prevention**: Cache frequently accessed data

#### **Data Loading Failures**
```javascript
// Fallback data
const fallbackData = {
    cpu_usage: 0,
    memory_usage: 0,
    network_sent_gb: 0,
    network_recv_gb: 0
};

// Use fallback on error
try {
    const data = await fetchWithAuth('/api/system/metrics');
    updateUI(data);
} catch (error) {
    updateUI(fallbackData);
    showError('Using cached data');
}
```

### **Performance Optimization**
1. **Lazy Loading**: Load components on demand
2. **Caching**: Store API responses locally
3. **Debouncing**: Limit rapid API calls
4. **Compression**: Enable gzip on server

### **Debug Mode**
```javascript
// Enable debug logging
const DEBUG = true;

function debugLog(message, data) {
    if (DEBUG) {
        console.log(`[DEBUG] ${message}`, data);
    }
}
```

---

## 🚀 **Future Enhancements**

### **Planned Features**
1. **WebSocket Integration**: Real-time push updates
2. **Advanced Analytics**: Historical data visualization
3. **User Roles**: Permission-based access control
4. **Mobile Responsive**: Touch-optimized interface
5. **Dark/Light Themes**: User preference themes
6. **Export Features**: Data export capabilities
7. **Alert System**: Custom notification rules
8. **Multi-language**: Internationalization support

### **Technical Improvements**
1. **TypeScript Migration**: Type safety
2. **Component Framework**: React/Vue integration
3. **State Management**: Redux/Zustand
4. **Testing Suite**: Unit and integration tests
5. **CI/CD Pipeline**: Automated deployment
6. **Performance Monitoring**: Real-time metrics

---

## 📞 **Support & Contributing**

### **Getting Help**
- **Documentation**: This file and inline code comments
- **Issues**: GitHub issue tracker
- **Community**: Development Discord/Slack

### **Contributing Guidelines**
1. **Code Style**: Follow existing patterns
2. **Testing**: Add tests for new features
3. **Documentation**: Update this file
4. **Review**: Submit pull requests

### **Version History**
- **v2.0**: Current modern dashboard
- **v1.0**: Legacy dashboard (deprecated)

---

**Last Updated**: December 3, 2025  
**Version**: 2.0.0  
**Maintainer**: Wolf Prowler Development Team

-- Wolf Prowler Database Schema
-- PostgreSQL 15+

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- NETWORK & PEERS
-- ============================================================================

CREATE TABLE peers (
    peer_id TEXT PRIMARY KEY,
    service_type TEXT NOT NULL,
    system_type TEXT NOT NULL,
    version TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    trust_score REAL DEFAULT 0.5 CHECK (trust_score >= 0.0 AND trust_score <= 1.0),
    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    protocol_version TEXT,
    agent_version TEXT,
    capabilities JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE peer_metrics (
    id BIGSERIAL PRIMARY KEY,
    peer_id TEXT NOT NULL REFERENCES peers(peer_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    latency_ms BIGINT,
    messages_sent BIGINT DEFAULT 0,
    messages_received BIGINT DEFAULT 0,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    requests_sent BIGINT DEFAULT 0,
    requests_received BIGINT DEFAULT 0,
    requests_success BIGINT DEFAULT 0,
    requests_failed BIGINT DEFAULT 0,
    health_score REAL CHECK (health_score >= 0.0 AND health_score <= 1.0),
    uptime_ms BIGINT DEFAULT 0
);

CREATE TABLE peer_connections (
    id BIGSERIAL PRIMARY KEY,
    peer_id TEXT NOT NULL REFERENCES peers(peer_id) ON DELETE CASCADE,
    connected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMPTZ,
    disconnect_reason TEXT,
    duration_ms BIGINT,
    bytes_transferred BIGINT DEFAULT 0
);

-- ============================================================================
-- SECURITY
-- ============================================================================

CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    source TEXT,
    peer_id TEXT REFERENCES peers(peer_id) ON DELETE SET NULL,
    description TEXT NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    resolved_by TEXT
);

CREATE TABLE security_alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_id UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'acknowledged', 'resolved', 'suppressed')),
    title TEXT NOT NULL,
    message TEXT,
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    escalation_level INTEGER DEFAULT 0,
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    resolved_by TEXT,
    resolved_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE threat_intelligence (
    id BIGSERIAL PRIMARY KEY,
    threat_id UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    indicators JSONB NOT NULL,
    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    source TEXT,
    confidence REAL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- ============================================================================
-- AUDIT & COMPLIANCE
-- ============================================================================

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    actor TEXT,
    resource TEXT,
    resource_type TEXT,
    result TEXT NOT NULL CHECK (result IN ('success', 'failure', 'partial')),
    details JSONB DEFAULT '{}'::jsonb,
    ip_address INET,
    user_agent TEXT
);

CREATE TABLE compliance_checks (
    id BIGSERIAL PRIMARY KEY,
    check_id UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    framework TEXT NOT NULL,
    control_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'warning', 'not_applicable')),
    details JSONB DEFAULT '{}'::jsonb
);

-- ============================================================================
-- CONFIGURATION
-- ============================================================================

CREATE TABLE config (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT
);

-- Key-Value Store for Runtime Config (Alternative access)
CREATE TABLE IF NOT EXISTS kv_store (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT
);

CREATE TABLE security_policies (
    id BIGSERIAL PRIMARY KEY,
    policy_id UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    name TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    rules JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- WOLF PACK
-- ============================================================================

CREATE TABLE pack_members (
    peer_id TEXT PRIMARY KEY REFERENCES peers(peer_id) ON DELETE CASCADE,
    rank TEXT NOT NULL CHECK (rank IN ('alpha', 'beta', 'delta', 'omega', 'scout', 'hunter', 'guardian')),
    pack_name TEXT NOT NULL,
    joined_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    contributions JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE pack_hierarchy (
    id BIGSERIAL PRIMARY KEY,
    pack_name TEXT NOT NULL,
    alpha_peer_id TEXT REFERENCES peers(peer_id) ON DELETE SET NULL,
    established_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    member_count INTEGER DEFAULT 0,
    territory JSONB DEFAULT '{}'::jsonb
);

-- ============================================================================
-- LOGS & METRICS
-- ============================================================================

CREATE TABLE system_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    level TEXT NOT NULL CHECK (level IN ('trace', 'debug', 'info', 'warn', 'error')),
    message TEXT NOT NULL,
    source TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE network_metrics (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    active_connections INTEGER DEFAULT 0,
    total_messages_sent BIGINT DEFAULT 0,
    total_messages_received BIGINT DEFAULT 0,
    total_bytes_sent BIGINT DEFAULT 0,
    total_bytes_received BIGINT DEFAULT 0,
    connection_failures BIGINT DEFAULT 0,
    average_latency_ms REAL
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Peers
CREATE INDEX idx_peers_status ON peers(status);
CREATE INDEX idx_peers_last_seen ON peers(last_seen DESC);
CREATE INDEX idx_peers_trust_score ON peers(trust_score DESC);
CREATE INDEX idx_peers_service_type ON peers(service_type);

-- Peer Metrics
CREATE INDEX idx_peer_metrics_peer_id ON peer_metrics(peer_id);
CREATE INDEX idx_peer_metrics_timestamp ON peer_metrics(timestamp DESC);
CREATE INDEX idx_peer_metrics_peer_time ON peer_metrics(peer_id, timestamp DESC);

-- Security Events
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_peer_id ON security_events(peer_id);
CREATE INDEX idx_security_events_resolved ON security_events(resolved);

-- Security Alerts
CREATE INDEX idx_security_alerts_timestamp ON security_alerts(timestamp DESC);
CREATE INDEX idx_security_alerts_status ON security_alerts(status);
CREATE INDEX idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX idx_security_alerts_category ON security_alerts(category);

-- Threat Intelligence
CREATE INDEX idx_threat_intel_active ON threat_intelligence(active);
CREATE INDEX idx_threat_intel_severity ON threat_intelligence(severity);
CREATE INDEX idx_threat_intel_type ON threat_intelligence(threat_type);

-- Audit Logs
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor);
CREATE INDEX idx_audit_logs_result ON audit_logs(result);

-- System Logs
CREATE INDEX idx_system_logs_timestamp ON system_logs(timestamp DESC);
CREATE INDEX idx_system_logs_level ON system_logs(level);
CREATE INDEX idx_system_logs_source ON system_logs(source);

-- Network Metrics
CREATE INDEX idx_network_metrics_timestamp ON network_metrics(timestamp DESC);

-- ============================================================================
-- TRIGGERS FOR AUTO-UPDATE
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_peers_updated_at BEFORE UPDATE ON peers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_config_updated_at BEFORE UPDATE ON config
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_policies_updated_at BEFORE UPDATE ON security_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active peers with recent metrics
CREATE VIEW active_peers_with_metrics AS
SELECT 
    p.*,
    pm.latency_ms,
    pm.health_score,
    pm.messages_sent,
    pm.messages_received
FROM peers p
LEFT JOIN LATERAL (
    SELECT * FROM peer_metrics
    WHERE peer_id = p.peer_id
    ORDER BY timestamp DESC
    LIMIT 1
) pm ON true
WHERE p.status = 'online';

-- Recent security alerts
CREATE VIEW recent_security_alerts AS
SELECT *
FROM security_alerts
WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours'
ORDER BY timestamp DESC;

-- Pack overview
CREATE VIEW pack_overview AS
SELECT 
    pm.pack_name,
    COUNT(*) as member_count,
    COUNT(*) FILTER (WHERE pm.rank = 'alpha') as alpha_count,
    COUNT(*) FILTER (WHERE pm.rank = 'beta') as beta_count,
    COUNT(*) FILTER (WHERE pm.rank = 'delta') as delta_count,
    COUNT(*) FILTER (WHERE pm.rank = 'omega') as omega_count,
    AVG(p.trust_score) as avg_trust_score
FROM pack_members pm
JOIN peers p ON pm.peer_id = p.peer_id
GROUP BY pm.pack_name;

-- ============================================================================
-- PARTITIONING FOR LARGE TABLES (Optional - for high volume)
-- ============================================================================

-- Partition system_logs by month (uncomment if needed)
-- CREATE TABLE system_logs_2025_01 PARTITION OF system_logs
--     FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert default configuration
INSERT INTO config (key, value, description) VALUES
    ('system.version', '"2.0.0"', 'Wolf Prowler version'),
    ('system.initialized_at', to_jsonb(CURRENT_TIMESTAMP), 'System initialization timestamp'),
    ('network.max_peers', '100', 'Maximum number of peer connections'),
    ('security.threat_threshold', '0.7', 'Threat detection threshold'),
    ('pack.default_rank', '"omega"', 'Default rank for new pack members')
ON CONFLICT (key) DO NOTHING;

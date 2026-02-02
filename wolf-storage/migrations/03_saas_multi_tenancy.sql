-- Migration: 03_saas_multi_tenancy.sql
-- Description: Adds organization isolation for SaaS multi-tenancy

-- 1. Create Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    org_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    org_key TEXT UNIQUE NOT NULL, -- The API key used by agents to identify themselves
    admin_email TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'disabled')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Add org_id to core tables
ALTER TABLE peers ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE peer_metrics ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE security_events ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE security_alerts ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE threat_intelligence ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE audit_logs ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE pack_members ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE pack_hierarchy ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE system_logs ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;
ALTER TABLE network_metrics ADD COLUMN org_id UUID REFERENCES organizations(org_id) ON DELETE CASCADE;

-- 3. Create indexes for multi-tenant isolation
CREATE INDEX idx_peers_org_id ON peers(org_id);
CREATE INDEX idx_peer_metrics_org_id ON peer_metrics(org_id);
CREATE INDEX idx_security_events_org_id ON security_events(org_id);
CREATE INDEX idx_security_alerts_org_id ON security_alerts(org_id);
CREATE INDEX idx_audit_logs_org_id ON audit_logs(org_id);
CREATE INDEX idx_system_logs_org_id ON system_logs(org_id);

-- 4. Initial Organization for testing
INSERT INTO organizations (name, org_key) VALUES ('Default Wolf Pack', 'dev-org-key-001');

-- Update existing records to the default organization (if any)
UPDATE peers SET org_id = (SELECT org_id FROM organizations WHERE org_key = 'dev-org-key-001') WHERE org_id IS NULL;
UPDATE security_events SET org_id = (SELECT org_id FROM organizations WHERE org_key = 'dev-org-key-001') WHERE org_id IS NULL;
UPDATE security_alerts SET org_id = (SELECT org_id FROM organizations WHERE org_key = 'dev-org-key-001') WHERE org_id IS NULL;

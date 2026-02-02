-- Migration: WolfSec Security Module Tables
-- Description: Tables required by wolfsec Clean Architecture repositories

-- Alerts (PostgresAlertRepository)
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    details JSONB NOT NULL,
    acknowledged_by TEXT,
    resolved_by TEXT
);

-- Users (PostgresAuthRepository)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    roles JSONB NOT NULL, -- Storing roles as a JSON array of strings
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Roles (PostgresAuthRepository)
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    permissions JSONB NOT NULL -- Storing permissions as a JSON array
);

-- Threats (ThreatRepository)
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    source_peer TEXT,
    target_asset TEXT,
    detected_at TIMESTAMPTZ NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    mitigation_steps JSONB,
    related_events JSONB,
    metadata JSONB
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at);
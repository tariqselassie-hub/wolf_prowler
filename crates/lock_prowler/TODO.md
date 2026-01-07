# Wolf Ecosystem Dashboard Integration Plan

## Current State Summary

The Lock Prowler ecosystem is a Rust-based secrets management and scanning platform with the following components:

- **lock_prowler**: Core library for vault, hunter (secret scanning), sharding, and storage
- **lock_prowler_dashboard**: Dioxus-based web dashboard for operations
- **wolf_db**: Database layer (external dependency)

## Remaining Integration Tasks

### Phase 1: Dashboard-to-WolfDb Wiring (Core Infrastructure)
- [x] Add WolfDbStorage dependency to lock_prowler_dashboard/Cargo.toml
- [x] Create dashboard connection module (dashboard_db.rs)
- [x] Implement DB initialization and unlock flow in dashboard
- [x] Add connection status indicator to dashboard UI

### Phase 2: Vault Integration with WolfDb
- [x] Add Vault::save_to_db() method
- [x] Add Vault::load_from_db() method
- [x] Add vault entry list view to dashboard
- [x] Add vault entry creation form to dashboard

### Phase 3: Hunter-to-WolfDb Reporting
- [x] Create Hunter::save_scan_result() method in hunter.rs
- [x] Add scan history table to wolf_db schema
- [x] Implement scan result storage with metadata
- [x] Add scan results dashboard view
- [x] Create scan filtering UI by secret type

### Phase 4: Shard Management Dashboard
- [x] Add ShardManager::save_shards_to_db() method
- [x] Add ShardManager::load_shards_from_db() method
- [x] Create shard visualization component
- [x] Add shard distribution status panel
- [x] Implement shard recovery workflow UI

### Phase 5: Unified Dashboard Operations
- [x] Create main dashboard navigation sidebar
- [x] Add unified status overview (DB connection, vault count, scan count, shards)
- [x] Implement activity log component
- [x] Add settings panel for DB path configuration
- [x] Create unified search across vault, scans, and shards

## Technical Notes

### Database Schema Requirements
The wolf_db integration requires:
- `forensics` table: Session and scan result storage
- `vault` table: Encrypted secret entries
- `shards` table: Key shard metadata and distribution

### Security Considerations
- All vault entries encrypted before storage
- Database unlock required before any operations
- Session-based key management

### Next Steps
1. Complete Phase 1 infrastructure
2. Wire vault operations to dashboard
3. Connect hunter reporting to database
4. Build shard management UI
5. Integrate all components into unified dashboard

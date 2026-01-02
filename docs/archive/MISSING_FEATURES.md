# Missing Features & Modules

This document lists the specific modules and features identified as missing or incomplete in the codebase, prioritized for implementation.

## 1. Wolfsec: Alert Notifications (High Priority)
The following notification channels are unimplemented placeholders in `wolfsec/src/alerts.rs`:
- [x] **Email Notifications**: `send_email_notification` (Line 676) - Implemented using `lettre`.
- [x] **Webhook Notifications**: `send_webhook_notification` (Line 688) - Implemented using `reqwest`.
- [x] **Slack Notifications**: `send_slack_notification` (Line 710) - Implemented using `reqwest`.
- [x] **Discord Notifications**: `send_discord_notification` (Line 738) - Implemented using `reqwest`.

## 2. Wolf Net: Metrics & Wiring (Medium Priority)
- [x] **Simple Metrics Logic**: `src/utils/metrics_simple.rs` - Implemented average calculations and integrated `sysinfo` for CPU/Memory metrics.
- [ ] **Dashboard Metrics**: `src/dashboard/api/v1/metrics.rs` needs to be wired to the real `SwarmManager` instead of returning placeholder data.

## 3. Wolf Pack: Enhanced Hierarchy (Low Priority)
- [ ] **Election Logic**: `wolfsec/src/wolf_pack/mod.rs` contains "primitive election logic" that should be enhanced for robust leader election.
- [ ] **Hierarchy Rules**: `wolfsec/src/wolf_pack/hierarchy.rs` contains basic structs but lacks deeper implementation of hierarchy enforcement rules found in legacy plans.

## 4. Wolf Net: Peer Status (Medium Priority)
- [ ] **PeerInfo Initialization**: `wolf_net/src/peer.rs` logic seems basic (verifying `PeerInfo::new` usage across the crate to ensuring it's fully utilized).

## 5. Security: Dashboard Endpoints
- [ ] **Real Data Connections**: Ensure all dashboard endpoints in `src/dashboard/api/v1/` are pulling data from the live `SecurityManager` and `WolfPack` instances, not just static or default structs.

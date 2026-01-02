# Remaining Functionality Gaps

This document tracks specific areas of the codebase that require implementation or updates.

## 🐺 Wolf Net (Networking)

### Peer Management (`wolf_net/src/peer.rs`)
- [ ] **PeerInfo Status**: `PeerInfo::new` currently uses `todo!()` for setting initial status. Needs proper initialization logic.
  - Location: `peer.rs:686`

### Network Behavior (`wolf_net/src/behavior.rs`)
- [ ] **Libp2p Update**: Behavior definitions need updating to libp2p v0.53.0 standards (referenced in file header TODO).
  - Location: `behavior.rs:2`

## 🛡️ Wolfsec (Security Monitoring)

### Alert Notifications (`wolfsec/src/security_advanced/alerts.rs`)
- [ ] **Email Notifications**: `send_email_notification` is unimplemented.
  - Location: `alerts.rs:676`
- [ ] **Webhook Notifications**: `send_webhook_notification` constructs payload but missing HTTP call.
  - Location: `alerts.rs:688`
- [ ] **Slack Notifications**: `send_slack_notification` constructs payload but missing webhook call.
  - Location: `alerts.rs:710`
- [ ] **Discord Notifications**: `send_discord_notification` constructs payload but missing webhook call.
  - Location: `alerts.rs:738`

## 🧩 Other Identified Gaps

- [ ] **Web Dashboard**: Verify if all endpoints in `src/dashboard` are fully connected to real services.
- [ ] **Legacy Code**: `legacy/` directory contains code that may need porting or deletion.

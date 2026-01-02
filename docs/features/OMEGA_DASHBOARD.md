# Omega Control Dashboard

**Status**: ✅ Implemented | **Access Level**: Omega Only

## Overview

The Omega Control Dashboard is a specialized administrative interface that provides system-wide dominance and control over the Wolf Prowler network. It is the highest level of access in the Wolf Pack hierarchy, allowing complete oversight and manipulation of all network participants.

## Access Control

- **URL**: `https://localhost:3030/omega_control.html`
- **Required Role**: `Omega` (Dev God Mode)
- **Authentication**: Verified via `/api/user/role` endpoint
- **Security Gate**: Displays "ACCESS DENIED" for non-Omega users

## Features

### 1. Pack Management

Real-time view of all peers in the Wolf Pack with:
- Peer ID
- Current Role (Stray, Scout, Hunter, Beta, Alpha, Omega)
- Prestige Score
- Interactive controls for each peer

### 2. Administrative Actions

#### Force Rank Changes
- **Endpoint**: `POST /api/omega/force_rank`
- **Function**: Change any peer's role instantly
- **Payload**: `{ target: "peer_id", role: "NewRole" }`
- **Effect**: Bypasses normal prestige-based evolution

#### Prestige Modification
- **Endpoint**: `POST /api/omega/force_prestige`
- **Function**: Add or subtract prestige points
- **Payload**: `{ target: "peer_id", change: ±100 }`
- **Effect**: Triggers automatic role evolution/devolution

### 3. System Overrides

Placeholder controls for future implementation:
- **Force Consensus**: Override active voting processes
- **Trigger Decay Cycle**: Manually initiate prestige decay
- **Broadcast Directive**: Send system-wide announcements

### 4. Danger Zone

Critical system controls:
- **Emergency Shutdown**: Immediately halt the node
- **Purge Stray Nodes**: Remove all untrusted peers

## Technical Implementation

### Frontend (`omega_control.html`)

```html
- Security gate with role verification
- Auto-refresh every 5 seconds
- Gold/Red color scheme (authority theme)
- Responsive grid layout
```

### Backend API

#### GET `/api/user/role`
Returns the authenticated user's role for access verification.

**Response**:
```json
{
  "role": "Omega"
}
```

#### POST `/api/omega/force_rank`
Forces a peer to a specific rank.

**Request**:
```json
{
  "target": "12D3KooW...",
  "role": "Alpha"
}
```

**Response**:
```json
{
  "success": true
}
```

#### POST `/api/omega/force_prestige`
Modifies a peer's prestige score.

**Request**:
```json
{
  "target": "12D3KooW...",
  "change": -100
}
```

**Response**:
```json
{
  "success": true
}
```

### SwarmManager Integration

The Omega commands are routed through the `SwarmManager` to the `HuntCoordinator`:

```rust
SwarmCommand::OmegaForceRank { target, role }
SwarmCommand::OmegaForcePrestige { target, change }
```

These commands directly modify the `WolfState` and trigger:
- Role updates via `CoordinatorMsg::ForceRank`
- Prestige changes via `add_prestige()` / `slash_prestige()`
- Automatic evolution/devolution checks

## Use Cases

1. **Emergency Response**: Quickly promote trusted peers during security incidents
2. **Testing**: Simulate different hierarchy configurations
3. **Moderation**: Demote or remove malicious actors
4. **Reward System**: Grant prestige to contributors
5. **System Maintenance**: Force consensus or trigger cleanup operations

## Security Considerations

- **Strict Role Check**: All endpoints verify `user.role == WolfRole::Omega`
- **Audit Trail**: All actions should be logged (future enhancement)
- **Rate Limiting**: Consider implementing to prevent abuse
- **Multi-Factor Auth**: Recommended for production deployments

## Future Enhancements

- [ ] Audit log for all Omega actions
- [ ] Batch operations (modify multiple peers at once)
- [ ] Scheduled actions (e.g., decay cycles)
- [ ] Role delegation (temporary Omega privileges)
- [ ] Visual analytics (prestige trends, role distribution)
- [ ] Export/Import pack configurations

## Related Documentation

- [Wolf Pack Hierarchy](../architecture/WOLF_PACK_STRATEGY.md)
- [Prestige System](./PRESTIGE_SYSTEM.md)
- [API Reference](../api/README.md)

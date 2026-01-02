# Prestige System

**Status**: ✅ Implemented | **Component**: `wolf_net`

## Overview

The Prestige System is a gamification mechanism that tracks peer contributions and determines their rank within the Wolf Pack hierarchy. It encourages active participation and rewards positive behavior while penalizing inactivity through automatic decay.

## How It Works

### Prestige Points

Each peer maintains a `prestige` score (u32) that represents their standing in the pack:

```rust
pub struct WolfState {
    pub role: WolfRole,
    pub prestige: u32,
    pub active_hunts: Vec<ActiveHunt>,
    pub territories: Vec<String>,
}
```

### Earning Prestige

Prestige is awarded for:
- **Successful Hunt Participation**: Detecting and verifying threats
- **Consensus Contributions**: Participating in decision-making
- **Territory Defense**: Protecting assigned network segments
- **Peer Assistance**: Helping other pack members

**API**:
```rust
wolf_state.add_prestige(amount: u32)
```

### Losing Prestige

Prestige can be reduced through:
- **Slashing**: Penalty for malicious behavior or false positives
- **Decay**: Automatic reduction over time (encourages activity)

**API**:
```rust
wolf_state.slash_prestige(amount: u32)  // Manual penalty
wolf_state.apply_decay()                // Automatic decay
```

## Prestige Decay

**Introduced**: v1.1 | **Frequency**: ~1 per minute

### Purpose
Prevents rank stagnation by gradually reducing prestige for inactive peers, ensuring that only active contributors maintain high ranks.

### Implementation

The `HuntCoordinator` applies decay probabilistically in its event loop:

```rust
// In handle_tick()
if rand::random::<f64>() < (1.0 / 60.0) {
    let mut state = wolf_state.write().await;
    state.apply_decay();
    if state.prestige > 0 {
        info!("📉 Prestige Decay Applied. Current: {}", state.prestige);
    }
}
```

### Decay Logic

```rust
pub fn apply_decay(&mut self) {
    if self.prestige > 0 {
        self.prestige -= 1;  // 1 point per decay event
        self.devolve();      // Check if rank should decrease
    }
}
```

### Configuration

Current settings:
- **Decay Amount**: 1 point per event
- **Decay Frequency**: ~1/60 chance per second (≈1 per minute)
- **Minimum**: Stops at 0 (no negative prestige)

## Rank Evolution

Prestige directly determines rank through threshold-based evolution:

### Thresholds

| Rank    | Minimum Prestige | Permissions                          |
|---------|------------------|--------------------------------------|
| Stray   | 0                | Listen only                          |
| Scout   | 50               | Initiate warnings                    |
| Hunter  | 200              | Participate in hunts                 |
| Beta    | 1000             | Authorize local hunts                |
| Alpha   | 5000             | Pack strategy & global bans          |
| Omega   | N/A              | Absolute authority (manually set)    |

### Evolution Logic

```rust
fn evolve(&mut self) {
    if self.role == WolfRole::Omega { return; }
    
    let new_role = match self.prestige {
        p if p > 5000 => WolfRole::Alpha,
        p if p > 1000 => WolfRole::Beta,
        p if p > 200  => WolfRole::Hunter,
        p if p > 50   => WolfRole::Scout,
        _             => WolfRole::Stray,
    };
    
    if new_role > self.role {
        self.role = new_role;  // Auto-promote
    }
}
```

### Devolution Logic

```rust
fn devolve(&mut self) {
    if self.role == WolfRole::Omega { return; }
    
    let correct_role = match self.prestige {
        p if p > 5000 => WolfRole::Alpha,
        p if p > 1000 => WolfRole::Beta,
        p if p > 200  => WolfRole::Hunter,
        p if p > 50   => WolfRole::Scout,
        _             => WolfRole::Stray,
    };
    
    if correct_role < self.role {
        self.role = correct_role;  // Auto-demote
    }
}
```

## Omega Override

The Omega role can bypass the prestige system entirely:

- **Force Rank**: Set any peer to any role
- **Force Prestige**: Add or remove prestige points
- **No Decay**: Omega role is immune to decay and devolution

See [Omega Dashboard](./OMEGA_DASHBOARD.md) for administrative controls.

## Monitoring

### Dashboard Integration

- **Pack Status**: View all peers with their prestige scores
- **Prestige Trends**: Track changes over time (future)
- **Decay Events**: Logged with emoji indicator 📉

### Logs

```
INFO  📉 Prestige Decay Applied. Current: 249
INFO  🎖️ Peer promoted: Hunter -> Beta (prestige: 1050)
WARN  ⬇️ Peer demoted: Beta -> Hunter (prestige: 999)
```

## Best Practices

1. **Active Participation**: Engage in hunts to maintain rank
2. **Consistent Contribution**: Regular activity prevents decay
3. **Quality Over Quantity**: Accurate threat detection earns more prestige
4. **Collaboration**: Help other pack members for bonus prestige

## Future Enhancements

- [ ] Configurable decay rates per rank
- [ ] Prestige multipliers for critical actions
- [ ] Reputation system (separate from prestige)
- [ ] Prestige leaderboard
- [ ] Historical prestige tracking
- [ ] Decay immunity periods (e.g., after major contributions)

## Related Documentation

- [Wolf Pack Hierarchy](../architecture/WOLF_PACK_STRATEGY.md)
- [Hunt Coordinator](../architecture/HUNT_COORDINATOR.md)
- [Omega Dashboard](./OMEGA_DASHBOARD.md)

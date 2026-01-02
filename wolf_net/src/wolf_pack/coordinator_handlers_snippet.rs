
async fn handle_hunt_request(
    &mut self,
    hunt_id: HuntId,
    source: PeerId,
    target_ip: String,
    min_role: WolfRole,
) {
    info!(
        "📜 HUNT REQUEST: {} requested hunt on {} (ID: {})",
        source, target_ip, hunt_id
    );
    // In a real implementation, we would verify the source's authority (Alpha/Beta)
    // For now, we accept it and initiate a hunt if not already active

    let mut state = self.state.write().await;
    if state.active_hunts.iter().any(|h| h.hunt_id == hunt_id) {
        info!("Hunt {} already active, ignoring request", hunt_id);
        return;
    }

    // Create the hunt
    let hunt = ActiveHunt {
        hunt_id: hunt_id.clone(),
        target_ip: target_ip.clone(),
        status: HuntStatus::Scent,
        participants: std::collections::HashSet::from([source.clone()]),
        start_time: std::time::SystemTime::now(),
        evidence: vec![format!("Requested by Authority {}", source)],
    };
    state.active_hunts.push(hunt);

    // Use timeout mechanism
    self.timeouts.insert(
        hunt_id.clone(),
        std::time::SystemTime::now() + std::time::Duration::from_secs(60),
    );

    info!("✅ Hunt {} initiated from request", hunt_id);
}

async fn handle_kill_order(
    &mut self,
    target_ip: String,
    authorizer: PeerId,
    reason: String,
    hunt_id: HuntId,
) {
    info!(
        "☠️ KILL ORDER RECEIVED: {} ordered neutralization of {} (Reason: {})",
        authorizer, target_ip, reason
    );

    // Execute Strike immediately
    self.execute_strike(&target_ip, &hunt_id).await;
}

async fn handle_territory_update(&mut self, region: String, owner: PeerId, status: String) {
    info!(
        "🗺️ TERRITORY UPDATE: {} claims {} (Status: {})",
        owner, region, status
    );

    let mut state = self.state.write().await;
    if !state.territories.contains(&region) {
        state.territories.push(region.clone());
        info!("Added new territory: {}", region);
    }
}

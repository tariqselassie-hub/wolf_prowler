// =========================================================================================
// HOWL COMMUNICATION API
// =========================================================================================

#[derive(Deserialize)]
pub struct SendHowlRequest {
    pub priority: String,     // "Info", "Warning", "Alert"
    pub payload_type: String, // "WarningHowl", "KillOrder", "TerritoryUpdate"

    // Payload Fields (Optional depending on type)
    pub target_ip: Option<String>,
    pub evidence: Option<String>,
    pub reason: Option<String>,
    pub region: Option<String>,
    pub status: Option<String>,
    pub hunt_id: Option<String>,
}

pub async fn api_howl_send(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<SendHowlRequest>,
) -> ApiResult<serde_json::Value> {
    let priority = match req.priority.as_str() {
        "Alert" => wolf_net::wolf_pack::howl::HowlPriority::Alert,
        "Warning" => wolf_net::wolf_pack::howl::HowlPriority::Warning,
        _ => wolf_net::wolf_pack::howl::HowlPriority::Info,
    };

    // Role Validation for High Priority
    if priority == wolf_net::wolf_pack::howl::HowlPriority::Alert && user.role < WolfRole::Alpha {
        return Err(ApiError::Forbidden(
            "Only Alpha can send Alert priority Howls".into(),
        ));
    }

    // Construct Payload
    let payload = match req.payload_type.as_str() {
        "WarningHowl" => wolf_net::wolf_pack::howl::HowlPayload::WarningHowl {
            target_ip: req
                .target_ip
                .ok_or(ApiError::BadRequest("Missing target_ip".into()))?,
            evidence: req.evidence.unwrap_or_default(),
        },
        "KillOrder" => {
            if user.role < WolfRole::Alpha {
                return Err(ApiError::Forbidden(
                    "Only Alpha can issue Kill Orders".into(),
                ));
            }
            wolf_net::wolf_pack::howl::HowlPayload::KillOrder {
                target_ip: req
                    .target_ip
                    .ok_or(ApiError::BadRequest("Missing target_ip".into()))?,
                reason: req.reason.unwrap_or_default(),
                hunt_id: req.hunt_id.unwrap_or_else(|| "manual".into()),
            }
        }
        "TerritoryUpdate" => wolf_net::wolf_pack::howl::HowlPayload::TerritoryUpdate {
            region_cidr: req
                .region
                .ok_or(ApiError::BadRequest("Missing region".into()))?,
            owner: state.swarm_manager.local_peer_id,
            status: req.status.unwrap_or("Patrolling".into()),
        },
        _ => {
            return Err(ApiError::BadRequest(
                "Unknown or unsupported payload type".into(),
            ))
        }
    };

    // Create Message
    let msg = wolf_net::wolf_pack::howl::HowlMessage::new(
        state.swarm_manager.local_peer_id,
        priority,
        payload,
    );

    // Send to Swarm
    let cmd = SwarmCommand::BroadcastHowl { message: msg };
    if let Err(e) = state.swarm_manager.command_sender().send(cmd).await {
        return Err(ApiError::Internal(format!(
            "Failed to broadcast Howl: {}",
            e
        )));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Howl broadcasted successfully"
    })))
}

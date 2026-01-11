//! Wolf Den Containers Module
//!
//! Container management with wolf den security principles

use anyhow::{anyhow, Result};
#[cfg(feature = "container_security")]
use bollard::container::{InspectContainerOptions, ListContainersOptions};
#[cfg(feature = "container_security")]
use bollard::Docker;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use wolf_net::PeerId;

use crate::security::advanced::container_security::{
    DenSecurityLevel, WolfDenAssignment, WolfDenType,
};
use crate::wolf_pack::hierarchy::{PackRank, WolfDenConfig};
use crate::wolf_pack::territory::TerritoryAccess;

/// Wolf Den Container Manager
pub struct WolfDenContainerManager {
    /// Configuration
    #[allow(dead_code)]
    config: WolfDenConfig,
    /// Active containers
    #[allow(dead_code)]
    containers: Arc<RwLock<HashMap<String, WolfDenContainer>>>,
    #[cfg(feature = "container_security")]
    /// Docker client
    docker: Option<Docker>,
    #[cfg(not(feature = "container_security"))]
    docker: Option<()>, // Dummy field when disabled
}

impl WolfDenContainerManager {
    /// Create new manager
    pub fn new(config: WolfDenConfig) -> Self {
        #[cfg(feature = "container_security")]
        let docker = match Docker::connect_with_socket_defaults() {
            Ok(d) => Some(d),
            Err(e) => {
                warn!("🐳 Failed to connect to Docker daemon: {}. Container security will be disabled.", e);
                None
            }
        };

        #[cfg(not(feature = "container_security"))]
        let docker = None;

        Self {
            config,
            containers: Arc::new(RwLock::new(HashMap::new())),
            docker,
        }
    }

    /// Scan a container for security risks
    pub async fn scan_container(&self, container_id: &str) -> Result<TerritoryAccess> {
        #[cfg(feature = "container_security")]
        if let Some(docker) = &self.docker {
            info!("🐳 Scanning container: {}", container_id);

            // 1. Inspect Container Configuration
            let inspect = docker
                .inspect_container(container_id, None::<InspectContainerOptions>)
                .await
                .map_err(|e| anyhow!("Docker inspect failed: {}", e))?;

            let mut risk_score = 0;
            let mut findings = Vec::new();

            // Check Privileged Mode
            if let Some(host_config) = inspect.host_config {
                if host_config.privileged.unwrap_or(false) {
                    risk_score += 50;
                    findings.push("Running in Privileged Mode");
                }

                // Check Network Mode
                if host_config.network_mode.as_deref() == Some("host") {
                    risk_score += 30;
                    findings.push("Using Host Network Mode");
                }

                // Check Sensitive Mounts
                if let Some(mounts) = host_config.binds {
                    for mount in mounts {
                        if mount.starts_with("/sys")
                            || mount.starts_with("/proc")
                            || mount.starts_with("/var/run/docker.sock")
                        {
                            risk_score += 40;
                            findings.push("Sensitive Path Mounted");
                            break;
                        }
                    }
                }
            }

            // Check Process State
            if let Some(state) = inspect.state {
                if state.oom_killed.unwrap_or(false) {
                    findings.push("Previously OOM Killed");
                    risk_score += 10;
                }
            }

            let passed = risk_score < 50;
            let rank_requirement = if risk_score > 70 {
                PackRank::Omega
            } else {
                PackRank::Hunter
            };

            // Return Territory Access Assessment
            Ok(TerritoryAccess {
                peer_id: PeerId::random(), // Placeholder, not mapping containers to peers yet
                territory_name: container_id.to_string(),
                timestamp: Utc::now(),
                access_granted: passed,
                reason: if passed {
                    format!("Passed Safety Checks. Findings: {:?}", findings)
                } else {
                    format!(
                        "Security Risk Detected (Score: {}). Findings: {:?}",
                        risk_score, findings
                    )
                },
                duration_seconds: Some(3600),
                pack_rank: rank_requirement,
            })
        } else {
            Err(anyhow!("Docker daemon not connected"))
        }
    }

    /// List all running containers in the Wolf Den
    pub async fn list_running_containers(&self) -> Result<Vec<WolfDenContainer>> {
        #[cfg(feature = "container_security")]
        if let Some(docker) = &self.docker {
            let options = ListContainersOptions::<String>::default();
            let containers = docker.list_containers(Some(options)).await?;

            let mut result = Vec::new();
            for c in containers {
                result.push(WolfDenContainer {
                    id: c.id.unwrap_or_default(),
                    name: c
                        .names
                        .unwrap_or_default()
                        .get(0)
                        .cloned()
                        .unwrap_or_default(),
                    security_level: PackRank::Stray, // Default
                    created_at: Utc::now(),          // Simplified
                    state: c.state.unwrap_or_default(),
                    status: c.status.unwrap_or_default(),
                });
            }
            Ok(result)
        } else {
            Ok(Vec::new())
        }

        #[cfg(not(feature = "container_security"))]
        Ok(Vec::new())
    }

    /// Isolate a compromised container (Stop/Kill)
    pub async fn isolate_container(&self, container_id: &str) -> Result<()> {
        #[cfg(feature = "container_security")]
        if let Some(docker) = &self.docker {
            warn!("🛑 ISOLATING CONTAINER: {}", container_id);
            docker
                .stop_container(container_id, None)
                .await
                .map_err(|e| anyhow!("Failed to stop container: {}", e))?;
            Ok(())
        } else {
            Err(anyhow!("Docker daemon not connected"))
        }

        #[cfg(not(feature = "container_security"))]
        Err(anyhow!("Container security feature disabled"))
    }

    /// Assign container to a den
    pub async fn assign_container(
        &self,
        container_id: &str,
        den_type: WolfDenType,
    ) -> Result<WolfDenAssignment> {
        Ok(WolfDenAssignment {
            den_id: uuid::Uuid::new_v4(),
            den_name: format!("Den for {}", container_id),
            den_type,
            security_level: DenSecurityLevel::High,
            pack_assignment: None,
            assigned_at: Utc::now(),
        })
    }
}

/// Wolf Den Container Representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfDenContainer {
    /// Container ID
    pub id: String,
    /// Container name
    pub name: String,
    /// Security rank
    pub security_level: PackRank,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Container state
    pub state: String,
    /// Container status
    pub status: String,
}

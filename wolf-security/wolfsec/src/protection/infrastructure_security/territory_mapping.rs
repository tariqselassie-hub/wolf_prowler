use super::{
    InfrastructureResource, InfrastructureResourceType, InfrastructureSecurityConfig,
    InfrastructureTerritoryType, TerritoryAssignment, TerritoryMappingResult,
    TerritorySecurityLevel,
};
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

pub struct TerritoryMappingManager {
    config: InfrastructureSecurityConfig,
}

impl TerritoryMappingManager {
    pub fn new(config: InfrastructureSecurityConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn map_territories(
        &self,
        resources: &[InfrastructureResource],
    ) -> Result<TerritoryMappingResult> {
        let mut assignments = Vec::new();
        let mut mapped_count = 0;

        if !self
            .config
            .territory_mapping_settings
            .automatic_territory_discovery
        {
            return Ok(TerritoryMappingResult::default());
        }

        for resource in resources {
            let (territory_type, security_level) = self.determine_territory(resource);

            let assignment = TerritoryAssignment {
                territory_id: Uuid::new_v4(),
                name: format!("{:?} Zone for {}", territory_type, resource.name),
                territory_type,
                security_level,
                wolf_pack_assignment: None,
                assigned_at: Utc::now(),
            };

            assignments.push(assignment);
            mapped_count += 1;
        }

        Ok(TerritoryMappingResult {
            mapping_id: Uuid::new_v4(),
            territories_mapped: mapped_count,
            territory_assignments: assignments,
            mapping_timestamp: Utc::now(),
        })
    }

    fn determine_territory(
        &self,
        resource: &InfrastructureResource,
    ) -> (InfrastructureTerritoryType, TerritorySecurityLevel) {
        match resource.resource_type {
            InfrastructureResourceType::Firewall | InfrastructureResourceType::VPN => (
                InfrastructureTerritoryType::HunterTerritory,
                TerritorySecurityLevel::Maximum,
            ),
            InfrastructureResourceType::Database | InfrastructureResourceType::Storage => (
                InfrastructureTerritoryType::AlphaTerritory,
                TerritorySecurityLevel::High,
            ),
            InfrastructureResourceType::KubernetesCluster
            | InfrastructureResourceType::VirtualMachine => (
                InfrastructureTerritoryType::BetaTerritory,
                TerritorySecurityLevel::Medium,
            ),
            InfrastructureResourceType::LoadBalancer
            | InfrastructureResourceType::DNS
            | InfrastructureResourceType::Network => (
                InfrastructureTerritoryType::GammaTerritory,
                TerritorySecurityLevel::Standard,
            ),
            InfrastructureResourceType::Container
            | InfrastructureResourceType::ServerlessFunction => (
                InfrastructureTerritoryType::DeltaTerritory,
                TerritorySecurityLevel::Standard,
            ),
            _ => (
                InfrastructureTerritoryType::OmegaTerritory,
                TerritorySecurityLevel::Basic,
            ),
        }
    }
}

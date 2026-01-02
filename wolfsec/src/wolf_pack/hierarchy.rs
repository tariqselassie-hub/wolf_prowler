use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfCommunicationRules {
    pub allow_inter_pack_comms: bool,
}

impl Default for WolfCommunicationRules {
    fn default() -> Self {
        Self {
            allow_inter_pack_comms: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfDenConfig {
    pub pack_name: String,
}

pub type PackRank = super::WolfRank;

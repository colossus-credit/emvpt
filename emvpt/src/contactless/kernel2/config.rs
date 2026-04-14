// Mastercard Contactless Kernel 2 configuration
// ref. EMV Contactless Book C-2, Section 3 - Requirements

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McAidConfig {
    pub aid: String,
    #[serde(default = "default_kernel_id")]
    pub kernel_id: u8,
    #[serde(default)]
    pub version: String,

    // Terminal Action Codes
    #[serde(default = "default_tac")]
    pub tac_denial: String,
    #[serde(default = "default_tac")]
    pub tac_online: String,
    #[serde(default = "default_tac")]
    pub tac_default: String,

    // Reader limits (in minor currency units)
    #[serde(default)]
    pub floor_limit: u64,
    #[serde(default = "default_transaction_limit")]
    pub contactless_transaction_limit: u64,
    #[serde(default = "default_transaction_limit")]
    pub contactless_transaction_limit_cdcvm: u64,
    #[serde(default = "default_cvm_limit")]
    pub cvm_required_limit: u64,

    // Terminal capabilities split for CVM/no-CVM
    #[serde(default = "default_terminal_cap_no_cvm")]
    pub terminal_cap_no_cvm: String,
    #[serde(default = "default_terminal_cap_cvm")]
    pub terminal_cap_cvm: String,

    // Kernel behavior
    #[serde(default)]
    pub kernel_configuration: u8,
    #[serde(default)]
    pub risk_management_data: Option<String>,
    #[serde(default)]
    pub force_online: bool,
}

fn default_kernel_id() -> u8 {
    0x02
}

fn default_tac() -> String {
    "0000000000".to_string()
}

fn default_transaction_limit() -> u64 {
    10000
}

fn default_cvm_limit() -> u64 {
    5000
}

fn default_terminal_cap_no_cvm() -> String {
    "E008C8".to_string()
}

fn default_terminal_cap_cvm() -> String {
    "E068C8".to_string()
}

impl McAidConfig {
    pub fn tac_denial_bytes(&self) -> Vec<u8> {
        hex::decode(&self.tac_denial).unwrap_or_else(|_| vec![0u8; 5])
    }

    pub fn tac_online_bytes(&self) -> Vec<u8> {
        hex::decode(&self.tac_online).unwrap_or_else(|_| vec![0u8; 5])
    }

    pub fn tac_default_bytes(&self) -> Vec<u8> {
        hex::decode(&self.tac_default).unwrap_or_else(|_| vec![0u8; 5])
    }

    pub fn terminal_cap_no_cvm_bytes(&self) -> Vec<u8> {
        hex::decode(&self.terminal_cap_no_cvm).unwrap_or_else(|_| vec![0xE0, 0x08, 0xC8])
    }

    pub fn terminal_cap_cvm_bytes(&self) -> Vec<u8> {
        hex::decode(&self.terminal_cap_cvm).unwrap_or_else(|_| vec![0xE0, 0x68, 0xC8])
    }

    pub fn aid_bytes(&self) -> Vec<u8> {
        hex::decode(&self.aid).unwrap_or_default()
    }

    pub fn version_bytes(&self) -> Vec<u8> {
        hex::decode(&self.version).unwrap_or_else(|_| vec![0x00, 0x02])
    }

    /// Check if the amount exceeds the contactless transaction limit
    pub fn exceeds_transaction_limit(&self, amount: u64, cdcvm: bool) -> bool {
        let limit = if cdcvm {
            self.contactless_transaction_limit_cdcvm
        } else {
            self.contactless_transaction_limit
        };
        amount > limit
    }

    /// Check if CVM is required based on amount
    pub fn cvm_required(&self, amount: u64) -> bool {
        amount > self.cvm_required_limit
    }

    /// Check if floor limit is exceeded
    pub fn floor_limit_exceeded(&self, amount: u64) -> bool {
        amount > self.floor_limit
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MastercardKernelConfig {
    pub aids: Vec<McAidConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactlessKernelSettings {
    pub mastercard: Option<MastercardKernelConfig>,
}

impl ContactlessKernelSettings {
    /// Find the McAidConfig matching the given AID bytes
    pub fn find_mc_config(&self, aid: &[u8]) -> Option<&McAidConfig> {
        let mc_config = self.mastercard.as_ref()?;
        let aid_hex = hex::encode_upper(aid);

        mc_config.aids.iter().find(|cfg| {
            let cfg_aid = cfg.aid.to_uppercase();
            // Match by prefix: AID from card may be longer than configured AID
            aid_hex.starts_with(&cfg_aid) || cfg_aid.starts_with(&aid_hex)
        })
    }
}

// Contactless Entry Point
// ref. EMV Contactless Book B - Entry Point Specification
// Handles AID-to-kernel routing and pre-processing

use log::{debug, info, warn};

use crate::EmvConnection;
use super::kernel_trait::{ContactlessKernel, KernelError};
use super::kernel2::config::ContactlessKernelSettings;
use super::kernel2::MastercardKernel;
use super::tags;

/// Pre-processing result from entry point before kernel dispatch
#[derive(Debug, Clone)]
pub struct PreProcessingResult {
    pub contactless_application_not_allowed: bool,
    pub transaction_limit_exceeded: bool,
    pub cvm_required: bool,
    pub floor_limit_exceeded: bool,
    pub zero_amount: bool,
}

/// Select and instantiate the appropriate contactless kernel for the given AID
/// ref. EMV Contactless Book B, Section 3.3 - Pre-Processing
pub fn select_kernel(
    aid: &[u8],
    kernel_settings: &ContactlessKernelSettings,
    conn: &mut EmvConnection,
) -> Result<(Box<dyn ContactlessKernel>, PreProcessingResult), KernelError> {
    let aid_hex = hex::encode_upper(aid);
    debug!("Entry Point: Selecting kernel for AID {}", aid_hex);

    // Check if AID matches Mastercard (RID = A000000004) or custom RID (A000000951)
    let is_mastercard = aid.len() >= 5 && aid[0..5] == *tags::MASTERCARD_RID;
    let is_custom_rid = aid.len() >= 5 && aid[0..5] == *tags::CUSTOM_RID;

    if is_mastercard || is_custom_rid {
        info!("Entry Point: AID matches {} RID, selecting Kernel 2",
            if is_mastercard { "Mastercard" } else { "custom" });

        let mc_config = kernel_settings
            .find_mc_config(aid)
            .ok_or_else(|| {
                KernelError::ConfigError(format!(
                    "No Mastercard kernel configuration found for AID {}",
                    aid_hex
                ))
            })?
            .clone();

        // Compute pre-processing based on amount vs limits
        let amount = get_amount(conn);
        let preprocessing = PreProcessingResult {
            contactless_application_not_allowed: mc_config.exceeds_transaction_limit(amount, false),
            transaction_limit_exceeded: mc_config.exceeds_transaction_limit(amount, false),
            cvm_required: mc_config.cvm_required(amount),
            floor_limit_exceeded: mc_config.floor_limit_exceeded(amount),
            zero_amount: amount == 0,
        };

        if preprocessing.contactless_application_not_allowed {
            warn!("Entry Point: Amount {} exceeds contactless transaction limit — application not allowed",
                amount);
        }

        // Modify TTQ based on pre-processing
        // ref. EMV Contactless Book B, Section 3.3.1.5
        if let Some(ttq) = conn.get_tag_value(tags::TAG_TTQ) {
            let mut ttq = ttq.clone();
            if ttq.len() >= 2 {
                if preprocessing.cvm_required {
                    ttq[1] |= 0x80; // Set byte 2 bit 8: CVM Required
                    debug!("Entry Point: CVM required, modified TTQ byte 2 → {:02X}", ttq[1]);
                } else {
                    ttq[1] &= !0x80; // Clear CVM Required bit
                }
                conn.add_tag(tags::TAG_TTQ, ttq);
            }
        }

        let mut kernel = MastercardKernel::new(mc_config);
        kernel.set_application(crate::EmvApplication {
            aid: aid.to_vec(),
            label: Vec::new(),
            priority: Vec::new(),
        });
        return Ok((Box::new(kernel), preprocessing));
    }

    Err(KernelError::ConfigError(format!(
        "No contactless kernel available for AID {}",
        aid_hex
    )))
}

fn get_amount(conn: &EmvConnection) -> u64 {
    match conn.get_tag_value(tags::TAG_AMOUNT_AUTHORISED) {
        Some(amount_bcd) => {
            let amount_hex = hex::encode(amount_bcd);
            amount_hex.parse::<u64>().unwrap_or(0)
        }
        None => 0,
    }
}

/// Run pre-processing checks for the selected kernel
/// ref. EMV Contactless Book B, Section 3.3.1
pub fn preprocess(
    conn: &EmvConnection,
    kernel_settings: &ContactlessKernelSettings,
    aid: &[u8],
) -> PreProcessingResult {
    let mut result = PreProcessingResult {
        contactless_application_not_allowed: false,
        transaction_limit_exceeded: false,
        cvm_required: false,
        floor_limit_exceeded: false,
        zero_amount: false,
    };

    // Get amount
    let amount = match conn.get_tag_value(tags::TAG_AMOUNT_AUTHORISED) {
        Some(amount_bcd) => {
            let amount_hex = hex::encode(amount_bcd);
            amount_hex.parse::<u64>().unwrap_or(0)
        }
        None => 0,
    };

    result.zero_amount = amount == 0;

    // Find MC config for this AID
    if let Some(mc_config) = kernel_settings.find_mc_config(aid) {
        result.transaction_limit_exceeded = mc_config.exceeds_transaction_limit(amount, false);
        result.cvm_required = mc_config.cvm_required(amount);
        result.floor_limit_exceeded = mc_config.floor_limit_exceeded(amount);

        if result.transaction_limit_exceeded {
            warn!(
                "Entry Point: Amount {} exceeds contactless transaction limit {}",
                amount, mc_config.contactless_transaction_limit
            );
            result.contactless_application_not_allowed = true;
        }

        debug!(
            "Entry Point: Pre-processing for AID {}: amount={}, CVM_required={}, floor_exceeded={}, tx_limit_exceeded={}",
            hex::encode_upper(aid),
            amount,
            result.cvm_required,
            result.floor_limit_exceeded,
            result.transaction_limit_exceeded
        );
    }

    result
}

// Mastercard Contactless Kernel 2 CVM determination
// ref. EMV Contactless Book C-2, Section 3.5 - CVM Determination
// ref. PAX BroadPOS decompiled reference (e3/i.java)

use log::{debug, info};

use crate::EmvConnection;
use crate::contactless::outcome::CvmOutcome;
use crate::contactless::tags;
use super::config::McAidConfig;

/// Card Transaction Qualifiers (CTQ) bit definitions
/// ref. EMV Contactless Book C-2, Table A.2
pub struct Ctq {
    // Byte 1
    pub online_pin_required: bool,           // bit 1 (0x01) — not used per C-2 but present
    pub signature_required: bool,            // bit 2 (0x02)
    pub online_if_oda_fails_and_reader_online: bool, // bit 3 (0x04)
    pub switch_interface_if_oda_fails: bool,         // bit 4 (0x08)
    pub online_if_application_expired: bool,         // bit 5 (0x10)
    pub switch_interface_for_cash: bool,             // bit 6 (0x20)
    pub switch_interface_for_cashback: bool,         // bit 7 (0x40)
    // bit 8 (0x80) RFU

    // Byte 2
    pub cdcvm_performed: bool,               // bit 8 (0x80)
    pub card_supports_cdcvm: bool,           // bit 7 (0x40)
    // bits 6-1 RFU
}

impl Ctq {
    pub fn from_bytes(ctq: &[u8]) -> Self {
        let b1 = if ctq.len() >= 1 { ctq[0] } else { 0 };
        let b2 = if ctq.len() >= 2 { ctq[1] } else { 0 };

        Ctq {
            online_pin_required: (b1 & 0x01) != 0,
            signature_required: (b1 & 0x02) != 0,
            online_if_oda_fails_and_reader_online: (b1 & 0x04) != 0,
            switch_interface_if_oda_fails: (b1 & 0x08) != 0,
            online_if_application_expired: (b1 & 0x10) != 0,
            switch_interface_for_cash: (b1 & 0x20) != 0,
            switch_interface_for_cashback: (b1 & 0x40) != 0,
            cdcvm_performed: (b2 & 0x80) != 0,
            card_supports_cdcvm: (b2 & 0x40) != 0,
        }
    }
}

/// Terminal Transaction Qualifiers (TTQ) bit definitions relevant to CVM
/// ref. EMV Contactless Book C-2, Table A.1
pub struct Ttq {
    // Byte 1
    pub online_pin_supported: bool,          // bit 4 (0x08)
    pub signature_supported: bool,           // bit 3 (0x04)
    pub online_cryptogram_required: bool,    // bit 2 (0x02)
    pub emv_mode_supported: bool,            // bit 1 (0x01) — actually bit 7 (0x80) in standard

    // Byte 2
    pub cvm_required: bool,                  // bit 8 (0x80)
    pub cdcvm_supported: bool,               // bit 7 (0x40) — consumer device CVM supported
}

impl Ttq {
    pub fn from_bytes(ttq: &[u8]) -> Self {
        let b1 = if ttq.len() >= 1 { ttq[0] } else { 0 };
        let b2 = if ttq.len() >= 2 { ttq[1] } else { 0 };

        Ttq {
            // ref. EMV Contactless Book C-3, Table A.1 (TTQ byte 1)
            // Bit 8 (0x80): Mag stripe mode supported
            // Bit 7 (0x40): not used
            // Bit 6 (0x20): EMV contact chip supported
            // Bit 5 (0x10): EMV mode supported
            // Bit 4 (0x08): Reader is offline only
            // Bit 3 (0x04): Online PIN supported
            // Bit 2 (0x02): Signature supported
            // Bit 1 (0x01): ODA for online authorizations supported
            //
            // But for Kernel 2 (MC) the TTQ is interpreted differently:
            // ref. EMV Contactless Book C-2, Table 3-5
            online_pin_supported: (b1 & 0x04) != 0,
            signature_supported: (b1 & 0x02) != 0,
            online_cryptogram_required: (b1 & 0x08) != 0,
            emv_mode_supported: (b1 & 0x10) != 0,

            // Byte 2
            cvm_required: (b2 & 0x80) != 0,
            cdcvm_supported: (b2 & 0x40) != 0,
        }
    }
}

/// Determine CVM for a Mastercard contactless transaction
/// ref. EMV Contactless Book C-2, Section 3.5
///
/// The CVM determination for MC contactless follows this priority:
/// 1. If amount < CVM Required Limit → No CVM
/// 2. If CDCVM was performed by the card/device → CDCVM
/// 3. If card + terminal support Online PIN → Online PIN
/// 4. If card + terminal support Signature → Signature
/// 5. Default: No CVM (terminal may still force online)
pub fn determine_cvm(
    conn: &EmvConnection,
    config: &McAidConfig,
) -> CvmOutcome {
    let amount = get_amount(conn);

    // Step 1: Check if CVM is required at all
    if !config.cvm_required(amount) {
        debug!(
            "Kernel 2 CVM: Amount {} below CVM limit {}, no CVM required",
            amount, config.cvm_required_limit
        );
        return CvmOutcome::NoCvm;
    }

    debug!("Kernel 2 CVM: Amount {} exceeds CVM limit {}, CVM required",
        amount, config.cvm_required_limit);

    // Get TTQ from terminal
    let ttq = conn.get_tag_value(tags::TAG_TTQ)
        .map(|v| Ttq::from_bytes(v))
        .unwrap_or_else(|| Ttq::from_bytes(&[0x36, 0x00]));

    // Step 2: Check CTQ from card (tag 9F6C)
    if let Some(ctq_bytes) = conn.get_tag_value(tags::TAG_CTQ) {
        let ctq = Ctq::from_bytes(ctq_bytes);
        return determine_cvm_from_ctq_ttq(&ctq, &ttq);
    }

    // No CTQ — fall back to Online PIN if terminal supports it, else No CVM
    if ttq.online_pin_supported {
        debug!("Kernel 2 CVM: No CTQ from card, terminal supports online PIN → Online PIN");
        CvmOutcome::OnlinePin
    } else if ttq.signature_supported {
        debug!("Kernel 2 CVM: No CTQ from card, terminal supports signature → Signature");
        CvmOutcome::ObtainSignature
    } else {
        debug!("Kernel 2 CVM: No CTQ, no terminal CVM support → No CVM");
        CvmOutcome::NoCvm
    }
}

/// Determine CVM from Card Transaction Qualifiers and Terminal Transaction Qualifiers
/// ref. EMV Contactless Book C-2, Table 3.5
fn determine_cvm_from_ctq_ttq(ctq: &Ctq, ttq: &Ttq) -> CvmOutcome {
    // Priority 1: CDCVM (Consumer Device CVM — e.g., phone fingerprint/face)
    if ctq.cdcvm_performed {
        info!("Kernel 2 CVM: CDCVM was performed by consumer device");
        return CvmOutcome::ConfirmationCodeVerified;
    }

    // Priority 2: Online PIN
    if ctq.online_pin_required && ttq.online_pin_supported {
        debug!("Kernel 2 CVM: CTQ requests Online PIN, terminal supports it");
        return CvmOutcome::OnlinePin;
    }

    // Priority 3: Signature
    if ctq.signature_required && ttq.signature_supported {
        debug!("Kernel 2 CVM: CTQ requests Signature, terminal supports it");
        return CvmOutcome::ObtainSignature;
    }

    // No matching CVM
    debug!("Kernel 2 CVM: No matching CVM method → No CVM");
    CvmOutcome::NoCvm
}

/// Build CVM Results tag (9F34) from the CVM outcome
/// ref. EMV Book 4, Annex A5
pub fn build_cvm_results(cvm: CvmOutcome) -> Vec<u8> {
    match cvm {
        CvmOutcome::NoCvm => {
            // CVM code 0x1F (No CVM), condition 0x00 (always), result 0x02 (successful)
            vec![0x1F, 0x00, 0x02]
        }
        CvmOutcome::OnlinePin => {
            // CVM code 0x02 (Enciphered PIN online), condition 0x00, result 0x00 (unknown)
            // Result is unknown because online PIN verification happens at the issuer
            vec![0x02, 0x00, 0x00]
        }
        CvmOutcome::ObtainSignature => {
            // CVM code 0x1E (Signature), condition 0x00, result 0x00 (unknown)
            vec![0x1E, 0x00, 0x00]
        }
        CvmOutcome::ConfirmationCodeVerified => {
            // CVM code 0x1F (No CVM per terminal perspective — CDCVM is transparent)
            // The CDCVM is indicated in the CTQ, not in the CVM Results
            vec![0x1F, 0x00, 0x02]
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctq_parsing() {
        // CTQ = 0x00 0x80 → CDCVM performed
        let ctq = Ctq::from_bytes(&[0x00, 0x80]);
        assert!(ctq.cdcvm_performed);
        assert!(!ctq.online_pin_required);
        assert!(!ctq.signature_required);

        // CTQ = 0x01 0x00 → Online PIN required
        let ctq = Ctq::from_bytes(&[0x01, 0x00]);
        assert!(ctq.online_pin_required);
        assert!(!ctq.cdcvm_performed);

        // CTQ = 0x02 0x00 → Signature required
        let ctq = Ctq::from_bytes(&[0x02, 0x00]);
        assert!(ctq.signature_required);
        assert!(!ctq.online_pin_required);

        // CTQ = 0x00 0x40 → Card supports CDCVM (but not performed)
        let ctq = Ctq::from_bytes(&[0x00, 0x40]);
        assert!(ctq.card_supports_cdcvm);
        assert!(!ctq.cdcvm_performed);
    }

    #[test]
    fn test_ttq_parsing() {
        // TTQ = 0x36 0x00 → EMV mode + online PIN + signature
        let ttq = Ttq::from_bytes(&[0x36, 0x00]);
        assert!(ttq.emv_mode_supported);
        assert!(ttq.online_pin_supported);
        assert!(ttq.signature_supported);
        assert!(!ttq.cdcvm_supported);

        // TTQ = 0x36 0x40 → also supports CDCVM
        let ttq = Ttq::from_bytes(&[0x36, 0x40]);
        assert!(ttq.cdcvm_supported);
    }

    #[test]
    fn test_cvm_cdcvm_highest_priority() {
        // CDCVM performed should always win
        let ctq = Ctq::from_bytes(&[0x03, 0x80]); // CDCVM + PIN + Signature
        let ttq = Ttq::from_bytes(&[0x36, 0x40]);  // supports everything
        assert_eq!(determine_cvm_from_ctq_ttq(&ctq, &ttq), CvmOutcome::ConfirmationCodeVerified);
    }

    #[test]
    fn test_cvm_online_pin() {
        let ctq = Ctq::from_bytes(&[0x01, 0x00]); // PIN required, no CDCVM
        let ttq = Ttq::from_bytes(&[0x06, 0x00]);  // online PIN + signature supported
        assert_eq!(determine_cvm_from_ctq_ttq(&ctq, &ttq), CvmOutcome::OnlinePin);
    }

    #[test]
    fn test_cvm_signature_when_no_pin_support() {
        let ctq = Ctq::from_bytes(&[0x03, 0x00]); // PIN + Signature required
        let ttq = Ttq::from_bytes(&[0x02, 0x00]);  // only signature supported
        assert_eq!(determine_cvm_from_ctq_ttq(&ctq, &ttq), CvmOutcome::ObtainSignature);
    }

    #[test]
    fn test_cvm_no_cvm_when_nothing_matches() {
        let ctq = Ctq::from_bytes(&[0x01, 0x00]); // PIN required
        let ttq = Ttq::from_bytes(&[0x00, 0x00]);  // nothing supported
        assert_eq!(determine_cvm_from_ctq_ttq(&ctq, &ttq), CvmOutcome::NoCvm);
    }

    #[test]
    fn test_cvm_results_encoding() {
        assert_eq!(build_cvm_results(CvmOutcome::NoCvm), vec![0x1F, 0x00, 0x02]);
        assert_eq!(build_cvm_results(CvmOutcome::OnlinePin), vec![0x02, 0x00, 0x00]);
        assert_eq!(build_cvm_results(CvmOutcome::ObtainSignature), vec![0x1E, 0x00, 0x00]);
        assert_eq!(build_cvm_results(CvmOutcome::ConfirmationCodeVerified), vec![0x1F, 0x00, 0x02]);
    }
}

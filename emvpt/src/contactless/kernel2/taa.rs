// Mastercard Contactless Kernel 2 Terminal Action Analysis
// ref. EMV Contactless Book C-2, Section 3.6
// ref. EMV Book 3, Section 10.7 - Terminal Action Analysis
//
// TAA determines whether the transaction should be:
// - Approved offline (TC)
// - Sent online for authorization (ARQC)
// - Declined offline (AAC)
//
// Kernel 2 uses MC-specific Terminal Action Codes (DF8120/21/22)
// instead of the card's IAC (Issuer Action Codes).

use log::{debug, info};

use crate::{EmvConnection, CryptogramType};
use super::config::McAidConfig;
use crate::contactless::tags;

/// Perform Terminal Action Analysis for Mastercard contactless.
///
/// Compares TVR against MC-specific TACs to determine the cryptogram
/// type to request in GENERATE AC.
///
/// ref. EMV Book 3, 10.7 Terminal Action Analysis
/// ref. EMV Contactless Book C-2, Section 3.6
pub fn perform_taa(
    conn: &EmvConnection,
    config: &McAidConfig,
) -> CryptogramType {
    // Get TVR as 5 bytes
    let tvr: Vec<u8> = conn.settings.terminal.tvr.into();
    debug!("TAA: TVR = {:02X?}", tvr);

    let tac_denial = config.tac_denial_bytes();
    let tac_online = config.tac_online_bytes();
    let tac_default = config.tac_default_bytes();

    debug!("TAA: TAC-Denial  = {:02X?}", tac_denial);
    debug!("TAA: TAC-Online  = {:02X?}", tac_online);
    debug!("TAA: TAC-Default = {:02X?}", tac_default);

    // Step 1: Force online if configured
    if config.force_online {
        info!("TAA: force_online set → ARQC");
        return CryptogramType::AuthorisationRequestCryptogram;
    }

    // Step 2: Check floor limit
    let amount = get_amount(conn);
    if config.floor_limit_exceeded(amount) {
        debug!("TAA: Amount {} exceeds floor limit {} → must go online",
            amount, config.floor_limit);
        // Don't return ARQC yet — denial check takes priority
    }

    // Step 3: TAC-Denial check
    // For each bit in TVR that is 1, check the corresponding bit in TAC-Denial.
    // If ANY corresponding bit in TAC-Denial is also 1, decline offline (AAC).
    if bitwise_match(&tvr, &tac_denial) {
        info!("TAA: TVR matches TAC-Denial → AAC (decline)");
        return CryptogramType::ApplicationAuthenticationCryptogram;
    }

    // Step 4: IAC-Denial check (from card, if present)
    // ref. EMV Book 3, 10.7: "If the corresponding bit in either of the action codes
    // [IAC-Denial or TAC-Denial] is set to 1, the terminal shall request an AAC"
    if let Some(iac_denial) = conn.get_tag_value("9F0E") {
        if bitwise_match(&tvr, iac_denial) {
            info!("TAA: TVR matches IAC-Denial (9F0E) → AAC (decline)");
            return CryptogramType::ApplicationAuthenticationCryptogram;
        }
    }

    // Step 5: TAC-Online check
    // If ANY corresponding bit in TAC-Online is 1, request online (ARQC).
    if bitwise_match(&tvr, &tac_online) {
        info!("TAA: TVR matches TAC-Online → ARQC (online)");
        return CryptogramType::AuthorisationRequestCryptogram;
    }

    // Step 6: IAC-Online check (from card, if present)
    // If IAC-Online not present, default is all 1s (force online for any TVR bit)
    let iac_online_default = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let iac_online = conn.get_tag_value("9F0F")
        .unwrap_or(&iac_online_default);
    if bitwise_match(&tvr, iac_online) {
        info!("TAA: TVR matches IAC-Online (9F0F) → ARQC (online)");
        return CryptogramType::AuthorisationRequestCryptogram;
    }

    // Step 7: Floor limit exceeded (deferred from step 2)
    if config.floor_limit_exceeded(amount) {
        info!("TAA: Floor limit exceeded → ARQC (online)");
        return CryptogramType::AuthorisationRequestCryptogram;
    }

    // Step 8: TAC-Default check
    // Used only when online is not possible (offline-only terminal) or when
    // TAC-Online didn't trigger. If TAC-Default matches, use it for the decision.
    if bitwise_match(&tvr, &tac_default) {
        // ref. EMV Book 3, 10.7: "If the terminal is online-capable,
        // the terminal shall request an ARQC"
        // For contactless, terminals are typically online-capable
        info!("TAA: TVR matches TAC-Default → ARQC (online, terminal is online-capable)");
        return CryptogramType::AuthorisationRequestCryptogram;
    }

    // Step 9: IAC-Default check (from card, if present)
    let iac_default_default = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let iac_default = conn.get_tag_value("9F0D")
        .unwrap_or(&iac_default_default);
    if bitwise_match(&tvr, iac_default) {
        info!("TAA: TVR matches IAC-Default (9F0D) → ARQC");
        return CryptogramType::AuthorisationRequestCryptogram;
    }

    // No denial, no online trigger, no default trigger → approve offline (TC)
    info!("TAA: No TAC/IAC triggers → TC (offline approval)");
    CryptogramType::TransactionCertificate
}

/// Check if any bit that is set in TVR also has the corresponding bit set in the action code.
/// Returns true if (TVR & action_code) != 0 for any byte.
fn bitwise_match(tvr: &[u8], action_code: &[u8]) -> bool {
    let len = tvr.len().min(action_code.len());
    for i in 0..len {
        if (tvr[i] & action_code[i]) != 0 {
            return true;
        }
    }
    false
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
    fn test_bitwise_match_no_overlap() {
        let tvr = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        let tac = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(!bitwise_match(&tvr, &tac));
    }

    #[test]
    fn test_bitwise_match_full_overlap() {
        let tvr = vec![0x80, 0x00, 0x00, 0x00, 0x00];
        let tac = vec![0x80, 0x00, 0x00, 0x00, 0x00];
        assert!(bitwise_match(&tvr, &tac));
    }

    #[test]
    fn test_bitwise_match_partial_overlap() {
        let tvr = vec![0x04, 0x00, 0x00, 0x80, 0x00]; // CDA failed + floor limit
        let tac = vec![0x00, 0x00, 0x00, 0x80, 0x00]; // Only checks floor limit
        assert!(bitwise_match(&tvr, &tac));
    }

    #[test]
    fn test_bitwise_match_no_match() {
        let tvr = vec![0x04, 0x00, 0x00, 0x00, 0x00]; // CDA failed
        let tac = vec![0x00, 0x00, 0x00, 0x80, 0x00]; // Only checks floor limit
        assert!(!bitwise_match(&tvr, &tac));
    }

    #[test]
    fn test_bitwise_match_different_lengths() {
        let tvr = vec![0x80, 0x00, 0x00, 0x00, 0x00];
        let tac = vec![0x80, 0x00]; // Short action code
        assert!(bitwise_match(&tvr, &tac));
    }
}

// Mastercard Contactless Kernel 2 Offline Data Authentication (ODA)
// ref. EMV Contactless Book C-2, Section 3.4 - Offline Data Authentication
// ref. EMV Book 2, 6.6 Combined DDA/Application Cryptogram Generation (CDA)
//
// MC contactless uses CDA combined with GENERATE AC.
// The kernel calls CDA validation after receiving the GENERATE AC response.
// This module wraps the existing CDA logic in lib.rs for the kernel interface.

use log::{debug, info, warn};

use crate::EmvConnection;
use crate::contactless::kernel_trait::KernelError;
use crate::contactless::tags;

/// Perform ODA (CDA) for a Mastercard contactless M/Chip transaction.
///
/// This should be called after GENERATE AC returns a response with tag 9F4B
/// (Signed Dynamic Application Data). It validates the cryptogram using
/// the ICC public key chain: CA → Issuer → ICC.
///
/// Returns Ok(true) if CDA passed, Ok(false) if CDA was not performed
/// (e.g., card doesn't support it), or Err if CDA failed.
pub fn perform_oda(
    conn: &mut EmvConnection,
    application: &crate::EmvApplication,
) -> Result<bool, KernelError> {
    // Check if CDA is supported by both card and terminal
    if !conn.icc.capabilities.cda || !conn.settings.terminal.capabilities.cda {
        debug!(
            "Kernel 2 ODA: CDA not supported (card={}, terminal={})",
            conn.icc.capabilities.cda,
            conn.settings.terminal.capabilities.cda
        );
        return Ok(false);
    }

    // Check if we have the SDAD (tag 9F4B) — it must be in the GENERATE AC response
    if conn.get_tag_value(tags::TAG_SIGNED_DYNAMIC_APPLICATION_DATA).is_none() {
        debug!("Kernel 2 ODA: No SDAD (9F4B) in response, skipping CDA");
        return Ok(false);
    }

    info!("Kernel 2 ODA: Performing CDA validation");

    // Step 1: Recover the public key chain (CA → Issuer → ICC)
    // This reuses the existing handle_public_keys which does:
    // - Load CA public key from config
    // - Recover Issuer PK from certificate (tag 90)
    // - Recover ICC PK from certificate (tag 9F46)
    if conn.icc.icc_pk.is_none() {
        debug!("Kernel 2 ODA: ICC PK not yet recovered, recovering key chain");
        conn.handle_public_keys(application).map_err(|_| {
            KernelError::CardDataMissing(
                "Failed to recover public key chain for CDA".into(),
            )
        })?;
    }

    // Step 2: Validate the Signed Dynamic Application Data (9F4B)
    // using the ICC public key and the unpredictable number as auth data
    let tag_9f37 = conn.get_tag_value(tags::TAG_UNPREDICTABLE_NUMBER)
        .ok_or_else(|| KernelError::CardDataMissing("Unpredictable Number (9F37) missing".into()))?
        .clone();

    match conn.validate_signed_dynamic_application_data(&tag_9f37) {
        Ok(dynamic_data) => {
            debug!("Kernel 2 ODA: SDAD validation passed, dynamic data={} bytes", dynamic_data.len());

            // Extract and verify the embedded data from SDAD:
            // [0] = ICC Dynamic Number length
            // [1..1+len] = ICC Dynamic Number
            // [next] = CID (Cryptogram Information Data)
            // [next..next+8] = Application Cryptogram
            // [next..next+20] = Transaction Data Hash Code
            if dynamic_data.len() >= 10 {
                let icc_dn_len = dynamic_data[0] as usize;
                let mut i = 1 + icc_dn_len;

                if i + 9 <= dynamic_data.len() {
                    let cid_from_sdad = dynamic_data[i];
                    i += 1;
                    let ac_from_sdad = &dynamic_data[i..i + 8];

                    // Cross-check CID from SDAD with tag 9F27
                    if let Some(cid_tag) = conn.get_tag_value(tags::TAG_CRYPTOGRAM_INFO_DATA) {
                        if cid_tag[0] != cid_from_sdad {
                            warn!(
                                "Kernel 2 ODA: CID mismatch! 9F27={:02X}, SDAD CID={:02X}",
                                cid_tag[0], cid_from_sdad
                            );
                            return Err(KernelError::CardDataMissing(
                                "CDA failed: CID mismatch between 9F27 and SDAD".into(),
                            ));
                        }
                    }

                    // Cross-check AC from SDAD with tag 9F26
                    if let Some(ac_tag) = conn.get_tag_value(tags::TAG_APPLICATION_CRYPTOGRAM) {
                        if ac_tag.as_slice() != ac_from_sdad {
                            warn!("Kernel 2 ODA: Application Cryptogram mismatch between 9F26 and SDAD");
                            return Err(KernelError::CardDataMissing(
                                "CDA failed: AC mismatch between 9F26 and SDAD".into(),
                            ));
                        }
                    }
                }
            }

            // Mark ODA as performed in TSI
            conn.settings.terminal.tsi.offline_data_authentication_was_performed = true;

            info!("Kernel 2 ODA: CDA passed");
            Ok(true)
        }
        Err(_) => {
            warn!("Kernel 2 ODA: CDA validation failed");
            conn.settings.terminal.tvr.cda_failed = true;
            conn.settings.terminal.tsi.offline_data_authentication_was_performed = true;
            Err(KernelError::CardDataMissing("CDA validation failed".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    // ODA tests require mock APDU data and are better suited for integration tests
    // with the card simulator. Unit tests here would need extensive fixture setup.
    //
    // See the integration test in tests/ for end-to-end CDA validation.
}

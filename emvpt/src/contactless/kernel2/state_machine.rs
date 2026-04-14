// Mastercard Contactless Kernel 2 state machine
// ref. EMV Contactless Book C-2, Section 3 - Kernel 2 Overview
// ref. PAX BroadPOS ClssProcMc.java (decompiled reference)

use log::{debug, info, warn, trace};
use std::convert::TryFrom;
use chrono::{NaiveDate, Utc};

use crate::{EmvConnection, EmvApplication, CryptogramType, DataObjectList, is_success_response, bcdutil};
use super::config::McAidConfig;
use super::cvm;
use super::oda;
use super::taa;
use crate::contactless::kernel_trait::{ContactlessKernel, TransactionPath, KernelError};
use crate::contactless::outcome::OutcomeParameterSet;
use crate::contactless::tags;

/// Mastercard Contactless Kernel 2 implementation
pub struct MastercardKernel {
    config: McAidConfig,
    application: Option<EmvApplication>,
    transaction_path: Option<TransactionPath>,
    data_authentication: Vec<u8>,
    /// Raw tag 77 response data from GENERATE AC (for CDA hash)
    genac_response_data: Vec<u8>,
    /// True if GPO response contained the cryptogram (tag 9F26)
    cryptogram_in_gpo: bool,
}

impl MastercardKernel {
    pub fn new(config: McAidConfig) -> Self {
        MastercardKernel {
            config,
            application: None,
            transaction_path: None,
            data_authentication: Vec::new(),
            genac_response_data: Vec::new(),
            cryptogram_in_gpo: false,
        }
    }

    /// Set the application (AID) for ODA key chain recovery
    pub fn set_application(&mut self, application: EmvApplication) {
        self.application = Some(application);
    }

    /// Set Kernel 2 specific terminal tags before GPO
    fn set_kernel_tags(&self, conn: &mut EmvConnection) {
        let version = self.config.version_bytes();
        if !version.is_empty() {
            conn.add_tag(tags::TAG_APPLICATION_VERSION_NUMBER_TERMINAL, version);
        }

        // Set terminal capabilities based on whether CVM is required
        let amount = self.get_amount(conn);
        let terminal_caps = if self.config.cvm_required(amount) {
            self.config.terminal_cap_cvm_bytes()
        } else {
            self.config.terminal_cap_no_cvm_bytes()
        };
        conn.add_tag(tags::TAG_TERMINAL_CAPABILITIES, terminal_caps);

        debug!(
            "Kernel 2: Set terminal capabilities for amount={}, CVM required={}",
            amount, self.config.cvm_required(amount)
        );
    }

    fn get_amount(&self, conn: &EmvConnection) -> u64 {
        match conn.get_tag_value(tags::TAG_AMOUNT_AUTHORISED) {
            Some(amount_bcd) => {
                let amount_hex = hex::encode(amount_bcd);
                amount_hex.parse::<u64>().unwrap_or(0)
            }
            None => 0,
        }
    }

    /// Parse AIP and determine transaction path
    fn determine_transaction_path(&self, conn: &EmvConnection) -> TransactionPath {
        if let Some(aip) = conn.get_tag_value(tags::TAG_AIP) {
            if aip.len() >= 2 {
                // ref. EMV Contactless Book C-2, Section 3.3
                // AIP byte 2, bit 8 (0x80): EMV mode (M/Chip) supported
                let emv_mode = (aip[1] & 0x80) != 0;
                if emv_mode {
                    debug!("Kernel 2: AIP byte2={:02X}, M/Chip path (EMV mode)", aip[1]);
                    return TransactionPath::MChip;
                } else {
                    debug!("Kernel 2: AIP byte2={:02X}, Mag Stripe path", aip[1]);
                    return TransactionPath::MagStripe;
                }
            }
        }
        warn!("Kernel 2: AIP missing, defaulting to M/Chip path");
        TransactionPath::MChip
    }

    // ================================================================
    // Card data validation — ref. EMV Book 3, Section 10
    // Sets TVR bits for any issues found
    // ================================================================

    fn validate_card_data(&self, conn: &mut EmvConnection) {
        debug!("Kernel 2: Validating card data");

        // Check mandatory tags
        if conn.get_tag_value(tags::TAG_PAN).is_none() {
            warn!("Kernel 2: PAN (5A) missing");
            conn.settings.terminal.tvr.icc_data_missing = true;
        } else {
            // Validate PAN is not all zeros
            if let Some(pan) = conn.get_tag_value(tags::TAG_PAN) {
                if pan.iter().all(|&b| b == 0x00) {
                    warn!("Kernel 2: PAN is all zeros");
                    conn.settings.terminal.tvr.icc_data_missing = true;
                }
            }
        }

        if conn.get_tag_value(tags::TAG_TRACK2_EQUIVALENT).is_none() {
            warn!("Kernel 2: Track 2 Equivalent Data (57) missing");
            conn.settings.terminal.tvr.icc_data_missing = true;
        }

        if conn.get_tag_value(tags::TAG_CDOL1).is_none() {
            warn!("Kernel 2: CDOL1 (8C) missing — GENERATE AC will fail");
            conn.settings.terminal.tvr.icc_data_missing = true;
        }

        // Check application expiry date (5F24)
        if let Some(expiry) = conn.get_tag_value("5F24") {
            if expiry.len() >= 3 {
                let expiry = expiry.clone();
                self.check_expiry_date(conn, &expiry);
            }
        }

        // Check application version number (9F08 vs 9F09)
        self.check_application_version(conn);

        // Check ODA capability in AIP
        if !conn.icc.capabilities.sda && !conn.icc.capabilities.dda && !conn.icc.capabilities.cda {
            debug!("Kernel 2: Card does not support any ODA method");
            conn.settings.terminal.tvr.offline_data_authentication_was_not_performed = true;
        }

        // Set TVR tag (95) with current TVR state
        let tvr_bytes: Vec<u8> = conn.settings.terminal.tvr.into();
        conn.process_tag_as_tlv("95", tvr_bytes);

        debug!("Kernel 2: Card data validation complete, TVR={:02X?}",
            Into::<Vec<u8>>::into(conn.settings.terminal.tvr));
    }

    fn check_expiry_date(&self, conn: &mut EmvConnection, expiry_bcd: &[u8]) {
        // Expiry is BCD YYMMDD (or YYMM with DD=00)
        if let Ok(ascii) = bcdutil::bcd_to_ascii(expiry_bcd) {
            if let Ok(ascii_str) = std::str::from_utf8(&ascii) {
                let yy = ascii_str.get(0..2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
                let mm = ascii_str.get(2..4).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

                // Assume 2000s for YY
                let expiry_year = 2000 + yy;
                let now = Utc::now().naive_utc().date();

                // Card expires at the end of the month
                if let Some(expiry_date) = NaiveDate::from_ymd_opt(expiry_year as i32, mm, 1) {
                    // Last day of expiry month
                    let expiry_end = if mm == 12 {
                        NaiveDate::from_ymd_opt((expiry_year + 1) as i32, 1, 1)
                    } else {
                        NaiveDate::from_ymd_opt(expiry_year as i32, mm + 1, 1)
                    }.unwrap_or(expiry_date);

                    if now >= expiry_end {
                        warn!("Kernel 2: Application expired ({:02}/{:04})", mm, expiry_year);
                        conn.settings.terminal.tvr.expired_application = true;
                    }
                }

                // Check not yet effective (5F25)
                if let Some(effective) = conn.get_tag_value("5F25") {
                    if effective.len() >= 3 {
                        let effective = effective.clone();
                        if let Ok(eff_ascii) = bcdutil::bcd_to_ascii(&effective) {
                            if let Ok(eff_str) = std::str::from_utf8(&eff_ascii) {
                                let eff_yy = eff_str.get(0..2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
                                let eff_mm = eff_str.get(2..4).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
                                let eff_dd = eff_str.get(4..6).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
                                let eff_year = 2000 + eff_yy;

                                if let Some(eff_date) = NaiveDate::from_ymd_opt(eff_year as i32, eff_mm, eff_dd) {
                                    if now < eff_date {
                                        warn!("Kernel 2: Application not yet effective ({})", eff_date);
                                        conn.settings.terminal.tvr.application_not_yet_effective = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_application_version(&self, conn: &mut EmvConnection) {
        // Compare card's Application Version Number (9F08) with terminal's (9F09)
        let card_version = conn.get_tag_value("9F08");
        let terminal_version = conn.get_tag_value(tags::TAG_APPLICATION_VERSION_NUMBER_TERMINAL);

        if let (Some(card_ver), Some(term_ver)) = (card_version, terminal_version) {
            if card_ver != term_ver {
                debug!(
                    "Kernel 2: App version mismatch: card={:02X?}, terminal={:02X?}",
                    card_ver, term_ver
                );
                conn.settings.terminal.tvr.icc_and_terminal_have_different_application_versions = true;
            }
        }
    }

    // ================================================================
    // M/Chip transaction processing
    // ref. EMV Contactless Book C-2, Section 3
    //
    // Order:
    // 1. Card data validation (TVR population)
    // 2. CVM determination
    // 3. Terminal Action Analysis (TVR + TACs → cryptogram decision)
    // 4. GENERATE AC
    // 5. Post-GENERATE AC CDA validation
    // 6. Outcome mapping
    // ================================================================

    fn process_mchip(
        &mut self,
        conn: &mut EmvConnection,
    ) -> Result<OutcomeParameterSet, KernelError> {
        debug!("Kernel 2: Processing M/Chip transaction");

        // If cryptogram was already in GPO response, skip the full flow
        if self.cryptogram_in_gpo {
            debug!("Kernel 2: Cryptogram returned in GPO response");
            return self.determine_outcome_from_cryptogram(conn);
        }

        // Step 1: Card data validation — populates TVR
        self.validate_card_data(conn);

        // Step 2: CVM determination
        let cvm_outcome = cvm::determine_cvm(conn, &self.config);
        debug!("Kernel 2: CVM determination: {}", cvm_outcome);
        let cvm_results = cvm::build_cvm_results(cvm_outcome);
        conn.process_tag_as_tlv("9F34", cvm_results);

        // Step 3: Terminal Action Analysis — uses TVR + MC TACs to decide cryptogram type
        let taa_decision = taa::perform_taa(conn, &self.config);
        debug!("Kernel 2: TAA decision: {:?}", taa_decision);

        // Step 4: GENERATE AC with TAA-determined cryptogram type
        let cryptogram_type = self.send_generate_ac(conn, taa_decision)?;

        // Step 5: Post-GENERATE AC CDA validation
        if conn.icc.capabilities.cda && conn.settings.terminal.capabilities.cda {
            if conn.get_tag_value(tags::TAG_SIGNED_DYNAMIC_APPLICATION_DATA).is_some() {
                // First recover the public key chain (CA → Issuer → ICC)
                if conn.icc.icc_pk.is_none() {
                    if let Some(ref app) = self.application {
                        if let Err(_) = conn.handle_public_keys(app) {
                            warn!("Kernel 2: Failed to recover public key chain for CDA");
                            conn.settings.terminal.tvr.cda_failed = true;
                        }
                    }
                }

                // If ICC PK is available, validate CDA using Transaction Data Hash
                if conn.icc.icc_pk.is_some() && !self.genac_response_data.is_empty() {
                    let tag_77_data = self.genac_response_data.clone();
                    let tag_77_data_offset = if tag_77_data.len() > 1 {
                        if tag_77_data[1] == 0x81 { 3 }
                        else if tag_77_data[1] == 0x82 { 4 }
                        else { 2 }
                    } else { 2 };

                    if tag_77_data_offset < tag_77_data.len() {
                        match conn.handle_application_cryptogram_card_authentication(
                            &tag_77_data[tag_77_data_offset..],
                            "8C",
                        ) {
                            Ok(()) => {
                                info!("Kernel 2: CDA passed (Transaction Data Hash verified)");
                                conn.settings.terminal.tsi.offline_data_authentication_was_performed = true;
                            }
                            Err(()) => {
                                warn!("Kernel 2: CDA failed");
                                conn.settings.terminal.tvr.cda_failed = true;
                                conn.settings.terminal.tsi.offline_data_authentication_was_performed = true;
                            }
                        }
                    }
                }

                // CDA failure on TC → must decline
                if conn.settings.terminal.tvr.cda_failed {
                    if let CryptogramType::TransactionCertificate = cryptogram_type {
                        warn!("Kernel 2: CDA failed on TC — declining");
                        return Ok(OutcomeParameterSet::declined());
                    }
                    // CDA failure on ARQC → continue (issuer authenticates online)
                }
            } else {
                debug!("Kernel 2: No SDAD (9F4B) in GENERATE AC response");
                conn.settings.terminal.tvr.offline_data_authentication_was_not_performed = true;
            }
        }

        // Update TVR tag with final state
        let tvr_bytes: Vec<u8> = conn.settings.terminal.tvr.into();
        conn.process_tag_as_tlv("95", tvr_bytes);

        // Step 6: Map cryptogram to outcome
        match cryptogram_type {
            CryptogramType::TransactionCertificate => {
                info!("Kernel 2: Card approved offline (TC)");
                Ok(OutcomeParameterSet::approved(cvm_outcome))
            }
            CryptogramType::AuthorisationRequestCryptogram => {
                info!("Kernel 2: Card requests online authorization (ARQC)");
                Ok(OutcomeParameterSet::online_request(cvm_outcome))
            }
            CryptogramType::ApplicationAuthenticationCryptogram => {
                info!("Kernel 2: Card declined (AAC)");
                Ok(OutcomeParameterSet::declined())
            }
        }
    }

    /// Build and send GENERATE AC command
    /// ref. EMV Contactless Book C-2, Section 7.6
    fn send_generate_ac(
        &mut self,
        conn: &mut EmvConnection,
        requested_type: CryptogramType,
    ) -> Result<CryptogramType, KernelError> {
        let mut p1: u8 = requested_type.into();

        // Request CDA if card and terminal both support it
        if conn.icc.capabilities.cda && conn.settings.terminal.capabilities.cda {
            p1 |= 0x10; // Set CDA bit
        }

        // Get CDOL1 from card
        let cdol1_data = match conn.get_tag_value(tags::TAG_CDOL1) {
            Some(cdol1) => {
                let cdol_list = DataObjectList::process_data_object_list(conn, &cdol1[..])
                    .map_err(|_| KernelError::CardDataMissing("Failed to parse CDOL1".into()))?;
                cdol_list.get_tag_list_tag_values(conn)
            }
            None => {
                return Err(KernelError::CardDataMissing("CDOL1 (tag 8C) not found".into()));
            }
        };

        // Build GENERATE AC APDU: 80 AE P1 00 Lc [CDOL data] 00
        let mut apdu = vec![0x80, 0xAE, p1, 0x00];
        apdu.push(cdol1_data.len() as u8);
        apdu.extend_from_slice(&cdol1_data);
        apdu.push(0x00); // Le

        debug!("Kernel 2: Sending GENERATE AC (P1={:02X}, requested={:?})", p1, requested_type);
        let (response_trailer, response_data) = conn.send_apdu(&apdu);

        if !is_success_response(&response_trailer) {
            warn!("Kernel 2: GENERATE AC failed: {:02X}{:02X}",
                response_trailer[0], response_trailer[1]);
            return Err(KernelError::ApduError(format!(
                "GENERATE AC failed: {:02X}{:02X}",
                response_trailer[0], response_trailer[1]
            )));
        }

        if response_data.is_empty() {
            return Err(KernelError::ParsingError("Empty GENERATE AC response".into()));
        }

        // Store raw response for CDA validation
        self.genac_response_data = response_data.clone();

        // Parse response
        if response_data[0] == 0x80 {
            // Format 1: 80 len CID ATC AC [IAD]
            conn.process_tag_as_tlv("9F27", response_data[2..3].to_vec());
            conn.process_tag_as_tlv("9F36", response_data[3..5].to_vec());
            conn.process_tag_as_tlv("9F26", response_data[5..13].to_vec());
            if response_data.len() > 13 {
                conn.process_tag_as_tlv("9F10", response_data[13..].to_vec());
            }
        } else if response_data[0] != 0x77 {
            return Err(KernelError::ParsingError("Unexpected GENERATE AC response format".into()));
        }
        // Format 2 (0x77): already parsed by send_apdu's auto-TLV processing

        // Extract cryptogram type from CID (tag 9F27)
        let cid = conn.get_tag_value(tags::TAG_CRYPTOGRAM_INFO_DATA)
            .ok_or_else(|| KernelError::CardDataMissing("CID (9F27) not in response".into()))?;

        let cryptogram_type = CryptogramType::try_from(cid[0])
            .map_err(|_| KernelError::ParsingError("Unknown cryptogram type in CID".into()))?;

        debug!("Kernel 2: GENERATE AC returned {:?} (requested {:?})", cryptogram_type, requested_type);
        Ok(cryptogram_type)
    }

    /// Determine outcome when cryptogram was returned in GPO response
    fn determine_outcome_from_cryptogram(
        &self,
        conn: &mut EmvConnection,
    ) -> Result<OutcomeParameterSet, KernelError> {
        let cid = conn.get_tag_value(tags::TAG_CRYPTOGRAM_INFO_DATA)
            .ok_or_else(|| KernelError::CardDataMissing("CID (9F27) not in GPO response".into()))?
            .clone();

        let cryptogram_type = CryptogramType::try_from(cid[0])
            .map_err(|_| KernelError::ParsingError("Unknown cryptogram type".into()))?;

        // Still do validation and CVM for cryptogram-in-GPO
        self.validate_card_data(conn);
        let cvm_outcome = cvm::determine_cvm(conn, &self.config);
        let cvm_results = cvm::build_cvm_results(cvm_outcome);
        conn.process_tag_as_tlv("9F34", cvm_results);

        match cryptogram_type {
            CryptogramType::TransactionCertificate => {
                info!("Kernel 2: GPO cryptogram is TC — approved offline");
                Ok(OutcomeParameterSet::approved(cvm_outcome))
            }
            CryptogramType::AuthorisationRequestCryptogram => {
                info!("Kernel 2: GPO cryptogram is ARQC — online request");
                Ok(OutcomeParameterSet::online_request(cvm_outcome))
            }
            CryptogramType::ApplicationAuthenticationCryptogram => {
                info!("Kernel 2: GPO cryptogram is AAC — declined");
                Ok(OutcomeParameterSet::declined())
            }
        }
    }
}

impl ContactlessKernel for MastercardKernel {
    fn kernel_id(&self) -> u8 {
        tags::KERNEL_ID_MASTERCARD
    }

    fn kernel_name(&self) -> &str {
        "Mastercard Kernel 2"
    }

    /// Application initiation: set kernel tags, build PDOL, send GPO
    fn initiate_application(
        &mut self,
        conn: &mut EmvConnection,
        _fci_data: &[u8],
    ) -> Result<(), KernelError> {
        info!("Kernel 2: Initiating Mastercard contactless application");

        self.set_kernel_tags(conn);

        debug!("Kernel 2: Sending GET PROCESSING OPTIONS");
        let apdu_gpo = b"\x80\xA8\x00\x00";
        let mut gpo_command = apdu_gpo.to_vec();

        match conn.get_tag_value(tags::TAG_PDOL) {
            Some(pdol) => {
                let pdol_data = DataObjectList::process_data_object_list(conn, &pdol[..])
                    .map_err(|_| KernelError::ParsingError("Failed to parse PDOL".into()))?
                    .get_tag_list_tag_values(conn);

                gpo_command.push((pdol_data.len() + 2) as u8);
                gpo_command.push(0x83);
                gpo_command.push(pdol_data.len() as u8);
                gpo_command.extend_from_slice(&pdol_data);
                gpo_command.push(0x00);
            }
            None => {
                gpo_command.push(0x02);
                gpo_command.push(0x83);
                gpo_command.push(0x00);
            }
        }

        let (response_trailer, response_data) = conn.send_apdu(&gpo_command);
        if !is_success_response(&response_trailer) {
            warn!("Kernel 2: GET PROCESSING OPTIONS failed");
            return Err(KernelError::ApduError("GPO failed".into()));
        }

        if response_data.is_empty() {
            return Err(KernelError::ParsingError("Empty GPO response".into()));
        }

        if response_data[0] == 0x80 {
            if response_data.len() < 4 {
                return Err(KernelError::ParsingError("GPO Format 1 too short".into()));
            }
            conn.process_tag_as_tlv("82", response_data[2..4].to_vec());
            if response_data.len() > 4 {
                conn.process_tag_as_tlv("94", response_data[4..].to_vec());
            }
        } else if response_data[0] != 0x77 {
            return Err(KernelError::ParsingError("Unexpected GPO response format".into()));
        }

        if conn.get_tag_value(tags::TAG_APPLICATION_CRYPTOGRAM).is_some() {
            debug!("Kernel 2: Cryptogram (9F26) present in GPO response");
            self.cryptogram_in_gpo = true;
        }

        // Parse AIP for ICC capabilities
        if let Some(aip) = conn.get_tag_value(tags::TAG_AIP) {
            let aip = aip.clone();
            let aip_b1 = aip[0];
            conn.icc.capabilities.sda = (aip_b1 & 0x40) != 0;
            conn.icc.capabilities.dda = (aip_b1 & 0x20) != 0;
            conn.icc.capabilities.cda = (aip_b1 & 0x01) != 0;
            conn.icc.capabilities.terminal_risk_management = (aip_b1 & 0x08) != 0;
            conn.icc.capabilities.issuer_authentication = (aip_b1 & 0x04) != 0;

            debug!(
                "Kernel 2: AIP={:02X?} — SDA={}, DDA={}, CDA={}, CVM={}",
                aip, conn.icc.capabilities.sda, conn.icc.capabilities.dda,
                conn.icc.capabilities.cda, (aip_b1 & 0x10) != 0
            );
        }

        self.transaction_path = Some(self.determine_transaction_path(conn));
        info!("Kernel 2: Transaction path = {}", self.transaction_path.unwrap());

        Ok(())
    }

    /// Read card data from AFL
    fn read_card_data(
        &mut self,
        conn: &mut EmvConnection,
    ) -> Result<TransactionPath, KernelError> {
        let path = self.transaction_path
            .ok_or_else(|| KernelError::ConfigError("Transaction path not determined".into()))?;

        let afl = match conn.get_tag_value(tags::TAG_AFL) {
            Some(afl) => afl.clone(),
            None => {
                if self.cryptogram_in_gpo {
                    debug!("Kernel 2: No AFL, cryptogram in GPO — skipping READ RECORD");
                    return Ok(path);
                }
                return Err(KernelError::CardDataMissing("AFL (tag 94) not found".into()));
            }
        };

        if afl.len() % 4 != 0 {
            return Err(KernelError::ParsingError("AFL length not multiple of 4".into()));
        }

        debug!("Kernel 2: Reading application data from AFL ({} entries)", afl.len() / 4);
        self.data_authentication.clear();

        for i in (0..afl.len()).step_by(4) {
            let sfi = afl[i] >> 3;
            let record_start = afl[i + 1];
            let record_end = afl[i + 2];
            let mut oda_records = afl[i + 3];

            for record_idx in record_start..=record_end {
                let apdu = vec![0x00, 0xB2, record_idx, (sfi << 3) | 0x04, 0x00];
                let (response_trailer, response_data) = conn.send_apdu(&apdu);

                if !is_success_response(&response_trailer) {
                    warn!("Kernel 2: READ RECORD failed for SFI={} record={}", sfi, record_idx);
                    continue;
                }

                if response_data.is_empty() || response_data[0] != 0x70 {
                    warn!("Kernel 2: Unexpected READ RECORD response format");
                    continue;
                }

                if oda_records > 0 {
                    oda_records -= 1;
                    if sfi <= 10 {
                        let inner_offset = if response_data.len() > 1 {
                            if response_data[1] == 0x81 { 3 }
                            else if response_data[1] == 0x82 { 4 }
                            else { 2 }
                        } else { 2 };
                        if inner_offset < response_data.len() {
                            self.data_authentication.extend_from_slice(&response_data[inner_offset..]);
                        }
                    } else {
                        self.data_authentication.extend_from_slice(&response_data);
                    }
                    trace!("Kernel 2: ODA data: SFI={}, record={}, total={}", sfi, record_idx, self.data_authentication.len());
                }
            }
        }

        debug!("Kernel 2: Read complete. ODA data={} bytes, Path={}", self.data_authentication.len(), path);
        conn.icc.data_authentication = Some(self.data_authentication.clone());

        Ok(path)
    }

    /// Process the transaction based on the determined path
    fn process_transaction(
        &mut self,
        conn: &mut EmvConnection,
        path: TransactionPath,
    ) -> Result<OutcomeParameterSet, KernelError> {
        info!("Kernel 2: Processing transaction on {} path", path);

        match path {
            TransactionPath::MChip => self.process_mchip(conn),
            TransactionPath::MagStripe => {
                warn!("Kernel 2: Mag Stripe path not implemented, falling back to TryAnotherInterface");
                Ok(OutcomeParameterSet::try_another_interface())
            }
        }
    }
}

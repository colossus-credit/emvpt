// Integration tests for Mastercard Contactless Kernel 2
// Tests the kernel components: config, CVM, outcome, entry point

use emvpt::contactless::kernel2::config::*;
use emvpt::contactless::kernel2::cvm;
use emvpt::contactless::outcome::*;
use emvpt::contactless::kernel_trait::*;
use emvpt::contactless::entry_point;
use emvpt::contactless::tags;

// ============================================================
// Config tests
// ============================================================

#[test]
fn test_mc_aid_config_defaults() {
    let yaml = r#"
        aid: 'A0000000041010'
    "#;
    let config: McAidConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.kernel_id, 0x02);
    assert_eq!(config.floor_limit, 0);
    assert_eq!(config.contactless_transaction_limit, 10000);
    assert_eq!(config.cvm_required_limit, 5000);
    assert!(!config.force_online);
}

#[test]
fn test_mc_aid_config_full() {
    let yaml = r#"
        aid: 'A0000000041010'
        kernel_id: 2
        version: '0002'
        tac_denial: 'FF00000000'
        tac_online: 'F850ACF800'
        tac_default: 'F850ACF800'
        floor_limit: 100
        contactless_transaction_limit: 25000
        contactless_transaction_limit_cdcvm: 50000
        cvm_required_limit: 10000
        terminal_cap_no_cvm: 'E008C8'
        terminal_cap_cvm: 'E068C8'
        kernel_configuration: 0
        force_online: true
    "#;
    let config: McAidConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.floor_limit, 100);
    assert_eq!(config.contactless_transaction_limit, 25000);
    assert_eq!(config.contactless_transaction_limit_cdcvm, 50000);
    assert_eq!(config.cvm_required_limit, 10000);
    assert!(config.force_online);
    assert_eq!(config.tac_denial_bytes(), vec![0xFF, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(config.tac_online_bytes(), vec![0xF8, 0x50, 0xAC, 0xF8, 0x00]);
}

#[test]
fn test_mc_aid_config_limit_checks() {
    let config = McAidConfig {
        aid: "A0000000041010".to_string(),
        kernel_id: 2,
        version: "0002".to_string(),
        tac_denial: "0000000000".to_string(),
        tac_online: "0000000000".to_string(),
        tac_default: "0000000000".to_string(),
        floor_limit: 100,
        contactless_transaction_limit: 10000,
        contactless_transaction_limit_cdcvm: 30000,
        cvm_required_limit: 5000,
        terminal_cap_no_cvm: "E008C8".to_string(),
        terminal_cap_cvm: "E068C8".to_string(),
        kernel_configuration: 0,
        risk_management_data: None,
        force_online: false,
    };

    // Floor limit
    assert!(!config.floor_limit_exceeded(50));
    assert!(!config.floor_limit_exceeded(100));
    assert!(config.floor_limit_exceeded(101));

    // CVM required
    assert!(!config.cvm_required(4999));
    assert!(!config.cvm_required(5000));
    assert!(config.cvm_required(5001));

    // Transaction limit
    assert!(!config.exceeds_transaction_limit(10000, false));
    assert!(config.exceeds_transaction_limit(10001, false));
    assert!(!config.exceeds_transaction_limit(30000, true)); // CDCVM limit
    assert!(config.exceeds_transaction_limit(30001, true));
}

#[test]
fn test_mc_aid_config_hex_conversion() {
    let config = McAidConfig {
        aid: "A0000000041010".to_string(),
        kernel_id: 2,
        version: "0096".to_string(),
        tac_denial: "0000000000".to_string(),
        tac_online: "0000000000".to_string(),
        tac_default: "0000000000".to_string(),
        floor_limit: 0,
        contactless_transaction_limit: 10000,
        contactless_transaction_limit_cdcvm: 10000,
        cvm_required_limit: 5000,
        terminal_cap_no_cvm: "E008C8".to_string(),
        terminal_cap_cvm: "E068C8".to_string(),
        kernel_configuration: 0,
        risk_management_data: None,
        force_online: false,
    };

    assert_eq!(config.aid_bytes(), vec![0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10]);
    assert_eq!(config.version_bytes(), vec![0x00, 0x96]);
    assert_eq!(config.terminal_cap_no_cvm_bytes(), vec![0xE0, 0x08, 0xC8]);
    assert_eq!(config.terminal_cap_cvm_bytes(), vec![0xE0, 0x68, 0xC8]);
}

// ============================================================
// ContactlessKernelSettings tests
// ============================================================

#[test]
fn test_kernel_settings_find_mc_config() {
    let yaml = r#"
        mastercard:
          aids:
            - aid: 'A0000000041010'
              floor_limit: 100
            - aid: 'A0000000043060'
              floor_limit: 200
    "#;
    let settings: ContactlessKernelSettings = serde_yaml::from_str(yaml).unwrap();

    // Match Mastercard Credit
    let mc_credit = hex::decode("A0000000041010").unwrap();
    let config = settings.find_mc_config(&mc_credit).unwrap();
    assert_eq!(config.floor_limit, 100);

    // Match Maestro
    let maestro = hex::decode("A0000000043060").unwrap();
    let config = settings.find_mc_config(&maestro).unwrap();
    assert_eq!(config.floor_limit, 200);

    // No match for Visa
    let visa = hex::decode("A0000000031010").unwrap();
    assert!(settings.find_mc_config(&visa).is_none());
}

#[test]
fn test_kernel_settings_deserialization_from_settings_yaml() {
    let yaml = r#"
        censor_sensitive_fields: false
        configuration_files:
          emv_tags: 'emv_tags.yaml'
          scheme_ca_public_keys: 'scheme_ca_public_keys_test.yaml'
          constants: 'constants.yaml'
        terminal:
          use_random: true
          capabilities:
            sda: true
            dda: true
            cda: true
            plaintext_pin: true
            enciphered_pin: true
            terminal_risk_management: true
            issuer_authentication: false
          tvr:
            offline_data_authentication_was_not_performed: false
            sda_failed: false
            icc_data_missing: false
            card_appears_on_terminal_exception_file: false
            dda_failed: false
            cda_failed: false
            icc_and_terminal_have_different_application_versions: false
            expired_application: false
            application_not_yet_effective: false
            requested_service_not_allowed_for_card_product: false
            new_card: false
            cardholder_verification_was_not_successful: false
            unrecognised_cvm: false
            pin_try_limit_exceeded: false
            pin_entry_required_and_pin_pad_not_present_or_not_working: false
            pin_entry_required_pin_pad_present_but_pin_was_not_entered: false
            online_pin_entered: false
            transaction_exceeds_floor_limit: false
            lower_consecutive_offline_limit_exceeded: false
            upper_consecutive_offline_limit_exceeded: false
            transaction_selected_randomly_for_online_processing: false
            merchant_forced_transaction_online: false
            default_tdol_used: false
            issuer_authentication_failed: false
            script_processing_failed_before_final_generate_ac: false
            script_processing_failed_after_final_generate_ac: false
          tsi:
            offline_data_authentication_was_performed: false
            cardholder_verification_was_performed: false
            card_risk_management_was_performed: false
            issuer_authentication_was_performed: false
            terminal_risk_management_was_performed: false
            script_processing_was_performed: false
          terminal_transaction_qualifiers:
            mag_stripe_mode_supported: false
            emv_mode_supported: true
            emv_contact_chip_supported: true
            offline_only_reader: false
            online_pin_supported: false
            signature_supported: true
            offline_data_authentication_for_online_authorizations_supported: true
            online_cryptogram_required: false
            cvm_required: false
            contact_chip_offline_pin_supported: true
            issuer_update_processing_supported: false
            consumer_device_cvm_supported: false
          c4_enhanced_contactless_reader_capabilities:
            contact_mode_supported: true
            contactless_mag_stripe_mode_supported: true
            contactless_emv_full_online_mode_not_supported: false
            contactless_emv_partial_online_mode_supported: false
            contactless_mode_supported: true
            try_another_interface_after_decline: true
            mobile_cvm_supported: true
            online_pin_supported: false
            signature: true
            plaintext_offline_pin: true
            reader_is_offline_only: true
            cvm_required: false
            terminal_exempt_from_no_cvm_checks: false
            delayed_authorisation_terminal: false
            transit_terminal: false
            c4_kernel_version: 3
          cryptogram_type: 'AuthorisationRequestCryptogram'
          cryptogram_type_arqc: 'TransactionCertificate'
        contactless_kernels:
          mastercard:
            aids:
              - aid: 'A0000000041010'
                kernel_id: 2
                floor_limit: 0
                contactless_transaction_limit: 10000
                cvm_required_limit: 5000
        default_tags:
          '9F1A': '0246'
          '5F2A': '0978'
          '9C': '21'
          '9F35': '23'
    "#;

    let settings: emvpt::Settings = serde_yaml::from_str(yaml).unwrap();
    assert!(settings.contactless_kernels.is_some());
    let ck = settings.contactless_kernels.as_ref().unwrap();
    assert!(ck.mastercard.is_some());
    let mc = ck.mastercard.as_ref().unwrap();
    assert_eq!(mc.aids.len(), 1);
    assert_eq!(mc.aids[0].aid, "A0000000041010");
    assert_eq!(mc.aids[0].contactless_transaction_limit, 10000);
}

// ============================================================
// Outcome tests
// ============================================================

#[test]
fn test_outcome_approved() {
    let outcome = OutcomeParameterSet::approved(CvmOutcome::NoCvm);
    assert_eq!(outcome.outcome, OutcomeType::Approved);
    assert_eq!(outcome.cvm, CvmOutcome::NoCvm);
    assert!(outcome.data_record_present);
    assert!(!outcome.receipt); // No CVM = no receipt
}

#[test]
fn test_outcome_approved_with_cvm() {
    let outcome = OutcomeParameterSet::approved(CvmOutcome::OnlinePin);
    assert_eq!(outcome.outcome, OutcomeType::Approved);
    assert_eq!(outcome.cvm, CvmOutcome::OnlinePin);
    assert!(outcome.receipt); // CVM = receipt required
}

#[test]
fn test_outcome_declined() {
    let outcome = OutcomeParameterSet::declined();
    assert_eq!(outcome.outcome, OutcomeType::Declined);
    assert_eq!(outcome.cvm, CvmOutcome::NoCvm);
    assert!(!outcome.receipt);
}

#[test]
fn test_outcome_online_request() {
    let outcome = OutcomeParameterSet::online_request(CvmOutcome::OnlinePin);
    assert_eq!(outcome.outcome, OutcomeType::OnlineRequest);
    assert!(outcome.online_response_data);
    assert!(outcome.receipt);
    assert!(outcome.data_record_present);
}

#[test]
fn test_outcome_try_another_interface() {
    let outcome = OutcomeParameterSet::try_another_interface();
    assert_eq!(outcome.outcome, OutcomeType::TryAnotherInterface);
    assert_eq!(
        outcome.alternate_interface_preference,
        AlternateInterfacePreference::Contact
    );
}

#[test]
fn test_outcome_display() {
    let outcome = OutcomeParameterSet::online_request(CvmOutcome::ConfirmationCodeVerified);
    let display = format!("{}", outcome);
    assert!(display.contains("ONLINE REQUEST"));
    assert!(display.contains("CDCVM"));
}

// ============================================================
// Entry point tests
// ============================================================

#[test]
fn test_entry_point_select_kernel_mastercard() {
    let yaml = r#"
        mastercard:
          aids:
            - aid: 'A0000000041010'
              floor_limit: 0
    "#;
    let settings: ContactlessKernelSettings = serde_yaml::from_str(yaml).unwrap();
    let mut conn = emvpt::EmvConnection::new("").unwrap();

    let mc_aid = hex::decode("A0000000041010").unwrap();
    let (kernel, _preprocessing) = entry_point::select_kernel(&mc_aid, &settings, &mut conn).unwrap();
    assert_eq!(kernel.kernel_id(), tags::KERNEL_ID_MASTERCARD);
    assert_eq!(kernel.kernel_name(), "Mastercard Kernel 2");
}

#[test]
fn test_entry_point_select_kernel_unknown_aid() {
    let yaml = r#"
        mastercard:
          aids:
            - aid: 'A0000000041010'
    "#;
    let settings: ContactlessKernelSettings = serde_yaml::from_str(yaml).unwrap();
    let mut conn = emvpt::EmvConnection::new("").unwrap();

    // Visa AID — no kernel available
    let visa_aid = hex::decode("A0000000031010").unwrap();
    assert!(entry_point::select_kernel(&visa_aid, &settings, &mut conn).is_err());
}

#[test]
fn test_entry_point_select_kernel_maestro() {
    let yaml = r#"
        mastercard:
          aids:
            - aid: 'A0000000041010'
            - aid: 'A0000000043060'
    "#;
    let settings: ContactlessKernelSettings = serde_yaml::from_str(yaml).unwrap();
    let mut conn = emvpt::EmvConnection::new("").unwrap();

    let maestro_aid = hex::decode("A0000000043060").unwrap();
    let (kernel, _) = entry_point::select_kernel(&maestro_aid, &settings, &mut conn).unwrap();
    assert_eq!(kernel.kernel_id(), 0x02);
}

// ============================================================
// CVM CTQ/TTQ parsing tests (delegates to cvm module tests)
// ============================================================

#[test]
fn test_ctq_cdcvm_performed() {
    let ctq = cvm::Ctq::from_bytes(&[0x00, 0x80]);
    assert!(ctq.cdcvm_performed);
}

#[test]
fn test_ctq_online_pin_and_signature() {
    let ctq = cvm::Ctq::from_bytes(&[0x03, 0x00]);
    assert!(ctq.online_pin_required);
    assert!(ctq.signature_required);
    assert!(!ctq.cdcvm_performed);
}

#[test]
fn test_ctq_switch_interface_flags() {
    let ctq = cvm::Ctq::from_bytes(&[0x68, 0x00]);
    assert!(ctq.switch_interface_for_cash);
    assert!(ctq.switch_interface_for_cashback);
    assert!(ctq.switch_interface_if_oda_fails);
}

#[test]
fn test_ttq_all_cvm_supported() {
    let ttq = cvm::Ttq::from_bytes(&[0x16, 0xC0]);
    assert!(ttq.emv_mode_supported);
    assert!(ttq.online_pin_supported);
    assert!(ttq.signature_supported);
    assert!(ttq.cvm_required);
    assert!(ttq.cdcvm_supported);
}

#[test]
fn test_cvm_results_tag_encoding() {
    // No CVM
    let result = cvm::build_cvm_results(CvmOutcome::NoCvm);
    assert_eq!(result, vec![0x1F, 0x00, 0x02]);

    // Online PIN
    let result = cvm::build_cvm_results(CvmOutcome::OnlinePin);
    assert_eq!(result, vec![0x02, 0x00, 0x00]);

    // Signature
    let result = cvm::build_cvm_results(CvmOutcome::ObtainSignature);
    assert_eq!(result, vec![0x1E, 0x00, 0x00]);
}

// ============================================================
// Error indication tests
// ============================================================

#[test]
fn test_error_indication_ok() {
    let err = ErrorIndication::ok();
    assert_eq!(err.l2_error, L2Error::Ok);
    assert_eq!(err.sw1, 0x90);
    assert_eq!(err.sw2, 0x00);
}

#[test]
fn test_error_indication_card_data_missing() {
    let err = ErrorIndication::card_data_missing("Missing CTQ");
    assert_eq!(err.l2_error, L2Error::CardDataMissing);
    assert_eq!(err.message, "Missing CTQ");
}

#[test]
fn test_error_indication_status_bytes() {
    let err = ErrorIndication::status_bytes(0x69, 0x85);
    assert_eq!(err.l2_error, L2Error::StatusBytes);
    assert_eq!(err.sw1, 0x69);
    assert_eq!(err.sw2, 0x85);
    assert!(err.message.contains("6985"));
}

// ============================================================
// Kernel trait interface test
// ============================================================

#[test]
fn test_mastercard_kernel_creation() {
    let config = McAidConfig {
        aid: "A0000000041010".to_string(),
        kernel_id: 2,
        version: "0002".to_string(),
        tac_denial: "0000000000".to_string(),
        tac_online: "F850ACF800".to_string(),
        tac_default: "F850ACF800".to_string(),
        floor_limit: 0,
        contactless_transaction_limit: 10000,
        contactless_transaction_limit_cdcvm: 30000,
        cvm_required_limit: 5000,
        terminal_cap_no_cvm: "E008C8".to_string(),
        terminal_cap_cvm: "E068C8".to_string(),
        kernel_configuration: 0,
        risk_management_data: None,
        force_online: false,
    };

    let kernel = emvpt::contactless::kernel2::MastercardKernel::new(config);
    assert_eq!(kernel.kernel_id(), 0x02);
    assert_eq!(kernel.kernel_name(), "Mastercard Kernel 2");
}

// ============================================================
// Outcome encoding tests (DF8129)
// ============================================================

#[test]
fn test_outcome_to_bytes_approved_no_cvm() {
    let outcome = OutcomeParameterSet::approved(CvmOutcome::NoCvm);
    let bytes = outcome.to_bytes();
    assert_eq!(bytes.len(), 8);
    assert_eq!(bytes[0], 0x10); // Approved
    assert_eq!(bytes[3], 0x00); // No CVM
    assert!((bytes[4] & 0x20) != 0); // Data record present
    assert!((bytes[4] & 0x08) == 0); // No receipt (no CVM)
}

#[test]
fn test_outcome_to_bytes_online_pin() {
    let outcome = OutcomeParameterSet::online_request(CvmOutcome::OnlinePin);
    let bytes = outcome.to_bytes();
    assert_eq!(bytes[0], 0x30); // OnlineRequest
    assert_eq!(bytes[3], 0x20); // Online PIN
    assert!((bytes[2] & 0x80) != 0); // Online response data
    assert!((bytes[4] & 0x08) != 0); // Receipt required
}

#[test]
fn test_outcome_to_bytes_declined() {
    let outcome = OutcomeParameterSet::declined();
    let bytes = outcome.to_bytes();
    assert_eq!(bytes[0], 0x20); // Declined
    assert_eq!(bytes[3], 0x00); // No CVM
    assert!((bytes[4] & 0x08) == 0); // No receipt
}

#[test]
fn test_outcome_to_bytes_try_another_interface() {
    let outcome = OutcomeParameterSet::try_another_interface();
    let bytes = outcome.to_bytes();
    assert_eq!(bytes[0], 0x60); // TryAnotherInterface
    assert_eq!(bytes[5], 0x01); // Contact preference
}

// ============================================================
// TAA tests
// ============================================================

#[test]
fn test_taa_bitwise_match() {
    // TAA's bitwise_match is tested internally via the taa module tests
    // Here we test the integration with EmvConnection

    // A clean TVR (all zeros) should never match any TAC
    // So TAA should return TC (offline approval)
    let mut conn = emvpt::EmvConnection::new("").unwrap();
    let config = McAidConfig {
        aid: "A0000000041010".to_string(),
        kernel_id: 2,
        version: "0002".to_string(),
        tac_denial: "0000000000".to_string(),
        tac_online: "0000000000".to_string(),
        tac_default: "0000000000".to_string(),
        floor_limit: 0,
        contactless_transaction_limit: 10000,
        contactless_transaction_limit_cdcvm: 30000,
        cvm_required_limit: 5000,
        terminal_cap_no_cvm: "E008C8".to_string(),
        terminal_cap_cvm: "E068C8".to_string(),
        kernel_configuration: 0,
        risk_management_data: None,
        force_online: false,
    };

    // Clean TVR → TC
    let result = emvpt::contactless::kernel2::taa::perform_taa(&conn, &config);
    assert!(matches!(result, emvpt::CryptogramType::TransactionCertificate));
}

#[test]
fn test_taa_force_online() {
    let conn = emvpt::EmvConnection::new("").unwrap();
    let mut config = McAidConfig {
        aid: "A0000000041010".to_string(),
        kernel_id: 2,
        version: "0002".to_string(),
        tac_denial: "0000000000".to_string(),
        tac_online: "0000000000".to_string(),
        tac_default: "0000000000".to_string(),
        floor_limit: 0,
        contactless_transaction_limit: 10000,
        contactless_transaction_limit_cdcvm: 30000,
        cvm_required_limit: 5000,
        terminal_cap_no_cvm: "E008C8".to_string(),
        terminal_cap_cvm: "E068C8".to_string(),
        kernel_configuration: 0,
        risk_management_data: None,
        force_online: true,
    };

    let result = emvpt::contactless::kernel2::taa::perform_taa(&conn, &config);
    assert!(matches!(result, emvpt::CryptogramType::AuthorisationRequestCryptogram));
}

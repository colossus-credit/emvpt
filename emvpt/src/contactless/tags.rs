// Kernel 2 (Mastercard) proprietary tag constants
// ref. EMV Contactless Book C-2, Annex A - Data Dictionary

// Terminal Action Codes (Kernel 2 specific)
pub const TAG_TAC_DEFAULT: &str = "DF8120";
pub const TAG_TAC_DENIAL: &str = "DF8121";
pub const TAG_TAC_ONLINE: &str = "DF8122";

// Reader limits
pub const TAG_READER_CONTACTLESS_FLOOR_LIMIT: &str = "DF8123";
pub const TAG_READER_CL_TRANSACTION_LIMIT_NO_CDCVM: &str = "DF8124";
pub const TAG_READER_CL_TRANSACTION_LIMIT_CDCVM: &str = "DF8125";
pub const TAG_READER_CVM_REQUIRED_LIMIT: &str = "DF8126";

// Kernel configuration and identification
pub const TAG_KERNEL_ID: &str = "DF811B";
pub const TAG_KERNEL_CONFIGURATION: &str = "DF811B";

// Terminal capabilities (Kernel 2 split)
pub const TAG_TERMINAL_CAPABILITIES_CL1: &str = "DF811D"; // Card Data Input
pub const TAG_TERMINAL_CAPABILITIES_CL2: &str = "DF811E"; // CVM Capability (CVM Required)
pub const TAG_TERMINAL_CAPABILITIES_CL3: &str = "DF811F"; // Security Capability

// Error and outcome
pub const TAG_ERROR_INDICATION: &str = "DF8115";
pub const TAG_USER_INTERFACE_REQUEST_DATA: &str = "DF8116";
pub const TAG_OUTCOME_PARAMETER_SET: &str = "DF8129";

// IDS
pub const TAG_IDS_STATUS: &str = "DF8128";

// Card Transaction Qualifiers (from card)
pub const TAG_CTQ: &str = "9F6C";

// Third Party Data / Form Factor Indicator
pub const TAG_THIRD_PARTY_DATA: &str = "9F6E";

// Terminal Transaction Qualifiers (already in base EMV as 9F66)
pub const TAG_TTQ: &str = "9F66";

// Standard EMV tags used heavily by Kernel 2
pub const TAG_AIP: &str = "82";
pub const TAG_AFL: &str = "94";
pub const TAG_PDOL: &str = "9F38";
pub const TAG_CDOL1: &str = "8C";
pub const TAG_CDOL2: &str = "8D";
pub const TAG_CVM_LIST: &str = "8E";
pub const TAG_CRYPTOGRAM_INFO_DATA: &str = "9F27";
pub const TAG_APPLICATION_CRYPTOGRAM: &str = "9F26";
pub const TAG_ATC: &str = "9F36";
pub const TAG_ISSUER_APPLICATION_DATA: &str = "9F10";
pub const TAG_TRACK2_EQUIVALENT: &str = "57";
pub const TAG_PAN: &str = "5A";
pub const TAG_AMOUNT_AUTHORISED: &str = "9F02";
pub const TAG_AMOUNT_OTHER: &str = "9F03";
pub const TAG_TERMINAL_COUNTRY_CODE: &str = "9F1A";
pub const TAG_TRANSACTION_CURRENCY_CODE: &str = "5F2A";
pub const TAG_TRANSACTION_TYPE: &str = "9C";
pub const TAG_UNPREDICTABLE_NUMBER: &str = "9F37";
pub const TAG_TERMINAL_CAPABILITIES: &str = "9F33";
pub const TAG_ADDITIONAL_TERMINAL_CAPABILITIES: &str = "9F40";
pub const TAG_TERMINAL_TYPE: &str = "9F35";
pub const TAG_RISK_MANAGEMENT_DATA: &str = "9F1D";
pub const TAG_APPLICATION_VERSION_NUMBER_TERMINAL: &str = "9F09";
pub const TAG_SIGNED_DYNAMIC_APPLICATION_DATA: &str = "9F4B";

// Mastercard AID prefixes
pub const MASTERCARD_RID: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x04];
pub const MASTERCARD_CREDIT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10];
pub const MAESTRO_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60];

// Custom RID (emv-card-sim default profile)
pub const CUSTOM_RID: &[u8] = &[0xA0, 0x00, 0x00, 0x09, 0x51];

pub const KERNEL_ID_MASTERCARD: u8 = 0x02;

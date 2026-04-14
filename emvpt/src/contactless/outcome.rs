// EMV Contactless Kernel outcome types
// ref. EMV Contactless Book C-2, Section 4.1 - Outcome

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutcomeType {
    Approved = 0x10,
    Declined = 0x20,
    OnlineRequest = 0x30,
    EndApplication = 0x40,
    SelectNext = 0x50,
    TryAnotherInterface = 0x60,
    TryAgain = 0x70,
}

impl fmt::Display for OutcomeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OutcomeType::Approved => write!(f, "APPROVED"),
            OutcomeType::Declined => write!(f, "DECLINED"),
            OutcomeType::OnlineRequest => write!(f, "ONLINE REQUEST"),
            OutcomeType::EndApplication => write!(f, "END APPLICATION"),
            OutcomeType::SelectNext => write!(f, "SELECT NEXT"),
            OutcomeType::TryAnotherInterface => write!(f, "TRY ANOTHER INTERFACE"),
            OutcomeType::TryAgain => write!(f, "TRY AGAIN"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CvmOutcome {
    NoCvm = 0x00,
    ObtainSignature = 0x10,
    OnlinePin = 0x20,
    ConfirmationCodeVerified = 0x30, // Consumer Device CVM (CDCVM)
}

impl fmt::Display for CvmOutcome {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CvmOutcome::NoCvm => write!(f, "No CVM"),
            CvmOutcome::ObtainSignature => write!(f, "Signature"),
            CvmOutcome::OnlinePin => write!(f, "Online PIN"),
            CvmOutcome::ConfirmationCodeVerified => write!(f, "CDCVM"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StartOption {
    A, // Start from beginning (full transaction)
    B, // Start from SELECT
    C, // Start from GPO
    D, // Start after GPO
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlternateInterfacePreference {
    NotApplicable,
    Contact,
    MagStripe,
}

#[derive(Debug, Clone)]
pub struct OutcomeParameterSet {
    pub outcome: OutcomeType,
    pub start: StartOption,
    pub online_response_data: bool,
    pub cvm: CvmOutcome,
    pub ui_request_on_outcome_present: bool,
    pub ui_request_on_restart_present: bool,
    pub data_record_present: bool,
    pub discretionary_data_present: bool,
    pub receipt: bool,
    pub alternate_interface_preference: AlternateInterfacePreference,
    pub field_off_request: u8, // Hold time in units of 100ms
}

impl OutcomeParameterSet {
    pub fn approved(cvm: CvmOutcome) -> Self {
        OutcomeParameterSet {
            outcome: OutcomeType::Approved,
            start: StartOption::NotApplicable,
            online_response_data: false,
            cvm,
            ui_request_on_outcome_present: true,
            ui_request_on_restart_present: false,
            data_record_present: true,
            discretionary_data_present: false,
            receipt: cvm != CvmOutcome::NoCvm,
            alternate_interface_preference: AlternateInterfacePreference::NotApplicable,
            field_off_request: 0,
        }
    }

    pub fn declined() -> Self {
        OutcomeParameterSet {
            outcome: OutcomeType::Declined,
            start: StartOption::NotApplicable,
            online_response_data: false,
            cvm: CvmOutcome::NoCvm,
            ui_request_on_outcome_present: true,
            ui_request_on_restart_present: false,
            data_record_present: true,
            discretionary_data_present: false,
            receipt: false,
            alternate_interface_preference: AlternateInterfacePreference::NotApplicable,
            field_off_request: 0,
        }
    }

    pub fn online_request(cvm: CvmOutcome) -> Self {
        OutcomeParameterSet {
            outcome: OutcomeType::OnlineRequest,
            start: StartOption::NotApplicable,
            online_response_data: true,
            cvm,
            ui_request_on_outcome_present: true,
            ui_request_on_restart_present: false,
            data_record_present: true,
            discretionary_data_present: false,
            receipt: true,
            alternate_interface_preference: AlternateInterfacePreference::NotApplicable,
            field_off_request: 0,
        }
    }

    pub fn try_another_interface() -> Self {
        OutcomeParameterSet {
            outcome: OutcomeType::TryAnotherInterface,
            start: StartOption::NotApplicable,
            online_response_data: false,
            cvm: CvmOutcome::NoCvm,
            ui_request_on_outcome_present: true,
            ui_request_on_restart_present: false,
            data_record_present: false,
            discretionary_data_present: false,
            receipt: false,
            alternate_interface_preference: AlternateInterfacePreference::Contact,
            field_off_request: 0,
        }
    }

    pub fn end_application() -> Self {
        OutcomeParameterSet {
            outcome: OutcomeType::EndApplication,
            start: StartOption::NotApplicable,
            online_response_data: false,
            cvm: CvmOutcome::NoCvm,
            ui_request_on_outcome_present: true,
            ui_request_on_restart_present: false,
            data_record_present: false,
            discretionary_data_present: false,
            receipt: false,
            alternate_interface_preference: AlternateInterfacePreference::NotApplicable,
            field_off_request: 0,
        }
    }

    /// Encode as DF8129 Outcome Parameter Set (8 bytes)
    /// ref. EMV Contactless Book C-2, Table 6.1
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 8];

        // Byte 0: Outcome
        bytes[0] = self.outcome as u8;

        // Byte 1: Start
        bytes[1] = match self.start {
            StartOption::A => 0x00,
            StartOption::B => 0x10,
            StartOption::C => 0x20,
            StartOption::D => 0x30,
            StartOption::NotApplicable => 0xF0,
        };

        // Byte 2: Online Response Data
        if self.online_response_data {
            bytes[2] |= 0x80;
        }

        // Byte 3: CVM
        bytes[3] = self.cvm as u8;

        // Byte 4: UI flags + data record + discretionary + receipt
        if self.ui_request_on_outcome_present {
            bytes[4] |= 0x80;
        }
        if self.ui_request_on_restart_present {
            bytes[4] |= 0x40;
        }
        if self.data_record_present {
            bytes[4] |= 0x20;
        }
        if self.discretionary_data_present {
            bytes[4] |= 0x10;
        }
        if self.receipt {
            bytes[4] |= 0x08;
        }

        // Byte 5: Alternate interface preference
        bytes[5] = match self.alternate_interface_preference {
            AlternateInterfacePreference::NotApplicable => 0x00,
            AlternateInterfacePreference::Contact => 0x01,
            AlternateInterfacePreference::MagStripe => 0x02,
        };

        // Byte 6: Field Off Request (hold time in 100ms units)
        bytes[6] = self.field_off_request;

        // Byte 7: Removal Timeout (RFU)
        bytes[7] = 0x00;

        bytes
    }
}

// UI message identifiers for DF8116
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageIdentifier {
    CardReadOk = 0x17,
    TryAgain = 0x21,
    Approved = 0x03,
    NotAuthorised = 0x07,
    PleaseInsertOrSwipeCard = 0x18,
    PleaseInsertCard = 0x1C,
    Processing = 0x0E,
    NoMessage = 0xFF,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UiStatus {
    NotReady = 0x00,
    Idle = 0x01,
    ReadyToRead = 0x02,
    Processing = 0x03,
    CardReadOk = 0x04,
    ProcessingError = 0x05,
}

#[derive(Debug, Clone)]
pub struct UserInterfaceRequestData {
    pub message_id: MessageIdentifier,
    pub status: UiStatus,
    pub hold_time_ms: u32,
}

impl UserInterfaceRequestData {
    /// Encode as DF8116 User Interface Request Data (22 bytes per spec)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 22];
        bytes[0] = self.message_id as u8;
        bytes[1] = self.status as u8;
        // Hold time: 3 bytes BCD
        bytes[2] = ((self.hold_time_ms / 10000) % 10) as u8;
        bytes[3] = (((self.hold_time_ms / 1000) % 10) << 4 | ((self.hold_time_ms / 100) % 10)) as u8;
        bytes[4] = (((self.hold_time_ms / 10) % 10) << 4 | (self.hold_time_ms % 10)) as u8;
        // Bytes 5-12: Language Preference (not set)
        // Bytes 13: Value Qualifier (not set)
        // Bytes 14-19: Value (not set)
        // Bytes 20-21: Currency Code (not set)
        bytes
    }

    pub fn approved() -> Self {
        UserInterfaceRequestData {
            message_id: MessageIdentifier::Approved,
            status: UiStatus::CardReadOk,
            hold_time_ms: 0,
        }
    }

    pub fn declined() -> Self {
        UserInterfaceRequestData {
            message_id: MessageIdentifier::NotAuthorised,
            status: UiStatus::ProcessingError,
            hold_time_ms: 0,
        }
    }

    pub fn online() -> Self {
        UserInterfaceRequestData {
            message_id: MessageIdentifier::Processing,
            status: UiStatus::Processing,
            hold_time_ms: 0,
        }
    }

    pub fn try_another() -> Self {
        UserInterfaceRequestData {
            message_id: MessageIdentifier::PleaseInsertCard,
            status: UiStatus::ReadyToRead,
            hold_time_ms: 0,
        }
    }
}

impl fmt::Display for OutcomeParameterSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Outcome: {}, CVM: {}, Data Record: {}, Receipt: {}",
            self.outcome, self.cvm, self.data_record_present, self.receipt
        )
    }
}

// Level 2 error codes for ErrorIndication
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum L2Error {
    Ok,
    CardDataMissing,
    CamFailed, // Card Authentication Method (ODA) failed
    StatusBytes,
    ParsingError,
    MaxLimitExceeded,
    CardDataError,
    MagStripeNotSupported,
    NoPdol,
    EmptyRecordCandidate,
    IdsReadError,
    IdsWriteError,
    IdsDataError,
    IdsNoMatchingAc,
}

#[derive(Debug, Clone)]
pub struct ErrorIndication {
    pub l2_error: L2Error,
    pub sw1: u8,
    pub sw2: u8,
    pub message: String,
}

impl ErrorIndication {
    pub fn ok() -> Self {
        ErrorIndication {
            l2_error: L2Error::Ok,
            sw1: 0x90,
            sw2: 0x00,
            message: String::new(),
        }
    }

    pub fn card_data_missing(msg: &str) -> Self {
        ErrorIndication {
            l2_error: L2Error::CardDataMissing,
            sw1: 0,
            sw2: 0,
            message: msg.to_string(),
        }
    }

    pub fn status_bytes(sw1: u8, sw2: u8) -> Self {
        ErrorIndication {
            l2_error: L2Error::StatusBytes,
            sw1,
            sw2,
            message: format!("Unexpected status: {:02X}{:02X}", sw1, sw2),
        }
    }

    pub fn parsing_error(msg: &str) -> Self {
        ErrorIndication {
            l2_error: L2Error::ParsingError,
            sw1: 0,
            sw2: 0,
            message: msg.to_string(),
        }
    }
}

// ContactlessKernel trait — the polymorphic kernel interface
// ref. EMV Contactless Book B, Entry Point Specification

use crate::EmvConnection;
use super::outcome::{OutcomeParameterSet, ErrorIndication};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionPath {
    MChip,     // EMV mode (full chip transaction)
    MagStripe, // Mag stripe profile
}

impl fmt::Display for TransactionPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TransactionPath::MChip => write!(f, "M/Chip"),
            TransactionPath::MagStripe => write!(f, "Mag Stripe"),
        }
    }
}

#[derive(Debug)]
pub enum KernelError {
    ApduError(String),
    CardDataMissing(String),
    ParsingError(String),
    TransactionDeclined(String),
    ConfigError(String),
    L2Error(ErrorIndication),
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KernelError::ApduError(msg) => write!(f, "APDU error: {}", msg),
            KernelError::CardDataMissing(msg) => write!(f, "Card data missing: {}", msg),
            KernelError::ParsingError(msg) => write!(f, "Parsing error: {}", msg),
            KernelError::TransactionDeclined(msg) => write!(f, "Transaction declined: {}", msg),
            KernelError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            KernelError::L2Error(err) => write!(f, "L2 error: {:?}", err),
        }
    }
}

pub trait ContactlessKernel {
    /// Returns the kernel identifier (e.g., 0x02 for Mastercard)
    fn kernel_id(&self) -> u8;

    /// Returns the kernel name for logging
    fn kernel_name(&self) -> &str;

    /// Application initiation: process FCI from SELECT AID, build and send GPO
    fn initiate_application(
        &mut self,
        conn: &mut EmvConnection,
        fci_data: &[u8],
    ) -> Result<(), KernelError>;

    /// Read card data: process AFL, send READ RECORDs, determine transaction path
    fn read_card_data(
        &mut self,
        conn: &mut EmvConnection,
    ) -> Result<TransactionPath, KernelError>;

    /// Process the transaction: ODA, CVM, TAA, GENERATE AC, determine outcome
    fn process_transaction(
        &mut self,
        conn: &mut EmvConnection,
        path: TransactionPath,
    ) -> Result<OutcomeParameterSet, KernelError>;
}

//! Fixed-size transport for the independently scheduled EL0 governance
//! coordinator. These bytes carry observations and requests only: decoding a
//! command never grants publication authority or attests a model transition.
mod codec;
mod command;
mod receipt;
mod snapshot;

pub use command::{Command, CommandAction, CommandKey, RejectReason, ScoreMode};
pub use receipt::{CreditEvidence, Receipt, ReceiptResult};
pub use snapshot::{
    CoordinatorSnapshot, LastCommandStatus, ObservedExecutionState, PendingObservation,
    PermitObservation, VerifiedScore,
};

pub const ABI: u16 = 1;
pub const SNAPSHOT_BYTES: usize = 512;
pub const COMMAND_BYTES: usize = 256;
pub const RECEIPT_BYTES: usize = 256;

pub(crate) const SNAPSHOT_MAGIC: &[u8; 8] = b"CXGVS001";
pub(crate) const COMMAND_MAGIC: &[u8; 8] = b"CXGVC001";
pub(crate) const RECEIPT_MAGIC: &[u8; 8] = b"CXGVR001";

const _: () = assert!(SNAPSHOT_BYTES == 512);
const _: () = assert!(COMMAND_BYTES == 256);
const _: () = assert!(RECEIPT_BYTES == 256);

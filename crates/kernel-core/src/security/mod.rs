//! V0.19 local security mechanisms (SEC-P/F/M/N/D/S).
//!
//! These bounded guards never consume AI output as authorization.  Their unit
//! tests exercise state-machine rules, not native EL1/EL0 enforcement.  Actual
//! adapters must pass authenticated identities and real completion evidence.
//! The source-bound G2/G3/G4 acceptance matrix is separate.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Unauthorized,
    Stale,
    Conflict,
    Capacity,
    Busy,
    Unknown,
    Exhausted,
}

pub mod process;
pub mod file;
pub mod file_service_v4;
pub mod file_media_v0199;
pub mod file_index_v0199;
pub mod file_receipt_store_v0199;
pub mod memory;
pub mod network;
pub mod device;
pub mod syscall;
pub mod syscall_v3;

#[cfg(test)]
mod integration_tests;

pub mod durable_role_epoch_v0199;

pub mod epoch_redo_v0199;

pub mod offline_config_v1;

pub mod cap_record_v3;

pub mod snapshot_restore_gate;

pub mod ipc_receive_v3;

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
pub mod memory;
pub mod network;
pub mod device;
pub mod syscall;

#[cfg(test)]
mod integration_tests;

//! Bounded business-plane mechanisms shared by native executors and host tests.
//! These mechanisms consume validated parameters; they never run inference.
mod types;
pub use types::*;

pub mod filesystem;
pub mod io;
pub mod maintenance;
pub mod platform;
pub mod tasks;

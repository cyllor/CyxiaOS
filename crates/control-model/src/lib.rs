#![no_std]
#![forbid(unsafe_code)]
//! Experimental, trained core-allocation head. Not the full 16-domain model.
//! Inference is pure integer arithmetic; no kernel service is invoked here.
pub mod abi;
pub mod model;

// Current local snapshot/feature/integer inference contract (no authority).
pub mod native_v0199;

pub mod reward_v2;

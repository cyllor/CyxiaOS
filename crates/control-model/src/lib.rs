#![no_std]
#![forbid(unsafe_code)]
//! Experimental, trained core-allocation head. Not the full 16-domain model.
//! Inference is pure integer arithmetic; no kernel service is invoked here.
pub mod abi;
pub mod model;

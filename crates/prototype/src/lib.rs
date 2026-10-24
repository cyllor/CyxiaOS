#![no_std]
#![forbid(unsafe_code)]
//! Versioned mechanisms for the 1.3 functional profile (approved Rust deviation).
//! Component tests are not proof of native integration or complete acceptance.
pub mod boot;
pub mod cores;
pub mod journal;
pub mod model;
pub mod storage;

pub mod cluster;
pub mod domains;
pub mod features;
pub mod policy;
pub mod policy_wire;

//! Deterministic control-plane contracts; no inference or allocation here.
//!
//! All management methods are called by a serialized, trusted EL1 owner, never
//! directly by EL0. The queue carries copied words, not shared mutable pointers.
//! This module does NOT start CPUs, install page tables, or authenticate an EL0
//! process. Architecture code must provide those operations and trustworthy
//! drain/handoff proofs before enabling physical isolation. See the integration
//! document; the existing CPU0-only kernel must not advertise SMP isolation.
#![forbid(unsafe_code)]

pub mod budget;
pub mod cores;
pub mod policy;
pub mod queue;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    Control,
    Business,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Busy,
    Stale,
    Expired,
    Denied,
    Exhausted,
    NotReady,
    Clock,
}

/// Kernel-authenticated process/thread identity, not a PID supplied by a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub id: u64,
    pub generation: u64,
}
impl Identity {
    pub const fn valid(self) -> bool {
        self.id != 0 && self.generation != 0
    }
}

/// Every independent invalidation domain must match at publication AND use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epochs {
    pub boot: u64,
    pub controller: u64,
    pub model: u64,
    pub resources: u64,
    pub cores: u64,
}
impl Epochs {
    pub const fn valid(self) -> bool {
        self.boot != 0
            && self.controller != 0
            && self.model != 0
            && self.resources != 0
            && self.cores != 0
    }
}
pub mod manager;
pub mod wire;

pub mod dispatch;
pub mod exchange;
pub mod image;
pub mod service;

pub mod service_image;
pub mod service_restart;

pub mod task_admission;

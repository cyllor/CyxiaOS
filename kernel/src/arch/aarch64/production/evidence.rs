//! V0.20 wave 11 evidence segment: words 128..160 of the QMP-readable page.
//!
//! The wave-10 skeleton owns words 0..128 (see `production.rs` run() seal).
//! Wave 11 adds a fixed, named segment above it. Each constant below is one row
//! of the wave-11 evidence table; `put` is the only writer.
//!
//! UNSAFE BOUNDARY REGISTRATION: this module has no `unsafe` blocks. It writes
//! only through the atomic `SMP_EVIDENCE` words with `Relaxed` stores, from the
//! CPU0 control plane before run() publishes the seal word (words[2]).
// Row constants are consumed by later wave-11 tasks; unused until then.
#![allow(dead_code)]

use super::super::{SMP_EVIDENCE, fatal};
use core::sync::atomic::Ordering;

/// First word of the wave-11 segment (inclusive).
pub const W11_BASE: usize = 128;
/// One past the last word of the wave-11 segment (words 145..159 are staging).
pub const W11_END: usize = 160;
/// "CYXPRD11".
pub const W11_MAGIC: u64 = 0x4359_5052_4431_3131;

pub const W11_FRAME_META: usize = 129;
pub const W11_FRAME_META_ROWS: usize = 130;
pub const W11_RECOVERY_ACCUMULATORS: usize = 131;
pub const W11_DEGRADED_EVENTS: usize = 132;
pub const W11_RECOVERY_PUBLISH_REJECTED: usize = 133;
pub const W11_RECOVERY_PAIR_FACTS_STAGED: usize = 134;
pub const W11_POLICY_LOCK_METERED: usize = 135;
pub const W11_CRITICAL_SECTIONS: usize = 136;
pub const W11_OVER_BUDGET: usize = 137;
pub const W11_REAL_NET_DEVICE: usize = 138;
pub const W11_TCP_TO_LOCAL_ECHO: usize = 139;
pub const W11_ADMISSION_LEASES: usize = 140;
pub const W11_ECHO_BYTES: usize = 141;
pub const W11_TLS_ECHO_TURN_VERIFIED: usize = 142;
pub const W11_STAGED_BOOT_EPOCH: usize = 143;
pub const W11_MEDIA_STAGING: usize = 144;
/// First word of the media-staging segment (Task 6); G-A leaves it zero.
pub const W11_STAGING_BASE: usize = 145;

/// Store `value` at evidence word `word`; only 128..160 is writable here.
pub fn put(word: usize, value: u64) {
    if !(W11_BASE..W11_END).contains(&word) {
        fatal(0x5731_1100 + word as u64);
    }
    SMP_EVIDENCE.words[word].store(value, Ordering::Relaxed);
}

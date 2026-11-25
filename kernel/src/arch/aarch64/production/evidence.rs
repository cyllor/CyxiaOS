//! V0.20 wave 11 evidence segment: words 128..160 of the QMP-readable page.
//!
//! The wave-10 skeleton owns words 0..128 (see `production.rs` run() seal).
//! Wave 11 adds a fixed, named segment above it. Each constant below is one row
//! of the wave-11 evidence table; `put` is the only writer.
//!
//! UNSAFE BOUNDARY REGISTRATION: this module has no `unsafe` blocks. It writes
//! only through the atomic `SMP_EVIDENCE` words with `Relaxed` stores, from the
//! CPU0 control plane before run() publishes the seal word (words[2]).
use super::super::super::log;
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
// Media-staging rows 145..151 (Task 6): written, and therefore declared, only
// under v020-production-media-staging; G-A leaves words 145..159 zero.
#[cfg(feature = "v020-production-media-staging")]
pub const W11_STAGING_FORMATTED: usize = 145;
#[cfg(feature = "v020-production-media-staging")]
pub const W11_STAGING_MOUNT_VALIDATED: usize = 146;
#[cfg(feature = "v020-production-media-staging")]
pub const W11_STAGING_UNIFIED_MAP: usize = 147;
#[cfg(feature = "v020-production-media-staging")]
pub const W11_STAGING_CONFIRMED_EPOCH: usize = 148;
#[cfg(feature = "v020-production-media-staging")]
pub const W11_STAGING_ADMISSION_FLOW: usize = 149;
#[cfg(feature = "v020-production-media-staging")]
pub const W11_STAGING_SNAPSHOT_FAIL_CLOSED: usize = 150;
#[cfg(feature = "v020-production-media-staging")]
pub const W11_STAGING_GOLDEN_VECTOR_PENDING: usize = 151;

/// Store `value` at evidence word `word`; only 128..160 is writable here.
pub fn put(word: usize, value: u64) {
    if !(W11_BASE..W11_END).contains(&word) {
        fatal(0x5731_1100 + word as u64);
    }
    SMP_EVIDENCE.words[word].store(value, Ordering::Relaxed);
}

fn flag(word: usize, expected: u64) -> bool {
    SMP_EVIDENCE.words[word].load(Ordering::Relaxed) == expected
}

/// Overwrite each `=0` value in `line`, in order, with the next flag digit.
fn fill(line: &mut [u8], flags: &[bool]) {
    let mut next = flags.iter();
    for i in 1..line.len() {
        if line[i - 1] == b'=' {
            if let Some(&set) = next.next() {
                line[i] = b'0' + u8::from(set);
            }
        }
    }
}

/// Emit the wave-11 completion marker, derived from the sealed words so the
/// verifier can cross-check serial against memory. The 98-byte line exceeds
/// the 96-byte framed-UART payload cap, so it goes out as two frames (CPU0 is
/// the only writer, so the decoded stream holds it as one line).
pub fn log_completion() {
    let mut head = *b"V020_W11_PRODUCTION frame_meta=0 recovery=0 metered=0 ";
    let mut tail = *b"net=0 tcp_echo=0 tls_echo=0 media_staging=0\n";
    let recovery = flag(W11_RECOVERY_ACCUMULATORS, 4) && flag(W11_RECOVERY_PUBLISH_REJECTED, 1);
    fill(
        &mut head,
        &[flag(W11_FRAME_META, 1), recovery, flag(W11_POLICY_LOCK_METERED, 1)],
    );
    fill(
        &mut tail,
        &[
            flag(W11_REAL_NET_DEVICE, 1),
            flag(W11_TCP_TO_LOCAL_ECHO, 1),
            flag(W11_TLS_ECHO_TURN_VERIFIED, 1),
            flag(W11_MEDIA_STAGING, 1),
        ],
    );
    log(&head);
    log(&tail);
}

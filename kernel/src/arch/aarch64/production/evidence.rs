//! V0.20 production evidence extensions at words 128..304 of the QMP-readable page.
//!
//! The wave-10 skeleton owns words 0..128 (see `production.rs` run() seal).
//! The extensions have fixed word assignments. `put` is the only writer.
//!
//! UNSAFE BOUNDARY REGISTRATION: this module has no `unsafe` blocks. It writes
//! only through the atomic `SMP_EVIDENCE` words with `Relaxed` stores, from the
//! CPU0 control plane before run() publishes the seal word (words[2]).
use super::super::super::log;
use super::super::{SMP_EVIDENCE, fatal};
use core::sync::atomic::Ordering;

/// First word of the wave-11 segment (inclusive).
pub const W11_BASE: usize = 128;
/// "CYXPRD11".
pub const W11_MAGIC: u64 = 0x4359_5052_4431_3131;

pub const W11_FRAME_META: usize = 129;
/// Registered static pages (NOT all permanent rows; gap rows are excluded).
pub const W11_FRAME_META_REGISTERED_STATIC_PAGES: usize = 130;
pub const W11_RECOVERY_ACCUMULATORS: usize = 131;
pub const W11_DEGRADED_EVENTS: usize = 132;
/// 0x41 calls refused in RECOVERY_REQUIRED after the staged single-copy probe.
pub const W11_RECOVERY_REQUIRED_REJECTS: usize = 133;
pub const W11_RECOVERY_PAIR_FACTS_STAGED: usize = 134;
pub const W11_POLICY_LOCK_METERED: usize = 135;
/// Metered sections that settled within the 45 us budget.
pub const W11_POLICY_LOCK_SETTLED_IN_BUDGET: usize = 136;
/// Metered sections that overran, or were not measured after the sticky latch.
pub const W11_POLICY_LOCK_OVERRUN_OR_UNMEASURED: usize = 137;
pub const W11_REAL_NET_DEVICE: usize = 138;
pub const W11_TCP_TO_LOCAL_ECHO: usize = 139;
pub const W11_ADMISSION_LEASES: usize = 140;
pub const W11_ECHO_BYTES: usize = 141;
pub const W11_TLS_ECHO_TURN_VERIFIED: usize = 142;
pub const W11_STAGED_BOOT_EPOCH: usize = 143;
/// The opt-in staging lane is compiled in and ran (says nothing about success).
pub const W11_MEDIA_STAGING_ENABLED: usize = 144;
/// Staging rows that must all be nonzero for `staging_ok` (145..150).
pub const W11_STAGING_STEPS: core::ops::Range<usize> = 145..151;
// Media-staging rows 145..151 are written only under the opt-in feature.
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
pub const W11_RECOVERY_WRITER_TAKEOVERS: usize = 152;
pub const W11_FRAME_META_ARENA_PAGES: usize = 153;
pub const W11_POLICY_LOCK_MEASURED_OVERRUNS: usize = 154;
pub const W11_POLICY_LOCK_MAX_ELAPSED_NS: usize = 155;

#[cfg(feature = "v020-production-authenticated-net")]
pub const W12_SEC_N_RNG_BYTES: usize = 160;
#[cfg(feature = "v020-production-media-reopen")]
pub const W12_STAGING_REOPENED: usize = 162;
#[cfg(feature = "v020-production-media-reopen")]
pub const W12_STAGING_PRIOR_EPOCH: usize = 163;
#[cfg(feature = "v020-production-live-control")]
pub const W12_SNAPSHOT_ROLES: usize = 164;
#[cfg(feature = "v020-production-live-control")]
pub const W12_SNAPSHOT_SEQUENCE: usize = 165;
#[cfg(feature = "v020-production-live-control")]
pub const W12_AUDIT_READ_SEQUENCE: usize = 166;
#[cfg(feature = "v020-production-live-control")]
pub const W12_CONTROL_EARLY_REFUSALS: usize = 167;
#[cfg(feature = "v020-production-authenticated-net")]
pub const W13_NET_RETIREMENTS: usize = 176;
#[cfg(feature = "v020-production-live-control")]
pub const W13_AUDIT_EL0_SEQUENCE: usize = 178;
#[cfg(feature = "v020-production-live-control")]
pub const W13_AUDIT_RELEASED: usize = 179;
#[cfg(feature = "v020-production-live-control")]
pub const W13_AUDIT_REPLAYS: usize = 180;
#[cfg(feature = "v020-production-media-signed")]
pub const W13_SIGNED_CONFIG_VERIFIED: usize = 181;
#[cfg(feature = "v020-production-media-signed")]
pub const W13_SIGNED_BOOT_EPOCH: usize = 182;
#[cfg(feature = "v020-production-media-signed")]
pub const W23_RECEIPT_VIEW_BOOT: usize = 183;
#[cfg(feature = "v020-production-media-signed")]
pub const W23_RECEIPT_VIEW_DIGEST: usize = 184;
#[cfg(feature = "v020-production-frame-pool")]
pub const W14_FRAME_POOL_LIFECYCLE: usize = 192;
#[cfg(feature = "v020-production-frame-pool")]
pub const W14_FRAME_POOL_PAGES: usize = 193;
#[cfg(feature = "v020-production-frame-pool")]
pub const W14_FRAME_POOL_FREE: usize = 194;
#[cfg(feature = "v020-production-media-envelopes")]
pub const W14_SNAPSHOT_ENVELOPES: usize = 196;
#[cfg(feature = "v020-production-media-envelopes")]
pub const W14_SNAPSHOT_ENVELOPE_GENERATION: usize = 197;
#[cfg(feature = "v020-production-media-envelopes")]
pub const W14_SNAPSHOT_ENVELOPE_VERIFIED: usize = 198;
#[cfg(feature = "v020-production-media-unified")]
pub const W15_UNIFIED_SYSTEM_INODES: usize = 208;
#[cfg(feature = "v020-production-media-unified")]
pub const W15_UNIFIED_SYSTEM_BLOCKS: usize = 209;
#[cfg(feature = "v020-production-media-unified")]
pub const W15_UNIFIED_DATA_BLOCKS: usize = 210;
#[cfg(feature = "v020-production-snapshot-catalog")]
pub const W16_CATALOG_BOOT: usize = 224;
#[cfg(feature = "v020-production-snapshot-catalog")]
pub const W16_CATALOG_GENERATION: usize = 225;
#[cfg(feature = "v020-production-snapshot-catalog")]
pub const W16_CATALOG_READS: usize = 226;
#[cfg(feature = "v020-production-snapshot-catalog")]
pub const W16_CATALOG_UNREADY: usize = 227;
#[cfg(feature = "v020-production-snapshot-catalog")]
pub const W16_CATALOG_REJECTS: usize = 228;
#[cfg(feature = "v020-production-snapshot-catalog")]
pub const W16_CATALOG_STALE: usize = 229;
#[cfg(feature = "v020-production-snapshot-catalog")]
pub const W16_CATALOG_SERVICE_GENERATION: usize = 230;
#[cfg(feature = "v020-production-snapshot-catalog")]
pub const W16_CATALOG_DIGEST: usize = 232;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_BOOT: usize = 240;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_OWNER: usize = 241;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_OWNER_GENERATION: usize = 242;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_READS: usize = 243;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_OPS: usize = 244;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_REPLAYS: usize = 245;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_REFUSALS: usize = 246;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_ACKS: usize = 247;
#[cfg(feature = "v020-production-file-read")]
pub const W18_FILE_DIGEST: usize = 248;
#[cfg(feature = "v020-production-snapshot-read")]
pub const W19_SNAPSHOT_BOOT: usize = 256;
#[cfg(feature = "v020-production-snapshot-read")]
pub const W19_SNAPSHOT_QUERY_MISSING: usize = 257;
#[cfg(feature = "v020-production-snapshot-read")]
pub const W19_SNAPSHOT_HISTORY_MISSING: usize = 258;
#[cfg(feature = "v020-production-snapshot-read")]
pub const W19_SNAPSHOT_DENIALS: usize = 259;
#[cfg(feature = "v020-production-snapshot-read")]
pub const W19_SNAPSHOT_STALE: usize = 260;
#[cfg(feature = "v020-production-snapshot-read")]
pub const W19_SNAPSHOT_SLOT_DIGEST: usize = 264;
#[cfg(feature = "v020-production-file-sessions")]
pub const W20_FILE_SESSIONS: usize = 272;
#[cfg(feature = "v020-production-file-volatile-write")]
pub const W21_VOLATILE_WRITE: usize = 288;
const W21_END: usize = 304;

/// Store a production-extension value before the final seal.
pub fn put(word: usize, value: u64) {
    if !(W11_BASE..W21_END).contains(&word) {
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
        if line[i - 1] == b'='
            && let Some(&set) = next.next()
        {
            line[i] = b'0' + u8::from(set);
        }
    }
}

/// Emit the wave-11 completion marker, derived from the sealed words so the
/// verifier can cross-check serial against memory. `staging_ok` is 1 only if
/// every selected staging check completes (G-A: always 0). The line exceeds
/// the 96-byte framed-UART payload cap, so it goes out as two frames (CPU0 is
/// the only writer, so the decoded stream holds it as one line).
pub fn log_completion() {
    let mut head = *b"V020_W11_PRODUCTION frame_meta=0 recovery=0 metered=0 ";
    let mut tail = *b"net=0 tcp_echo=0 tls_echo=0 media_staging_enabled=0 staging_ok=0\n";
    let recovery = flag(W11_RECOVERY_ACCUMULATORS, 4)
        && flag(W11_RECOVERY_REQUIRED_REJECTS, 1)
        && flag(W11_RECOVERY_WRITER_TAKEOVERS, 3);
    #[cfg(feature = "v020-production-media-reopen")]
    let media_ready = flag(W12_STAGING_REOPENED, 1);
    #[cfg(not(feature = "v020-production-media-reopen"))]
    let media_ready = flag(W11_STAGING_STEPS.start, 1);
    let staging_ok = media_ready
        && SMP_EVIDENCE.words[W11_STAGING_STEPS.start + 1..W11_STAGING_STEPS.end]
            .iter()
            .all(|w| w.load(Ordering::Relaxed) != 0);
    #[cfg(feature = "v020-production-media-signed")]
    let staging_ok = staging_ok
        && flag(
            W23_RECEIPT_VIEW_BOOT,
            SMP_EVIDENCE.words[W11_STAGING_CONFIRMED_EPOCH].load(Ordering::Relaxed),
        )
        && SMP_EVIDENCE.words[W23_RECEIPT_VIEW_DIGEST..W23_RECEIPT_VIEW_DIGEST + 4]
            .iter()
            .any(|word| word.load(Ordering::Relaxed) != 0);
    #[cfg(feature = "v020-production-snapshot-catalog")]
    let staging_ok = staging_ok && flag(W16_CATALOG_READS, 2) && flag(W16_CATALOG_STALE, 1);
    #[cfg(feature = "v020-production-file-read")]
    let staging_ok =
        staging_ok && flag(W18_FILE_READS, 3) && flag(W18_FILE_REFUSALS, u8::MAX.into());
    fill(
        &mut head,
        &[
            flag(W11_FRAME_META, 1),
            recovery,
            flag(W11_POLICY_LOCK_METERED, 1),
        ],
    );
    fill(
        &mut tail,
        &[
            flag(W11_REAL_NET_DEVICE, 1),
            flag(W11_TCP_TO_LOCAL_ECHO, 1),
            flag(W11_TLS_ECHO_TURN_VERIFIED, 1),
            flag(W11_MEDIA_STAGING_ENABLED, 1),
            staging_ok,
        ],
    );
    log(&head);
    log(&tail);
}

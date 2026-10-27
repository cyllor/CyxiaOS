//! Frozen wall-clock escape budgets for the native A10 scenarios.
//!
//! These are evidence-run bounds, not scheduler or filesystem policy budgets.
//! Modes 1-3 have a small finite ordinary-file sequence. Mode 4 performs the
//! separately verified 274-operation same-boot cache-pressure sequence.

pub const STANDARD_CLIENT_NS: u64 = 1_800_000_000_000;
pub const CACHE_CLIENT_NS: u64 = 21_600_000_000_000;
pub const MAX_POLL_REQUESTS: u64 = 90;
#[allow(dead_code)]
pub const CAPTURE_MARGIN_NS: u64 = 120_000_000_000;
pub const STANDARD_CLIENT_PAGES: usize = 16;
pub const CACHE_CLIENT_PAGES: usize = 27;
/// The dedicated cache-pressure profile needs the largest normal filesystem
/// writeback batch so its 4096 real dirty pages do not become 1024 tiny journal
/// transactions. This is a boot baseline, not a policy selection or receipt.
pub const CACHE_WRITEBACK_PAGES: u16 = 32;

pub const fn client_deadline_ns(mode: u64) -> Option<u64> {
    match mode {
        1..=3 => Some(STANDARD_CLIENT_NS),
        4 => Some(CACHE_CLIENT_NS),
        _ => None,
    }
}

pub const fn client_poll_ns(mode: u64) -> Option<u64> {
    match client_deadline_ns(mode) {
        Some(deadline) => Some(deadline / MAX_POLL_REQUESTS),
        None => None,
    }
}

pub const fn client_memory_pages(mode: u64) -> Option<usize> {
    match mode {
        1..=3 => Some(STANDARD_CLIENT_PAGES),
        4 => Some(CACHE_CLIENT_PAGES),
        _ => None,
    }
}

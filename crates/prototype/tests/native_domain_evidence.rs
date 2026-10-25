//! Exercise the production native evidence lifecycle with a host clock.
mod domain_platform {
    pub fn now_ns() -> u64 {
        1
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_evidence.rs"]
mod domain_evidence;

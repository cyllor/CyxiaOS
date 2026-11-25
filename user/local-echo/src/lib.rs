#![no_std]
#![forbid(unsafe_code)]
//! Restricted V0.19 EL0 read-only Echo broker surface.
//! The guest never calls task, store, cluster membership or policy RPC.
//! Kernel-side capability checks remain independently authoritative.

pub mod abi;
pub mod broker_surface {
    pub const ENTROPY: u64 = 1;
    pub const TIME: u64 = 2;
    pub const POLL: u64 = 3;
    pub const READ: u64 = 4;
    pub const WRITE: u64 = 5;
    pub const CLOSE: u64 = 6;
    pub const YIELD: u64 = 12;
    pub const PAYLOAD: usize = 4096;
    /// Reserved ciphertext writes bypass the old cluster task/output queue
    /// and use only the native broker's existing bounded TCP send operation.
    pub const DIRECT_TLS_CIPHERTEXT: u64 = 1;
    /// Gate every broker operation at the guest side, *in addition to*
    /// independent protected kernel service rights.
    pub const fn allowed(op: u64, len: usize, arg0: u64) -> bool {
        if len > PAYLOAD {
            return false;
        }
        match op {
            ENTROPY | READ => arg0 == 0,
            WRITE => arg0 == DIRECT_TLS_CIPHERTEXT && len != 0,
            TIME | POLL | CLOSE | YIELD => len == 0 && arg0 == 0,
            _ => false,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::broker_surface::*;
    #[test]
    fn sec_n_native_guest_has_no_remote_or_file_mutation_syscalls() {
        for op in [7, 8, 9, 10, 11, 13, 19, 20, 0xffff] {
            assert!(!allowed(op, 0, 0), "unexpected broker right {op}");
        }
        assert!(allowed(ENTROPY, 32, 0));
        assert!(allowed(READ, 4096, 0));
        assert!(allowed(WRITE, 20, DIRECT_TLS_CIPHERTEXT));
        assert!(!allowed(WRITE, 20, 0));
        assert!(!allowed(WRITE, 0, DIRECT_TLS_CIPHERTEXT));
        assert!(!allowed(READ, 4097, 0));
        assert!(allowed(POLL, 0, 0));
        assert!(allowed(CLOSE, 0, 0));
        assert!(!allowed(CLOSE, 1, 0));
    }
}

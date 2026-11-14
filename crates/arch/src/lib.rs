#![no_std]
//! Optional architecture acceleration. Shared policy never names a backend.
//! Unsupported acceleration returns None so callers use their portable path.
pub mod sha256 {
    #[cfg(target_arch = "aarch64")]
    pub use cyxia_arch_aarch64::sha256::digest;

    #[cfg(not(target_arch = "aarch64"))]
    pub fn digest(_bytes: &[u8]) -> Option<[u8; 32]> {
        None
    }
}

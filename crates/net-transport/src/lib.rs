#![no_std]
#![forbid(unsafe_code)]
//! Native local-only TLS 1.3 and read-only Echo protocol, independent of
//! cluster discovery, membership, remote tasks and authority-bearing wire RPC.
//! The Rust TLS engine requires a real EL0 quota-backed allocator/CSPRNG.
//! This library alone is NOT an EL0 service, execution grant or QEMU evidence.
pub const IDLE_TIMEOUT_SECS: u64 = 60;
pub mod echo;
#[cfg(feature = "tls")]
pub mod admission;
#[cfg(feature = "tls")]
pub mod tls;

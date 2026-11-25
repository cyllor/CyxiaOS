#![no_std]
#![forbid(unsafe_code)]
//! Native local-only TLS 1.3 and read-only Echo protocol, independent of
//! cluster membership, remote tasks and authority-bearing wire RPC.
//! The Rust TLS engine requires a real EL0 quota-backed allocator/CSPRNG.
//! This library alone is NOT an EL0 service, execution grant or QEMU evidence.
//!
//! The `smoltcp` feature hosts the bounded native Ethernet/IPv4/TCP device
//! stack (`device`, `tcp`) and the legacy CXD1 paired-node endpoint discovery
//! wire (`discovery`), relocated from the excluded cluster crate so the
//! single-machine SEC-N wiring never depends on cluster-named code. The local
//! Echo/admission path never invokes discovery. `tls` implies `smoltcp`, so
//! the `local_echo_tcp` NativeSocket adapter is available whenever the
//! `native_tcp` trait bridge is.
pub const IDLE_TIMEOUT_SECS: u64 = 60;
#[cfg(feature = "tls")]
pub mod admission;
#[cfg(feature = "smoltcp")]
pub mod device;
#[cfg(feature = "smoltcp")]
pub mod discovery;
pub mod echo;
#[cfg(feature = "tls")]
pub mod local_echo_tcp;
#[cfg(feature = "tls")]
pub mod native_tcp;
#[cfg(feature = "tls")]
pub mod service;
#[cfg(feature = "smoltcp")]
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tls;

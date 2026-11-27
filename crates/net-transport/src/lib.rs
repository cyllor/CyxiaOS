#![no_std]
#![forbid(unsafe_code)]
//! Native local-only TLS 1.3 and read-only Echo protocol, independent of
//! cluster membership, remote tasks and authority-bearing wire RPC.
//! The Rust TLS engine requires a real EL0 quota-backed allocator/CSPRNG.
//! This library alone is NOT an EL0 service, execution grant or QEMU evidence.
//!
//! The `smoltcp` feature hosts the bounded native Ethernet/IPv4/TCP device
//! stack (`device`, `tcp`), relocated from the excluded cluster crate so the
//! single-machine SEC-N wiring never depends on cluster-named code. The local
//! Echo/admission path never invokes discovery. `tls` implies `smoltcp`, so
//! the `local_echo_tcp` NativeSocket adapter is available whenever the
//! `native_tcp` trait bridge is.
//!
//! This crate is discovery-FREE: the legacy CXD1 paired-node cluster
//! discovery wire and its UDP socket integration were relocated to the
//! excluded legacy cluster-transport crate. The single-machine kernel
//! closure (`sec-n-native`) never compiles dual-node equipment.
pub const IDLE_TIMEOUT_SECS: u64 = 60;
#[cfg(feature = "tls")]
pub mod admission;
#[cfg(feature = "smoltcp")]
pub mod device;
pub mod echo;
#[cfg(feature = "smoltcp")]
pub mod ingress;
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
#[cfg(feature = "smoltcp")]
pub mod virtio_custody;

#![no_std]
#![forbid(unsafe_code)]
//! Legacy cluster diagnostics facade. The native Ethernet/IPv4/TCP device
//! stack and the SEC-N NativeSocket adapter live in cyxia-net-transport (the
//! active single-machine network crate) and are re-exported here so historical
//! diagnostics keep compiling against one transport implementation. Only the
//! cluster RPC wire framing and the CXD1 paired-node discovery machinery remain
//! local. TCP connectivity is never a cluster admission proof.
//!
//! The CXD1 discovery wire (`discovery`) and its UDP socket integration
//! (`tcp::DiscoveringTcp`) were relocated OUT of net-transport: V0.20 is
//! single-machine, so the active crate is discovery-free and the legacy
//! dual-node equipment lives only in this excluded facade.

pub use cyxia_net_transport::device;
pub mod discovery;
#[cfg(feature = "tls")]
pub use cyxia_net_transport::local_echo_tcp;
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tls;
pub mod wire;

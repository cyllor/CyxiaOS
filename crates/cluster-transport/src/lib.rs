#![no_std]
#![forbid(unsafe_code)]
//! Legacy cluster diagnostics facade. The native Ethernet/IPv4/TCP device
//! stack, the CXD1 endpoint discovery wire and the SEC-N NativeSocket adapter
//! live in cyxia-net-transport (the active single-machine network crate) and
//! are re-exported here so historical diagnostics keep compiling against one
//! transport implementation. Only the cluster RPC wire framing remains local.
//! TCP connectivity is never a cluster admission proof.
//!
//! This facade enables net-transport's `cluster-discovery` feature: the CXD1
//! paired-node discovery wire is cluster machinery and is NOT compiled into
//! the single-machine closure (`smoltcp`/`tls` alone) — only legacy cluster
//! consumers such as this facade pull it in.

pub use cyxia_net_transport::device;
pub use cyxia_net_transport::discovery;
#[cfg(feature = "tls")]
pub use cyxia_net_transport::local_echo_tcp;
pub use cyxia_net_transport::tcp;
#[cfg(feature = "tls")]
pub mod tls;
pub mod wire;

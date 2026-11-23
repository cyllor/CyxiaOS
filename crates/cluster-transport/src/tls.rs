//! Legacy import path. All TLS state, signature checks and keying live in
//! the separate single-node-capable network TLS package. This module cannot
//! silently reintroduce a second, divergent cryptographic implementation.
pub use cyxia_net_transport::tls::*;

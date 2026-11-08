#![no_std]
#![forbid(unsafe_code)]
//! Guest-resident Ethernet/IPv4/TCP and authenticated cluster transport.
//! TCP connectivity is never a cluster admission proof.

pub mod device;
pub mod discovery;
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tls;
pub mod wire;

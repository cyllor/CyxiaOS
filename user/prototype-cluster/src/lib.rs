#![no_std]
extern crate alloc;
#[path = "../../shared/calls.rs"]
pub mod calls;
pub mod abi;
pub mod application;
pub mod application_journal;
pub mod arena;
pub mod domain_ingress;
pub mod domain_placement;
pub mod quote_stop;
pub mod replay_work;
pub mod session_exit;

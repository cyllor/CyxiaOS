#![no_std]
//! x86-64 instruction, descriptor and page-table mechanisms.
//! PC discovery and device policy belong to the platform adapter.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod cpu;
pub mod descriptors;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod interrupts;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod io;
pub mod paging;
pub mod trap;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod user;

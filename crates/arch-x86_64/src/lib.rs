#![no_std]
//! x86-64 instruction, descriptor and page-table mechanisms.
//! PC discovery and device policy belong to the platform adapter.
pub mod accounting;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod cpu;
pub mod apic;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod ap_boot;
pub mod descriptors;
pub mod dispatch;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod interrupts;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod io;
pub mod paging;
pub mod space;
#[cfg(all(feature="runtime",target_arch="x86_64",target_os="none"))]
pub mod kernel_space;
pub mod trap;
pub mod user;

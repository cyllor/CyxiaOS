#![no_std]
pub mod fdt;
pub const RAM_BASE: u64 = 0x40000000;
pub const ENTRY: u64 = 0x40200000;
pub const HIGH_BASE: u64 = 0xffffffc000000000;

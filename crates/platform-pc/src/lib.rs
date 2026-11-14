#![no_std]
//! The bounded legacy PC board: Multiboot memory discovery and PC devices.
//!
//! Page ownership and policy belong to kernel-core; CPU instructions and
//! descriptor tables belong to arch-x86_64. No ARM device descriptions are
//! manufactured to adapt this board to the shared memory contracts.

pub mod boot;
pub use boot::{
    BootError, MAX_MMAP_BYTES, MAX_PHYSICAL_MEMORY, MB_INFO_BYTES, MULTIBOOT_BOOT_MAGIC,
    PcBootInfo, memory_map_location, parse_multiboot,
};

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub mod hardware;

pub const COM1_BASE: u16 = 0x3f8;
pub const PIC_MASTER_COMMAND: u16 = 0x20;
pub const PIC_SLAVE_COMMAND: u16 = 0xa0;
pub const PIC_VECTOR_BASE: u8 = 0x20;
pub const TIMER_VECTOR: u8 = PIC_VECTOR_BASE;
pub const PIT_CHANNEL_0: u16 = 0x40;
pub const PIT_COMMAND: u16 = 0x43;
pub const PIT_INPUT_HZ: u32 = 1_193_182;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoardResources {
    pub console_port: u16,
    pub pic_master_command: u16,
    pub pic_slave_command: u16,
    pub timer_port: u16,
    pub timer_command: u16,
    pub timer_irq: u8,
    pub timer_vector: u8,
}

pub const RESOURCES: BoardResources = BoardResources {
    console_port: COM1_BASE,
    pic_master_command: PIC_MASTER_COMMAND,
    pic_slave_command: PIC_SLAVE_COMMAND,
    timer_port: PIT_CHANNEL_0,
    timer_command: PIT_COMMAND,
    timer_irq: 0,
    timer_vector: TIMER_VECTOR,
};

/// The exact programmed rate is `input_hz / divisor`, not exactly 100 Hz.
/// Convert elapsed ticks using the shared `ticks_to_ns` implementation and
/// checked multiplication of ticks by `divisor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PitConfig {
    pub input_hz: u32,
    pub divisor: u16,
}

pub const PIT_100HZ: PitConfig = PitConfig {
    input_hz: PIT_INPUT_HZ,
    divisor: ((PIT_INPUT_HZ + 50) / 100) as u16,
};

//! ARM boot/exception integration. Board devices and runtime profiles are registered separately.
#[cfg(feature = "unified-runtime")]
use crate::domain_services;
#[cfg(feature = "graphics")]
use crate::graphics;
#[cfg(all(feature = "selftest", not(feature = "smp-selftest")))]
use crate::selftest;
#[cfg(feature = "smp-selftest")]
use crate::smp;
use crate::{clock, interrupts};
#[cfg(all(feature = "ported", not(feature = "selftest")))]
use crate::{entropy, exec_memory, shared_memory};
#[cfg(not(feature = "selftest"))]
use crate::{storage, user_heap};
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "unified-runtime")]
use cyxia_arch_aarch64::timer;
use cyxia_contracts::*;

mod boot;
mod console;
mod exceptions;
pub(crate) mod panic_stop;
#[cfg(any(
    feature = "v020-production-signed-resident",
    all(
        feature = "v020-production",
        not(feature = "v020-production-diagnostic")
    )
))]
pub(crate) use console::enqueue_resident_frame;
#[cfg(feature = "v0199-epoch-disk-selftest")]
pub(crate) use console::enqueue_v0199;
pub(crate) use console::{UART, halt, log, try_log};
pub(crate) use exceptions::ExceptionFrame;
#[cfg(not(feature = "smp-selftest"))]
pub(crate) use exceptions::hex;

pub(crate) const HIGH: u64 = cyxia_platform_virt::HIGH_BASE;
// The default release resident path is covered by check_v020_el1_stack.py.
// Catalog verification, diagnostics and debug builds have separate frames.
const BOUNDED_DEFAULT_STACKS: bool = cfg!(all(
    feature = "v020-production",
    not(feature = "v020-production-diagnostic"),
    not(feature = "v020-panic-stop-selftest"),
    not(cyxia_startup_catalog),
    not(debug_assertions),
));
const BOOT_EXEC_STACK_BYTES: usize = if BOUNDED_DEFAULT_STACKS {
    16 * 1024
} else {
    256 * 1024
};
#[cfg(feature = "smp-selftest")]
pub(crate) const SMP_EXEC_STACK_BYTES: usize = if BOUNDED_DEFAULT_STACKS {
    16 * 1024
} else {
    64 * 1024
};
core::arch::global_asm!(
    include_str!("../../../../crates/arch-aarch64/src/entry.S"),
    ram_base = const cyxia_platform_virt::RAM_BASE,
    entry = const cyxia_platform_virt::ENTRY,
    gic_base = const 0x08000000,
    uart_base = const 0x09000000,
    ram_end = const cyxia_platform_virt::USER_RAM_END,
    ram_table_count = const cyxia_platform_virt::RAM_MIB / 2,
    ram_tables_bytes = const cyxia_platform_virt::RAM_MIB / 2 * 4096,
    exec_stack_bytes = const BOOT_EXEC_STACK_BYTES,
);
// Versioned loader contract, retained in the ELF's read-only load segment.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.boot")]
static CYXIA_BOOT_PROFILE: [u64; 3] = [
    1,
    cyxia_platform_virt::RAM_MIB,
    cyxia_posix::vm::PAGE_COUNT as u64,
];
core::arch::global_asm!(
    include_str!("../../../../crates/arch-aarch64/src/vectors.S"),
    legacy_guard_probe = const cfg!(all(
        feature = "selftest",
        feature = "legacy-desktop",
        not(feature = "smp-selftest")
    )) as u8,
    stop_selftest = const cfg!(feature = "v020-panic-stop-selftest") as u8,
);
unsafe extern "C" {
    #[cfg(not(feature = "smp-selftest"))]
    static __kernel_end: u8;
    #[cfg(not(feature = "smp-selftest"))]
    static __stack_guard: u8;
    static exception_vectors: u8;
    #[cfg(all(feature = "selftest", not(feature = "smp-selftest")))]
    static probe_read_fault: u8;
    #[cfg(not(feature = "smp-selftest"))]
    static probe_write_fault: u8;
    #[cfg(all(feature = "selftest", not(feature = "smp-selftest")))]
    fn probe_read(p: u64);
    #[cfg(all(feature = "selftest", not(feature = "smp-selftest")))]
    fn probe_write(p: u64);
}

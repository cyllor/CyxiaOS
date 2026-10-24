//! Logical slot identity installed by trusted bootstrap, not truncated MPIDR.
use core::arch::asm;
pub const MAX_CPUS: usize = cyxia_contracts::BOOT_CPUS;
pub fn slot() -> usize {
    let value: u64;
    unsafe {
        asm!("mrs {}, tpidr_el1", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    assert!(value < MAX_CPUS as u64, "unregistered CPU slot");
    value as usize
}
pub fn affinity() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value & 0x0000_00ff_00ff_ffff
}
/// # Safety
/// Own the EL1 physical timer; call while IRQs are masked. The caller must drain
/// any banked interrupt before treating this as a complete IRQ handoff.
pub unsafe fn disable_timer() {
    unsafe {
        asm!(
            "msr cntp_ctl_el0, xzr",
            "isb",
            options(nomem, nostack, preserves_flags)
        );
    }
}
/// # Safety
/// Conduit must be verified from the DTB. Firmware owns x0-x3; the returned
/// signed value is the PSCI status. Not a success until the CPU handshake arrives.
pub unsafe fn start(
    conduit: cyxia_contracts::PsciConduit,
    affinity: u64,
    entry: u64,
    context: u64,
) -> i64 {
    let mut result = 0xc400_0003u64; // PSCI 0.2 CPU_ON, 64-bit ABI.
    unsafe {
        match conduit {
            cyxia_contracts::PsciConduit::Hvc => asm!("hvc #0", inout("x0") result,
                inout("x1") affinity => _, inout("x2") entry => _, inout("x3") context => _, options(nostack)),
            cyxia_contracts::PsciConduit::Smc => asm!("smc #0", inout("x0") result,
                inout("x1") affinity => _, inout("x2") entry => _, inout("x3") context => _, options(nostack)),
        }
    }
    result as i64
}

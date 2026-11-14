//! Explicit privileged x86 port I/O. Platform adapters own the port allocation.
/// # Safety
/// Caller must own the device at `port` and execute at sufficient privilege.
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags));
    }
    value
}
/// # Safety
/// Caller must own the device at `port` and execute at sufficient privilege.
pub unsafe fn outb(port: u16, value: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
    }
}
/// # Safety
/// Caller must own the 32-bit register at `port` and execute at sufficient privilege.
pub unsafe fn outl(port: u16, value: u32) {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack, preserves_flags));
    }
}

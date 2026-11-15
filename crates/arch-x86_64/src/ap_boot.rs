//! The low bootstrap reservation is separate from full-width kernel pointers.
// QEMU Multiboot retains its E820/MBI structures at 9000/9500.
pub const TRAMPOLINE_PHYSICAL: u64 = 0x7000;
pub const MAILBOX_PHYSICAL: u64 = 0x8000;
core::arch::global_asm!(include_str!("ap_entry.S"), options(att_syntax));
unsafe extern "C" {
    static x86_ap_trampoline_start: u8;
    static x86_ap_trampoline_end: u8;
}

#[repr(C)]
pub struct Mailbox {
    pub root: u64,
    pub stack: u64,
    pub entry: u64,
    pub slot: u64,
    pub apic_id: u64,
    pub generation: u64,
    pub error: u64,
}
fn canonical(value: u64) -> bool {
    value <= 0x0000_7fff_ffff_ffff || value >= 0xffff_8000_0000_0000
}
/// # Safety
/// BSP only, before the RX trampoline mapping is sealed. Both low pages have
/// been checked against firmware/loader reservations and are writable RAM.
pub unsafe fn copy_trampoline() {
    let start = core::ptr::addr_of!(x86_ap_trampoline_start);
    let bytes = core::ptr::addr_of!(x86_ap_trampoline_end) as usize - start as usize;
    assert!(bytes > 0 && bytes <= 4096);
    unsafe {
        core::ptr::copy_nonoverlapping(start, TRAMPOLINE_PHYSICAL as *mut u8, bytes);
    }
}
/// # Safety
/// Prior AP has acknowledged online and no longer reads this mailbox. IF is
/// clear; root is a physical PML4 below 4 GiB; stack/entry remain mapped.
pub unsafe fn prepare(mailbox: Mailbox) {
    assert!(mailbox.root > 0 && mailbox.root < 1 << 32 && mailbox.root.is_multiple_of(4096));
    assert!(mailbox.stack >= 4096 && canonical(mailbox.stack) && mailbox.stack.is_multiple_of(16));
    assert!(mailbox.entry >= 4096 && canonical(mailbox.entry));
    assert!(
        mailbox.slot < 4 && mailbox.apic_id < 255 && mailbox.generation > 0 && mailbox.error == 0
    );
    unsafe {
        core::ptr::write_volatile(MAILBOX_PHYSICAL as *mut Mailbox, mailbox);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
}
pub fn error() -> u64 {
    unsafe { core::ptr::read_volatile((MAILBOX_PHYSICAL + 48) as *const u64) }
}

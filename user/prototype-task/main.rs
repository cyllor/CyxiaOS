#![no_std]
#![no_main]
// AArch64 ABI v1 pure vector_sum: immutable little-endian i64 input, checked
// signed sum, one result page. No syscalls/capabilities except terminal return.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start() -> ! {
    let len = unsafe { (0x20000 as *const u64).read_volatile() } as usize;
    let mut sum = 0i64;
    let mut status = 0u64;
    if len == 0 || len > 32768 || !len.is_multiple_of(8) {
        status = 1;
    } else {
        for i in 0..len / 8 {
            let value = unsafe { (0x21000 as *const i64).add(i).read_volatile() };
            match sum.checked_add(value) {
                Some(v) => sum = v,
                None => {
                    status = 2;
                    break;
                }
            }
        }
    }
    unsafe {
        (0x30000 as *mut u64).write_volatile(status);
        (0x30008 as *mut i64).write_volatile(sum);
        core::arch::asm!("svc #0x44", options(nostack));
    }
    loop {
        core::hint::spin_loop()
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop()
    }
}

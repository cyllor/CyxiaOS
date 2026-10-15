#![no_std]
#![no_main]
use cyxia_contracts::*;
mod selftest;
unsafe extern "C" {static __kernel_end:u8;}
core::arch::global_asm!(include_str!("../../crates/arch-aarch64/src/entry.S"));
#[unsafe(no_mangle)]
extern "C" fn boot_entry() -> ! {
    let ptr = cyxia_platform_virt::RAM_BASE as *const u8;
    let header = unsafe { core::slice::from_raw_parts(ptr, 40) };
    let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if !(40..=0x200000).contains(&len) {
        halt()
    }
    let info =
        cyxia_platform_virt::fdt::parse_fdt(unsafe { core::slice::from_raw_parts(ptr, len) })
            .unwrap();
    let mut uart = unsafe { cyxia_driver_pl011::Pl011::new(info.uart.unwrap()) }.unwrap();
    let _ = uart.try_write(b"BOOT_ENTRY v1 EL1 CPU0 BOOTSTRAP\n");
    let _ = uart.try_write(b"PLATFORM_OK DTB RAM UART GIC TIMER BOOTSTRAP\n");
    if selftest::pages(&info,0,core::ptr::addr_of!(__kernel_end) as u64) {let _=uart.try_write(b"PAGE_SELFTEST_OK BOOTSTRAP\n");}else{let _=uart.try_write(b"FAIL pages\n");}
    halt()
}
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("wfe") }
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    halt()
}

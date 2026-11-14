#[cfg(all(feature = "selftest", not(feature = "smp-selftest")))]
use super::exceptions::{FAULT_COUNT, fault_probe};
use super::*;

#[unsafe(no_mangle)]
extern "C" fn boot_entry() -> ! {
    let ptr = (HIGH + cyxia_platform_virt::RAM_BASE) as *const u8;
    let header = unsafe { core::slice::from_raw_parts(ptr, 40) };
    let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if !(40..=0x200000).contains(&len) {
        halt()
    }
    let info =
        cyxia_platform_virt::fdt::parse_fdt(unsafe { core::slice::from_raw_parts(ptr, len) })
            .unwrap();
    let u = info.uart.unwrap();
    assert_eq!(u.base.0, 0x09000000);
    assert_eq!(info.ram_count, 1);
    assert_eq!(info.ram[0].start.0, 0x40000000);
    assert_eq!(info.ram[0].len, cyxia_platform_virt::RAM_MIB * 1024 * 1024);
    UART.store(u.base.0 + HIGH, Ordering::Relaxed);
    // The only configuration write. Subsequent log/console handles attach without
    // resetting incoming bytes. All console operations run on CPU0 foreground.
    let _ = unsafe {
        cyxia_driver_pl011::Pl011::new(UartResource {
            base: PhysAddr(u.base.0 + HIGH),
            len: u.len,
        })
    }
    .unwrap();
    log(b"BOOT_ENTRY v1 EL1 CPU0 BOOTSTRAP\n");
    log(b"PLATFORM_OK DTB RAM UART GIC TIMER BOOTSTRAP\n");
    let sp: u64;
    let vbar: u64;
    unsafe {
        core::arch::asm!("mov {}, sp",out(reg)sp);
        core::arch::asm!("mrs {}, vbar_el1",out(reg)vbar)
    }
    assert!(sp >= HIGH && boot_entry as *const () as u64 >= HIGH);
    assert_eq!(vbar, core::ptr::addr_of!(exception_vectors) as u64);
    log(b"HIGH_VA_OK BOOTSTRAP\n");
    clock::init(&info);
    #[cfg(feature = "unified-runtime")]
    unsafe {
        timer::init_cpu_accounting();
    }
    #[cfg(feature = "smp-selftest")]
    smp::run(&info);
    #[cfg(not(feature = "smp-selftest"))]
    primary_services(info)
}
#[cfg(not(feature = "smp-selftest"))]
fn primary_services(info: BootInfo) -> ! {
    #[cfg(feature = "selftest")]
    {
        fault_probe(cyxia_platform_virt::ENTRY, false);
        log(b"IDENTITY_UNMAPPED BOOTSTRAP\n");
        fault_probe(core::ptr::addr_of!(__stack_guard) as u64, false);
        fault_probe((boot_entry as *const () as u64) & !7, true);
        assert_eq!(FAULT_COUNT.load(Ordering::Relaxed), 3);
        log(b"WX_SELFTEST_OK GUARD_OK BOOTSTRAP\n");
        if selftest::pages(&info, HIGH, core::ptr::addr_of!(__kernel_end) as u64 - HIGH) {
            log(b"PAGE_SELFTEST_OK BOOTSTRAP\n")
        } else {
            panic!("pages")
        }
    }
    #[cfg(not(feature = "selftest"))]
    let info = {
        let mut info = info;
        match user_heap::init(&mut info) {
            Ok(()) => {
                #[cfg(not(feature = "large-memory"))]
                log(b"USER_HEAP_RESERVED 64MiB BOOTSTRAP\n");
                #[cfg(feature = "large-memory")]
                log(b"USER_HEAP_RESERVED 128MiB BOOTSTRAP\n");
            }
            Err(_) => log(b"USER_HEAP_UNAVAILABLE BOOTSTRAP\n"),
        }
        #[cfg(feature = "ported")]
        match exec_memory::init(&mut info) {
            Ok(()) => log(b"EXEC_MEMORY_RESERVED 128MiB BOOTSTRAP\n"),
            Err(_) => log(b"EXEC_MEMORY_UNAVAILABLE BOOTSTRAP\n"),
        }
        #[cfg(feature = "ported")]
        match shared_memory::init(&mut info) {
            Ok(()) => log(b"SHARED_MEMORY_RESERVED 16MiB BOOTSTRAP\n"),
            Err(_) => log(b"SHARED_MEMORY_UNAVAILABLE BOOTSTRAP\n"),
        }
        info
    };
    #[cfg(feature = "graphics")]
    graphics::init(&info);
    #[cfg(all(feature = "ported", not(feature = "selftest")))]
    entropy::init(&info);
    #[cfg(not(feature = "selftest"))]
    storage::init(&info);
    interrupts::start(&info);
}

use super::checks::{protection_checks, shared_policy_check};
use super::*;

#[unsafe(no_mangle)]
extern "C" fn x86_boot_entry(magic: u32, info_address: u32) -> ! {
    arch::cpu::disable_interrupts();
    unsafe { super::console::init() };
    assert_eq!(magic, pc::MULTIBOOT_BOOT_MAGIC, "boot magic");
    let address = u64::from(info_address);
    assert!(
        address >= 4096 && address + pc::MB_INFO_BYTES as u64 <= pc::MAX_PHYSICAL_MEMORY,
        "boot header range"
    );
    // Multiboot is supplied by the trusted loader. Validate pointer ranges
    // before taking bounded views, then parse all contents in safe board code.
    let header = unsafe { core::slice::from_raw_parts(address as *const u8, pc::MB_INFO_BYTES) };
    let (map_address, map_len) = pc::memory_map_location(header).expect("boot map location");
    assert!(map_address >= 4096, "boot map null page");
    let map = unsafe { core::slice::from_raw_parts(map_address as *const u8, map_len) };
    let info = pc::parse_multiboot(
        magic,
        header,
        address,
        map,
        map_address,
        core::ptr::addr_of!(__kernel_start) as u64,
        core::ptr::addr_of!(__kernel_end) as u64,
    )
    .expect("boot memory map");
    log(b"X86_BOOT_OK");

    let layout = arch::paging::Layout {
        text_start: core::ptr::addr_of!(__text_start) as u64,
        text_end: core::ptr::addr_of!(__text_end) as u64,
        rodata_start: core::ptr::addr_of!(__rodata_start) as u64,
        rodata_end: core::ptr::addr_of!(__rodata_end) as u64,
        user_text_start: core::ptr::addr_of!(__user_text_start) as u64,
        user_text_end: core::ptr::addr_of!(__user_text_end) as u64,
        user_stack_start: core::ptr::addr_of!(__user_stack_start) as u64,
        user_stack_end: core::ptr::addr_of!(__user_stack_end) as u64,
        guard_start: core::ptr::addr_of!(__stack_guard_start) as u64,
        guard_end: core::ptr::addr_of!(__stack_guard_end) as u64,
    };
    unsafe {
        arch::interrupts::init(core::ptr::addr_of!(__trap_stack_top) as u64);
        arch::paging::install(layout, pc::MAX_PHYSICAL_MEMORY).expect("paging layout");
    }
    assert_ne!(
        arch::cpu::read_cr0() & (1 << 16),
        0,
        "supervisor write protection"
    );
    unsafe { core::arch::asm!("int3") };
    assert_eq!(BREAKPOINTS.load(Ordering::Relaxed), 1);
    protection_checks(layout);
    log(b"PAGING_WX_OK");
    log(b"EXCEPTION_OK");

    assert!(selftest::pages_from_memory(
        info.ram_regions(),
        info.reserved_regions(),
        0
    ));
    log(b"FRAME_POOL_OK");
    shared_policy_check();
    log(b"SHARED_CORE_OK");

    let timer = unsafe { pc::hardware::init_timer_100hz() };
    loop {
        arch::cpu::disable_interrupts();
        if TICKS.load(Ordering::Acquire) >= 5 {
            break;
        }
        unsafe { arch::cpu::enable_and_wait() };
    }
    unsafe { pc::hardware::mask_timer_irq() };
    let ticks = TICKS.load(Ordering::Acquire);
    let time = cyxia_kernel_core::time::ticks_to_ns(
        ticks.checked_mul(u64::from(timer.divisor)).unwrap(),
        u64::from(timer.input_hz),
    )
    .unwrap();
    assert!(time.0 >= 40_000_000);
    assert!(cyxia_kernel_core::time::next_deadline(0, 10_000_000, time.0).unwrap() > time.0);
    log(b"TIMER_IRQ_OK");

    USER_PROBE.store(1, Ordering::Release);
    let result = unsafe {
        arch::user::enter(
            arch::user::x86_user_probe as *const () as u64,
            layout.user_stack_end,
        )
    };
    assert_eq!(result, 0, "user syscall roundtrip");
    assert_eq!(USER_CALLS.load(Ordering::Acquire), 2);
    USER_PROBE.store(2, Ordering::Release);
    let result = unsafe {
        arch::user::enter(
            arch::user::x86_user_fault_probe as *const () as u64,
            layout.user_stack_end,
        )
    };
    USER_PROBE.store(0, Ordering::Release);
    assert_eq!(result, 14, "user supervisor isolation");
    assert_eq!(USER_FAULTS.load(Ordering::Acquire), 1);
    log(b"USER_MODE_OK");
    log(b"X86_SELFTEST_OK");
    if cfg!(feature = "selftest") {
        exit(true);
    }
    arch::cpu::halt()
}

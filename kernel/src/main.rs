#![no_std]
#![no_main]
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_contracts::*;
mod interrupts;
#[cfg(feature = "selftest")]
mod selftest;
const HIGH: u64 = cyxia_platform_virt::HIGH_BASE;
core::arch::global_asm!(include_str!("../../crates/arch-aarch64/src/entry.S"),ram_base=const cyxia_platform_virt::RAM_BASE,entry=const cyxia_platform_virt::ENTRY,gic_base=const 0x08000000,uart_base=const 0x09000000);
core::arch::global_asm!(include_str!("../../crates/arch-aarch64/src/vectors.S"));
unsafe extern "C" {
    static __kernel_end: u8;
    static __stack_guard: u8;
    static exception_vectors: u8;
    #[cfg(feature = "selftest")]
    static probe_read_fault: u8;
    static probe_write_fault: u8;
    #[cfg(feature = "selftest")]
    fn probe_read(p: u64);
    #[cfg(feature = "selftest")]
    fn probe_write(p: u64);
}
static UART: AtomicU64 = AtomicU64::new(0);
static EXPECTED_PC: AtomicU64 = AtomicU64::new(0);
static EXPECTED_FAR: AtomicU64 = AtomicU64::new(0);
static FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static LOG_LOSS: AtomicU64 = AtomicU64::new(0);
fn log(s: &[u8]) {
    let a = UART.load(Ordering::Relaxed);
    if a == 0 {
        return;
    }
    let seq = LOG_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1))
        .unwrap_or_else(|_| halt());
    let mut frame = [0u8; 128];
    let Ok(n) = cyxia_contracts::transport::encode(1, seq, s, &mut frame) else {
        LOG_LOSS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let mut uart = unsafe {
        cyxia_driver_pl011::Pl011::new(UartResource {
            base: PhysAddr(a),
            len: 4096,
        })
    }
    .unwrap();
    for chunk in frame[..n].chunks(64) {
        match uart.try_write(chunk) {
            Ok(w) => {
                interrupts::TEST_PROGRESS
                    .bytes
                    .fetch_add(w as u64, Ordering::Relaxed);
                if w != chunk.len() {
                    LOG_LOSS.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
            Err(_) => {
                LOG_LOSS.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
}
#[repr(C)]
pub struct ExceptionFrame {
    regs: [u64; 31],
    elr: u64,
    spsr: u64,
    esr: u64,
    far: u64,
    pad: u64,
}
#[unsafe(no_mangle)]
extern "C" fn exception_dispatch(f: &mut ExceptionFrame, kind: u64) {
    if kind == 5 {
        interrupts::handle();
        return;
    }
    let pc = EXPECTED_PC.load(Ordering::Relaxed);
    if kind == 4
        && pc != 0
        && f.elr == pc
        && f.far == EXPECTED_FAR.load(Ordering::Relaxed)
        && f.esr >> 26 == 0x25
    {
        let expected = if pc == core::ptr::addr_of!(probe_write_fault) as u64 {
            0x4f
        } else if f.far < HIGH {
            0x04
        } else {
            0x07
        };
        if f.esr & 0x7f == expected {
            f.elr += 4;
            EXPECTED_PC.store(0, Ordering::Relaxed);
            FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    hex(f.esr);
    hex(f.elr);
    hex(f.far);
    hex(kind);
    log(b"FAIL unexpected exception\n");
    halt()
}
fn hex(v: u64) {
    let mut b = *b"0000000000000000\n";
    for (i, x) in b[..16].iter_mut().enumerate() {
        *x = b"0123456789abcdef"[((v >> (60 - i * 4)) & 15) as usize];
    }
    log(&b);
}
#[cfg(feature = "selftest")]
fn fault_probe(addr: u64, write: bool) {
    EXPECTED_FAR.store(addr, Ordering::Relaxed);
    EXPECTED_PC.store(
        if write {
            core::ptr::addr_of!(probe_write_fault) as u64
        } else {
            core::ptr::addr_of!(probe_read_fault) as u64
        },
        Ordering::Relaxed,
    );
    unsafe {
        if write {
            probe_write(addr)
        } else {
            probe_read(addr)
        }
    };
    assert_eq!(EXPECTED_PC.load(Ordering::Relaxed), 0);
}
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
    assert_eq!(info.ram[0].len, 256 * 1024 * 1024);
    UART.store(u.base.0 + HIGH, Ordering::Relaxed);
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
    interrupts::start(&info);
}
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("msr daifset, #15", "wfe") }
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    log(b"FAIL panic\n");
    halt()
}

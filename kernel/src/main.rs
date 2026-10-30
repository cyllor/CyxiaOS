#![no_std]
#![no_main]
#[cfg(all(
    feature = "smp-selftest",
    any(feature = "ported", feature = "graphics", feature = "large-memory")
))]
compile_error!("smp-selftest cannot certify the CPU0-only desktop/ported profile");
#[cfg(all(feature = "net-selftest", feature = "ai-control-selftest"))]
compile_error!("net-selftest and ai-control-selftest have separate evidence scopes");
#[cfg(all(
    feature = "model-v13-selftest",
    any(feature = "ai-control-selftest", feature = "net-selftest")
))]
compile_error!("model-v13-selftest must run as a separate evidence profile");
#[cfg(all(
    feature = "storage-v13-selftest",
    any(
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "prototype-runtime"
    )
))]
compile_error!("storage-v13-selftest must run as a separate evidence profile");
#[cfg(all(
    feature = "prototype-runtime",
    any(
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest"
    )
))]
compile_error!("prototype-runtime must run as a separate evidence profile");
#[cfg(any(
    feature = "storage-v13-selftest",
    feature = "prototype-runtime",
    feature = "tcp-v13-selftest"
))]
mod prototype_storage;
#[cfg(all(
    feature = "tcp-v13-selftest",
    any(
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "prototype-runtime",
        feature = "storage-v13-selftest"
    )
))]
compile_error!("tcp-v13-selftest must run as a separate evidence profile");
#[cfg(feature = "unified-runtime")]
mod a02_capture;
#[cfg(feature = "unified-runtime")]
mod boot_recovery;
#[cfg(feature = "tcp-v13-selftest")]
mod cluster_transport;
#[cfg(feature = "unified-runtime")]
mod control_pool;
#[cfg(feature = "unified-runtime")]
mod domain_control;
#[cfg(feature = "unified-runtime")]
mod domain_evidence;
#[cfg(feature = "unified-runtime")]
mod domain_file_abi;
#[cfg(feature = "unified-runtime")]
mod domain_network;
#[cfg(feature = "unified-runtime")]
mod domain_platform;
#[cfg(feature = "unified-runtime")]
mod domain_services;
#[cfg(feature = "unified-runtime")]
mod domain_storage;
#[cfg(feature = "unified-runtime")]
mod domain_tasks;
#[cfg(feature = "unified-runtime")]
mod learning_canary;
#[cfg(feature = "unified-runtime")]
mod learning_evidence;
#[cfg(feature = "unified-runtime")]
mod learning_history;
#[cfg(feature = "unified-runtime")]
mod learning_prewarm;
#[cfg(feature = "unified-runtime")]
mod learning_replay;
#[cfg(feature = "unified-runtime")]
mod learning_session;
#[cfg(feature = "unified-runtime")]
mod learning_workload;
#[cfg(feature = "unified-runtime")]
mod local_placement;
#[cfg(feature = "unified-runtime")]
mod model_bank;
#[cfg(feature = "net-selftest")]
mod net_selftest;
#[cfg(feature = "unified-runtime")]
mod network_diagnostics;
#[cfg(feature = "unified-runtime")]
mod peer_replay;
#[cfg(feature = "unified-runtime")]
mod service_windows;
#[cfg(feature = "smp-selftest")]
#[cfg_attr(
    any(
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "storage-v13-selftest",
        feature = "prototype-runtime",
        feature = "tcp-v13-selftest"
    ),
    allow(dead_code)
)]
mod smp;
#[cfg(feature = "unified-runtime")]
mod storage_fault_capture;
#[cfg(feature = "unified-runtime")]
mod unified;
#[cfg(feature = "unified-runtime")]
mod unified_store;
#[cfg(feature = "unified-runtime")]
mod unified_task;
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "unified-runtime")]
use cyxia_arch_aarch64::timer;
use cyxia_contracts::*;
#[cfg(not(feature = "selftest"))]
mod ai;
mod clock;
#[cfg(any(
    feature = "tcp-v13-selftest",
    feature = "unified-runtime",
    all(feature = "ported", not(feature = "selftest"))
))]
mod entropy;
#[cfg(all(feature = "ported", not(feature = "selftest")))]
mod exec_memory;
#[cfg(feature = "graphics")]
mod graphics;
#[cfg_attr(feature = "smp-selftest", allow(dead_code))]
mod interrupts;
#[cfg(all(feature = "selftest", not(feature = "smp-selftest")))]
mod selftest;
#[cfg(all(feature = "ported", not(feature = "selftest")))]
mod shared_memory;
#[cfg(not(feature = "selftest"))]
mod shell;
#[cfg(not(feature = "selftest"))]
mod storage;
#[cfg(not(feature = "selftest"))]
mod user;
#[cfg(not(feature = "selftest"))]
mod user_heap;
#[cfg(any(
    feature = "graphics",
    feature = "storage-v13-selftest",
    feature = "tcp-v13-selftest",
    feature = "prototype-runtime",
    feature = "net-selftest",
    not(feature = "selftest")
))]
mod virtio_platform;
const HIGH: u64 = cyxia_platform_virt::HIGH_BASE;
core::arch::global_asm!(include_str!("../../crates/arch-aarch64/src/entry.S"),ram_base=const cyxia_platform_virt::RAM_BASE,entry=const cyxia_platform_virt::ENTRY,gic_base=const 0x08000000,uart_base=const 0x09000000,ram_end=const cyxia_platform_virt::USER_RAM_END,ram_table_count=const cyxia_platform_virt::RAM_MIB/2,ram_tables_bytes=const cyxia_platform_virt::RAM_MIB/2*4096);
// Versioned loader contract, retained in the ELF's read-only load segment.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.boot")]
static CYXIA_BOOT_PROFILE: [u64; 3] = [
    1,
    cyxia_platform_virt::RAM_MIB,
    cyxia_posix::vm::PAGE_COUNT as u64,
];
core::arch::global_asm!(include_str!("../../crates/arch-aarch64/src/vectors.S"));
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
static UART: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "smp-selftest"))]
static EXPECTED_PC: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "smp-selftest"))]
static EXPECTED_FAR: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "smp-selftest"))]
static FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static LOG_LOSS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "unified-runtime")]
#[repr(C, align(64))]
pub struct PanicEvidence {
    pub words: [AtomicU64; 8],
}
#[cfg(feature = "unified-runtime")]
#[used]
#[unsafe(no_mangle)]
pub static PANIC_EVIDENCE: PanicEvidence = PanicEvidence {
    words: [const { AtomicU64::new(0) }; 8],
};
fn log(s: &[u8]) {
    if let Err(PlatformError::Again) = try_log(s) {
        // Best-effort diagnostic caller drops this record; keep that loss visible.
        LOG_LOSS.fetch_add(1, Ordering::Relaxed);
        LOG_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1))
            .unwrap_or_else(|_| halt());
    }
}
fn try_log(s: &[u8]) -> Result<(), PlatformError> {
    let a = UART.load(Ordering::Relaxed);
    if a == 0 {
        return Err(PlatformError::Invalid);
    }
    let seq = LOG_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1))
        .unwrap_or_else(|_| halt());
    #[cfg(feature = "unified-runtime")]
    if domain_services::console_ready() {
        return match domain_services::enqueue_frame(1, seq, s) {
            Ok(()) => Ok(()),
            Err(cyxia_prototype::domains::Error::Busy | cyxia_prototype::domains::Error::Again) => {
                LOG_SEQUENCE.store(seq, Ordering::Relaxed);
                Err(PlatformError::Again)
            }
            Err(_) => {
                LOG_LOSS.fetch_add(1, Ordering::Relaxed);
                Err(PlatformError::Invalid)
            }
        };
    }
    let mut uart = unsafe {
        cyxia_driver_pl011::Pl011::attach(UartResource {
            base: PhysAddr(a),
            len: 4096,
        })
    }
    .unwrap();
    use cyxia_kernel_core::console::{TransmitError, write_frame};
    match write_frame(&mut uart, 1, seq, s) {
        Ok(written) => {
            interrupts::TEST_PROGRESS
                .bytes
                .fetch_add(written as u64, Ordering::Relaxed);
            Ok(())
        }
        Err(TransmitError::Again) => {
            // CPU0 foreground is the sole nonfatal writer. No byte escaped, so
            // a later attempt can use the same sequence without an artificial gap.
            LOG_SEQUENCE.store(seq, Ordering::Relaxed);
            Err(PlatformError::Again)
        }
        Err(error) => {
            if let TransmitError::Failed(written) = error {
                interrupts::TEST_PROGRESS
                    .bytes
                    .fetch_add(written as u64, Ordering::Relaxed);
            }
            LOG_LOSS.fetch_add(1, Ordering::Relaxed);
            Err(PlatformError::Invalid)
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
    #[cfg(feature = "smp-selftest")]
    {
        smp::exception(f, kind);
    }
    #[cfg(not(feature = "smp-selftest"))]
    exception_dispatch_primary(f, kind);
}
#[cfg(not(feature = "smp-selftest"))]
fn exception_dispatch_primary(f: &mut ExceptionFrame, kind: u64) {
    #[cfg(not(feature = "selftest"))]
    if kind == 8 || kind == 9 {
        if kind == 9 {
            interrupts::handle();
        }
        // Only AArch64 EL0 sync/IRQ vectors may return to the suspended caller.
        if let Some(pc) =
            unsafe { cyxia_arch_aarch64::user::capture(&f.regs, f.elr, f.spsr, f.esr, f.far, kind) }
        {
            f.elr = pc;
            f.spsr = 0x3c5;
            return;
        }
    }
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
#[cfg(not(feature = "smp-selftest"))]
fn hex(v: u64) {
    let mut b = *b"0000000000000000\n";
    for (i, x) in b[..16].iter_mut().enumerate() {
        *x = b"0123456789abcdef"[((v >> (60 - i * 4)) & 15) as usize];
    }
    log(&b);
}
#[cfg(all(feature = "selftest", not(feature = "smp-selftest")))]
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
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("msr daifset, #15", "wfe") }
    }
}
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(feature = "unified-runtime")]
    {
        // Panic diagnostics never need the ordinary console/task/policy gate.
        // First writer keeps the original failure if a secondary also panics.
        if PANIC_EVIDENCE.words[0]
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let (elr, esr, far): (u64, u64, u64);
            unsafe {
                core::arch::asm!("mrs {}, elr_el1", out(reg) elr, options(nostack, preserves_flags));
                core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, preserves_flags));
                core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, preserves_flags));
            }
            let (line, column, file) = info.location().map_or((0, 0, 0), |location| {
                let mut hash = 0xcbf29ce484222325u64;
                for byte in location.file().bytes() {
                    hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
                }
                (
                    u64::from(location.line()),
                    u64::from(location.column()),
                    hash,
                )
            });
            for (i, value) in [
                cyxia_arch_aarch64::cpu::slot() as u64,
                line,
                column,
                file,
                elr,
                esr,
                far,
            ]
            .into_iter()
            .enumerate()
            {
                PANIC_EVIDENCE.words[i + 1].store(value, Ordering::Relaxed);
            }
            PANIC_EVIDENCE.words[0].store(0x435950414e490001, Ordering::Release);
        }
    }
    #[cfg(not(feature = "unified-runtime"))]
    let _ = info;
    #[cfg(feature = "smp-selftest")]
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        smp::fatal(99);
    }
    #[cfg(not(feature = "unified-runtime"))]
    log(b"FAIL panic\n");
    halt()
}

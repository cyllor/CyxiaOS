use super::*;

#[cfg(not(feature = "smp-selftest"))]
static EXPECTED_PC: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "smp-selftest"))]
static EXPECTED_FAR: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "smp-selftest"))]
pub(super) static FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
#[repr(C)]
pub struct ExceptionFrame {
    pub(crate) regs: [u64; 31],
    pub(crate) elr: u64,
    pub(crate) spsr: u64,
    pub(crate) esr: u64,
    pub(crate) far: u64,
    pub(crate) pad: u64,
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
pub(crate) fn hex(v: u64) {
    let mut b = *b"0000000000000000\n";
    for (i, x) in b[..16].iter_mut().enumerate() {
        *x = b"0123456789abcdef"[((v >> (60 - i * 4)) & 15) as usize];
    }
    log(&b);
}
#[cfg(all(feature = "selftest", not(feature = "smp-selftest")))]
pub(super) fn fault_probe(addr: u64, write: bool) {
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

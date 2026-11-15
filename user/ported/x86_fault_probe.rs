//! Caught hardware page faults through the pinned Linux x86 musl signal ABI.
use super::{Action, nr, rust_probe_restore, syscall};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static CODE: AtomicUsize = AtomicUsize::new(0);
static ERROR: AtomicUsize = AtomicUsize::new(0);
static RESUME: AtomicUsize = AtomicUsize::new(0);
static HITS: AtomicUsize = AtomicUsize::new(0);
static FAILURES: AtomicUsize = AtomicUsize::new(0);

std::arch::global_asm!(
    ".global rust_probe_fault_read",
    "rust_probe_fault_read:",
    "mov (%rdi), %rax",
    ".global rust_probe_fault_read_resume",
    "rust_probe_fault_read_resume:",
    "ret",
    ".global rust_probe_fault_write",
    "rust_probe_fault_write:",
    "movb $1, (%rdi)",
    ".global rust_probe_fault_write_resume",
    "rust_probe_fault_write_resume:",
    "ret",
    options(att_syntax)
);
unsafe extern "C" {
    fn rust_probe_fault_read(address: usize);
    fn rust_probe_fault_read_resume();
    fn rust_probe_fault_write(address: usize);
    fn rust_probe_fault_write_resume();
}

extern "C" fn caught(signal: i32, info: *const u8, context: *mut u8) {
    // Musl x86_64 bits/signal.h: uc_mcontext.gregs begins at byte40;
    // RIP=16, ERR=19, TRAPNO=20 and CR2=22. siginfo has si_code at8,
    // si_addr at16. Read only ABI fields present in the real kernel frame.
    unsafe {
        let greg = |index: usize| context.add(40 + index * 8).cast::<u64>().read_unaligned();
        let valid = signal == 11
            && info.add(8).cast::<i32>().read_unaligned() == CODE.load(Relaxed) as i32
            && info.add(16).cast::<u64>().read_unaligned() == ADDRESS.load(Relaxed) as u64
            && greg(19) == ERROR.load(Relaxed) as u64
            && greg(20) == 14
            && greg(22) == ADDRESS.load(Relaxed) as u64;
        if !valid { FAILURES.fetch_add(1, Relaxed); }
        context.add(40 + 16 * 8).cast::<u64>().write_unaligned(RESUME.load(Relaxed) as u64);
    }
    HITS.fetch_add(1, Relaxed);
}

fn fault(address: usize, code: usize, error: usize, write: bool) {
    ADDRESS.store(address, Relaxed);
    CODE.store(code, Relaxed);
    ERROR.store(error, Relaxed);
    RESUME.store(if write { rust_probe_fault_write_resume as *const () as usize }
                 else { rust_probe_fault_read_resume as *const () as usize }, Relaxed);
    let before = HITS.load(Relaxed);
    unsafe {
        if write { rust_probe_fault_write(address); } else { rust_probe_fault_read(address); }
    }
    assert_eq!(HITS.load(Relaxed), before + 1, "hardware fault was not caught exactly once");
    assert_eq!(FAILURES.load(Relaxed), 0, "incorrect x86 siginfo or hardware fault metadata");
}

pub fn run() {
    assert_eq!(unsafe { syscall(213, [u64::MAX, 0, 0, 0, 0, 0]) }, -22);
    assert_eq!(unsafe { syscall(213, [0; 6]) }, -22);
    println!("RUST_STD_PROBE EPOLL_SIZE PASS");
    let action = Action { handler: caught as *const () as u64, flags: 0x0400_0004,
                          restorer: rust_probe_restore as *const () as u64, mask: 0 };
    let mut prior = Action::default();
    assert_eq!(unsafe { syscall(nr::RT_SIGACTION, [11, &action as *const _ as u64,
        &mut prior as *mut _ as u64, 8, 0, 0]) }, 0);
    fault(0x6000_0000, 1, 4, false);
    println!("RUST_STD_PROBE PF_MAPERR PASS");
    // Real anonymous mmap, mprotect and munmap Linux64 numbers. First touch
    // makes the readonly write a present-page hardware protection fault.
    let page = unsafe { syscall(9, [0, 4096, 3, 0x22, u64::MAX, 0]) };
    assert!(page > 0);
    unsafe { (page as *mut u8).write_volatile(0); }
    assert_eq!(unsafe { syscall(10, [page as u64, 4096, 1, 0, 0, 0]) }, 0);
    fault(page as usize, 2, 7, true);
    println!("RUST_STD_PROBE PF_READONLY PASS");
    assert_eq!(unsafe { syscall(10, [page as u64, 4096, 0, 0, 0, 0]) }, 0);
    // PTE is absent (ERR4), but allocated VMA exists: still SEGV_ACCERR.
    fault(page as usize, 2, 4, false);
    println!("RUST_STD_PROBE PF_PROT_NONE PASS");
    assert_eq!(unsafe { syscall(11, [page as u64, 4096, 0, 0, 0, 0]) }, 0);
    assert_eq!(unsafe { syscall(nr::RT_SIGACTION, [11, &prior as *const _ as u64, 0, 8, 0, 0]) }, 0);
}

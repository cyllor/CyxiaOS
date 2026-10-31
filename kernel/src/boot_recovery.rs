//! A01 boot failures retain deterministic local progress without an identity.
//! Test configuration is read once before storage; it cannot forge a receipt.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_arch_aarch64::{cpu, timer};

const MAGIC: u64 = 0x4359_5842_4f4f_5431;
const CONFIG_MAGIC: u64 = 0x4359_5841_3031_4346;
const SELFTEST: bool = include!(concat!(env!("OUT_DIR"), "/domain-selftest.rs"));
#[used]
#[unsafe(no_mangle)]
static mut A01_BOOT_CONFIG: [u64; 64] = [u64::MAX; 64];
#[repr(C, align(64))]
struct Evidence([AtomicU64; 64]);
#[used]
#[unsafe(no_mangle)]
static A01_BOOT_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 64]);
static MODEL_PASSED: AtomicBool = AtomicBool::new(false);
static MODE: AtomicU64 = AtomicU64::new(0);
static ALLOCATING: AtomicBool = AtomicBool::new(false);
static INJECTED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    assert_eq!(cpu::slot(), 0);
    let c = unsafe { core::ptr::addr_of!(A01_BOOT_CONFIG).read_volatile() };
    if SELFTEST
        && c[0] == CONFIG_MAGIC
        && c[1] == 1
        && c[2] <= 3
        && c[3] == 0
        && c[4..6] != [0; 2]
        && c[6..18].chunks(4).all(|h| h != [0; 4])
        && c[18..].iter().all(|v| *v == 0)
    {
        MODE.store(c[2], Ordering::Relaxed);
        for (word, value) in A01_BOOT_EVIDENCE.0[32..46].iter().zip(&c[4..18]) {
            word.store(*value, Ordering::Relaxed);
        }
    }
    A01_BOOT_EVIDENCE.0[1].store(1, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[3].store(1, Ordering::Relaxed); // booting, not ACTIVE
    A01_BOOT_EVIDENCE.0[5].store(MODE.load(Ordering::Relaxed), Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[0].store(MAGIC, Ordering::Release);
}
pub fn model_corruption() -> bool {
    SELFTEST && MODE.load(Ordering::Acquire) == 3
}
pub fn model_turn(spent: u64, kind: u64, result: Option<bool>) {
    A01_BOOT_EVIDENCE.0[20].store(spent, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[21].store(kind, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[22].store(cpu::slot() as u64, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[23].fetch_add(1, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[24].store(
        result.map_or(0, |v| if v { 1 } else { 2 }),
        Ordering::Release,
    );
}
/// CPU0 publishes only the worker's validated, successfully settled response.
/// The final total replaces the earlier checkpoint; faults, cancellation and
/// failed/late settlement leave result=0 and cannot certify model rejection.
pub fn model_settled(spent: u64, passed: bool) {
    assert_eq!(cpu::slot(), 0);
    A01_BOOT_EVIDENCE.0[20].store(spent, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[24].store(if passed { 1 } else { 2 }, Ordering::Release);
}
pub fn model_passed() {
    A01_BOOT_EVIDENCE.0[14].store(timer::ticks(), Ordering::Relaxed);
    MODEL_PASSED.store(true, Ordering::Release);
}
pub fn activation_allowed(epoch: u64) -> bool {
    epoch != 0
        && A01_BOOT_EVIDENCE.0[6].load(Ordering::Acquire) == epoch
        && MODEL_PASSED.load(Ordering::Acquire)
        && A01_BOOT_EVIDENCE.0[4].load(Ordering::Acquire) == 0
}
pub fn active() {
    assert!(activation_allowed(
        A01_BOOT_EVIDENCE.0[6].load(Ordering::Acquire)
    ));
    // Capture actual registered guest CPUs before sealing the normal terminal
    // state, just as SAFE_EXEC captures them below. A QEMU -smp argument alone
    // does not prove secondary startup. These are observations, never grants.
    for (word, value) in A01_BOOT_EVIDENCE.0[9..14]
        .iter()
        .zip(crate::smp::boot_progress())
    {
        word.store(value, Ordering::Relaxed);
    }
    A01_BOOT_EVIDENCE.0[15].store(timer::ticks(), Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[3].store(3, Ordering::Release);
}
pub fn allocating(value: bool) {
    ALLOCATING.store(value, Ordering::Release);
}
pub fn inject(operation: u64, block: u64) -> bool {
    if !SELFTEST
        || !ALLOCATING.load(Ordering::Acquire)
        || MODE.load(Ordering::Relaxed) != operation
        || INJECTED.swap(true, Ordering::AcqRel)
    {
        return false;
    }
    A01_BOOT_EVIDENCE.0[16].store(operation, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[17].store(block, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[18].store(timer::ticks(), Ordering::Release);
    true
}
pub fn durable(epoch: u64) {
    A01_BOOT_EVIDENCE.0[6].store(epoch, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[7].store(timer::ticks(), Ordering::Release);
}
/// No mount retry, auto-format, epoch substitute, network service or CACP is
/// reachable here. Failed DMA/journal custody stays pinned in the storage owner.
pub fn run(reason: u64) -> ! {
    assert_eq!(cpu::slot(), 0);
    crate::smp::prototype_runtime::enable_boot_baseline().expect("boot baseline ownership");
    A01_BOOT_EVIDENCE.0[4].store(reason, Ordering::Relaxed);
    A01_BOOT_EVIDENCE.0[3].store(2, Ordering::Release); // deterministic SAFE_EXEC
    crate::log(b"BOOT_SAFE_EXEC new_ai=closed cluster=closed\n");
    loop {
        let _ = crate::domain_tasks::service_segment(|| {
            let _ = crate::domain_platform::poll(crate::domain_tasks::now_ns());
            A01_BOOT_EVIDENCE.0[2].fetch_add(1, Ordering::AcqRel);
            for (word, value) in A01_BOOT_EVIDENCE.0[9..14]
                .iter()
                .zip(crate::smp::boot_progress())
            {
                word.store(value, Ordering::Relaxed);
            }
            A01_BOOT_EVIDENCE.0[8].store(timer::ticks(), Ordering::Relaxed);
            A01_BOOT_EVIDENCE.0[2].fetch_add(1, Ordering::Release);
        });
        // The fixed hardware heartbeat wakes progress without inference.
        unsafe { core::arch::asm!("wfe", options(nostack)) };
    }
}

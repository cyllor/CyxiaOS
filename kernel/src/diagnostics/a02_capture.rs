//! Optional EL1-only capture of the real unified scheduler boundaries.
//! QEMU loads a nonce/artifact identity into CONFIG before the first instruction;
//! it never supplies roles, ownership, counters, events, or a verdict.
//! 1 MiB of event storage is reserved in the kernel image's physical footprint,
//! outside (and never borrowed from) the eight-MiB control allocation pool.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_arch_aarch64::{cpu, timer};
#[path = "a02_capture/state.rs"]
mod state;
pub use state::{PreparedTask, Task};

pub const EVENTS: usize = 8192;
const TASKS: usize = 512;
const CONFIG_MAGIC: u64 = 0x4359584130324346;
#[repr(transparent)]
struct Protected(UnsafeCell<state::Capture<EVENTS, TASKS>>);
unsafe impl Sync for Protected {}
#[used]
#[unsafe(no_mangle)]
static A02_CAPTURE: Protected = Protected(UnsafeCell::new(state::Capture::new()));
// Nonzero initialization keeps this outside .bss: boot zeroing must not erase
// the loader's immutable test input. EL0 page tables never map this storage.
#[used]
#[unsafe(no_mangle)]
static mut A02_CONFIG: [u64; 64] = [u64::MAX; 64];
#[used]
#[unsafe(no_mangle)]
static A02_CAPTURE_LAYOUT: [u64; 8] = [
    2,
    EVENTS as u64,
    TASKS as u64,
    512,
    128,
    (512 + EVENTS * 128) as u64,
    512,
    core::mem::size_of::<state::Capture<EVENTS, TASKS>>() as u64,
];
#[used]
#[unsafe(no_mangle)]
static A02_BOOT_MODEL: [u8; 2772] = cyxia_prototype::learning::seed::UNTRAINED_SEED0_BYTES;
static ENABLED: AtomicBool = AtomicBool::new(false);
static LOCK: AtomicBool = AtomicBool::new(false);
static WAITERS: AtomicBool = AtomicBool::new(false);

fn locked<R>(f: impl FnOnce(&mut state::Capture<EVENTS, TASKS>) -> R) -> R {
    while LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        // A capture update is short but its owner can be descheduled by the
        // host. Sleeping in the architectural event state prevents another
        // paid vCPU from turning that wall delay into charged spin execution.
        // Strong CAS is required: a spurious weak-CAS failure with no owner
        // would otherwise sleep without a corresponding unlock event.
        WAITERS.store(true, Ordering::Release);
        // Recheck after publishing waiter state. If unlock raced before the
        // publication, the next CAS can acquire immediately; if it raced
        // after, its SEV remains in this CPU's event register for WFE.
        if LOCK.load(Ordering::Acquire) {
            unsafe {
                core::arch::asm!("wfe", options(nostack));
            }
        }
    }
    let result = f(unsafe { &mut *A02_CAPTURE.0.get() });
    LOCK.store(false, Ordering::Release);
    // SEV is a relatively expensive QEMU synchronization helper. Broadcast it
    // only when a contender published that it may sleep; the recheck above
    // closes the unlock-before-WFE race. Multiple waiters are all woken, and
    // losers publish WAITERS again before sleeping for the next owner.
    if WAITERS.load(Ordering::Acquire) && WAITERS.swap(false, Ordering::AcqRel) {
        unsafe {
            core::arch::asm!("dsb ishst", "sev", options(nostack));
        }
    }
    result
}
/// CPU0, before any gate can dispatch an EL0 context.
pub fn init() {
    let config = unsafe { core::ptr::addr_of!(A02_CONFIG).read_volatile() };
    if config[0] != CONFIG_MAGIC
        || config[1] != 2
        || config[2..4] == [0, 0]
        || config[4..16].chunks(4).any(|h| h == [0; 4])
        || config[16..].iter().any(|v| *v != 0)
    {
        return;
    }
    locked(|s| s.begin(timer::ticks(), timer::frequency(), &config));
    ENABLED.store(true, Ordering::Release);
}
pub fn init_boot(epoch: u64) {
    if ENABLED.load(Ordering::Acquire) {
        locked(|s| s.boot(epoch));
    }
}
/// Register immutable task identity in its own paid owner turn before the
/// first architectural entry. The later `enter` still records the exact
/// boundary and verifies that the prepared identity is unchanged.
pub fn prepare(task: Task) -> Option<usize> {
    if ENABLED.load(Ordering::Acquire) {
        locked(|s| s.prepare(timer::ticks(), task))
    } else {
        None
    }
}
pub fn enter_prepared(task: Task, task_index: usize) {
    if ENABLED.load(Ordering::Acquire)
        && !locked(|s| s.enter_prepared(timer::ticks(), cpu::slot(), task, task_index))
    {
        loop {
            core::hint::spin_loop();
        }
    }
}
/// Called immediately around the actual arch user::enter, after IRQ masking.
/// Once complete, park all further EL0 entries; do not synthesize returns.
pub fn enter(task: Task) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    if !locked(|s| s.enter(timer::ticks(), cpu::slot(), task)) {
        loop {
            core::hint::spin_loop();
        }
    }
}
pub fn returned() {
    if ENABLED.load(Ordering::Acquire) {
        locked(|s| s.exit(timer::ticks(), cpu::slot()));
    }
}
pub fn returned_prepared(task_index: usize) {
    if ENABLED.load(Ordering::Acquire) {
        locked(|s| s.exit_prepared(timer::ticks(), cpu::slot(), task_index));
    }
}
pub fn publish(generation: u64, masks: [u64; 6]) {
    if ENABLED.load(Ordering::Acquire) {
        locked(|s| s.owner(timer::ticks(), generation, masks));
    }
}
pub fn bind(cpu: usize, id: u64, generation: u64, mask: u64, result: u64) {
    if ENABLED.load(Ordering::Acquire) {
        locked(|s| s.bind(timer::ticks(), cpu, id, generation, mask, result));
    }
}

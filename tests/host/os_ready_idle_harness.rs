use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
static NOW: AtomicU64 = AtomicU64::new(100);
static DEADLINE: AtomicU64 = AtomicU64::new(0);
static HALTS: AtomicU64 = AtomicU64::new(0);
static ARMS: AtomicU64 = AtomicU64::new(0);
static ENABLED: AtomicBool = AtomicBool::new(true);
static READY: AtomicBool = AtomicBool::new(false);
static ARRIVE_ON_CLI: AtomicBool = AtomicBool::new(false);
static ARM_FAIL: AtomicBool = AtomicBool::new(false);
mod user {
    #[allow(dead_code)] // The original OS idle never queries this fixture.
    pub fn runnable() -> bool {
        assert!(!super::ENABLED.load(super::Ordering::SeqCst), "readiness must be checked with IF clear");
        super::READY.load(super::Ordering::SeqCst)
    }
}
mod arch {
    pub mod cpu {
        use super::super::*;
        pub fn disable_interrupts() {
            ENABLED.store(false, Ordering::SeqCst);
            if ARRIVE_ON_CLI.swap(false, Ordering::SeqCst) {
                READY.store(true, Ordering::SeqCst);
            }
        }
        pub unsafe fn enable_interrupts() { ENABLED.store(true, Ordering::SeqCst); }
        pub unsafe fn enable_and_wait() {
            assert!(!ENABLED.swap(true, Ordering::SeqCst));
            HALTS.fetch_add(1, Ordering::SeqCst);
            NOW.store(DEADLINE.load(Ordering::SeqCst), Ordering::SeqCst);
        }
    }
}
mod machine {
    pub mod runtime {
        use crate::{arch, ARMS, ARM_FAIL, DEADLINE, NOW, Ordering};
        type Error = ();
        pub fn now_ns() -> u64 { NOW.load(Ordering::SeqCst) }
        pub fn arm_deadline(deadline: u64) -> Result<(), Error> {
            assert!(!crate::ENABLED.load(Ordering::SeqCst));
            ARMS.fetch_add(1, Ordering::SeqCst);
            DEADLINE.store(deadline, Ordering::SeqCst);
            if ARM_FAIL.load(Ordering::SeqCst) { Err(()) } else { Ok(()) }
        }
        // PRODUCTION_PRIMITIVE
    }
}
// PRODUCTION_IDLE
fn reset(ready: bool) {
    NOW.store(100, Ordering::SeqCst);
    HALTS.store(0, Ordering::SeqCst);
    ARMS.store(0, Ordering::SeqCst);
    ENABLED.store(true, Ordering::SeqCst);
    READY.store(ready, Ordering::SeqCst);
    ARRIVE_ON_CLI.store(false, Ordering::SeqCst);
    ARM_FAIL.store(false, Ordering::SeqCst);
}
#[test]
fn ready_syscall_producer_does_not_sleep_between_dispatches() {
    reset(true);
    for _ in 0..1000 { idle(); }
    assert_eq!(HALTS.load(Ordering::SeqCst), 0, "runnable work paid 1000 unnecessary idle ticks");
    assert_eq!(ARMS.load(Ordering::SeqCst), 0);
    assert_eq!(NOW.load(Ordering::SeqCst), 100);
    assert!(ENABLED.load(Ordering::SeqCst));
}
#[test]
fn no_runnable_work_keeps_the_existing_one_millisecond_backstop() {
    reset(false);
    idle();
    assert_eq!(HALTS.load(Ordering::SeqCst), 1);
    assert_eq!(NOW.load(Ordering::SeqCst), 1_000_100);
    assert!(ENABLED.load(Ordering::SeqCst));
}
#[test]
fn work_arriving_at_interrupt_mask_boundary_prevents_the_sleep() {
    reset(false);
    ARRIVE_ON_CLI.store(true, Ordering::SeqCst);
    idle();
    assert_eq!(HALTS.load(Ordering::SeqCst), 0);
    assert!(ENABLED.load(Ordering::SeqCst));
}
#[test]
fn expired_deadline_and_arm_failure_restore_interrupts_without_halting() {
    reset(false);
    machine::runtime::idle_until(100).unwrap();
    assert!(ENABLED.load(Ordering::SeqCst));
    ARM_FAIL.store(true, Ordering::SeqCst);
    assert_eq!(machine::runtime::idle_until(200), Err(()));
    assert!(ENABLED.load(Ordering::SeqCst));
    assert_eq!(HALTS.load(Ordering::SeqCst), 0);
}

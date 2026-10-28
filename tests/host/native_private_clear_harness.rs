//! The native cursor/turn/accounting function runs unchanged. ARM stores and
//! DSB are observable host substitutes; this does not establish native WCET.
#![allow(dead_code, unused_unsafe)]
use std::sync::{Mutex, atomic::{AtomicU64, Ordering}};
static CPU_NS: AtomicU64 = AtomicU64::new(0);
static BARRIERS: AtomicU64 = AtomicU64::new(0);
static DATA: Mutex<[[u8; 9 * 4096]; 2]> = Mutex::new([[0xcc; 9 * 4096]; 2]);
static VISITS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());
mod timer {
    pub fn cpu_ticks() -> u64 { super::CPU_NS.load(super::Ordering::Acquire) }
    pub fn cpu_elapsed_ns(start: u64) -> u64 { cpu_ticks() - start }
}
struct Native { clear_next: u32, in_job: bool, probing: bool, cpu_ns: u64, phase: u64 }
impl Native { fn phase(&mut self, value: u64) { self.phase = value; } }
struct Worker { native: Native }
fn clear_private_block(slot: usize, offset: usize) {
    assert!(matches!(slot, 1 | 2));
    assert_eq!(offset % 32, 0);
    assert!(offset + 32 <= 9 * 4096);
    DATA.lock().unwrap()[slot - 1][offset..offset + 32].fill(0);
    VISITS.lock().unwrap().push((slot, offset));
    CPU_NS.fetch_add(1000, Ordering::AcqRel);
}
// NATIVE_CLEAR
fn reset(job: bool) -> Worker {
    *DATA.lock().unwrap() = [[0xcc; 9 * 4096]; 2];
    VISITS.lock().unwrap().clear();
    CPU_NS.store(0, Ordering::Release);
    BARRIERS.store(0, Ordering::Release);
    Worker { native: Native { clear_next: 1, in_job: job, probing: !job, cpu_ns: 0, phase: 0 } }
}
#[test]
fn normal_250us_wakes_cannot_spend_the_entire_snapshot_lifetime_on_dispatch_overhead() {
    let mut worker = reset(true);
    let mut wall_ns = 0;
    while worker.native.clear_next != 0 && wall_ns < 50_000_000 {
        assert!(!continue_private_clear(&mut worker, 1));
        wall_ns += 250_000;
    }
    assert_eq!(worker.native.clear_next, 0, "private clearing consumed the entire 50ms snapshot before EL0 entry");
    assert!(wall_ns < 50_000_000);
    assert!(continue_private_clear(&mut worker, 1));
    assert_eq!(worker.native.cpu_ns, 9 * 4096 / 32 * 1000 + 500);
}
#[test]
fn exact_bytes_disjoint_owner_and_independent_barrier_are_retained() {
    let mut worker = reset(true);
    while worker.native.clear_next != PRIVATE_CLEAR_BARRIER {
        let before = CPU_NS.load(Ordering::Acquire);
        assert!(!continue_private_clear(&mut worker, 1));
        assert_eq!(BARRIERS.load(Ordering::Acquire), 0);
        assert!(CPU_NS.load(Ordering::Acquire) - before <= 2_500_000);
    }
    assert!(DATA.lock().unwrap()[0].iter().all(|byte| *byte == 0));
    assert!(DATA.lock().unwrap()[1].iter().all(|byte| *byte == 0xcc));
    let expected: Vec<_> = (0..PRIVATE_CLEAR_BYTES).step_by(32).map(|offset| (1, offset)).collect();
    assert_eq!(*VISITS.lock().unwrap(), expected);
    assert!(!continue_private_clear(&mut worker, 1));
    assert_eq!(BARRIERS.load(Ordering::Acquire), 1);
    assert_eq!(worker.native.clear_next, 0);
    assert!(continue_private_clear(&mut worker, 1));
    assert_eq!(BARRIERS.load(Ordering::Acquire), 1);
}
#[test]
fn a_retained_cursor_never_reclears_an_already_completed_prefix() {
    let mut worker = reset(true);
    DATA.lock().unwrap()[0][..4096].fill(0);
    worker.native.clear_next = 4097;
    assert!(!continue_private_clear(&mut worker, 1));
    assert_eq!(VISITS.lock().unwrap().first(), Some(&(1, 4096)));
    assert!(VISITS.lock().unwrap().iter().all(|(_, offset)| *offset >= 4096));
    assert!(DATA.lock().unwrap()[0][..4096].iter().all(|byte| *byte == 0));
}
#[test]
fn boot_probe_uses_separate_physical_credit_without_fabricating_job_cost() {
    let mut worker = reset(false);
    while worker.native.clear_next != 0 { assert!(!continue_private_clear(&mut worker, 2)); }
    assert_eq!(worker.native.phase, 1);
    assert_eq!(worker.native.cpu_ns, 0);
    assert!(CPU_NS.load(Ordering::Acquire) > 0);
    assert!(DATA.lock().unwrap()[1].iter().all(|byte| *byte == 0));
}
#[test]
fn idle_cursor_does_not_charge_or_modify_anything() {
    let mut worker = reset(true);
    worker.native.clear_next = 0;
    assert!(continue_private_clear(&mut worker, 1));
    assert_eq!(CPU_NS.load(Ordering::Acquire), 0);
    assert_eq!(BARRIERS.load(Ordering::Acquire), 0);
    assert!(VISITS.lock().unwrap().is_empty());
}

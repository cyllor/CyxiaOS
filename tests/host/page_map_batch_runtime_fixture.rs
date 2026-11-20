use crate::{code_permissions::{self, Backend, Pages, Phase, PhaseTable}, space::Error};
use std::sync::atomic::{AtomicBool as StdBool, AtomicU64, Ordering};
pub static TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());
@RAM@
static CPU: AtomicU64 = AtomicU64::new(0);
static ACQUIRES: AtomicU64 = AtomicU64::new(0);
static RELEASES: AtomicU64 = AtomicU64::new(0);
static SEAL_CALLS: AtomicU64 = AtomicU64::new(0);
// Hardware fixtures: preserve local-refresh-before-remote-failure ordering.
const MODEL_PAGES: usize = 8192;
static PTE_WRITABLE: [StdBool; MODEL_PAGES] = [const { StdBool::new(true) }; MODEL_PAGES];
static LOCAL_WRITABLE: [StdBool; MODEL_PAGES] = [const { StdBool::new(true) }; MODEL_PAGES];
static PEER_WRITABLE: [StdBool; MODEL_PAGES] = [const { StdBool::new(true) }; MODEL_PAGES];
static PTE_CALLS: AtomicU64 = AtomicU64::new(0);
static FENCE_CALLS: AtomicU64 = AtomicU64::new(0);
static PTE_FAIL_AT: AtomicU64 = AtomicU64::new(u64::MAX);
static FENCE_FAIL_AT: AtomicU64 = AtomicU64::new(u64::MAX);
static PUBLISH_RANGES: std::sync::Mutex<Vec<(u64, usize)>> = std::sync::Mutex::new(Vec::new());
// Observation only: each production atomic operation is forwarded unchanged.
struct AtomicBool(StdBool);
impl AtomicBool {
    const fn new(value: bool) -> Self { Self(StdBool::new(value)) }
    fn compare_exchange(&self, old: bool, new: bool, success: Ordering, failure: Ordering) -> Result<bool, bool> {
        let result = self.0.compare_exchange(old, new, success, failure);
        if result.is_ok() { ACQUIRES.fetch_add(1, Ordering::Relaxed); }
        result
    }
    fn store(&self, value: bool, ordering: Ordering) {
        self.0.store(value, ordering);
        if !value { RELEASES.fetch_add(1, Ordering::Relaxed); }
    }
}
@CODE_PHASES@
@USER_ALIASES@
@ALIAS_GATE@
@ALIAS_BATCH_OWNER@
fn cpu_slot() -> usize { CPU.load(Ordering::Relaxed) as usize }

@PRODUCTION_ALIAS_RUNTIME@
pub fn reset() {
    CPU.store(0, Ordering::Relaxed);
    ALIAS_GATE.0.store(false, Ordering::Relaxed);
    ALIAS_BATCH_OWNER.store(0, Ordering::Relaxed);
    ACQUIRES.store(0, Ordering::Relaxed);
    RELEASES.store(0, Ordering::Relaxed);
    SEAL_CALLS.store(0, Ordering::Relaxed);
    clear_observations();
    for page in 0..MODEL_PAGES {
        CODE_PHASES.set(page, Phase::StableWritable).unwrap();
        USER_ALIASES[page].store(0, Ordering::Relaxed);
        PTE_WRITABLE[page].store(true, Ordering::Relaxed);
        LOCAL_WRITABLE[page].store(true, Ordering::Relaxed);
        PEER_WRITABLE[page].store(true, Ordering::Relaxed);
    }
}
pub fn phase(physical: u64, phase: Phase) {
    CODE_PHASES.set((physical / 4096) as usize, phase).unwrap();
}
pub fn count(physical: u64) -> u64 {
    USER_ALIASES[(physical / 4096) as usize].load(Ordering::Acquire)
}
pub fn set_count(physical: u64, value: u64) {
    USER_ALIASES[(physical / 4096) as usize].store(value, Ordering::Release);
}
pub fn locks() -> (u64, u64) {
    (ACQUIRES.load(Ordering::Relaxed), RELEASES.load(Ordering::Relaxed))
}
pub fn force_gate(value: bool) { ALIAS_GATE.0.store(value, Ordering::Release); }
pub fn gate() -> bool { ALIAS_GATE.0.load(Ordering::Acquire) }
pub fn owner() -> u64 { ALIAS_BATCH_OWNER.load(Ordering::Acquire) }
pub fn set_cpu(cpu: usize) { CPU.store(cpu as u64, Ordering::Release); }
pub fn single_change(physical: u64, old: u64, new: u64) -> bool {
    x86_runtime_mapping_change(physical, old, new)
}
pub fn begin() -> u64 { x86_runtime_mapping_batch_begin() }
pub fn change(owner: u64, physical: u64, old: u64, new: u64) -> bool {
    x86_runtime_mapping_batch_change(owner, physical, old, new)
}
pub fn end(owner: u64) -> bool { x86_runtime_mapping_batch_end(owner) }
pub fn fail_fence_at(call: u64) { FENCE_FAIL_AT.store(call, Ordering::Release); }
pub fn fail_pte_at(call: u64) { PTE_FAIL_AT.store(call, Ordering::Release); }
pub fn seal_calls() -> u64 { SEAL_CALLS.load(Ordering::Acquire) }
pub fn publish_code_fixture(address: u64, length: usize) -> Result<(), crate::Errno> {
    assert!(!gate(), "RX publication must not run while alias batch holds gate");
    SEAL_CALLS.fetch_add(1, Ordering::AcqRel);
    PUBLISH_RANGES.lock().unwrap().push((address - crate::HIGH, length));
    // Observation only: actual production wrapper and transaction perform all
    // checks, phases, original alias-gate handling and every backend operation.
    crate::production_process_arch::publish_code(address, length)
}
pub fn ranges() -> Vec<(u64, usize)> { PUBLISH_RANGES.lock().unwrap().clone() }
pub fn clear_observations() {
    ACQUIRES.store(0, Ordering::Relaxed);
    RELEASES.store(0, Ordering::Relaxed);
    SEAL_CALLS.store(0, Ordering::Relaxed);
    PTE_CALLS.store(0, Ordering::Relaxed);
    FENCE_CALLS.store(0, Ordering::Relaxed);
    PTE_FAIL_AT.store(u64::MAX, Ordering::Relaxed);
    FENCE_FAIL_AT.store(u64::MAX, Ordering::Relaxed);
    PUBLISH_RANGES.lock().unwrap().clear();
}
pub fn operations() -> (u64, u64) {
    (PTE_CALLS.load(Ordering::Acquire), FENCE_CALLS.load(Ordering::Acquire))
}
pub fn current_phase(physical: u64) -> Phase { code_phase(physical).unwrap() }
pub fn writable_views(physical: u64) -> (bool, bool, bool) {
    let page = (physical / 4096) as usize;
    (PTE_WRITABLE[page].load(Ordering::Acquire),
     LOCAL_WRITABLE[page].load(Ordering::Acquire),
     PEER_WRITABLE[page].load(Ordering::Acquire))
}
pub fn zero_eligible(physical: u64, bytes: usize) -> bool {
    (physical..physical + bytes as u64).step_by(4096).all(|page| {
        current_phase(page) == Phase::StableWritable && count(page) == 0
            && writable_views(page) == (true, true, true)
    })
}
// Only physical link-address translation and hardware PTE/fence effects are
// fixtures here; all permission transaction bodies below are extracted intact.
#[allow(non_upper_case_globals)]
static __rodata_end: u8 = 0;
fn pa(_: u64) -> u64 { 0x00100000 }
mod arch {
    pub use crate::space;
    pub mod kernel_space {
        pub unsafe fn set_direct_permissions(physical: u64, writable: bool) -> Result<(), crate::space::Error> {
            super::super::write_direct_pte(physical, writable)
        }
    }
}
fn write_direct_pte(physical: u64, writable: bool) -> Result<(), Error> {
    assert!(gate(), "production alias guard must span every permission PTE write");
    let call = PTE_CALLS.fetch_add(1, Ordering::AcqRel) + 1;
    if call == PTE_FAIL_AT.load(Ordering::Acquire) { return Err(Error::Timeout); }
    PTE_WRITABLE.get((physical / 4096) as usize).ok_or(Error::Address)?
        .store(writable, Ordering::Release);
    Ok(())
}
fn synchronize_tlb() -> Result<(), Error> {
    assert!(gate(), "production alias guard must span every permission fence");
    let call = FENCE_CALLS.fetch_add(1, Ordering::AcqRel) + 1;
    for page in 0..MODEL_PAGES {
        LOCAL_WRITABLE[page].store(PTE_WRITABLE[page].load(Ordering::Acquire), Ordering::Release);
    }
    // Production synchronize_tlb reloads local CR3 before an IPI/ACK timeout.
    if call == FENCE_FAIL_AT.load(Ordering::Acquire) { return Err(Error::Timeout); }
    for page in 0..MODEL_PAGES {
        PEER_WRITABLE[page].store(PTE_WRITABLE[page].load(Ordering::Acquire), Ordering::Release);
    }
    Ok(())
}
@PRODUCTION_CODE_RUNTIME@

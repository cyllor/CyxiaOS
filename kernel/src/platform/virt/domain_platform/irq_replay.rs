//! The hard IRQ only appends fixed atomic raw events. CPU0 later imports the
//! measured original core and timestamps through the protected capture API.
use super::*;
use cyxia_prototype::learning::{self, capture::RunKey, reward::CpuClass};
const EVENTS: usize = 128;
// event id, run generation, actual core, first ticks, last ticks
static ROWS: [[AtomicU64; 5]; EVENTS] = [const { [const { AtomicU64::new(0) }; 5] }; EVENTS];
static HEAD: AtomicU64 = AtomicU64::new(0);
static TAIL: AtomicU64 = AtomicU64::new(0);
static SERIAL: AtomicU64 = AtomicU64::new(0);
static ACTIVE_IRQ: AtomicU64 = AtomicU64::new(0);
static BOUND_IRQ: AtomicU64 = AtomicU64::new(0);
static BOOT: AtomicU64 = AtomicU64::new(0);
static TRIAL: AtomicU64 = AtomicU64::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static ENTERED: AtomicU64 = AtomicU64::new(0);
static CORE: AtomicU64 = AtomicU64::new(0);
static FIRST: AtomicU64 = AtomicU64::new(0);
static LOST: AtomicU64 = AtomicU64::new(0);
fn run() -> RunKey {
    RunKey {
        boot_epoch: BOOT.load(Ordering::Acquire),
        trial_id: TRIAL.load(Ordering::Acquire),
        generation: GENERATION.load(Ordering::Acquire),
    }
}
fn ns(ticks: u64) -> u64 {
    ((u128::from(ticks) * 1_000_000_000) / u128::from(timer::frequency())).min(u128::from(u64::MAX))
        as u64
}
pub fn source() -> Result<ObjectKey, Error> {
    (0..IRQ_SLOTS)
        .filter_map(registered_irq)
        .find(|(_, kind, _)| *kind == 2)
        .map(|v| v.0)
        .ok_or(Error::NotReady)
}
pub fn activate(key: RunKey) -> Result<(), Error> {
    owner();
    let irq = source()?;
    if run() == key && BOUND_IRQ.load(Ordering::Acquire) == irq.id {
        return Ok(());
    }
    if ACTIVE_IRQ.load(Ordering::Acquire) != 0
        || HEAD.load(Ordering::Acquire) != TAIL.load(Ordering::Acquire)
        || ENTERED.load(Ordering::Acquire) != 0
        || INFLIGHT[slot(irq.id as u32)?].load(Ordering::Acquire) != 0
    {
        return Err(Error::Busy);
    }
    crate::learning_evidence::register_recorded_core_owner(irq, attest)
        .map_err(|_| Error::NotReady)?;
    BOOT.store(key.boot_epoch, Ordering::Relaxed);
    TRIAL.store(key.trial_id, Ordering::Relaxed);
    GENERATION.store(key.generation, Ordering::Relaxed);
    LOST.store(0, Ordering::Relaxed);
    BOUND_IRQ.store(irq.id, Ordering::Release);
    ACTIVE_IRQ.store(irq.id, Ordering::Release);
    Ok(())
}
pub(super) fn entered(irq: u32, core: usize, first: u64) {
    if ACTIVE_IRQ.load(Ordering::Acquire) != u64::from(irq) {
        return;
    }
    // GIC masks this SPI and its existing INFLIGHT ownership remains held
    // through completed(). The same device cannot have two live producers.
    if ENTERED.load(Ordering::Acquire) != 0 {
        LOST.fetch_add(1, Ordering::Relaxed);
        return;
    }
    CORE.store(core as u64, Ordering::Relaxed);
    FIRST.store(first, Ordering::Relaxed);
    ENTERED.store(GENERATION.load(Ordering::Acquire), Ordering::Release);
}
pub(super) fn completed(irq: u32, last: u64) {
    if BOUND_IRQ.load(Ordering::Acquire) != u64::from(irq) {
        return;
    }
    let generation = ENTERED.swap(0, Ordering::AcqRel);
    if generation == 0 {
        return;
    }
    let head = HEAD.load(Ordering::Relaxed);
    let tail = TAIL.load(Ordering::Acquire);
    if generation != GENERATION.load(Ordering::Acquire)
        || head == u64::MAX
        || head.saturating_sub(tail) >= EVENTS as u64
    {
        LOST.fetch_add(1, Ordering::Release);
        return;
    }
    let Some(next) = SERIAL.load(Ordering::Relaxed).checked_add(1) else {
        LOST.fetch_add(1, Ordering::Release);
        return;
    };
    SERIAL.store(next, Ordering::Relaxed);
    let row = &ROWS[head as usize % EVENTS];
    row[1].store(generation, Ordering::Relaxed);
    row[2].store(CORE.load(Ordering::Relaxed), Ordering::Relaxed);
    row[3].store(FIRST.load(Ordering::Relaxed), Ordering::Relaxed);
    row[4].store(last, Ordering::Relaxed);
    row[0].store(next, Ordering::Release);
    HEAD.store(head + 1, Ordering::Release);
}
fn attest(
    key: RunKey,
    owner: ObjectKey,
    id: u64,
    core: u16,
    first: u64,
    last: u64,
) -> Result<(), learning::Error> {
    if run() != key
        || owner.id != BOUND_IRQ.load(Ordering::Acquire)
        || owner.generation != 1
        || LOST.load(Ordering::Acquire) != 0
    {
        return Err(learning::Error::Evidence);
    }
    let tail = TAIL.load(Ordering::Acquire);
    if tail >= HEAD.load(Ordering::Acquire) {
        return Err(learning::Error::Stale);
    }
    let row = &ROWS[tail as usize % EVENTS];
    if row[0].load(Ordering::Acquire) != id
        || row[1].load(Ordering::Relaxed) != key.generation
        || row[2].load(Ordering::Relaxed) != u64::from(core)
        || ns(row[3].load(Ordering::Relaxed)) != first
        || ns(row[4].load(Ordering::Relaxed)) != last
    {
        return Err(learning::Error::Evidence);
    }
    Ok(())
}
pub fn poll(key: RunKey) -> Result<bool, Error> {
    owner();
    if run() != key {
        return Err(Error::Stale);
    }
    if LOST.load(Ordering::Acquire) != 0 {
        return Err(Error::Capacity);
    }
    for _ in 0..8 {
        let tail = TAIL.load(Ordering::Acquire);
        if tail >= HEAD.load(Ordering::Acquire) {
            return Ok(true);
        }
        let row = &ROWS[tail as usize % EVENTS];
        let id = row[0].load(Ordering::Acquire);
        let owner = ObjectKey {
            id: BOUND_IRQ.load(Ordering::Acquire),
            generation: 1,
        };
        crate::learning_evidence::record_on_core(
            key,
            owner,
            CpuClass::ExecutorWork,
            id,
            row[2].load(Ordering::Relaxed) as u16,
            ns(row[3].load(Ordering::Relaxed)),
            ns(row[4].load(Ordering::Relaxed)),
        )
        .map_err(|_| Error::Busy)?;
        TAIL.store(tail + 1, Ordering::Release);
    }
    Ok(TAIL.load(Ordering::Acquire) == HEAD.load(Ordering::Acquire))
}
pub fn drain(key: RunKey) -> Result<bool, Error> {
    owner();
    if run() != key {
        return Err(Error::Stale);
    }
    ACTIVE_IRQ.store(0, Ordering::Release);
    if ENTERED.load(Ordering::Acquire) != 0
        || INFLIGHT[slot(BOUND_IRQ.load(Ordering::Acquire) as u32)?].load(Ordering::Acquire) != 0
    {
        return Ok(false);
    }
    poll(key)
}
pub fn release(key: RunKey) -> Result<(), Error> {
    if !drain(key)? {
        return Err(Error::Busy);
    }
    BOUND_IRQ.store(0, Ordering::Release);
    Ok(())
}

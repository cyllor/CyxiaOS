//! A03 ordinary, paid read-only demand. No learning scope or policy injection.
pub const PROFILE: bool = cfg!(cyxia_a03_demand);
pub const HIGH_NS: u64 = 10_000_000_000;
pub const QUIET_NS: u64 = 2_000_000_000;
#[used]
#[unsafe(no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".cyxia.boot"))]
pub static A03_DEMAND_V16_LAYOUT: [u64; 6] = [
    0x4359413033443136,
    1,
    PROFILE as u64,
    1024,
    HIGH_NS,
    QUIET_NS,
];

#[cfg(any(cyxia_a03_demand, test))]
mod native {
    use super::*;
    use crate::domain_control::core_replay::{self as queue, OrdinarySnapshot};
    use core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use cyxia_prototype::domains::Error;
    use sha2::{Digest, Sha256};

    // The bank is an observation, never an authority for ownership or labels.
    #[repr(C, align(64))]
    pub struct Evidence([AtomicU64; 128]);
    #[used]
    #[unsafe(no_mangle)]
    pub static A03_DEMAND_V16_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 128]);
    #[repr(C, align(64))]
    pub struct ModelEvidence([AtomicU64; 640]);
    #[used]
    #[unsafe(no_mangle)]
    pub static A03_QUIET_MODEL_V16_EVIDENCE: ModelEvidence =
        ModelEvidence([const { AtomicU64::new(0) }; 640]);
    struct State {
        phase: u64,
        first: u64,
        withdrawn: u64,
        drained: u64,
        complete: u64,
        last: OrdinarySnapshot,
        schedule: [u8; 32],
        image: [u8; 32],
        target: [u64; 2],
        error: u64,
    }
    impl State {
        const fn new() -> Self {
            Self {
                phase: 1,
                first: 0,
                withdrawn: 0,
                drained: 0,
                complete: 0,
                last: OrdinarySnapshot {
                    first_ns: 0,
                    withdrawn: false,
                    released: 0,
                    queued: 0,
                    running: 0,
                    retirement_pending: 0,
                    retired: 0,
                    completed: 0,
                    rejected: 0,
                    worker_ns: 0,
                },
                schedule: [0; 32],
                image: [0; 32],
                target: [0; 2],
                error: 0,
            }
        }
    }
    struct Cell(UnsafeCell<State>);
    unsafe impl Sync for Cell {}
    static STATE: Cell = Cell(UnsafeCell::new(State::new()));
    static GATE: AtomicBool = AtomicBool::new(false);
    // The root gate serializes writers. A separate publication counter makes
    // a C0 snapshot fail closed when interrupted by a new ordinary decision.
    static DECISION_SEQ: AtomicU64 = AtomicU64::new(0);
    static DECISION_JOB: AtomicU64 = AtomicU64::new(0);
    static DECISION_VERSION: AtomicU64 = AtomicU64::new(0);
    static DECISION_AT: AtomicU64 = AtomicU64::new(0);
    static DECISION_INPUT_AT: AtomicU64 = AtomicU64::new(0);
    static RETAINED: AtomicBool = AtomicBool::new(false);
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            GATE.store(false, Ordering::Release);
        }
    }
    fn decision() -> Option<[u64; 4]> {
        let seq = DECISION_SEQ.load(Ordering::Acquire);
        if seq & 1 != 0 {
            return None;
        }
        let row = [
            DECISION_JOB.load(Ordering::Relaxed),
            DECISION_VERSION.load(Ordering::Relaxed),
            DECISION_AT.load(Ordering::Relaxed),
            DECISION_INPUT_AT.load(Ordering::Relaxed),
        ];
        (seq == DECISION_SEQ.load(Ordering::Acquire)).then_some(row)
    }
    pub fn ordinary_decision(job: u64, version: u64, input_at: u64, at: u64, slot: usize) {
        let b = &A03_DEMAND_V16_EVIDENCE.0;
        let publication = b[4].load(Ordering::Acquire);
        if publication == 0
            || publication & 1 != 0
            || b[5].load(Ordering::Relaxed) != 5
            || input_at <= b[10].load(Ordering::Relaxed)
            || publication != b[4].load(Ordering::Acquire)
            || job == 0
            || version == 0
            || input_at > at
            || RETAINED.load(Ordering::Acquire)
        {
            return;
        }
        DECISION_SEQ.fetch_add(1, Ordering::AcqRel);
        if crate::domain_evidence::visit_record(slot, job, |i, value| {
            A03_QUIET_MODEL_V16_EVIDENCE.0[i].store(value, Ordering::Relaxed);
        }) {
            DECISION_JOB.store(job, Ordering::Relaxed);
            DECISION_VERSION.store(version, Ordering::Relaxed);
            DECISION_AT.store(at, Ordering::Relaxed);
            DECISION_INPUT_AT.store(input_at, Ordering::Relaxed);
            RETAINED.store(true, Ordering::Release);
        }
        DECISION_SEQ.fetch_add(1, Ordering::Release);
    }
    fn publish(s: &State, at: u64) {
        let bank = &A03_DEMAND_V16_EVIDENCE.0;
        bank[4].fetch_add(1, Ordering::AcqRel);
        let mut w = [0; 128];
        w[..15].copy_from_slice(&[
            0x4359413033443136,
            1,
            128,
            1,
            0,
            s.phase,
            at,
            s.first,
            s.first.saturating_add(HIGH_NS),
            s.withdrawn,
            s.drained,
            s.complete,
            HIGH_NS,
            QUIET_NS,
            s.error,
        ]);
        let f = s.last;
        w[16..26].copy_from_slice(&[
            u64::from(f.withdrawn),
            f.released,
            f.queued,
            f.running,
            f.retirement_pending,
            f.retired,
            f.completed,
            f.rejected,
            f.worker_ns,
            100,
        ]);
        w[26..28].copy_from_slice(&s.target);
        for (offset, bytes) in [(32, s.schedule), (36, s.image)] {
            for (i, chunk) in bytes.chunks_exact(8).enumerate() {
                w[offset + i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
        }
        if let Some(row) = decision() {
            w[40..44].copy_from_slice(&row);
        }
        // Explicit scope: observed workload and last ordinary root decision;
        // no model response, Applied owner chain or full A03 PASS is asserted.
        w[44] = 1;
        for (i, value) in w.into_iter().enumerate() {
            if i != 4 {
                bank[i].store(value, Ordering::Relaxed);
            }
        }
        bank[4].fetch_add(1, Ordering::Release);
    }
    pub fn service_step() -> Result<bool, Error> {
        if cyxia_arch_aarch64::cpu::slot() != 0 {
            return Err(Error::Auth);
        }
        crate::domain_tasks::authorize_service_turn()?;
        GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        let _guard = Guard;
        let s = unsafe { &mut *STATE.0.get() };
        let at = crate::domain_platform::now_ns();
        let outcome = (|| {
            match s.phase {
                1 => {
                    let image = queue::prepare_ordinary(at)?;
                    s.first = at;
                    s.image = image.digest;
                    s.target = [image.target.id, image.target.generation];
                    let mut h = Sha256::new();
                    h.update(b"CYXIA_A03_ORDINARY_DEMAND_V1\0");
                    h.update(HIGH_NS.to_le_bytes());
                    h.update(QUIET_NS.to_le_bytes());
                    h.update(b"100-owned-arrivals;relative=((id-1)/10)*1000000000+((id-1)%10)*1000;deadline=5000000000;no-publication\0");
                    s.schedule = h.finalize().into();
                    s.phase = 2;
                }
                2 => {
                    let stop = s.first.checked_add(HIGH_NS).ok_or(Error::Overflow)?;
                    s.last = queue::ordinary_release(at.min(stop))?;
                    if at >= stop {
                        s.phase = 3;
                    }
                }
                3 => {
                    s.last = queue::ordinary_withdraw()?;
                    s.withdrawn = at;
                    s.phase = 4;
                }
                4 => {
                    s.last = queue::ordinary_snapshot()?;
                    if s.last.drained() {
                        if s.last.completed == 0 {
                            return Err(Error::Conflict);
                        }
                        s.drained = at;
                        s.phase = 5;
                    }
                }
                5 => {
                    s.last = queue::ordinary_snapshot()?;
                    if !s.last.drained() {
                        return Err(Error::Conflict);
                    }
                    if at >= s.drained.checked_add(QUIET_NS).ok_or(Error::Overflow)?
                        && decision().is_some_and(|d| {
                            d[0] > 0 && d[1] > 0 && d[2] > s.drained && d[3] > s.drained
                        })
                    {
                        queue::ordinary_finish()?;
                        s.complete = at;
                        s.phase = 6;
                    }
                }
                _ => return Ok(false),
            }
            Ok(true)
        })();
        if let Err(error) = outcome {
            if !matches!(error, Error::Busy | Error::Again | Error::NotReady) {
                s.error = error as u64 + 1;
                s.phase = 7;
            }
        }
        publish(s, at);
        outcome
    }
    pub fn quiescent() -> bool {
        let b = &A03_DEMAND_V16_EVIDENCE.0;
        let first = b[4].load(Ordering::Acquire);
        let phase = b[5].load(Ordering::Relaxed);
        first > 0 && first & 1 == 0 && phase == 6 && first == b[4].load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(super) fn observed() -> [u64; 128] {
        core::array::from_fn(|i| A03_DEMAND_V16_EVIDENCE.0[i].load(Ordering::Acquire))
    }
    // Profile-only state and snapshot scratch; learning collection is disabled.
    const _: () = assert!(
        core::mem::size_of::<State>()
            + core::mem::size_of::<Evidence>()
            + core::mem::size_of::<ModelEvidence>()
            + 128 * 8
            + 6 * 8
            + 2
            <= 8192
    );
}
pub fn ordinary_decision(job: u64, version: u64, input_at: u64, at: u64, slot: usize) {
    #[cfg(any(cyxia_a03_demand, test))]
    native::ordinary_decision(job, version, input_at, at, slot);
    #[cfg(not(any(cyxia_a03_demand, test)))]
    let _ = (job, version, input_at, at, slot);
}
pub fn service_step() -> Result<bool, cyxia_prototype::domains::Error> {
    #[cfg(any(cyxia_a03_demand, test))]
    {
        native::service_step()
    }
    #[cfg(not(any(cyxia_a03_demand, test)))]
    {
        Ok(false)
    }
}
pub fn quiescent() -> bool {
    #[cfg(any(cyxia_a03_demand, test))]
    {
        native::quiescent()
    }
    #[cfg(not(any(cyxia_a03_demand, test)))]
    {
        true
    }
}
#[cfg(test)]
pub(crate) fn observed() -> [u64; 128] {
    native::observed()
}

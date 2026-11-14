//! Diagnostic facts from the first real terminal LOCAL admission failure.
//! This record neither authorizes a retry nor changes a task receipt. Writers
//! run on the actual CPU0 owner; the seqlock also makes stopped reads explicit.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::domains::{
    Error, ObjectKey, WINDOW_NS,
    tasks::{CpuLayout, Scheduler},
};

const MAGIC: u64 = 0x4359_4c4f_4341_4c31;

#[derive(Clone, Copy)]
pub(crate) struct Event {
    pub stage: u64,
    pub error: Error,
    pub observed_ns: u64,
    pub spawn_id: u64,
    pub deadline_ns: u64,
    pub task: ObjectKey,
    pub cpu: u16,
    pub group: ObjectKey,
    pub layout: CpuLayout,
    pub entered_ns: u64,
}

/// Taken before rollback can alter scheduler/resource state. Publishing this
/// snapshot is permitted only after the actual owner returns a terminal error.
pub(crate) struct Failure([u64; 31]);
impl Failure {
    pub fn capture(event: Event, scheduler: &Scheduler) -> Self {
        let cpu = usize::from(event.cpu);
        let active = scheduler.active(cpu);
        let (unspent_budget, minimum_remaining) = scheduler.admission_observation(cpu);
        Self([
            MAGIC,
            1,
            event.stage,
            event.error as u64 + 1,
            event.observed_ns,
            event.spawn_id,
            0,
            0,
            event.deadline_ns,
            event.task.id,
            event.task.generation,
            u64::from(event.cpu),
            event.group.id,
            event.group.generation,
            event.layout.business_mask,
            event.layout.healthy_mask,
            event.layout.generation,
            scheduler.committed_ns(cpu),
            scheduler.cpu_spent_ns(cpu).unwrap_or(u64::MAX),
            minimum_remaining,
            WINDOW_NS - event.observed_ns % WINDOW_NS,
            active.map_or(0, |a| a.sequence),
            active.map_or(0, |a| a.thread.id),
            active.map_or(0, |a| a.thread.generation),
            active.map_or(0, |a| a.window),
            active.map_or(0, |a| a.started_ns),
            active.map_or(0, |a| a.reserved_ns),
            scheduler.thread_count() as u64,
            event.entered_ns,
            0,
            unspent_budget,
        ])
    }
}

/// 0 seqlock; 1 magic; 2 schema; 3 operation stage; 4 domain error + 1;
/// 5 observed ns; 6 spawn id; 7/8 application request id/generation;
/// 9 original task deadline; 10/11 candidate task id/generation; 12 CPU;
/// 13/14 group; 15/16 business/healthy mask; 17 core generation;
/// 18 committed ns; 19 spent ns; 20 runnable minimum remaining ns;
/// 21 window remaining ns;
/// 22 active sequence; 23/24 active task; 25 active window; 26 active start;
/// 27 active reserved ns; 28 thread count; 29 operation entry ns;
/// 30 exact request identity bound; 31 unspent thread budget ns.
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 32]);
impl Evidence {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 32])
    }
    pub(crate) fn retain(&self, failure: Failure) {
        if self.0[0]
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        for (word, value) in self.0[1..].iter().zip(failure.0) {
            word.store(value, Ordering::Relaxed);
        }
        self.0[0].store(2, Ordering::Release);
    }
    pub(crate) fn bind_request(&self, spawn_id: u64, key: ObjectKey, deadline_ns: u64) {
        if key.id == 0 || key.generation == 0 {
            return;
        }
        let sequence = self.0[0].load(Ordering::Acquire);
        if sequence == 0
            || sequence & 1 != 0
            || self.0[6].load(Ordering::Relaxed) != spawn_id
            || self.0[9].load(Ordering::Relaxed) != deadline_ns
            || self.0[30].load(Ordering::Relaxed) != 0
        {
            return;
        }
        if self.0[0]
            .compare_exchange(sequence, sequence + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.0[7].store(key.id, Ordering::Relaxed);
        self.0[8].store(key.generation, Ordering::Relaxed);
        self.0[30].store(1, Ordering::Relaxed);
        self.0[0].store(sequence + 2, Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn words(&self) -> [u64; 32] {
        core::array::from_fn(|i| self.0[i].load(Ordering::Acquire))
    }
}
const _: () = assert!(core::mem::size_of::<Evidence>() == 256);

#[used]
#[unsafe(no_mangle)]
pub static LOCAL_PLACEMENT_EVIDENCE: Evidence = Evidence::new();

/// The kernel broker supplies the real Entry only after observing its result.
/// No table lookup or root reentry occurs here while that Entry is borrowed.
pub fn bind_local_failure_request(spawn_id: u64, key: ObjectKey, deadline_ns: u64) {
    LOCAL_PLACEMENT_EVIDENCE.bind_request(spawn_id, key, deadline_ns);
}

pub(crate) fn retain(failure: Failure) {
    LOCAL_PLACEMENT_EVIDENCE.retain(failure);
}

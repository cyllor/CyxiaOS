//! Stopped-VM evidence for the fixed CPU0 diagnostic scheduler.
//!
//! Each row ends one contiguous interval in the Generic Timer and patched
//! per-vCPU counter. Both wall observations bracket the counter read within
//! one window. A grant description comes from the exact EL1 Turn.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_kernel_core::control_plane::role_budget_v0199::Turn;

const CAPACITY: usize = 4096;
const MAGIC: u64 = 0x4359_5842_5544_4731;
const FAILURE_MAGIC: u64 = 0x4359_5842_4641_494c;

#[repr(C, align(4096))]
struct Evidence {
    header: [AtomicU64; 6],
    rows: [[AtomicU64; 6]; CAPACITY],
}

pub(super) const BYTES: usize = core::mem::size_of::<Evidence>();

#[unsafe(no_mangle)]
static V0199_BUDGET_TRACE: Evidence = Evidence {
    header: [const { AtomicU64::new(0) }; 6],
    rows: [const { [const { AtomicU64::new(0) }; 6] }; CAPACITY],
};

#[derive(Clone, Copy)]
pub(super) struct Sample {
    pub(super) before_ns: u64,
    pub(super) wall_ns: u64,
    pub(super) cpu_tick: u64,
}

pub(super) struct Trace {
    next: usize,
}

impl Trace {
    pub(super) fn new(sample: Sample) -> Self {
        V0199_BUDGET_TRACE.header[3].store(sample.wall_ns, Ordering::Relaxed);
        V0199_BUDGET_TRACE.header[4].store(sample.cpu_tick, Ordering::Relaxed);
        V0199_BUDGET_TRACE.header[5].store(sample.before_ns, Ordering::Relaxed);
        Self { next: 0 }
    }

    #[inline]
    pub(super) fn record(&mut self, sample: Sample, grant: Option<Turn>) {
        let (scope, quota, deadline) = match grant {
            Some(turn) => {
                let (class, role, domain) = turn.accounting_scope();
                let (slot, generation) = role.map_or((0, 0), |(index, actor)| {
                    let generation =
                        u32::try_from(actor.generation).expect("diagnostic generation");
                    ((index + 1) as u64, u64::from(generation))
                });
                let scope = (class as u64 + 1)
                    | (slot << 8)
                    | (u64::from(domain) << 16)
                    | (generation << 32);
                (scope, turn.reserved_ns(), turn.deadline_ns())
            }
            None => (0, 0, 0),
        };
        let row = V0199_BUDGET_TRACE
            .rows
            .get(self.next)
            .expect("budget trace capacity");
        for (field, value) in row.iter().zip([
            sample.wall_ns,
            sample.cpu_tick,
            quota,
            deadline,
            scope,
            sample.before_ns,
        ]) {
            field.store(value, Ordering::Relaxed);
        }
        self.next += 1;
    }

    // Terminal failure prefixes are deliberately not valid successful traces.
    pub(super) fn seal_failure(&self) {
        self.publish(FAILURE_MAGIC);
    }

    pub(super) fn seal(self) {
        self.publish(MAGIC);
    }

    fn publish(&self, magic: u64) {
        V0199_BUDGET_TRACE.header[0].store(magic, Ordering::Relaxed);
        V0199_BUDGET_TRACE.header[1].store(4, Ordering::Relaxed);
        V0199_BUDGET_TRACE.header[2].store(self.next as u64, Ordering::Release);
    }

    pub(super) fn intervals(&self) -> usize {
        self.next
    }
}

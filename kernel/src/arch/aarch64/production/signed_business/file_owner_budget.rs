//! Bounded B3 observation of the values submitted to the real scheduler.
//! Per-turn rows retain the first settlements. A second witness keeps
//! accounting every turn, publishing closed windows and a partial window.

use super::{BUSINESS_THREAD_ID_BASE, CPU_BUDGET_NS, MAX_SLICE_NS, WINDOW_NS, file_owner::CPU};
use core::{
    mem::MaybeUninit,
    ptr::addr_of_mut,
    sync::atomic::{AtomicU64, Ordering},
};
use cyxia_kernel_core::security::file_auth_v3::FILE_SERVICE_ROLE;
use cyxia_prototype::domains::tasks::Dispatch;

const CAPACITY: usize = 128;
const HEADER_WORDS: usize = 8;
const ROW_WORDS: usize = 9;

#[repr(C)]
struct Evidence {
    header: [AtomicU64; HEADER_WORDS],
    rows: [[AtomicU64; ROW_WORDS]; CAPACITY],
}

#[unsafe(no_mangle)]
static V020_G1_FILE_OWNER_BUDGET: Evidence = Evidence {
    header: [const { AtomicU64::new(0) }; HEADER_WORDS],
    rows: [const { [const { AtomicU64::new(0) }; ROW_WORDS] }; CAPACITY],
};

const WINDOW_CAPACITY: usize = 16;
const WINDOW_HEADER_WORDS: usize = 16;
const WINDOW_ROW_WORDS: usize = 17;

#[repr(C)]
struct WindowEvidence {
    header: [AtomicU64; WINDOW_HEADER_WORDS],
    rows: [[AtomicU64; WINDOW_ROW_WORDS]; WINDOW_CAPACITY],
    open: [AtomicU64; WINDOW_ROW_WORDS],
}

#[unsafe(no_mangle)]
static V020_G1_FILE_OWNER_WINDOWS: WindowEvidence = WindowEvidence {
    header: [const { AtomicU64::new(0) }; WINDOW_HEADER_WORDS],
    rows: [const { [const { AtomicU64::new(0) }; WINDOW_ROW_WORDS] }; WINDOW_CAPACITY],
    open: [const { AtomicU64::new(0) }; WINDOW_ROW_WORDS],
};

struct Window {
    index: u64,
    first_dispatch: u64,
    last_dispatch: u64,
    turns: [u64; 2],
    charged: [u64; 2],
    carry: [u64; 2],
    peak_reserved: [u64; 2],
    core_peak_reserved: u64,
    reads: [u64; 4],
    straddled_reads: u64,
}

impl Window {
    const fn new(index: u64) -> Self {
        Self {
            index,
            first_dispatch: 0,
            last_dispatch: 0,
            turns: [0; 2],
            charged: [0; 2],
            carry: [0; 2],
            peak_reserved: [0; 2],
            core_peak_reserved: 0,
            reads: [0; 4],
            straddled_reads: 0,
        }
    }

    fn publish(&self, row: &[AtomicU64; WINDOW_ROW_WORDS]) {
        let values = [
            self.index,
            self.first_dispatch,
            self.last_dispatch,
            self.turns[0],
            self.turns[1],
            self.charged[0],
            self.charged[1],
            self.carry[0],
            self.carry[1],
            self.peak_reserved[0],
            self.peak_reserved[1],
            self.core_peak_reserved,
            self.reads[0],
            self.reads[1],
            self.reads[2],
            self.reads[3],
            self.straddled_reads,
        ];
        for (cell, value) in row.iter().zip(values) {
            cell.store(value, Ordering::Relaxed);
        }
    }
}

struct Tracker {
    epoch: u64,
    owner_generation: u64,
    limits: [u64; 2],
    open: Option<Window>,
    closed: u64,
    omitted: u64,
    invalid: u64,
    turns: [u64; 2],
    last_dispatch: u64,
    last_finish: u64,
    reads: [u64; 4],
}

// CPU0 initializes this before publishing the business epoch. B3 owns the
// tracker after the acquire and never lends its mutable borrow to an IRQ.
static mut TRACKER: MaybeUninit<Tracker> = MaybeUninit::uninit();

impl Tracker {
    fn roll(&mut self, index: u64) -> &mut Window {
        if self
            .open
            .as_ref()
            .is_none_or(|window| window.index != index)
        {
            if let Some(finished) = self.open.take() {
                if let Some(row) = V020_G1_FILE_OWNER_WINDOWS.rows.get(self.closed as usize) {
                    finished.publish(row);
                    self.closed += 1;
                } else {
                    self.omitted = self.omitted.saturating_add(1);
                }
            }
            self.open = Some(Window::new(index));
        }
        self.open.as_mut().unwrap()
    }

    fn publish(&self) {
        let evidence = &V020_G1_FILE_OWNER_WINDOWS;
        for (cell, value) in evidence.header[3..].iter().zip([
            self.closed,
            self.omitted,
            self.invalid,
            self.turns[0],
            self.turns[1],
            self.last_dispatch,
            self.last_finish,
            self.reads[0],
            self.reads[1],
            self.reads[2],
            self.reads[3],
            u64::from(self.open.is_some()),
            0,
        ]) {
            cell.store(value, Ordering::Relaxed);
        }
        if let Some(window) = &self.open {
            window.publish(&evidence.open);
        }
    }

    fn settle(
        &mut self,
        dispatch: Dispatch,
        cost: u64,
        finish: u64,
        settled: bool,
        reads: [u64; 4],
    ) {
        let peer = dispatch.thread.id != FILE_SERVICE_ROLE;
        let actor = if peer {
            (BUSINESS_THREAD_ID_BASE + CPU as u64, self.epoch)
        } else {
            (FILE_SERVICE_ROLE, self.owner_generation)
        };
        let Some(end) = dispatch
            .window
            .checked_add(1)
            .and_then(|w| w.checked_mul(WINDOW_NS))
        else {
            self.invalid = self.invalid.saturating_add(1);
            return;
        };
        let side = usize::from(peer);
        self.turns[side] = self.turns[side].saturating_add(1);
        if !settled
            || (dispatch.thread.id, dispatch.thread.generation) != actor
            || dispatch.cpu as usize != CPU
            || dispatch.core_generation != self.epoch
            || dispatch.sequence <= self.last_dispatch
            || dispatch.started_ns < self.last_finish
            || dispatch.window != dispatch.started_ns / WINDOW_NS
            || finish < dispatch.started_ns
            || !(1..=MAX_SLICE_NS).contains(&dispatch.reserved_ns)
            || cost > dispatch.reserved_ns
        {
            self.invalid = self.invalid.saturating_add(1);
            return;
        }
        let mut operations = [0; 4];
        for (index, (&seen, &known)) in reads.iter().zip(&self.reads).enumerate() {
            operations[index] = seen.saturating_sub(known);
            let client_op = index == 0 || index == 3;
            if seen < known
                || operations[index] > 1
                || (operations[index] != 0 && client_op != peer)
            {
                self.invalid = self.invalid.saturating_add(1);
                return;
            }
        }
        let read_work: u64 = operations.iter().sum();
        if read_work > 1 {
            self.invalid = self.invalid.saturating_add(1);
            return;
        }
        self.reads = reads;
        self.last_dispatch = dispatch.sequence;
        self.last_finish = finish;

        let limits = self.limits;
        let window = self.roll(dispatch.window);
        if window.first_dispatch == 0 {
            window.first_dispatch = dispatch.sequence;
        }
        window.last_dispatch = dispatch.sequence;
        let reserved = window.charged[side].saturating_add(dispatch.reserved_ns);
        let core_reserved = window.charged[1 - side].saturating_add(reserved);
        window.peak_reserved[side] = window.peak_reserved[side].max(reserved);
        window.core_peak_reserved = window.core_peak_reserved.max(core_reserved);
        window.charged[side] = window.charged[side].saturating_add(cost);
        window.turns[side] = window.turns[side].saturating_add(1);
        for (total, delta) in window.reads.iter_mut().zip(operations) {
            *total += delta;
        }

        let mut valid = reserved <= limits[side] && core_reserved <= CPU_BUDGET_NS;
        // Scheduler::complete charges the original window, and exactly
        // repeats that charge in the finish window iff finish > end.
        if finish > end {
            window.straddled_reads += read_work;
            let carried = self.roll(finish / WINDOW_NS);
            carried.carry[side] = carried.carry[side].saturating_add(cost);
            carried.charged[side] = carried.charged[side].saturating_add(cost);
            valid &= carried.charged[side] <= limits[side]
                && carried.charged[0].saturating_add(carried.charged[1]) <= CPU_BUDGET_NS;
        }
        self.invalid = self.invalid.saturating_add(u64::from(!valid));
    }
}

/// CPU0 configures the witness once, before releasing the B3 scheduler.
pub(super) fn configure(epoch: u64, owner_generation: u64, owner_limit_ns: u64) {
    // SAFETY: only the boot foreground can configure, before publishing any
    // B3 turns. observe acquires the same release edge as the prefix.
    unsafe {
        (*addr_of_mut!(TRACKER)).write(Tracker {
            epoch,
            owner_generation,
            limits: [owner_limit_ns, CPU_BUDGET_NS - owner_limit_ns],
            open: None,
            closed: 0,
            omitted: 0,
            invalid: 0,
            turns: [0; 2],
            last_dispatch: 0,
            last_finish: 0,
            reads: [0; 4],
        })
    };
    V020_G1_FILE_OWNER_WINDOWS.header[1].store(epoch, Ordering::Relaxed);
    V020_G1_FILE_OWNER_WINDOWS.header[2].store(owner_generation, Ordering::Relaxed);
    let header = &V020_G1_FILE_OWNER_BUDGET.header;
    for (cell, value) in header[1..].iter().zip([
        WINDOW_NS,
        CPU_BUDGET_NS,
        owner_limit_ns,
        CPU as u64,
        FILE_SERVICE_ROLE,
        0,
        0,
    ]) {
        cell.store(value, Ordering::Relaxed);
    }
    header[0].store(epoch, Ordering::Release);
}

/// Only B3 writes rows, after the exact dispatch charge leaves the lock.
pub(super) fn observe(slot: usize, dispatch: Dispatch, cost: u64, finished_ns: u64, settled: bool) {
    if slot != CPU {
        return;
    }
    let evidence = &V020_G1_FILE_OWNER_BUDGET;
    if evidence.header[0].load(Ordering::Acquire) == 0 {
        return;
    }
    // The paused readback can detect a stop inside this publication. Both
    // artifacts refer to the same even revision.
    let revision = &V020_G1_FILE_OWNER_WINDOWS.header[0];
    revision.fetch_add(1, Ordering::AcqRel);
    record_prefix(evidence, dispatch, cost, finished_ns, settled);
    #[cfg(cyxia_file_read_client)]
    let reads = super::file_owner::client_read::settled_custody();
    #[cfg(not(cyxia_file_read_client))]
    let reads = [0; 4];
    // SAFETY: B3 has acquired configure's stores and is the sole writer.
    let tracker = unsafe { (*addr_of_mut!(TRACKER)).assume_init_mut() };
    tracker.settle(dispatch, cost, finished_ns, settled, reads);
    tracker.publish();
    revision.fetch_add(1, Ordering::Release);
}

fn record_prefix(
    evidence: &Evidence,
    dispatch: Dispatch,
    cost: u64,
    finished_ns: u64,
    settled: bool,
) {
    let count = &evidence.header[6];
    let index = count.load(Ordering::Relaxed);
    let Some(row) = evidence.rows.get(index as usize) else {
        evidence.header[7].fetch_add(1, Ordering::Relaxed);
        return;
    };
    for (cell, value) in row.iter().zip([
        dispatch.sequence,
        dispatch.thread.id,
        dispatch.thread.generation,
        dispatch.window,
        dispatch.started_ns,
        finished_ns,
        dispatch.reserved_ns,
        cost,
        u64::from(settled),
    ]) {
        cell.store(value, Ordering::Relaxed);
    }
    count.store(index + 1, Ordering::Release);
}

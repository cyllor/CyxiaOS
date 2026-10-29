//! Fixed network-piece provenance, never credit or accepted CPU evidence.
//! CPU0 owns the live marker and pending bank. The existing TaskGuard owns
//! the separate settlement bank. Neither writer waits for the other owner.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU64, Ordering, fence},
};
use cyxia_arch_aarch64::cpu;
use cyxia_prototype::domains::{Error, ObjectKey, tasks::Dispatch};

#[repr(C, align(64))]
struct Bank {
    words: [AtomicU64; 64],
}
impl Bank {
    const fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; 64],
        }
    }
    fn get(&self, i: usize) -> u64 {
        self.words[i].load(Ordering::Acquire)
    }
    fn put(&self, i: usize, value: u64) {
        self.words[i].store(value, Ordering::Relaxed);
    }
    fn add(&self, i: usize) {
        self.put(i, self.get(i).saturating_add(1));
    }
    fn row(&self, at: usize, values: &[u64]) {
        for (i, value) in values.iter().enumerate() {
            self.put(at + i, *value);
        }
    }
    fn write(&self, f: impl FnOnce(&Self)) {
        self.words[63].fetch_add(1, Ordering::AcqRel);
        f(self);
        self.words[63].fetch_add(1, Ordering::Release);
    }
    fn snapshot(&self) -> Option<[u64; 64]> {
        let first = self.get(63);
        if first & 1 != 0 {
            return None;
        }
        let values = core::array::from_fn(|i| self.words[i].load(Ordering::Relaxed));
        fence(Ordering::Acquire);
        (first == self.get(63)).then_some(values)
    }
}
#[used]
#[unsafe(no_mangle)]
static NETWORK_PIECE_EVIDENCE: Bank = Bank::new();
#[used]
#[unsafe(no_mangle)]
static NETWORK_SETTLEMENT_EVIDENCE: Bank = Bank::new();
use NETWORK_PIECE_EVIDENCE as CPU0_BANK;
use NETWORK_SETTLEMENT_EVIDENCE as TASK_BANK;
const _: () = assert!(core::mem::size_of::<Bank>() == 512);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ticket {
    dispatch: Dispatch,
    turn: u64,
    ordinal: u64,
}
#[derive(Clone, Copy)]
struct Piece {
    ticket: Ticket,
    first: u64,
    last: u64,
    mask: u64,
    marks: u64,
}
struct CpuState {
    granted: Option<Dispatch>,
    active: Option<Piece>,
    turns: u64,
}
impl CpuState {
    const fn new() -> Self {
        Self {
            granted: None,
            active: None,
            turns: 0,
        }
    }
}
struct CpuStorage(UnsafeCell<CpuState>);
// Every access checks CPU0 first; IRQ handlers never run these device queues.
unsafe impl Sync for CpuStorage {}
static CPU_STATE: CpuStorage = CpuStorage(UnsafeCell::new(CpuState::new()));
const DIAGNOSTIC_BYTES: usize =
    2 * core::mem::size_of::<Bank>() + core::mem::size_of::<CpuStorage>();
const _: () = assert!(DIAGNOSTIC_BYTES <= 1536);

/// Copy the original grant under TaskGuard, before its CPU origin is sampled.
pub(crate) fn admitted(dispatch: Dispatch) {
    if cpu::slot() != 0 {
        return;
    }
    unsafe {
        (*CPU_STATE.0.get()).granted = Some(dispatch);
    }
}
pub(crate) fn new_turn() -> u64 {
    if cpu::slot() != 0 {
        return 0;
    }
    let s = unsafe { &mut *CPU_STATE.0.get() };
    s.turns = s.turns.saturating_add(1);
    s.turns
}
/// Matching is diagnostic only. A mismatch never changes the real execution.
pub(crate) fn begin(
    sequence: u64,
    thread: ObjectKey,
    reserved: u64,
    turn: u64,
    ordinal: u64,
) -> Option<Ticket> {
    if cpu::slot() != 0 {
        return None;
    }
    let s = unsafe { &mut *CPU_STATE.0.get() };
    let Some(dispatch) = s.granted.filter(|d| {
        d.sequence == sequence && d.thread == thread && d.reserved_ns == reserved && d.cpu == 0
    }) else {
        CPU0_BANK.write(|b| b.add(3));
        return None;
    };
    if s.active.is_some() {
        CPU0_BANK.write(|b| b.add(4));
        return None;
    }
    let ticket = Ticket {
        dispatch,
        turn,
        ordinal,
    };
    s.active = Some(Piece {
        ticket,
        first: 0,
        last: 0,
        mask: 0,
        marks: 0,
    });
    Some(ticket)
}
/// No clock, lock, owner query or progress callback. Non-network work ignores
/// this marker, including nested helpers between two network reservations.
pub(crate) fn stage(stage: u64) {
    if cpu::slot() != 0 {
        return;
    }
    let s = unsafe { &mut *CPU_STATE.0.get() };
    let Some(piece) = s.active.as_mut() else {
        return;
    };
    if stage == 0 || stage >= 64 {
        return;
    }
    unsafe {
        if core::ptr::read_volatile(&piece.first) == 0 {
            core::ptr::write_volatile(&mut piece.first, stage);
        }
        core::ptr::write_volatile(&mut piece.last, stage);
        core::ptr::write_volatile(&mut piece.mask, piece.mask | (1u64 << stage));
        core::ptr::write_volatile(&mut piece.marks, piece.marks.saturating_add(1));
    }
}
fn identity(d: Dispatch) -> [u64; 13] {
    [
        d.sequence,
        d.thread.id,
        d.thread.generation,
        d.group.id,
        d.group.generation,
        u64::from(d.cpu),
        d.core_generation,
        d.window,
        d.started_ns,
        d.reserved_ns,
        d.reason as u64,
        d.waited_ns,
        d.policy_version,
    ]
}
/// Freeze the caller's original measurements before completion publication;
/// clear live marking before a nested mechanism or new owner can run.
pub(crate) fn finish(ticket: Option<Ticket>, actual_ns: u64, finished_ns: u64) {
    if cpu::slot() != 0 {
        return;
    }
    let Some(ticket) = ticket else {
        return;
    };
    let s = unsafe { &mut *CPU_STATE.0.get() };
    if s.active.is_none_or(|p| p.ticket != ticket) {
        CPU0_BANK.write(|b| b.add(4));
        return;
    }
    let p = s.active.take().unwrap();
    CPU0_BANK.write(|b| {
        b.row(0, &[0x4359_4e50_4945_0001, 1]);
        b.add(2);
        b.row(8, &identity(ticket.dispatch));
        b.row(
            21,
            &[
                ticket.turn,
                ticket.ordinal,
                p.first,
                p.last,
                p.mask,
                p.marks,
                actual_ns,
                finished_ns,
            ],
        );
    });
}
/// Called under the existing TaskGuard after the original Scheduler result.
/// One bounded snapshot attempt; missing/malformed diagnostics never affect it.
pub(crate) fn settled(
    dispatch: Dispatch,
    actual_ns: u64,
    finished_ns: u64,
    result: Result<(), Error>,
    still_active: bool,
) {
    if dispatch.cpu != 0 || CPU0_BANK.get(8) != dispatch.sequence {
        return;
    }
    let Some(pending) = CPU0_BANK.snapshot() else {
        TASK_BANK.write(|b| b.add(3));
        return;
    };
    if pending[0] != 0x4359_4e50_4945_0001
        || pending[1] != 1
        || pending[8..21] != identity(dispatch)
        || pending[27] != actual_ns
        || pending[28] != finished_ns
    {
        TASK_BANK.write(|b| b.add(4));
        return;
    }
    let outcome = result.map_or_else(|e| 2 | ((e as u64 + 1) << 8), |()| 1);
    let physical_overrun =
        !still_active && actual_ns > dispatch.reserved_ns && result == Err(Error::Budget);
    TASK_BANK.write(|b| {
        b.row(0, &[0x4359_4e53_4554_0001, 1]);
        b.add(2);
        b.row(8, &pending[8..29]);
        b.row(29, &[outcome, u64::from(still_active)]);
        if physical_overrun {
            b.add(5);
            if b.get(36) == 0 {
                b.row(36, &pending[8..29]);
                b.row(57, &[outcome, u64::from(still_active)]);
            }
        }
    });
}

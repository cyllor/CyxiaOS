//! Bounded first-trial diagnostics, never authority or accepted CPU evidence.
//! Control/work writers are CPU0-only. Task writers run under the existing
//! task-owner gate, including CPU3 settlement. Each bank has its own seqlock;
//! no mutable borrow or diagnostic lock crosses an owner call or progress.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_arch_aarch64::cpu;
use cyxia_prototype::{
    domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp, tasks::Dispatch},
    learning::{Family, capture::RunKey},
    policy::ExecutionState,
};

#[repr(C, align(64))]
struct Evidence<const N: usize> {
    words: [AtomicU64; N],
}
impl<const N: usize> Evidence<N> {
    const fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; N],
        }
    }
    fn get(&self, i: usize) -> u64 {
        self.words[i].load(Ordering::Acquire)
    }
    fn put(&self, i: usize, value: u64) {
        self.words[i].store(value, Ordering::Relaxed);
    }
    fn add(&self, i: usize, value: u64) {
        self.put(i, self.get(i).saturating_add(value));
    }
    fn write(&self, f: impl FnOnce(&Self)) {
        self.words[N - 1].fetch_add(1, Ordering::AcqRel);
        f(self);
        self.words[N - 1].fetch_add(1, Ordering::Release);
    }
    fn row(&self, i: usize, values: &[u64]) {
        for (n, value) in values.iter().enumerate() {
            self.put(i + n, *value);
        }
    }
}
#[used]
#[unsafe(no_mangle)]
static TRACE_CONTROL_EVIDENCE: Evidence<224> = Evidence::new();
#[used]
#[unsafe(no_mangle)]
static TRACE_TASK_EVIDENCE: Evidence<128> = Evidence::new();
#[used]
#[unsafe(no_mangle)]
static TRACE_WORK_EVIDENCE: Evidence<64> = Evidence::new();
#[used]
#[unsafe(no_mangle)]
static TRACE_CLOSING_EVIDENCE: Evidence<64> = Evidence::new();
pub const OWNED_BYTES: usize = core::mem::size_of::<Evidence<224>>()
    + core::mem::size_of::<Evidence<128>>()
    + 2 * core::mem::size_of::<Evidence<64>>();
const _: () = assert!(OWNED_BYTES == 3840);
fn active() -> bool {
    TRACE_CONTROL_EVIDENCE.get(10) == 1
}
fn run_matches(run: RunKey) -> bool {
    let b = &TRACE_CONTROL_EVIDENCE;
    active() && [b.get(2), b.get(3), b.get(4)] == [run.boot_epoch, run.trial_id, run.generation]
}
fn target_matches(target: ObjectKey) -> bool {
    let b = &TRACE_CONTROL_EVIDENCE;
    active() && (b.get(6), b.get(7)) == (target.id, target.generation)
}
pub fn begin(run: RunKey, family: Family, target: ObjectKey, first: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    let b = &TRACE_CONTROL_EVIDENCE;
    if b.get(10) != 0 || run.generation == 0 || first == 0 {
        return;
    }
    b.write(|b| {
        b.row(
            0,
            &[
                0x4359_5452_4354_0001,
                1,
                run.boot_epoch,
                run.trial_id,
                run.generation,
                first,
                target.id,
                target.generation,
            ],
        );
        b.row(12, &[u64::from(family.domain), u64::from(family.kind)]);
        // Release publishes the immutable scope before any task CPU reads it.
        b.words[10].store(1, Ordering::Release);
    });
}
pub fn close(run: RunKey, at: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    if !run_matches(run) {
        return;
    }
    TRACE_CONTROL_EVIDENCE.write(|b| {
        b.put(11, at);
        b.words[10].store(2, Ordering::Release);
    });
}
fn state(value: ExecutionState) -> u64 {
    match value {
        ExecutionState::Pending => 1,
        ExecutionState::Applied => 2,
        ExecutionState::Unknown => 3,
        ExecutionState::Failed(error) => 4 | ((error as u64 + 1) << 8),
    }
}
fn result(value: Result<ExecutionState, Error>) -> u64 {
    value.map_or_else(|e| 5 | ((e as u64 + 1) << 8), state)
}
pub struct ControlEvent {
    pub action: Action,
    pub apply: ApplyId,
    pub stamp: PolicyStamp,
    pub was_started: bool,
    pub entered_ns: u64,
    pub finished_ns: u64,
    pub cpu_ns: u64,
    pub published_ns: u64,
    pub result: Result<ExecutionState, Error>,
}
pub fn control(e: ControlEvent) {
    debug_assert_eq!(cpu::slot(), 0);
    if !target_matches(e.apply.target) {
        return;
    }
    let b = &TRACE_CONTROL_EVIDENCE;
    let id = [
        e.apply.boot_epoch,
        e.apply.controller_epoch,
        e.apply.plan_seq,
        u64::from(e.apply.action_index),
        e.apply.target.id,
        e.apply.target.generation,
        e.stamp.version,
    ];
    b.write(|b| {
        let mut payload = [0; 16];
        let encoded = cyxia_prototype::learning::baseline::encode(e.action, &mut payload);
        if e.apply.boot_epoch != b.get(2)
            || e.entered_ns < b.get(5)
            || e.finished_ns < e.entered_ns
            || encoded.is_err()
        {
            b.add(14, 1);
            return;
        }
        let action_bytes = [
            u64::from_le_bytes(payload[..8].try_into().unwrap()),
            u64::from_le_bytes(payload[8..].try_into().unwrap()),
            encoded.unwrap() as u64,
        ];
        let count = b.get(8) as usize;
        let found = (0..count).find(|i| (0..7).all(|j| b.get(16 + i * 24 + j) == id[j]));
        let i = if let Some(i) = found {
            let at = 16 + i * 24;
            if b.get(at + 7) != u64::from(e.action.domain())
                || b.get(at + 8) != u64::from(e.action.kind())
                || [b.get(at + 21), b.get(at + 18), b.get(at + 23)] != action_bytes
            {
                b.add(14, 1);
                return;
            }
            i
        } else {
            if count == 8 {
                b.add(9, 1);
                return;
            }
            let at = 16 + count * 24;
            b.row(at, &id);
            b.row(
                at + 7,
                &[
                    u64::from(e.action.domain()),
                    u64::from(e.action.kind()),
                    e.entered_ns,
                ],
            );
            b.put(at + 13, result(e.result));
            b.put(at + 19, e.stamp.snapshot_ns);
            b.put(at + 20, e.published_ns);
            b.put(at + 21, action_bytes[0]);
            b.put(at + 18, action_bytes[1]);
            b.put(at + 23, action_bytes[2]);
            b.put(8, count as u64 + 1);
            count
        };
        let at = 16 + i * 24;
        b.put(at + 10, e.entered_ns);
        b.add(at + if e.was_started { 12 } else { 11 }, 1);
        b.put(at + 14, result(e.result));
        if e.result == Ok(ExecutionState::Applied) && b.get(at + 15) == 0 {
            b.put(at + 15, e.finished_ns);
        }
        if b.get(at + 16).checked_add(e.cpu_ns).is_none() {
            b.add(15, 1);
        }
        b.add(at + 16, e.cpu_ns);
        b.put(at + 17, e.finished_ns);
        if matches!(e.result, Err(Error::Busy | Error::Again)) {
            b.add(at + 22, 1);
        }
    });
}
fn task_matches(target: ObjectKey, version: u64) -> bool {
    let b = &TRACE_TASK_EVIDENCE;
    target_matches(target) && b.get(2) == 1 && b.get(5) == version && version != 0
}
pub fn tracks_dispatch(d: Dispatch) -> bool {
    first_dispatch(d) || closing_target(d.group, d.policy_version)
}
fn first_dispatch(d: Dispatch) -> bool {
    task_matches(d.group, d.policy_version)
}
/// All task functions below are called only under the actual task-owner gate.
pub fn installed(target: ObjectKey, stamp: PolicyStamp, at: u64) {
    let b = &TRACE_TASK_EVIDENCE;
    if closing_target(target, stamp.version) {
        if stamp.snapshot_ns != TRACE_CLOSING_EVIDENCE.get(15) {
            b.write(|b| b.add(91, 1));
        } else if b.get(88) == 0 {
            b.write(|b| b.row(88, &[stamp.version, stamp.snapshot_ns, at]));
        }
    }
    if !target_matches(target)
        || b.get(2) != 0
        || stamp.version == 0
        || stamp.snapshot_ns != TRACE_CONTROL_EVIDENCE.get(5)
    {
        return;
    }
    b.write(|b| {
        b.row(
            0,
            &[
                0x4359_5452_5453_0001,
                1,
                1,
                target.id,
                target.generation,
                stamp.version,
                stamp.snapshot_ns,
                at,
            ],
        )
    });
}
pub fn selected(d: Dispatch) {
    if closing_target(d.group, d.policy_version) {
        TRACE_TASK_EVIDENCE.write(|b| {
            b.add(93, 1);
            if b.get(96) == 0 {
                b.row(
                    96,
                    &[
                        d.sequence,
                        d.thread.id,
                        d.thread.generation,
                        u64::from(d.cpu),
                        d.started_ns,
                        d.reserved_ns,
                        d.window,
                        d.policy_version,
                    ],
                );
            }
        });
    }
    if !first_dispatch(d) {
        return;
    }
    TRACE_TASK_EVIDENCE.write(|b| {
        b.add(8, 1);
        if b.get(16) == 0 {
            b.row(
                16,
                &[
                    d.sequence,
                    d.thread.id,
                    d.thread.generation,
                    u64::from(d.cpu),
                    d.started_ns,
                    d.reserved_ns,
                    d.window,
                    d.policy_version,
                ],
            );
        }
    });
}
pub fn cancelled(d: Dispatch, at: u64) {
    if closing_target(d.group, d.policy_version) {
        TRACE_TASK_EVIDENCE.write(|b| b.add(92, 1));
    }
    if !first_dispatch(d) {
        return;
    }
    TRACE_TASK_EVIDENCE.write(|b| {
        b.add(9, 1);
        if b.get(24) == 0 {
            b.row(24, &[d.sequence, at]);
        }
    });
}
pub struct Settlement {
    pub dispatch: Dispatch,
    pub actual_ns: u64,
    pub physical_finished_ns: u64,
    pub settled_ns: u64,
    pub before_version: Result<u64, Error>,
    pub after_version: Result<u64, Error>,
    pub still_active: bool,
    pub result: Result<(), Error>,
}
pub fn settled(e: Settlement) {
    let d = e.dispatch;
    if closing_target(d.group, d.policy_version) {
        TRACE_TASK_EVIDENCE.write(|b| {
            b.add(94, 1);
            if e.before_version.is_err() || e.after_version.is_err() {
                b.add(126, 1);
            }
            if e.actual_ns != 0 && b.get(104) == 0 {
                b.row(
                    104,
                    &[
                        d.sequence,
                        d.thread.id,
                        d.thread.generation,
                        u64::from(d.cpu),
                        d.started_ns,
                        e.physical_finished_ns,
                        e.actual_ns,
                        e.settled_ns,
                    ],
                );
            }
            if let (Ok(before), Ok(after)) = (e.before_version, e.after_version)
                && before != d.policy_version
                && after == d.policy_version
                && b.get(112) == 0
            {
                b.row(
                    112,
                    &[
                        d.policy_version,
                        d.sequence,
                        e.physical_finished_ns,
                        e.settled_ns,
                        before,
                        after,
                        e.result.err().map_or(0, |v| v as u64 + 1),
                        u64::from(e.still_active),
                    ],
                );
            }
        });
    }
    if !first_dispatch(d) {
        return;
    }
    TRACE_TASK_EVIDENCE.write(|b| {
        b.add(10, 1);
        if e.result.is_err() {
            b.add(13, 1);
        }
        if e.before_version.is_err() || e.after_version.is_err() {
            b.add(15, 1);
            if b.get(80) == 0 {
                b.row(
                    80,
                    &[
                        e.settled_ns,
                        d.sequence,
                        e.before_version.err().map_or(0, |v| v as u64 + 1),
                        e.after_version.err().map_or(0, |v| v as u64 + 1),
                    ],
                );
            }
        }
        if e.actual_ns != 0 && b.get(32) == 0 {
            b.row(
                32,
                &[
                    d.sequence,
                    d.thread.id,
                    d.thread.generation,
                    u64::from(d.cpu),
                    d.started_ns,
                    e.physical_finished_ns,
                    e.actual_ns,
                    e.settled_ns,
                ],
            );
        }
        if let (Ok(before), Ok(after)) = (e.before_version, e.after_version)
            && before != d.policy_version
            && after == d.policy_version
        {
            b.add(11, 1);
            if b.get(40) == 0 {
                b.row(
                    40,
                    &[
                        d.policy_version,
                        d.sequence,
                        e.physical_finished_ns,
                        e.settled_ns,
                        before,
                        after,
                        e.result.err().map_or(0, |v| v as u64 + 1),
                        u64::from(e.still_active),
                    ],
                );
            }
        }
    });
}
pub struct Reconciliation {
    pub target: ObjectKey,
    pub stamp: PolicyStamp,
    pub version: u64,
    pub in_flight: bool,
    pub state: ExecutionState,
    pub at: u64,
}
pub fn reconciled(e: Reconciliation) {
    if closing_target(e.target, e.stamp.version)
        && e.stamp.snapshot_ns == TRACE_CLOSING_EVIDENCE.get(15)
    {
        TRACE_TASK_EVIDENCE.write(|b| {
            b.add(95, 1);
            if e.state == ExecutionState::Applied && b.get(120) == 0 {
                b.row(
                    120,
                    &[
                        e.at,
                        e.version,
                        u64::from(e.in_flight),
                        state(e.state),
                        e.stamp.version,
                        e.stamp.snapshot_ns,
                    ],
                );
            }
        });
    }
    if !task_matches(e.target, e.stamp.version) {
        return;
    }
    TRACE_TASK_EVIDENCE.write(|b| {
        b.add(12, 1);
        let values = [
            e.at,
            e.version,
            u64::from(e.in_flight),
            state(e.state),
            e.stamp.version,
            e.stamp.snapshot_ns,
        ];
        if b.get(48) == 0 {
            b.row(48, &values);
        }
        if e.state == ExecutionState::Applied && b.get(56) == 0 {
            b.row(56, &values);
        }
    });
}
pub struct Child {
    pub group: ObjectKey,
    pub child: ObjectKey,
    pub parent: ObjectKey,
    pub request_id: u64,
    pub at: u64,
}
pub fn created(e: Child) {
    if !target_matches(e.group) {
        return;
    }
    TRACE_TASK_EVIDENCE.write(|b| {
        if probe_matches(e.group, e.parent, e.request_id) && b.get(72) == 0 {
            b.row(
                72,
                &[
                    e.child.id,
                    e.child.generation,
                    e.request_id,
                    e.at,
                    e.group.id,
                    e.group.generation,
                    e.parent.id,
                    e.parent.generation,
                ],
            );
        }
        b.add(14, 1);
        if b.get(64) == 0 {
            b.row(
                64,
                &[
                    e.child.id,
                    e.child.generation,
                    e.request_id,
                    e.at,
                    e.group.id,
                    e.group.generation,
                    e.parent.id,
                    e.parent.generation,
                ],
            );
        }
    });
}

fn closing_target(target: ObjectKey, version: u64) -> bool {
    target_matches(target) && version != 0 && TRACE_WORK_EVIDENCE.get(37) == version
}
#[derive(Clone, Copy)]
pub enum ClosingWork {
    DrainStart,
    PollReturned {
        result: Result<bool, Error>,
    },
    /// Stage and original tagged error, before a generic native conversion.
    PollOrigin {
        stage: u64,
        code: u64,
    },
    ClosingObserved {
        version: u64,
        state: ExecutionState,
    },
    ProbeCreated {
        version: u64,
        id: u64,
        deadline: u64,
    },
    ProbeSubmit {
        id: u64,
        entered_ns: u64,
        result: Result<(), Error>,
    },
    ProbeOutcome {
        id: u64,
        result: Result<u64, Error>,
    },
    Block {
        reason: u64,
    },
    Drained,
}
/// Root's CPU0 gate publishes this before the asynchronous closing executor.
/// The original first snapshot binds it to the first capture; later closing
/// replacements remain explicit conflicts rather than replacing that identity.
pub fn closing(
    target: ObjectKey,
    first: u64,
    apply: ApplyId,
    stamp: PolicyStamp,
    published: u64,
    deadline: u64,
    at: u64,
) {
    debug_assert_eq!(cpu::slot(), 0);
    if !target_matches(target)
        || first != TRACE_CONTROL_EVIDENCE.get(5)
        || stamp.version == 0
        || apply.target != target
        || apply.boot_epoch != TRACE_CONTROL_EVIDENCE.get(2)
        || deadline < published
        || at < published
    {
        return;
    }
    if TRACE_WORK_EVIDENCE.get(37) != 0 {
        let identity = [
            apply.boot_epoch,
            apply.controller_epoch,
            apply.plan_seq,
            u64::from(apply.action_index),
            apply.target.id,
            apply.target.generation,
            stamp.version,
            stamp.snapshot_ns,
            published,
            deadline,
        ];
        if identity
            .iter()
            .enumerate()
            .any(|(i, value)| TRACE_CLOSING_EVIDENCE.get(8 + i) != *value)
        {
            TRACE_CLOSING_EVIDENCE.write(|b| b.add(58, 1));
        }
        return;
    }
    TRACE_CLOSING_EVIDENCE.write(|b| {
        let c = &TRACE_CONTROL_EVIDENCE;
        b.row(
            0,
            &[
                0x4359_5452_434c_0001,
                1,
                c.get(2),
                c.get(3),
                c.get(4),
                first,
                target.id,
                target.generation,
            ],
        );
        b.row(
            8,
            &[
                apply.boot_epoch,
                apply.controller_epoch,
                apply.plan_seq,
                u64::from(apply.action_index),
                apply.target.id,
                apply.target.generation,
                stamp.version,
                stamp.snapshot_ns,
                published,
                deadline,
                at,
            ],
        );
    });
    TRACE_WORK_EVIDENCE.write(|b| {
        b.put(38, apply.plan_seq);
        if b.get(0) == 0 {
            let c = &TRACE_CONTROL_EVIDENCE;
            b.row(
                0,
                &[
                    0x4359_5452_574b_0001,
                    1,
                    c.get(2),
                    c.get(3),
                    c.get(4),
                    target.id,
                    target.generation,
                    first,
                ],
            );
        }
        // Release publishes the closing identity before any task CPU reads it.
        b.words[37].store(stamp.version, Ordering::Release);
    });
}
pub fn closing_work(run: RunKey, event: ClosingWork, at: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    if !run_matches(run) || TRACE_WORK_EVIDENCE.get(37) == 0 {
        return;
    }
    TRACE_WORK_EVIDENCE.write(|b| match event {
        ClosingWork::DrainStart => {
            b.add(31, 1);
            if b.get(32) == 0 {
                b.put(32, at);
            }
            b.put(33, at);
        }
        ClosingWork::PollReturned { result: Err(e) } => {
            b.add(34, 1);
            if b.get(35) == 0 {
                b.row(35, &[e as u64 + 1, at]);
            }
        }
        ClosingWork::PollReturned { .. } => (),
        ClosingWork::PollOrigin { .. } => (),
        ClosingWork::ClosingObserved {
            version,
            state: ExecutionState::Applied,
        } => {
            if version == b.get(37) && b.get(54) == 0 {
                b.put(54, at);
            }
        }
        ClosingWork::ClosingObserved { .. } => (),
        ClosingWork::ProbeCreated {
            version,
            id,
            deadline,
        } => {
            if version != b.get(37) {
                b.add(39, 1);
            } else if b.get(40) == 0 {
                b.row(40, &[id, deadline, at]);
            }
        }
        ClosingWork::ProbeSubmit {
            id,
            entered_ns,
            result: reply,
        } => {
            if id == b.get(40) {
                b.add(56, 1);
                b.row(57, &[at, result(reply.map(|_| ExecutionState::Applied))]);
                if b.get(43) == 0 {
                    b.row(
                        43,
                        &[
                            entered_ns,
                            at,
                            result(reply.map(|_| ExecutionState::Applied)),
                        ],
                    );
                }
                if reply.is_ok() && b.get(46) == 0 {
                    b.put(46, at);
                }
            }
        }
        ClosingWork::ProbeOutcome { id, result: reply } => {
            if id == b.get(40) && b.get(47) == 0 {
                b.row(
                    47,
                    &[
                        at,
                        reply.unwrap_or(0),
                        result(reply.map(|_| ExecutionState::Applied)),
                    ],
                );
            }
        }
        ClosingWork::Block { reason } => {
            if b.get(50) == 0 {
                b.row(50, &[reason, at]);
            }
            b.row(52, &[reason, at]);
        }
        ClosingWork::Drained => {
            if b.get(55) == 0 {
                b.put(55, at);
            }
        }
    });
    if let ClosingWork::PollOrigin { stage, code } = event {
        TRACE_CLOSING_EVIDENCE.write(|b| {
            b.add(55, 1);
            if b.get(52) == 0 {
                b.row(52, &[stage, code, at]);
            }
        });
    }
}
fn closing_active() -> bool {
    active() && TRACE_WORK_EVIDENCE.get(37) != 0
}
/// Bound at the actual replay spawn boundary, before queuing its effect.
/// Request IDs are scoped to this complete caller ObjectKey, not the group.
pub fn probe_caller(run: RunKey, id: u64, caller: ObjectKey, _at: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    if !run_matches(run)
        || !closing_active()
        || id != TRACE_WORK_EVIDENCE.get(40)
        || caller.id == 0
        || caller.generation == 0
    {
        return;
    }
    TRACE_CLOSING_EVIDENCE.write(|b| {
        if b.get(62) == 0 {
            b.put(61, caller.id);
            b.words[62].store(caller.generation, Ordering::Release);
        } else if b.get(61) != caller.id || b.get(62) != caller.generation {
            b.add(58, 1);
        }
    });
}
fn probe_matches(group: ObjectKey, caller: ObjectKey, id: u64) -> bool {
    let b = &TRACE_CLOSING_EVIDENCE;
    let generation = b.get(62);
    closing_active()
        && generation != 0
        && generation == caller.generation
        && b.get(61) == caller.id
        && TRACE_WORK_EVIDENCE.get(40) == id
        && target_matches(group)
}
pub fn admission_opportunity(root_ok: bool, root_again: bool, pending: bool, at: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    if !closing_active() {
        return;
    }
    TRACE_CLOSING_EVIDENCE.write(|b| {
        b.add(19, 1);
        if (root_ok || root_again) && pending {
            b.add(20, 1);
        }
        b.put(39, at);
        b.put(
            56,
            u64::from(root_ok) | u64::from(pending) << 1 | u64::from(root_again) << 2,
        );
    });
}
pub fn admission_body(sequence: u64, at: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    if !closing_active() {
        return;
    }
    TRACE_CLOSING_EVIDENCE.write(|b| {
        b.add(22, 1);
        if b.get(23) == 0 {
            b.row(23, &[sequence, at]);
        }
    });
}
pub fn admission_result(granted: bool, at: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    if !closing_active() {
        return;
    }
    TRACE_CLOSING_EVIDENCE.write(|b| {
        if !granted {
            b.add(21, 1);
        }
        b.put(57, at);
    });
}
pub fn admitted(
    request: &cyxia_prototype::domains::tasks::SpawnRequest,
    value: cyxia_prototype::domains::tasks::SpawnState,
    at: u64,
    sequence: u64,
) {
    use cyxia_prototype::domains::tasks::SpawnState;
    debug_assert_eq!(cpu::slot(), 0);
    if !closing_active() {
        return;
    }
    let tag = match value {
        SpawnState::Queued => 1,
        SpawnState::Created(_) => 2,
        SpawnState::Failed(e) => 3 | ((e as u64 + 1) << 8),
        SpawnState::Unknown => 4,
        SpawnState::Cancelled => 5,
    };
    TRACE_CLOSING_EVIDENCE.write(|b| {
        b.add(35, 1);
        b.add(
            match value {
                SpawnState::Queued => 36,
                SpawnState::Created(_) => 37,
                _ => 38,
            },
            1,
        );
        let values = [
            request.request_id,
            request.caller.id,
            request.caller.generation,
            tag,
            at,
        ];
        if b.get(25) == 0 {
            b.row(25, &values);
            b.put(59, sequence);
        }
        if probe_matches(request.group, request.caller, request.request_id) && b.get(30) == 0 {
            b.row(30, &values);
            b.put(60, sequence);
        }
    });
    if probe_matches(request.group, request.caller, request.request_id) {
        TRACE_WORK_EVIDENCE.write(|b| {
            b.add(59, 1);
            b.row(60, &[tag, at, sequence]);
        });
    }
}
pub fn task_block(run: RunKey, reason: u64, detail: [u64; 6], at: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    if !run_matches(run) || !closing_active() {
        return;
    }
    TRACE_CLOSING_EVIDENCE.write(|b| {
        if reason == 0 {
            if b.get(51) == 0 {
                b.put(51, at);
            }
            return;
        }
        b.add(50, 1);
        b.row(48, &[reason, at]);
        if b.get(40) == 0 {
            b.row(40, &[at, reason]);
            b.row(42, &detail);
        }
    });
}
pub enum WorkEvent {
    Activated,
    Poll,
    WarmCreated {
        id: u64,
        deadline: u64,
    },
    WarmSubmit {
        id: u64,
        entered_ns: u64,
        result: Result<(), Error>,
    },
    WarmOutcome {
        id: u64,
        result: Result<u64, Error>,
    },
}
pub fn work(run: RunKey, event: WorkEvent, at: u64) {
    debug_assert_eq!(cpu::slot(), 0);
    if !run_matches(run) {
        return;
    }
    TRACE_WORK_EVIDENCE.write(|b| {
        if b.get(0) == 0 {
            b.row(
                0,
                &[
                    0x4359_5452_574b_0001,
                    1,
                    run.boot_epoch,
                    run.trial_id,
                    run.generation,
                    TRACE_CONTROL_EVIDENCE.get(6),
                    TRACE_CONTROL_EVIDENCE.get(7),
                    TRACE_CONTROL_EVIDENCE.get(5),
                ],
            );
        }
        match event {
            WorkEvent::Activated => {
                b.add(8, 1);
                if b.get(9) == 0 {
                    b.put(9, at);
                }
            }
            WorkEvent::Poll => {
                b.add(23, 1);
                if b.get(24) == 0 {
                    b.put(24, at);
                }
                let previous = b.get(25);
                if previous != 0 && at.saturating_sub(previous) > b.get(26) {
                    b.row(26, &[at - previous, previous, at]);
                }
                b.put(25, at);
            }
            WorkEvent::WarmCreated { id, deadline } => {
                b.add(10, 1);
                if b.get(11) == 0 {
                    b.row(11, &[id, at, deadline]);
                }
            }
            WorkEvent::WarmSubmit {
                id,
                entered_ns,
                result: reply,
            } => {
                b.add(14, 1);
                if b.get(15) == 0 {
                    b.row(
                        15,
                        &[
                            id,
                            entered_ns,
                            result(reply.map(|_| ExecutionState::Applied)),
                        ],
                    );
                    b.put(29, at);
                }
                if reply.is_ok() && b.get(18) == 0 {
                    b.row(18, &[at, id]);
                }
            }
            WorkEvent::WarmOutcome { id, result: reply } => {
                if b.get(20) == 0 {
                    b.row(
                        20,
                        &[at, id, result(reply.map(|_| ExecutionState::Applied))],
                    );
                    if let Ok(finished) = reply {
                        b.put(30, finished);
                    }
                }
            }
        }
    });
}

//! Typed in-place initialization of pool-backed governance state. The trusted
//! owner writes one small field/slot per charged step, retaining the exclusive
//! allocation and real model pins. No Governance reference exists until every
//! piece is written and the current commit gate is rechecked at finish.
use super::*;
use core::{
    marker::PhantomData,
    mem::{align_of, offset_of, size_of},
};

#[allow(clippy::large_enum_variant)]
pub enum InitValue<'a, 'model> {
    Candidate(&'a ValidatedCandidate<'model>),
    Old(&'a [u8; MODEL_BYTES]),
    Binding(ModelBinding),
    OptionalBinding(Option<ModelBinding>),
    Stage(Stage),
    U64(u64),
    U16(u16),
    Bool(bool),
    U32(u32),
    Target(Option<TargetRegistration>),
    Permit(Option<CanaryPermit>),
    Restoration(Option<RestorationRequest>),
    OptionalU64(Option<u64>),
    Usize(usize),
    OptionalUsize(Option<usize>),
    U8(u8),
    Fault(Option<Error>),
    Submission(Option<Submission>),
    Second(Option<SecondResult>),
    Incomplete(Option<IncompleteSecond>),
}
impl InitValue<'_, '_> {
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Candidate(_) => size_of::<&ValidatedCandidate<'_>>(),
            Self::Old(_) => size_of::<&[u8; MODEL_BYTES]>(),
            Self::Binding(_) => size_of::<ModelBinding>(),
            Self::OptionalBinding(_) => size_of::<Option<ModelBinding>>(),
            Self::Stage(_) => size_of::<Stage>(),
            Self::U64(_) => size_of::<u64>(),
            Self::U16(_) => size_of::<u16>(),
            Self::Bool(_) => size_of::<bool>(),
            Self::U32(_) => size_of::<u32>(),
            Self::Target(_) => size_of::<Option<TargetRegistration>>(),
            Self::Permit(_) => size_of::<Option<CanaryPermit>>(),
            Self::Restoration(_) => size_of::<Option<RestorationRequest>>(),
            Self::OptionalU64(_) => size_of::<Option<u64>>(),
            Self::Usize(_) => size_of::<usize>(),
            Self::OptionalUsize(_) => size_of::<Option<usize>>(),
            Self::U8(_) => size_of::<u8>(),
            Self::Fault(_) => size_of::<Option<Error>>(),
            Self::Submission(_) => size_of::<Option<Submission>>(),
            Self::Second(_) => size_of::<Option<SecondResult>>(),
            Self::Incomplete(_) => size_of::<Option<IncompleteSecond>>(),
        }
    }
    pub fn alignment(&self) -> usize {
        match self {
            Self::Candidate(_) => align_of::<&ValidatedCandidate<'_>>(),
            Self::Old(_) => align_of::<&[u8; MODEL_BYTES]>(),
            Self::Binding(_) => align_of::<ModelBinding>(),
            Self::OptionalBinding(_) => align_of::<Option<ModelBinding>>(),
            Self::Stage(_) => align_of::<Stage>(),
            Self::U64(_) => align_of::<u64>(),
            Self::U16(_) => align_of::<u16>(),
            Self::Bool(_) => align_of::<bool>(),
            Self::U32(_) => align_of::<u32>(),
            Self::Target(_) => align_of::<Option<TargetRegistration>>(),
            Self::Permit(_) => align_of::<Option<CanaryPermit>>(),
            Self::Restoration(_) => align_of::<Option<RestorationRequest>>(),
            Self::OptionalU64(_) => align_of::<Option<u64>>(),
            Self::Usize(_) => align_of::<usize>(),
            Self::OptionalUsize(_) => align_of::<Option<usize>>(),
            Self::U8(_) => align_of::<u8>(),
            Self::Fault(_) => align_of::<Option<Error>>(),
            Self::Submission(_) => align_of::<Option<Submission>>(),
            Self::Second(_) => align_of::<Option<SecondResult>>(),
            Self::Incomplete(_) => align_of::<Option<IncompleteSecond>>(),
        }
    }
}
pub struct InitPiece<'a, 'model> {
    pub sequence: usize,
    pub offset: usize,
    pub value: InitValue<'a, 'model>,
}
/// This proves ordered recipe completion and exact gate revalidation only.
/// External writes, allocation identity and model lifetimes remain the actual
/// pool owner's responsibility; it must keep this token with that allocation.
pub struct InitComplete<'a, 'model> {
    original: ModelBinding,
    boot_epoch: u64,
    pieces: usize,
    models: PhantomData<&'a ValidatedCandidate<'model>>,
}
impl InitComplete<'_, '_> {
    pub const fn bytes(&self) -> usize {
        size_of::<Governance<'_, '_>>()
    }
    pub const fn alignment(&self) -> usize {
        align_of::<Governance<'_, '_>>()
    }
    pub const fn pieces(&self) -> usize {
        self.pieces
    }
    pub const fn original_binding(&self) -> ModelBinding {
        self.original
    }
    pub const fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }
}
pub struct GovernanceInit<'a, 'model> {
    candidate: &'a ValidatedCandidate<'model>,
    old: &'a [u8; MODEL_BYTES],
    original: ModelBinding,
    boot_epoch: u64,
    start_window: u64,
    next: usize,
}
impl<'a, 'model> GovernanceInit<'a, 'model> {
    const FIXED: usize = 20;
    pub fn new(
        gate: &CommitGate,
        candidate: &'a ValidatedCandidate<'model>,
        old: &'a [u8; MODEL_BYTES],
        start_window: u64,
    ) -> Result<Self, Error> {
        Governance::validate_new(gate, candidate, old, start_window)?;
        Ok(Self {
            candidate,
            old,
            original: gate.active,
            boot_epoch: gate.boot_epoch,
            start_window,
            next: 0,
        })
    }
    pub const fn bytes(&self) -> usize {
        size_of::<Governance<'a, 'model>>()
    }
    pub const fn alignment(&self) -> usize {
        align_of::<Governance<'a, 'model>>()
    }
    pub const fn total_pieces(&self) -> usize {
        Self::FIXED + MAX_SUBMISSIONS + 30 + 30 + 1
    }
    pub const fn completed_pieces(&self) -> usize {
        self.next
    }
    pub fn peek(&self) -> Option<InitPiece<'a, 'model>> {
        type G<'a, 'm> = Governance<'a, 'm>;
        let n = self.next;
        let (offset, value) = match n {
            0 => (
                offset_of!(G<'a, 'model>, candidate),
                InitValue::Candidate(self.candidate),
            ),
            1 => (offset_of!(G<'a, 'model>, old), InitValue::Old(self.old)),
            2 => (
                offset_of!(G<'a, 'model>, original),
                InitValue::Binding(self.original),
            ),
            3 => (
                offset_of!(G<'a, 'model>, promoted_binding),
                InitValue::OptionalBinding(None),
            ),
            4 => (
                offset_of!(G<'a, 'model>, stage),
                InitValue::Stage(Stage::Shadow),
            ),
            5 => (offset_of!(G<'a, 'model>, shadow_closed), InitValue::U16(0)),
            6 => (
                offset_of!(G<'a, 'model>, shadow_seen),
                InitValue::Bool(false),
            ),
            7 => (
                offset_of!(G<'a, 'model>, shadow_families),
                InitValue::U32(0),
            ),
            8 => (offset_of!(G<'a, 'model>, target), InitValue::Target(None)),
            9 => (offset_of!(G<'a, 'model>, permit), InitValue::Permit(None)),
            10 => (
                offset_of!(G<'a, 'model>, restoration),
                InitValue::Restoration(None),
            ),
            11 => (
                offset_of!(G<'a, 'model>, last_submit_window),
                InitValue::OptionalU64(None),
            ),
            12 => (offset_of!(G<'a, 'model>, submitted), InitValue::Usize(0)),
            13 => (
                offset_of!(G<'a, 'model>, pending),
                InitValue::OptionalUsize(None),
            ),
            14 => (offset_of!(G<'a, 'model>, applied), InitValue::U16(0)),
            15 => (offset_of!(G<'a, 'model>, seconds_seen), InitValue::U16(0)),
            16 => (offset_of!(G<'a, 'model>, valid_seconds), InitValue::U16(0)),
            17 => (offset_of!(G<'a, 'model>, degraded_run), InitValue::U8(0)),
            18 => (offset_of!(G<'a, 'model>, reason), InitValue::Fault(None)),
            19 => (
                offset_of!(G<'a, 'model>, closing_deadline_ns),
                InitValue::OptionalU64(None),
            ),
            _ => {
                let i = n - Self::FIXED;
                if i < MAX_SUBMISSIONS {
                    (
                        offset_of!(G<'a, 'model>, history) + i * size_of::<Option<Submission>>(),
                        InitValue::Submission(None),
                    )
                } else if i < MAX_SUBMISSIONS + 30 {
                    (
                        offset_of!(G<'a, 'model>, seconds)
                            + (i - MAX_SUBMISSIONS) * size_of::<Option<SecondResult>>(),
                        InitValue::Second(None),
                    )
                } else if i < MAX_SUBMISSIONS + 60 {
                    (
                        offset_of!(G<'a, 'model>, incomplete_seconds)
                            + (i - MAX_SUBMISSIONS - 30) * size_of::<Option<IncompleteSecond>>(),
                        InitValue::Incomplete(None),
                    )
                } else if i == MAX_SUBMISSIONS + 60 {
                    (
                        offset_of!(G<'a, 'model>, shadow_next),
                        InitValue::U64(self.start_window),
                    )
                } else {
                    return None;
                }
            }
        };
        Some(InitPiece {
            sequence: n,
            offset,
            value,
        })
    }
    pub fn commit(&mut self, sequence: usize) -> Result<(), Error> {
        if sequence != self.next || self.next == self.total_pieces() {
            return Err(Error::Order);
        }
        self.next += 1;
        Ok(())
    }
    pub fn start_window(&self) -> u64 {
        self.start_window
    }
    /// Only the final shadow-start field is re-emitted if a delayed root-gate
    /// retry missed its future window. No Governance reference may exist yet.
    pub fn set_start_window(&mut self, window: u64) -> Result<(), Error> {
        window
            .checked_add(10)
            .and_then(|n| n.checked_mul(WINDOW_NS))
            .ok_or(Error::Numeric)?;
        if window < self.start_window {
            return Err(Error::Stale);
        }
        if window != self.start_window && self.next == self.total_pieces() {
            self.next -= 1;
        }
        self.start_window = window;
        Ok(())
    }
    pub fn check_finish(&self, gate: &CommitGate) -> Result<(), Error> {
        if self.next != self.total_pieces() {
            return Err(Error::State);
        }
        if gate.boot_epoch != self.boot_epoch
            || gate.active != self.original
            || gate.permit.is_some()
            || gate.closing.is_some()
            || gate.restore.is_some()
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn finish(self, gate: &CommitGate) -> Result<InitComplete<'a, 'model>, Error> {
        self.check_finish(gate)?;
        Ok(InitComplete {
            original: self.original,
            boot_epoch: self.boot_epoch,
            pieces: self.next,
            models: PhantomData,
        })
    }
}
const _: () = assert!(size_of::<InitValue<'_, '_>>() <= 512);

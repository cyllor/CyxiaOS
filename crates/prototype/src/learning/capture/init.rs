//! A typed, bounded write recipe for caller-owned uninitialized capture memory.
//! No reference to `Capture` is needed while the recipe is being applied. The
//! memory owner writes each small value, then acknowledges its sequence. Only
//! after `finish` may that owner establish a reference to the initialized object.
//! The recipe cannot attest that an external unsafe writer actually performed
//! its writes; the pool owner must retain its exclusive allocation throughout.
use super::*;
use core::mem::{align_of, offset_of, size_of};

pub enum InitValue {
    Config(Option<Config>),
    U64(u64),
    Usize(usize),
    Raw([u64; 4]),
    Source(Option<SourceState>),
    Open(Option<Open>),
    Cpu(CpuInterval),
    Request(RequestState),
    Work(WorkRequest),
    Fault(Option<Error>),
    Hash(Option<Sha256>),
    Seal(Option<Seal>),
}
impl InitValue {
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Config(_) => size_of::<Option<Config>>(),
            Self::U64(_) => size_of::<u64>(),
            Self::Usize(_) => size_of::<usize>(),
            Self::Raw(_) => size_of::<[u64; 4]>(),
            Self::Source(_) => size_of::<Option<SourceState>>(),
            Self::Open(_) => size_of::<Option<Open>>(),
            Self::Cpu(_) => size_of::<CpuInterval>(),
            Self::Request(_) => size_of::<RequestState>(),
            Self::Work(_) => size_of::<WorkRequest>(),
            Self::Fault(_) => size_of::<Option<Error>>(),
            Self::Hash(_) => size_of::<Option<Sha256>>(),
            Self::Seal(_) => size_of::<Option<Seal>>(),
        }
    }
    pub fn alignment(&self) -> usize {
        match self {
            Self::Config(_) => align_of::<Option<Config>>(),
            Self::U64(_) => align_of::<u64>(),
            Self::Usize(_) => align_of::<usize>(),
            Self::Raw(_) => align_of::<[u64; 4]>(),
            Self::Source(_) => align_of::<Option<SourceState>>(),
            Self::Open(_) => align_of::<Option<Open>>(),
            Self::Cpu(_) => align_of::<CpuInterval>(),
            Self::Request(_) => align_of::<RequestState>(),
            Self::Work(_) => align_of::<WorkRequest>(),
            Self::Fault(_) => align_of::<Option<Error>>(),
            Self::Hash(_) => align_of::<Option<Sha256>>(),
            Self::Seal(_) => align_of::<Option<Seal>>(),
        }
    }
}

pub struct InitPiece {
    pub sequence: usize,
    pub offset: usize,
    pub value: InitValue,
}

/// Completion of the ordered recipe, not an assertion about external memory.
/// Keep this token with the exact allocation on which the writes took place.
pub struct InitComplete<const I: usize, const R: usize> {
    pieces: usize,
}
impl<const I: usize, const R: usize> InitComplete<I, R> {
    pub const fn bytes(&self) -> usize {
        size_of::<Capture<I, R>>()
    }
    pub const fn alignment(&self) -> usize {
        align_of::<Capture<I, R>>()
    }
    pub const fn pieces(&self) -> usize {
        self.pieces
    }
}

pub struct CaptureInit<const I: usize, const R: usize> {
    next: usize,
}
impl<const I: usize, const R: usize> CaptureInit<I, R> {
    const FIXED: usize = 15;
    pub fn new() -> Result<Self, Error> {
        if I == 0 || I > MAX_CPU_INTERVALS || R > MAX_REQUESTS {
            return Err(Error::Capacity);
        }
        Ok(Self { next: 0 })
    }
    pub const fn bytes(&self) -> usize {
        size_of::<Capture<I, R>>()
    }
    pub const fn alignment(&self) -> usize {
        align_of::<Capture<I, R>>()
    }
    pub const fn total_pieces(&self) -> usize {
        Self::FIXED + MAX_SOURCES + MAX_OPEN + I + R + R
    }
    pub const fn completed_pieces(&self) -> usize {
        self.next
    }

    /// A retry returns the same typed value until that sequence is committed.
    pub fn peek(&self) -> Option<InitPiece> {
        let n = self.next;
        let (offset, value) = match n {
            0 => (offset_of!(Capture<I, R>, config), InitValue::Config(None)),
            1 => (offset_of!(Capture<I, R>, instance), InitValue::U64(0)),
            2 => (offset_of!(Capture<I, R>, boot_epoch), InitValue::U64(0)),
            3 => (
                offset_of!(Capture<I, R>, high_generation),
                InitValue::U64(0),
            ),
            4 => (offset_of!(Capture<I, R>, serial), InitValue::U64(0)),
            5 => (offset_of!(Capture<I, R>, source_count), InitValue::Usize(0)),
            6 => (
                offset_of!(Capture<I, R>, interval_count),
                InitValue::Usize(0),
            ),
            7 => (
                offset_of!(Capture<I, R>, request_count),
                InitValue::Usize(0),
            ),
            8 => (offset_of!(Capture<I, R>, fault), InitValue::Fault(None)),
            9 => (offset_of!(Capture<I, R>, missing), InitValue::U64(0)),
            10 => (offset_of!(Capture<I, R>, warmup), InitValue::U64(0)),
            11 => (offset_of!(Capture<I, R>, later), InitValue::U64(0)),
            12 => (offset_of!(Capture<I, R>, events), InitValue::Hash(None)),
            13 => (offset_of!(Capture<I, R>, sealed), InitValue::Seal(None)),
            14 => (offset_of!(Capture<I, R>, raw), InitValue::Raw([0; 4])),
            _ => {
                let mut index = n - Self::FIXED;
                if index < MAX_SOURCES {
                    (
                        offset_of!(Capture<I, R>, sources)
                            + index * size_of::<Option<SourceState>>(),
                        InitValue::Source(None),
                    )
                } else {
                    index -= MAX_SOURCES;
                    if index < MAX_OPEN {
                        (
                            offset_of!(Capture<I, R>, open) + index * size_of::<Option<Open>>(),
                            InitValue::Open(None),
                        )
                    } else {
                        index -= MAX_OPEN;
                        if index < I {
                            (
                                offset_of!(Capture<I, R>, intervals)
                                    + index * size_of::<CpuInterval>(),
                                InitValue::Cpu(EMPTY_CPU),
                            )
                        } else {
                            index -= I;
                            if index < R {
                                (
                                    offset_of!(Capture<I, R>, request_state)
                                        + index * size_of::<RequestState>(),
                                    InitValue::Request(EMPTY_REQUEST),
                                )
                            } else {
                                index -= R;
                                if index < R {
                                    (
                                        offset_of!(Capture<I, R>, requests)
                                            + index * size_of::<WorkRequest>(),
                                        InitValue::Work(EMPTY_WORK),
                                    )
                                } else {
                                    return None;
                                }
                            }
                        }
                    }
                }
            }
        };
        Some(InitPiece {
            sequence: n,
            offset,
            value,
        })
    }
    /// Call only after the matching write has completed. Skipping or replaying
    /// an acknowledgement is rejected without changing progress.
    pub fn commit(&mut self, sequence: usize) -> Result<(), Error> {
        if sequence != self.next || self.next == self.total_pieces() {
            return Err(Error::Order);
        }
        self.next += 1;
        Ok(())
    }
    pub fn finish(self) -> Result<InitComplete<I, R>, Error> {
        if self.next != self.total_pieces() {
            return Err(Error::State);
        }
        Ok(InitComplete { pieces: self.next })
    }
}

const _: () = assert!(size_of::<InitValue>() <= 256);

//! Single-producer/single-worker ownership transfer for pinned CPU work.
//! No payload reference escapes `run`; only a completed generation is collected.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;
const RUNNING: u8 = 3;
const DONE: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Stale,
    GenerationExhausted,
}
pub struct Cancellation<'a>(&'a AtomicBool);
impl Cancellation<'_> {
    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
pub struct Handoff<J, R> {
    state: AtomicU8,
    generation: AtomicU64,
    cancel: AtomicBool,
    job: UnsafeCell<Option<J>>,
    result: UnsafeCell<Option<R>>,
}
// Payload access is confined to the unsafe producer/worker operations below.
// Transfer also requires Send on the payloads: a board-specific owner must prove
// that its pinned raw mappings remain valid on the receiving CPU.
unsafe impl<J: Send, R: Send> Sync for Handoff<J, R> {}
impl<J, R> Handoff<J, R> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            generation: AtomicU64::new(0),
            cancel: AtomicBool::new(false),
            job: UnsafeCell::new(None),
            result: UnsafeCell::new(None),
        }
    }
    pub fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == READY
    }
    /// # Safety
    /// Exactly one producer calls publish/collect/stop. One fixed worker calls
    /// run. The handoff remains pinned until collected; payload ownership and
    /// all referenced mappings may cross between those CPUs. A published job
    /// must not be accessed by the producer before successful collection.
    pub unsafe fn publish(&self, job: J) -> Result<u64, (Error, J)> {
        if self
            .state
            .compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err((Error::Busy, job));
        }
        let Some(generation) = self.generation.load(Ordering::Relaxed).checked_add(1) else {
            self.state.store(EMPTY, Ordering::Release);
            return Err((Error::GenerationExhausted, job));
        };
        unsafe {
            *self.job.get() = Some(job);
            *self.result.get() = None;
        }
        self.cancel.store(false, Ordering::Relaxed);
        self.generation.store(generation, Ordering::Release);
        self.state.store(READY, Ordering::Release);
        Ok(generation)
    }
    /// # Safety
    /// The fixed worker exclusively runs the published payload in place. The
    /// closure must finish all CPU accesses before returning (including loading
    /// a kernel CR3 and clearing residency for a user context).
    pub unsafe fn run(&self, execute: impl FnOnce(&mut J, Cancellation<'_>) -> R) -> bool {
        if self
            .state
            .compare_exchange(READY, RUNNING, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        let job = unsafe { (&mut *self.job.get()).as_mut().expect("published CPU job") };
        let result = execute(job, Cancellation(&self.cancel));
        unsafe { *self.result.get() = Some(result) };
        self.state.store(DONE, Ordering::Release);
        true
    }
    fn state_for(&self, generation: u64) -> Result<u8, Error> {
        if generation == 0 || self.generation.load(Ordering::Acquire) != generation {
            return Err(Error::Stale);
        }
        match self.state.load(Ordering::Acquire) {
            state @ (READY | RUNNING | DONE) => Ok(state),
            _ => Err(Error::Stale),
        }
    }
    pub fn is_done(&self, generation: u64) -> Result<bool, Error> {
        Ok(self.state_for(generation)? == DONE)
    }
    /// # Safety
    /// Producer-only; the caller must wake a running worker after publication
    /// and must still collect completion before touching any job memory.
    pub unsafe fn request_stop(&self, generation: u64) -> Result<bool, Error> {
        if self.state_for(generation)? == DONE {
            return Ok(false);
        }
        self.cancel.store(true, Ordering::Release);
        Ok(true)
    }
    /// # Safety
    /// Producer-only, under publish's ownership contract. After collection the
    /// worker has no references into either returned value.
    pub unsafe fn try_collect(&self, generation: u64) -> Result<Option<(J, R)>, Error> {
        if self.state_for(generation)? != DONE {
            return Ok(None);
        }
        self.state
            .compare_exchange(DONE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        let job = unsafe { (&mut *self.job.get()).take().expect("completed CPU job") };
        let result = unsafe {
            (&mut *self.result.get())
                .take()
                .expect("completed CPU result")
        };
        self.state.store(EMPTY, Ordering::Release);
        Ok(Some((job, result)))
    }
}

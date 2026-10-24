//! Bounded, nonblocking EL1-to-EL1 mailbox for a controller's copied messages.
//! No raw user pointers. A timed-out request is not overwritten while a worker
//! might still write it: complete/drop its Work token, drain, then reuse.
use super::Error;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;
const WORKING: u8 = 3;
const DONE: u8 = 4;
const READING: u8 = 5;
pub struct Exchange<const I: usize, const O: usize> {
    state: AtomicU8,
    input: [AtomicU64; I],
    output: [AtomicU64; O],
}
impl<const I: usize, const O: usize> Default for Exchange<I, O> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const I: usize, const O: usize> Exchange<I, O> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            input: [const { AtomicU64::new(0) }; I],
            output: [const { AtomicU64::new(0) }; O],
        }
    }
    pub fn submit(&self, words: [u64; I]) -> Result<(), Error> {
        if I == 0 || O == 0 {
            return Err(Error::Invalid);
        }
        self.state
            .compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        for (s, v) in self.input.iter().zip(words) {
            s.store(v, Ordering::Relaxed);
        }
        self.state.store(READY, Ordering::Release);
        Ok(())
    }
    pub fn take(&self) -> Option<Work<'_, I, O>> {
        self.state
            .compare_exchange(READY, WORKING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(Work {
            exchange: self,
            input: core::array::from_fn(|i| self.input[i].load(Ordering::Relaxed)),
        })
    }
    pub fn receive(&self) -> Option<[u64; O]> {
        self.state
            .compare_exchange(DONE, READING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let words = core::array::from_fn(|i| self.output[i].load(Ordering::Relaxed));
        self.state.store(EMPTY, Ordering::Release);
        Some(words)
    }
    pub fn idle(&self) -> bool {
        self.state.load(Ordering::Acquire) == EMPTY
    }
}
pub struct Work<'a, const I: usize, const O: usize> {
    exchange: &'a Exchange<I, O>,
    pub input: [u64; I],
}
impl<const I: usize, const O: usize> Work<'_, I, O> {
    pub fn complete(self, words: [u64; O]) {
        for (s, v) in self.exchange.output.iter().zip(words) {
            s.store(v, Ordering::Relaxed);
        }
        self.exchange.state.store(DONE, Ordering::Release);
        core::mem::forget(self);
    }
}
impl<const I: usize, const O: usize> Drop for Work<'_, I, O> {
    fn drop(&mut self) {
        // A worker failure still returns an explicitly invalid response. Never
        // publish a partially copied previous reply or silently replay input.
        for s in &self.exchange.output {
            s.store(0, Ordering::Relaxed);
        }
        self.exchange.state.store(DONE, Ordering::Release);
    }
}

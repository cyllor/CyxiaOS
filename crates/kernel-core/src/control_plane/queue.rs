//! Bounded SPSC word transport without allocation, unsafe code, spins or waits.
//! Split once with exclusive access. Tokens are Send but !Sync and not Clone.
//! Payloads are COPIED atomics; EL0 shared pages must first be copied/validated
//! by the syscall adapter. One reserved slot distinguishes full from empty.
use core::cell::Cell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    InvalidCapacity,
    Full,
    Empty,
}
pub struct Channel<const N: usize, const W: usize> {
    words: [[AtomicU64; W]; N],
    head: AtomicUsize,
    tail: AtomicUsize,
}
pub struct Sender<'a, const N: usize, const W: usize> {
    channel: &'a Channel<N, W>,
    single: PhantomData<Cell<()>>,
}
pub struct Receiver<'a, const N: usize, const W: usize> {
    channel: &'a Channel<N, W>,
    single: PhantomData<Cell<()>>,
}
impl<const N: usize, const W: usize> Default for Channel<N, W> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize, const W: usize> Channel<N, W> {
    pub const fn new() -> Self {
        Self {
            words: [const { [const { AtomicU64::new(0) }; W] }; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }
    pub const fn capacity(&self) -> usize {
        N.saturating_sub(1)
    }
    pub fn split(&mut self) -> Result<(Sender<'_, N, W>, Receiver<'_, N, W>), QueueError> {
        if N < 2 || W == 0 {
            return Err(QueueError::InvalidCapacity);
        }
        Ok((
            Sender {
                channel: self,
                single: PhantomData,
            },
            Receiver {
                channel: self,
                single: PhantomData,
            },
        ))
    }
    /// Requires both endpoint tokens to have been dropped. A controller restart
    /// must also change its epoch so an already copied old message is rejected.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
    fn next(at: usize) -> usize {
        if at + 1 == N { 0 } else { at + 1 }
    }
}
impl<const N: usize, const W: usize> Sender<'_, N, W> {
    pub fn try_send(&mut self, message: [u64; W]) -> Result<(), QueueError> {
        let c = self.channel;
        let tail = c.tail.load(Ordering::Relaxed);
        let next = Channel::<N, W>::next(tail);
        if next == c.head.load(Ordering::Acquire) {
            return Err(QueueError::Full);
        }
        for (slot, value) in c.words[tail].iter().zip(message) {
            slot.store(value, Ordering::Relaxed);
        }
        c.tail.store(next, Ordering::Release);
        Ok(())
    }
}
impl<const N: usize, const W: usize> Receiver<'_, N, W> {
    pub fn try_receive(&mut self) -> Result<[u64; W], QueueError> {
        let c = self.channel;
        let head = c.head.load(Ordering::Relaxed);
        if head == c.tail.load(Ordering::Acquire) {
            return Err(QueueError::Empty);
        }
        let message = core::array::from_fn(|i| c.words[head][i].load(Ordering::Relaxed));
        c.head.store(Channel::<N, W>::next(head), Ordering::Release);
        Ok(message)
    }
}

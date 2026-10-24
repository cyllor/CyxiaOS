//! Short, nonblocking publication of immutable owner observations. A reader
//! never borrows an executor and the owner never waits for a control worker.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

pub struct ReadSnapshot<T: Copy> {
    gate: AtomicBool,
    value: UnsafeCell<Option<T>>,
}
// All accesses to value are protected by the same acquire/release gate.
unsafe impl<T: Copy + Send> Sync for ReadSnapshot<T> {}
struct Guard<'a>(&'a AtomicBool);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl<T: Copy> ReadSnapshot<T> {
    pub const fn new() -> Self {
        Self {
            gate: AtomicBool::new(false),
            value: UnsafeCell::new(None),
        }
    }
    fn lock(&self) -> Result<Guard<'_>, ()> {
        self.gate
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Guard(&self.gate))
            .map_err(|_| ())
    }
    pub fn publish(&self, value: T) -> Result<(), ()> {
        let _guard = self.lock()?;
        unsafe {
            *self.value.get() = Some(value);
        }
        Ok(())
    }
    /// Project a small result while the immutable observation is protected by
    /// the publication gate. The callback must be bounded and must not wait on
    /// or call an executor; a competing owner or reader receives Busy instead.
    /// No reference to the protected value can escape the callback.
    pub fn inspect<R>(&self, inspect: impl FnOnce(&T) -> R) -> Result<Option<R>, ()> {
        let _guard = self.lock()?;
        Ok(unsafe { (&*self.value.get()).as_ref().map(inspect) })
    }
    pub fn read(&self) -> Result<Option<T>, ()> {
        self.inspect(|value| *value)
    }
}

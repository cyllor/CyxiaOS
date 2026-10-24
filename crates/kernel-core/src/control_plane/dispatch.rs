//! Per-CPU, linearizable dispatch fence. This is a kernel-owned gate, NOT an
//! EL0 capability. One serialized manager calls open/close; the CPU's dispatcher
//! calls try_enter. A closed gate cannot admit a late dispatch, and is drained
//! only after the last entered context has returned and its permit was dropped.
//! Closing never waits for a model or forcibly forgets a running context.
use super::{Error, Plane};
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};
const ENABLED: u64 = 2;
const BUSY: u64 = 4;
pub const MAX_GENERATION: u64 = u64::MAX >> 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub generation: u64,
    pub plane: Plane,
}
impl Token {
    fn word(self) -> Result<u64, Error> {
        if self.generation == 0 || self.generation > MAX_GENERATION {
            return Err(Error::Invalid);
        }
        Ok((self.generation << 3) | u64::from(self.plane == Plane::Control))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    pub token: Option<Token>,
    pub enabled: bool,
    pub running: bool,
}
pub struct Gate {
    state: AtomicU64,
}
impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}
impl Gate {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }
    pub fn view(&self) -> View {
        let word = self.state.load(Ordering::Acquire);
        View {
            token: if word >> 3 == 0 {
                None
            } else {
                Some(Token {
                    generation: word >> 3,
                    plane: if word & 1 == 0 {
                        Plane::Business
                    } else {
                        Plane::Control
                    },
                })
            },
            enabled: word & ENABLED != 0,
            running: word & BUSY != 0,
        }
    }
    /// The configuration manager is the unique writer. Generation is local to
    /// this dispatch gate and cannot be reset on a model/controller restart.
    pub fn open(&self, token: Token) -> Result<(), Error> {
        let next = token.word()? | ENABLED;
        let old = self.state.load(Ordering::Acquire);
        if old & (ENABLED | BUSY) != 0 {
            return Err(Error::Busy);
        }
        if token.generation <= old >> 3 {
            return Err(Error::Stale);
        }
        self.state
            .compare_exchange(old, next, Ordering::Release, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| Error::Busy)
    }
    /// Only the unique configuration manager may call this method concurrently
    /// with dispatch. It cannot race another manager's open/close operation.
    /// A single CAS disables entry without losing a concurrent completion. Busy
    /// asks the management loop to retry; this call never spins or waits.
    pub fn close(&self, token: Token) -> Result<(), Error> {
        let expected = token.word()?;
        let old = self.state.load(Ordering::Acquire);
        if old & !(ENABLED | BUSY) != expected {
            return Err(Error::Stale);
        }
        self.state
            .compare_exchange(old, old & !ENABLED, Ordering::AcqRel, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| Error::Busy)
    }
    /// A single CAS is the dispatch linearization point. No spins or queues.
    pub fn try_enter(&self, token: Token) -> Result<Permit<'_>, Error> {
        let expected = token.word()? | ENABLED;
        match self.state.compare_exchange(
            expected,
            expected | BUSY,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => Ok(Permit {
                gate: self,
                single_cpu: PhantomData,
            }),
            Err(word) if word & !(ENABLED | BUSY) != expected & !(ENABLED | BUSY) => {
                Err(Error::Stale)
            }
            Err(word) if word & ENABLED == 0 => Err(Error::NotReady),
            Err(_) => Err(Error::Busy),
        }
    }
    /// True is an observation, not a mapping/TLB/device drain proof. The caller
    /// also needs the architecture-specific barriers and no outstanding work.
    pub fn quiescent(&self) -> bool {
        self.state.load(Ordering::Acquire) & (ENABLED | BUSY) == 0
    }
}
/// Drop only after returning to EL1, disabling low walks, completing required
/// TLB barriers and accounting the dispatch. Not Clone; forgetting it fails shut.
pub struct Permit<'a> {
    gate: &'a Gate,
    single_cpu: PhantomData<*mut ()>,
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.gate.state.fetch_and(!BUSY, Ordering::Release);
    }
}

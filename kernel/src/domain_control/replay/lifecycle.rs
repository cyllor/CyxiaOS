//! Small state shared by the native root and the CPU0 replay coordinator.
//! Callers supply actual protected custody facts; this module creates neither
//! execution receipts nor request completions.
use cyxia_prototype::{domains::Error, learning::capture::RunKey};

#[derive(Clone, Copy)]
pub(crate) struct CloseGate {
    closing: Option<RunKey>,
    activated: Option<RunKey>,
}
impl CloseGate {
    pub const fn new() -> Self {
        Self {
            closing: None,
            activated: None,
        }
    }
    pub fn closing(self) -> Option<RunKey> {
        self.closing
    }
    pub fn activated(self) -> Option<RunKey> {
        self.activated
    }
    pub fn begin(&mut self, run: RunKey, published: bool, unresolved: bool) -> Result<bool, Error> {
        if self.activated.is_some() {
            return Err(Error::Conflict);
        }
        if let Some(old) = self.closing {
            return if old == run {
                Ok(true)
            } else {
                Err(Error::Stale)
            };
        }
        // Published Pending/Unknown is real custody. It may need the original
        // workload activated before the existing executor can ever settle.
        if published {
            return Ok(false);
        }
        if unresolved {
            return Err(Error::Busy);
        }
        self.closing = Some(run);
        Ok(true)
    }
    pub fn finish_activation(&mut self, run: RunKey) -> Result<(), Error> {
        if self.closing.is_some() {
            return Err(Error::Auth);
        }
        if self.activated.is_some_and(|old| old != run) {
            return Err(Error::Stale);
        }
        self.activated = Some(run);
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkPhase {
    Prepared,
    Entered,
    Complete,
}
#[derive(Clone, Copy)]
pub(crate) struct WorkActivation(WorkPhase);
impl WorkActivation {
    pub const fn new() -> Self {
        Self(WorkPhase::Prepared)
    }
    pub fn entered(self) -> bool {
        self.0 != WorkPhase::Prepared
    }
    pub fn complete(self) -> bool {
        self.0 == WorkPhase::Complete
    }
    /// Set before calling any owner facade. Busy can follow a real effect.
    pub fn enter(&mut self) {
        if self.0 == WorkPhase::Prepared {
            self.0 = WorkPhase::Entered;
        }
    }
    /// Called only after the original owner's complete activation returns Ok.
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.0 == WorkPhase::Prepared {
            return Err(Error::Conflict);
        }
        self.0 = WorkPhase::Complete;
        Ok(())
    }
}

/// Installing a closing baseline can wait for the initial owner command to
/// settle. That command may itself require real workload progress. Always
/// drive the original owner before returning the restoration result, while
/// preserving that exact result (including unresolved Pending/Unknown).
pub(crate) fn restore_and_drain(
    restore: impl FnOnce() -> Result<(), Error>,
    drain: impl FnOnce() -> Result<bool, Error>,
) -> Result<bool, Error> {
    let restoration = restore();
    let drained = drain();
    restoration?;
    drained
}

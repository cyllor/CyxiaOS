//! Separate CPU0 CoreSet service authority, never task-family ownership.
use super::*;

pub(crate) struct CoreSetServiceAuthority {
    state: &'static State,
    _guard: Guard,
    _local: core::marker::PhantomData<*mut ()>,
}

pub(crate) fn reserve_core_set_service_authority(
    action: Action,
) -> Result<Option<CoreSetServiceAuthority>, Error> {
    // This is service authority only. CoreSet remains outside the task
    // publication owns/validate/current/prerequisite action families.
    if cpu::slot() != 0 || !matches!(action, Action::ControlSet(_)) {
        return Ok(None);
    }
    let guard = acquire_guard()?;
    let state = unsafe { &*core::ptr::addr_of!(STATE) };
    service_witness_locked(state)?;
    Ok(Some(CoreSetServiceAuthority {
        state,
        _guard: guard,
        _local: core::marker::PhantomData,
    }))
}

impl CoreSetServiceAuthority {
    pub(crate) fn authorize_service_turn(&self) -> Result<(), Error> {
        // Read the still-live actual owner/dispatch/credit at every protected
        // callback. Keeping the gate does not extend or settle its budget.
        service_witness_locked(self.state).map(|_| ())
    }
    pub(crate) fn can_control_move(&self, slot: usize) -> Result<(), Error> {
        if cpu::slot() != 0 || slot != 2 {
            return Err(Error::Auth);
        }
        can_control_move_locked(self.state, slot)
    }
}

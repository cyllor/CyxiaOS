//! SEC-P: bounded spawn idempotency, local CPU admission and exit fencing.
//! A VerifiedSpawn is built only from the protected task/package registry.
use super::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub id: u64,
    pub caller: u64,
    pub group: u8,
    pub package: [u8; 32],
    pub cpu: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSpawn {
    owner: u64,
    group: u8,
    package: [u8; 32],
    business: u64,
    healthy: u64,
    draining: u64,
    suspect: u64,
}
impl VerifiedSpawn {
    /// Only the privileged registry adapter may turn a capability and live
    /// ledger observation into this value; AI fields cannot construct one.
    /// Both registry constructors share the single V0.20 fixed CPU0 boundary.
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_registry(
        owner: u64,
        group: u8,
        package: [u8; 32],
        business: u64,
        healthy: u64,
        draining: u64,
        suspect: u64,
    ) -> Self {
        Self {
            owner,
            group,
            package,
            business,
            healthy,
            draining,
            suspect,
        }
    }
    /// Retained constructor name for the V0.19.9 protected registry adapter;
    /// identical to from_registry now that CPU0 is the only control core.
    #[allow(dead_code)]
    pub(crate) const fn from_registry_v0199(
        owner: u64,
        group: u8,
        package: [u8; 32],
        business: u64,
        healthy: u64,
        draining: u64,
        suspect: u64,
    ) -> Self {
        Self {
            owner,
            group,
            package,
            business,
            healthy,
            draining,
            suspect,
        }
    }
    fn permits(&self, request: Request) -> bool {
        let cpu = 1u64.checked_shl(request.cpu as u32).unwrap_or(0);
        self.owner != 0
            && self.owner == request.caller
            && self.group == request.group
            && self.package == request.package
            && cpu != 0
            // Standalone SEC-P ledger shares the same V0.20 native role
            // boundary as authorize_business_core: CPU0 is the only control
            // CPU and may not be an ordinary business CPU; CPU1-3 are business.
            && crate::control_plane::cpu0_v0199::permits_business(
                u16::from(request.cpu), self.business, self.healthy, self.draining, self.suspect,
            )
    }
}

/// Gate for the actual native business-core placement. A snapshot is supplied
/// by the protected scheduler/ownership adapter, never by the AI or a task.
/// It is checked again at creation publication; it does not reserve a CPU.
pub fn authorize_business_core(
    cpu: u16,
    core_generation: u64,
    business_mask: u64,
    healthy_mask: u64,
    draining_mask: u64,
    quarantined_mask: u64,
) -> Result<(), Error> {
    // V0.20 native four-core layout: CPU0 is the only control CPU and can never
    // run ordinary business; CPU1-3 are the business cores. A damaged mask that
    // claims CPU0 (or any core outside CPU1-3) is healthy business fails closed.
    if cpu == 0 {
        return Err(Error::Unauthorized);
    }
    authorize_business_core_v0199(
        cpu,
        core_generation,
        business_mask,
        healthy_mask,
        draining_mask,
        quarantined_mask,
    )
}

/// V0.19.9 native placement gate; the single authoritative CPU0 business
/// boundary that authorize_business_core now delegates to. Recheck at publication.
pub fn authorize_business_core_v0199(
    cpu: u16,
    core_generation: u64,
    business_mask: u64,
    healthy_mask: u64,
    draining_mask: u64,
    quarantined_mask: u64,
) -> Result<(), Error> {
    if core_generation == 0
        || !crate::control_plane::cpu0_v0199::permits_business(
            cpu,
            business_mask,
            healthy_mask,
            draining_mask,
            quarantined_mask,
        )
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    pub slot: u16,
    pub generation: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Reserved,
    Runnable,
    Exiting,
    Reapable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Row {
    request: Request,
    ticket: Ticket,
    state: State,
    references: u16,
    tlb_pending: u64,
    dma_pins: u16,
}
/// Bounded ledger of request receipts. Terminal records are deliberately
/// retained, so a repeated request ID cannot create a second task.
pub struct SpawnLedger<const N: usize> {
    rows: [Option<Row>; N],
}
impl<const N: usize> Default for SpawnLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> SpawnLedger<N> {
    pub const fn new() -> Self {
        Self { rows: [None; N] }
    }
    pub fn admit(&mut self, request: Request, authority: VerifiedSpawn) -> Result<Ticket, Error> {
        if request.id == 0 || request.caller == 0 || request.group >= 16 {
            return Err(Error::Invalid);
        }
        if let Some(row) = self
            .rows
            .iter()
            .flatten()
            .find(|r| r.request.id == request.id)
        {
            if row.request != request {
                return Err(Error::Conflict);
            }
            // Matching an old id is not authorization to see or reuse its receipt.
            if !authority.permits(request) {
                return Err(Error::Unauthorized);
            }
            return Ok(row.ticket);
        }
        if !authority.permits(request) {
            return Err(Error::Unauthorized);
        }
        let at = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let slot = u16::try_from(at).map_err(|_| Error::Capacity)?;
        let ticket = Ticket {
            slot,
            generation: 1,
        };
        self.rows[at] = Some(Row {
            request,
            ticket,
            state: State::Reserved,
            references: 0,
            tlb_pending: 0,
            dma_pins: 0,
        });
        Ok(ticket)
    }
    fn row_mut(&mut self, ticket: Ticket) -> Result<&mut Row, Error> {
        let row = self
            .rows
            .get_mut(ticket.slot as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::Stale)?;
        if row.ticket != ticket {
            return Err(Error::Stale);
        }
        Ok(row)
    }
    pub fn state(&self, ticket: Ticket) -> Result<State, Error> {
        let row = self
            .rows
            .get(ticket.slot as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::Stale)?;
        if row.ticket != ticket {
            return Err(Error::Stale);
        }
        Ok(row.state)
    }
    pub fn publish_runnable(
        &mut self,
        ticket: Ticket,
        authority: VerifiedSpawn,
    ) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Reserved {
            return Err(Error::Busy);
        }
        if !authority.permits(row.request) {
            return Err(Error::Unauthorized);
        }
        row.state = State::Runnable;
        Ok(())
    }
    pub fn hold_ref(&mut self, ticket: Ticket) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Runnable {
            return Err(Error::Busy);
        }
        row.references = row.references.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(())
    }
    pub fn end_ref(&mut self, ticket: Ticket) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        row.references = row.references.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn begin_exit(
        &mut self,
        ticket: Ticket,
        tlb_pending: u64,
        dma_pins: u16,
    ) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Runnable && row.state != State::Reserved {
            return Err(Error::Busy);
        }
        row.state = State::Exiting;
        row.tlb_pending = tlb_pending;
        row.dma_pins = dma_pins;
        Ok(())
    }
    pub fn ack_tlb(&mut self, ticket: Ticket, cpu: u8) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Exiting {
            return Err(Error::Busy);
        }
        let bit = 1u64.checked_shl(cpu as u32).ok_or(Error::Invalid)?;
        if row.tlb_pending & bit == 0 {
            return Err(Error::Stale);
        }
        row.tlb_pending &= !bit;
        Ok(())
    }
    pub fn dma_done(&mut self, ticket: Ticket) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Exiting {
            return Err(Error::Busy);
        }
        row.dma_pins = row.dma_pins.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn mark_reapable(&mut self, ticket: Ticket) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Exiting {
            return Err(Error::Busy);
        }
        if row.references != 0 || row.tlb_pending != 0 || row.dma_pins != 0 {
            return Err(Error::Busy);
        }
        row.state = State::Reapable;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req(id: u64) -> Request {
        Request {
            id,
            caller: 7,
            group: 2,
            package: [5; 32],
            cpu: 2,
        }
    }
    fn cap() -> VerifiedSpawn {
        VerifiedSpawn::from_registry(7, 2, [5; 32], 0b1110, 0b1110, 0, 0)
    }
    #[test]
    fn sec_p01_unauthorized_package_and_caller() {
        let mut ledger = SpawnLedger::<2>::new();
        let mut input = req(1);
        input.package = [9; 32];
        assert_eq!(ledger.admit(input, cap()), Err(Error::Unauthorized));
        input = req(1);
        input.caller = 8;
        assert_eq!(ledger.admit(input, cap()), Err(Error::Unauthorized));
        assert_eq!(ledger.rows.iter().flatten().count(), 0);
    }
    #[test]
    fn sec_p02_idempotent_retries_and_conflict() {
        let mut l = SpawnLedger::<2>::new();
        let t = l.admit(req(1), cap()).unwrap();
        for _ in 0..100 {
            assert_eq!(l.admit(req(1), cap()), Ok(t));
        }
        let revoked = VerifiedSpawn::from_registry(7, 2, [9; 32], 0b1110, 0b1110, 0, 0);
        assert_eq!(l.admit(req(1), revoked), Err(Error::Unauthorized));
        let mut conflict = req(1);
        conflict.package = [4; 32];
        assert_eq!(l.admit(conflict, cap()), Err(Error::Conflict));
    }
    #[test]
    fn sec_p03_capacity_and_no_hidden_slot() {
        let mut l = SpawnLedger::<1>::new();
        l.admit(req(1), cap()).unwrap();
        assert_eq!(l.admit(req(2), cap()), Err(Error::Capacity));
    }
    #[test]
    fn sec_p04_stale_ticket_fails() {
        let mut l = SpawnLedger::<2>::new();
        let t = l.admit(req(1), cap()).unwrap();
        assert_eq!(l.state(Ticket { generation: 2, ..t }), Err(Error::Stale));
    }
    #[test]
    fn sec_p05_exit_waits_for_refs_and_tlb() {
        let mut l = SpawnLedger::<1>::new();
        let t = l.admit(req(1), cap()).unwrap();
        l.publish_runnable(t, cap()).unwrap();
        l.hold_ref(t).unwrap();
        l.begin_exit(t, 1 << 2, 0).unwrap();
        assert_eq!(l.mark_reapable(t), Err(Error::Busy));
        l.end_ref(t).unwrap();
        l.ack_tlb(t, 2).unwrap();
        l.mark_reapable(t).unwrap();
    }
    #[test]
    fn sec_p06_no_control_or_draining_cpu() {
        let mut l = SpawnLedger::<1>::new();
        let denied = VerifiedSpawn::from_registry(7, 2, [5; 32], 0b0001, 0b1111, 0, 0);
        assert_eq!(l.admit(req(1), denied), Err(Error::Unauthorized));
        let draining = VerifiedSpawn::from_registry(7, 2, [5; 32], 0b1110, 0b1111, 1 << 2, 0);
        assert_eq!(l.admit(req(1), draining), Err(Error::Unauthorized));
    }
    #[test]
    fn v020_sec_p06_bad_registry_cannot_make_cpu0_business() {
        let mut l = SpawnLedger::<2>::new();
        let misclassified = VerifiedSpawn::from_registry(7, 2, [5; 32], u64::MAX, u64::MAX, 0, 0);
        // CPU0 is the control core; even an all-ones mask cannot make it business.
        let mut input = req(1);
        input.cpu = 0;
        assert_eq!(l.admit(input, misclassified), Err(Error::Unauthorized));
        // A business mask with bits outside CPU1-3 fails closed on every core.
        assert_eq!(l.admit(req(7), misclassified), Err(Error::Unauthorized));
        assert_eq!(l.rows.iter().flatten().count(), 0);
        // CPU1 is now legal business with a correct CPU1-3 mask.
        let good = VerifiedSpawn::from_registry(7, 2, [5; 32], 0b1110, 0b1110, 0, 0);
        let mut cpu1 = req(2);
        cpu1.cpu = 1;
        assert!(l.admit(cpu1, good).is_ok());
    }
    #[test]
    fn v0199_business_placement_and_spawn_use_fixed_cpu0_boundary() {
        let mut ledger = SpawnLedger::<3>::new();
        let authority = VerifiedSpawn::from_registry_v0199(7, 2, [5; 32], 0b1110, 0b1111, 0, 0);
        for cpu in 1..=3 {
            let mut input = req(u64::from(cpu));
            input.cpu = cpu;
            let ticket = ledger.admit(input, authority).unwrap();
            ledger.publish_runnable(ticket, authority).unwrap();
        }
        for cpu in [0, 4, 63, 64, u16::MAX] {
            assert_eq!(
                authorize_business_core_v0199(cpu, 1, u64::MAX, u64::MAX, 0, 0),
                Err(Error::Unauthorized)
            );
        }
        assert_eq!(
            authorize_business_core_v0199(1, 1, 0b1110, 0b1111, 0, 0),
            Ok(())
        );
        assert_eq!(
            authorize_business_core_v0199(1, 0, 0b1110, 0b1111, 0, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core_v0199(1, 1, 0b1110, 0b1111, 2, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core_v0199(1, 1, 0b1110, 0b1111, 0, 2),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core_v0199(1, 1, 0b1111, 0b1111, 0, 0),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn sec_p07_exiting_cannot_take_new_references() {
        let mut l = SpawnLedger::<1>::new();
        let t = l.admit(req(1), cap()).unwrap();
        l.publish_runnable(t, cap()).unwrap();
        l.begin_exit(t, 0, 0).unwrap();
        assert_eq!(l.hold_ref(t), Err(Error::Busy));
    }
    #[test]
    fn native_business_core_guard_refuses_draining_quarantine_and_wrong_generation() {
        assert_eq!(authorize_business_core(2, 1, 0b1100, 0b1100, 0, 0), Ok(()));
        assert_eq!(
            authorize_business_core(2, 0, 0b1100, 0b1100, 0, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core(2, 1, 0b1100, 0b1100, 0b0100, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core(2, 1, 0b1100, 0b1100, 0, 0b0100),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core(1, 1, 0b1100, 0b1100, 0, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core(64, 1, u64::MAX, u64::MAX, 0, 0),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn v020_sec_p06_protected_cpu0_misclassification_fails_closed() {
        assert_eq!(
            authorize_business_core(0, 1, u64::MAX, u64::MAX, 0, 0),
            Err(Error::Unauthorized)
        );
        // A misclassified all-ones business mask fails closed even for CPU1.
        assert_eq!(
            authorize_business_core(1, 1, u64::MAX, u64::MAX, 0, 0),
            Err(Error::Unauthorized)
        );
        // CPU1-3 are legal business with a correct CPU1-3 mask.
        assert_eq!(authorize_business_core(1, 1, 0b1110, 0b1110, 0, 0), Ok(()));
        assert_eq!(authorize_business_core(2, 1, 0b1100, 0b1100, 0, 0), Ok(()));
        assert_eq!(authorize_business_core(3, 1, 0b1110, 0b1110, 0, 0), Ok(()));
    }
    #[test]
    fn sec_p08_no_ai_required_for_local_admission() {
        let mut l = SpawnLedger::<1>::new();
        let t = l.admit(req(1), cap()).unwrap();
        l.publish_runnable(t, cap()).unwrap();
        assert_eq!(l.state(t), Ok(State::Runnable));
    }
}

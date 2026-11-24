//! SEC-D: bounded descriptor ownership, reliable completion/reset, IRQ routing.
//! This bookkeeper never proves physical DMA cessation by timeout.
use super::Error;

pub const MAX_CHAINS: usize = 8;
pub const NOTIFY_DEADLINE_NS: u64 = 50_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token {
    pub slot: u8,
    pub generation: u64,
    pub submit_id: u64,
    pub device_generation: u64,
    pub queue_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State { Private, Published, Unknown }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Lease {
    token: Token,
    descriptors: u8,
    pinned_pages: u8,
    state: State,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionProof { token: Token }
impl CompletionProof {
    #[allow(dead_code)]
    pub(crate) const fn from_driver(token: Token) -> Self { Self { token } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReliableReset {
    device_generation: u64,
    queue_generation: u64,
    quiesced: bool,
    dma_stopped: bool,
    reconciled: bool,
}
impl ReliableReset {
    /// Only the privileged native driver may create a proof after actually
    /// stopping the DMA engine and reconciling every in-flight operation.
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_driver(
        device_generation: u64, queue_generation: u64,
        quiesced: bool, dma_stopped: bool, reconciled: bool,
    ) -> Self {
        Self { device_generation, queue_generation, quiesced, dma_stopped, reconciled }
    }
}
/// A physical queue cannot have more than its negotiated descriptor capacity,
/// nor may its descriptor, DMA pin or completion credit be loaned twice.
pub struct Queue<const N: usize> {
    slots: [Option<Lease>; N],
    generations: [u64; N],
    device_generation: u64,
    queue_generation: u64,
}
impl<const N: usize> Queue<N> {
    pub const fn new(device_generation: u64, queue_generation: u64) -> Self {
        Self {
            slots: [None; N], generations: [0; N],
            device_generation, queue_generation,
        }
    }
    pub fn prepare(
        &mut self, submit_id: u64, descriptors: u8, pinned_pages: u8,
        credit_reserved: bool,
    ) -> Result<Token, Error> {
        if submit_id == 0 || descriptors == 0 || usize::from(descriptors) > MAX_CHAINS
            || pinned_pages == 0 || !credit_reserved
            || self.device_generation == 0 || self.queue_generation == 0
        {
            return Err(Error::Invalid);
        }
        if let Some(row) = self.slots.iter().flatten().find(|r| r.token.submit_id == submit_id) {
            return if row.descriptors == descriptors && row.pinned_pages == pinned_pages {
                Ok(row.token)
            } else {
                Err(Error::Conflict)
            };
        }
        // Count all reserved/published/UNKNOWN chains, not only occupied
        // request slots. A queue of eight descriptors cannot admit eight
        // eight-descriptor chains. UNKNOWN still consumes real DMA credit.
        let allocated = self.slots.iter().flatten()
            .try_fold(0usize, |total, lease| {
                total.checked_add(usize::from(lease.descriptors))
            }).ok_or(Error::Capacity)?;
        if allocated.checked_add(usize::from(descriptors))
            .is_none_or(|total|total > MAX_CHAINS)
        {
            return Err(Error::Capacity);
        }
        let at = self.slots.iter().position(Option::is_none).ok_or(Error::Capacity)?;
        let next = self.generations[at].checked_add(1).ok_or(Error::Exhausted)?;
        let token = Token {
            slot: u8::try_from(at).map_err(|_| Error::Capacity)?,
            generation: next, submit_id,
            device_generation: self.device_generation,
            queue_generation: self.queue_generation,
        };
        self.generations[at] = next;
        self.slots[at] = Some(Lease {
            token, descriptors, pinned_pages, state: State::Private,
        });
        Ok(token)
    }
    fn lease(&mut self, token: Token) -> Result<&mut Lease, Error> {
        // A newly constructed queue can begin its slot counters at one.
        // Bind every transition to the registered device/queue lifecycle,
        // not just a slot and local submit ID. The native registry must also
        // select the correct physical queue before invoking this component.
        if token.device_generation != self.device_generation
            || token.queue_generation != self.queue_generation {
            return Err(Error::Stale);
        }
        let lease = self.slots.get_mut(token.slot as usize).and_then(Option::as_mut)
            .ok_or(Error::Stale)?;
        if lease.token != token { return Err(Error::Stale); }
        Ok(lease)
    }
    pub fn publish(&mut self, token: Token) -> Result<(), Error> {
        let lease = self.lease(token)?;
        if lease.state != State::Private { return Err(Error::Busy); }
        lease.state = State::Published;
        Ok(())
    }
    pub fn timeout(&mut self, token: Token) -> Result<(), Error> {
        let lease = self.lease(token)?;
        if lease.state != State::Published { return Err(Error::Busy); }
        lease.state = State::Unknown;
        Ok(())
    }
    pub fn complete(&mut self, token: Token, proof: CompletionProof) -> Result<(), Error> {
        if proof.token != token { return Err(Error::Unauthorized); }
        let state = self.lease(token)?.state;
        if state != State::Published && state != State::Unknown { return Err(Error::Busy); }
        self.slots[token.slot as usize] = None;
        Ok(())
    }
    pub fn state(&mut self, token: Token) -> Result<State, Error> { Ok(self.lease(token)?.state) }
    pub fn has_inflight(&self) -> bool { self.slots.iter().any(Option::is_some) }
    pub fn reset(&mut self, proof: ReliableReset) -> Result<(), Error> {
        if proof.device_generation != self.device_generation
            || proof.queue_generation != self.queue_generation
        {
            return Err(Error::Stale);
        }
        if !proof.quiesced || !proof.dma_stopped || !proof.reconciled {
            return Err(Error::Unknown);
        }
        let next_device = self.device_generation.checked_add(1).ok_or(Error::Exhausted)?;
        let next_queue = self.queue_generation.checked_add(1).ok_or(Error::Exhausted)?;
        self.slots.fill(None);
        self.device_generation = next_device;
        self.queue_generation = next_queue;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqKind { VirtioSpi, Timer, Ipi, Watchdog }
pub fn validate_irq_route(
    kind: IrqKind, target_cpu: u8, core_generation: u64,
    healthy_business: u64, draining: u64, suspect: u64,
    source_quiesced: bool,
) -> Result<(), Error> {
    let bit = 1u64.checked_shl(target_cpu as u32).ok_or(Error::Invalid)?;
    // CPU1 is the single V0.19 advisory-control CPU. Ordinary VirtIO SPI
    // work must never be rerouted there even if a damaged mask marks it
    // as healthy business; CPU0's mechanism-broker IRQ is a separate owner.
    if target_cpu == 1 || kind != IrqKind::VirtioSpi
        || core_generation == 0 || !source_quiesced
        || bit & healthy_business & !draining & !suspect == 0
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
/// V0.19.9 ordinary SPI route admission. The legacy CPU1 gate remains
/// isolated for archival fixtures; native CPU0 never receives ordinary SPI.
pub fn validate_irq_route_v0199(
    kind: IrqKind, target_cpu: u8, core_generation: u64,
    healthy_business: u64, draining: u64, suspect: u64,
    source_quiesced: bool,
) -> Result<(), Error> {
    if kind != IrqKind::VirtioSpi || !source_quiesced || core_generation == 0
        || !crate::control_plane::cpu0_v0199::permits_business(
            u16::from(target_cpu), crate::control_plane::cpu0_v0199::BUSINESS_MASK,
            healthy_business, draining, suspect,
        )
        || healthy_business & !crate::control_plane::cpu0_v0199::BUSINESS_MASK != 0
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub fn must_notify(queued: u8, batch: u8, age_ns: u64, isolated: bool) -> Result<bool, Error> {
    if ![1,2,4,8].contains(&batch) || queued > MAX_CHAINS as u8 {
        return Err(Error::Invalid);
    }
    Ok(queued != 0 && (isolated || queued >= batch || age_ns >= NOTIFY_DEADLINE_NS))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn sec_d01_unreserved_dma_or_credit_denied() {
        let mut q=Queue::<2>::new(1,1);
        assert_eq!(q.prepare(1,1,0,true),Err(Error::Invalid));
        assert_eq!(q.prepare(1,1,1,false),Err(Error::Invalid));
    }
    #[test] fn sec_d02_bounded_descriptor_chains() {
        let mut q=Queue::<1>::new(1,1);
        assert_eq!(q.prepare(1,9,1,true),Err(Error::Invalid));
        assert!(q.prepare(1,1,1,true).is_ok());
        assert_eq!(q.prepare(2,1,1,true),Err(Error::Capacity));
    }
    #[test] fn v019_sec_d02_aggregate_descriptors_stay_reserved_while_unknown() {
        let mut q=Queue::<2>::new(1,1);
        let t=q.prepare(1,5,1,true).unwrap();
        assert_eq!(q.prepare(2,4,1,true),Err(Error::Capacity));
        q.publish(t).unwrap();
        q.timeout(t).unwrap();
        assert_eq!(q.prepare(2,4,1,true),Err(Error::Capacity));
        q.complete(t,CompletionProof::from_driver(t)).unwrap();
        assert!(q.prepare(2,4,1,true).is_ok());
    }
    #[test] fn sec_d03_duplicate_submit_is_not_a_second_lease() {
        let mut q=Queue::<2>::new(1,1);
        let t=q.prepare(1,1,1,true).unwrap();
        assert_eq!(q.prepare(1,1,1,true),Ok(t));
        assert_eq!(q.prepare(1,2,1,true),Err(Error::Conflict));
    }
    #[test] fn sec_d04_timeout_is_unknown_not_dma_release() {
        let mut q=Queue::<1>::new(1,1);
        let t=q.prepare(1,1,1,true).unwrap();
        q.publish(t).unwrap(); q.timeout(t).unwrap();
        assert!(q.has_inflight());
        assert_eq!(q.state(t),Ok(State::Unknown));
    }
    #[test] fn sec_d05_reset_needs_reliable_proof() {
        let mut q=Queue::<1>::new(1,1);
        let t=q.prepare(1,1,1,true).unwrap();q.publish(t).unwrap();
        assert_eq!(q.reset(ReliableReset::from_driver(1,1,true,false,true)),Err(Error::Unknown));
        assert!(q.has_inflight());
        q.reset(ReliableReset::from_driver(1,1,true,true,true)).unwrap();
        assert!(!q.has_inflight());
    }
    #[test] fn sec_d06_old_or_forged_completion_rejected() {
        let mut q=Queue::<1>::new(1,1);
        let t=q.prepare(1,1,1,true).unwrap();q.publish(t).unwrap();
        assert_eq!(q.complete(t,CompletionProof::from_driver(Token { generation: 2, ..t })),Err(Error::Unauthorized));
        assert_eq!(q.complete(Token { generation: 2, ..t },CompletionProof::from_driver(Token { generation: 2, ..t })),Err(Error::Stale));
        q.complete(t,CompletionProof::from_driver(t)).unwrap();
        assert_eq!(q.complete(t,CompletionProof::from_driver(t)),Err(Error::Stale));
    }
    #[test] fn v0199_recreated_queue_rejects_old_lifecycle_completion() {
        let mut old=Queue::<1>::new(1,1);
        let old_token=old.prepare(7,1,1,true).unwrap();
        old.publish(old_token).unwrap();
        old.timeout(old_token).unwrap();
        // The registry obtains reliable reset proof before reconstruction.
        old.reset(ReliableReset::from_driver(1,1,true,true,true)).unwrap();
        let mut fresh=Queue::<1>::new(2,2);
        let new_token=fresh.prepare(7,1,1,true).unwrap();
        fresh.publish(new_token).unwrap();
        assert_eq!(old_token.generation,new_token.generation);
        assert_eq!(old_token.submit_id,new_token.submit_id);
        assert_eq!(fresh.complete(old_token,CompletionProof::from_driver(old_token)),Err(Error::Stale));
        assert_eq!(fresh.complete(new_token,CompletionProof::from_driver(old_token)),Err(Error::Unauthorized));
        assert_eq!(fresh.state(new_token),Ok(State::Published));
        assert!(fresh.has_inflight());
        fresh.complete(new_token,CompletionProof::from_driver(new_token)).unwrap();
        assert!(!fresh.has_inflight());
    }
    #[test] fn sec_d07_irq_must_target_healthy_business_only() {
        assert_eq!(validate_irq_route(IrqKind::Timer,1,1,0b10,0,0,true),Err(Error::Unauthorized));
        assert_eq!(validate_irq_route(IrqKind::VirtioSpi,1,1,0b10,0b10,0,true),Err(Error::Unauthorized));
        assert_eq!(validate_irq_route(IrqKind::VirtioSpi,1,1,0b10,0,0,true),Err(Error::Unauthorized));
        assert_eq!(validate_irq_route(IrqKind::VirtioSpi,2,1,0b100,0,0,true),Ok(()));
    }
    #[test] fn v0199_irq_route_is_only_to_fixed_business_cpu_after_quiescence() {
        for cpu in 1..=3 {
            assert_eq!(validate_irq_route_v0199(IrqKind::VirtioSpi,cpu,1,0b1110,0,0,true),Ok(()));
            assert_eq!(validate_irq_route_v0199(IrqKind::VirtioSpi,cpu,1,0b1110,1<<cpu,0,true),Err(Error::Unauthorized));
            assert_eq!(validate_irq_route_v0199(IrqKind::VirtioSpi,cpu,1,0b1110,0,1<<cpu,true),Err(Error::Unauthorized));
        }
        for cpu in [0,4,63,64] {
            assert_eq!(validate_irq_route_v0199(IrqKind::VirtioSpi,cpu,1,0b1110,0,0,true),Err(Error::Unauthorized));
        }
        assert_eq!(validate_irq_route_v0199(IrqKind::VirtioSpi,1,1,0b1111,0,0,true),Err(Error::Unauthorized));
        assert_eq!(validate_irq_route_v0199(IrqKind::VirtioSpi,1,1,0b1110,0,0,false),Err(Error::Unauthorized));
        assert_eq!(validate_irq_route_v0199(IrqKind::Timer,1,1,0b1110,0,0,true),Err(Error::Unauthorized));
    }
    #[test] fn sec_d08_lonely_chain_reaches_notification_deadline() {
        assert_eq!(must_notify(1,8,49_999,false),Ok(false));
        assert_eq!(must_notify(1,8,50_000,false),Ok(true));
        assert_eq!(must_notify(1,8,0,true),Ok(true));
        assert_eq!(must_notify(0,8,50_000,true),Ok(false));
    }
}

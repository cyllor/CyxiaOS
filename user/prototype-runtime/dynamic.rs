//! Trusted adapter between actual native stop producers and opaque core proofs.
//! A NativeStop is kernel-only evidence, never an EL0 or network wire type.
use cyxia_prototype::cores::{CoreSet, Cores, Error, Snapshot, StopDomain, ThreadHandle, Ticket};
#[derive(Clone, Copy, Default)]
pub struct NativeStop {
    pub dispatch: bool,
    pub tasks: bool,
    pub irq: bool,
    pub dma: bool,
    pub tlb: bool,
    pub references: bool,
}
impl NativeStop {
    pub fn complete(self) -> bool {
        self.dispatch && self.tasks && self.irq && self.dma && self.tlb && self.references
    }
}
pub struct Handoff {
    generation: u64,
    target: u64,
    accepted_ms: u64,
    finished: bool,
    ticket: Option<Ticket>,
}
impl Handoff {
    pub fn new(snapshot: &Snapshot, target: u64, now_ms: u64) -> Result<Self, Error> {
        if ![2, 6].contains(&target)
            || snapshot.control.bits() ^ target != 4
            || snapshot.suspect.bits() != 0
            || snapshot.draining.bits() != 0
        {
            return Err(Error::Invalid);
        }
        now_ms.checked_add(200).ok_or(Error::Exhausted)?;
        Ok(Self {
            generation: snapshot.core_generation,
            target,
            accepted_ms: now_ms,
            finished: false,
            ticket: None,
        })
    }
    pub fn poll(
        &mut self,
        owner: &mut Cores,
        stop: NativeStop,
        now_ms: u64,
    ) -> Result<bool, Error> {
        self.poll_with_thread(owner, stop, now_ms, &mut None)
    }
    /// The optional CPU2 best-effort bounded workload is retired only after its
    /// actual execution/context references have ceased. Its per-window debit is
    /// retained by Cores even when it is re-admitted after a later return to B.
    pub fn poll_with_thread(
        &mut self,
        owner: &mut Cores,
        stop: NativeStop,
        now_ms: u64,
        thread: &mut Option<ThreadHandle>,
    ) -> Result<bool, Error> {
        if self.finished || owner.snapshot().core_generation != self.generation {
            return Err(Error::Stale);
        }
        if now_ms < self.accepted_ms {
            return Err(Error::ClockRegression);
        }
        if now_ms - self.accepted_ms >= 200 {
            self.finished = true;
            // No ACK: retain original C/B and all obligations, disable admission.
            if self.ticket.is_some() {
                owner.expire(now_ms)?;
            } else {
                owner.suspect(2)?;
            }
            return Err(Error::Expired);
        }
        if self.ticket.is_none() {
            let state = owner.snapshot();
            let target = CoreSet::from_bits(self.target);
            self.ticket = Some(if let Some(handle) = *thread {
                if self.target == 6 {
                    owner.begin_retiring(
                        target,
                        state.core_generation,
                        state.ledger_generation,
                        self.accepted_ms,
                        handle,
                    )?
                } else {
                    owner.begin(
                        target,
                        state.core_generation,
                        state.ledger_generation,
                        self.accepted_ms,
                    )?
                }
            } else {
                owner.begin(
                    target,
                    state.core_generation,
                    state.ledger_generation,
                    self.accepted_ms,
                )?
            });
            self.generation = owner.snapshot().core_generation;
        }
        if !stop.complete() {
            return Ok(false);
        }
        if self.target == 6 {
            if let Some(handle) = *thread {
                owner.release(handle)?;
                *thread = None;
            }
        }
        let ticket = self.ticket.unwrap();
        let request = owner.stop_request(ticket, 2)?;
        // Each entry is justified by its independent producer above. Never
        // iterate ALL domains to turn dispatch quiescence into a fabricated proof.
        if stop.dispatch {
            owner.record_stop_completion(request, StopDomain::Dispatch)?;
        }
        if stop.tasks {
            owner.record_stop_completion(request, StopDomain::Tasks)?;
        }
        if stop.irq {
            owner.record_stop_completion(request, StopDomain::Irq)?;
        }
        if stop.dma {
            owner.record_stop_completion(request, StopDomain::Dma)?;
        }
        if stop.tlb {
            owner.record_stop_completion(request, StopDomain::Tlb)?;
        }
        if stop.references {
            owner.record_stop_completion(request, StopDomain::References)?;
        }
        owner.ack_quiescent(ticket, 2)?;
        owner.publish(ticket, now_ms)?;
        self.finished = true;
        Ok(true)
    }
}

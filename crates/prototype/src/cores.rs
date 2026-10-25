//! Bounded 1.3 guest CPU ownership and business-thread admission.
//!
//! The caller serializes this object with the final dispatch/resource gate.
//! Snapshots are observations, never durable dispatch capabilities. Native EL1
//! adapters must recheck `permits` at dispatch under that same serialization.
//! `record_stop_completion` is a TRUSTED ingress: it must only receive actual
//! task/dispatch, IRQ, DMA, TLB and reference-drain completions, never EL0/RPC
//! claims. The component cannot verify hardware; host tests supply synthetic
//! events and do not establish native stopping or system acceptance.

pub const MAX_CPUS: usize = 64;
pub const MAX_THREADS: usize = 64;
pub const CAPACITY_MILLI: u16 = 900;
pub const TRANSITION_MS: u64 = 200;
pub const NORMAL_PROPOSAL_INTERVAL_MS: u64 = 1000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreSet(u64);
impl CoreSet {
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub const fn contains(self, cpu: usize) -> bool {
        cpu < MAX_CPUS && self.0 & (1u64 << cpu) != 0
    }
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    Control,
    Business,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    UnknownCpu,
    Stale,
    Busy,
    Unhealthy,
    MissingProof,
    Duplicate,
    Expired,
    Exhausted,
    Capacity,
    Affinity,
    Budget,
    Full,
    RateLimited,
    ClockRegression,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub online: CoreSet,
    pub control: CoreSet,
    pub business: CoreSet,
    pub transition: CoreSet,
    pub quarantined: CoreSet,
    pub suspect: CoreSet,
    pub draining: CoreSet,
    pub core_generation: u64,
    pub ledger_generation: u64,
}
impl Snapshot {
    pub const fn permits(self, cpu: usize, plane: Plane) -> bool {
        let owner = match plane {
            Plane::Control => self.control,
            Plane::Business => self.business,
        };
        owner.contains(cpu) && !self.suspect.contains(cpu) && !self.draining.contains(cpu)
    }
}

/// Opaque, monotonic within one live owner instance. Never deserialize a ticket
/// from an untrusted peer. A native adapter must additionally bind boot identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    sequence: u64,
}
impl Ticket {
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopRequest {
    operation: u64,
    cpu: usize,
    cpu_generation: u64,
}
impl StopRequest {
    pub const fn operation(self) -> u64 {
        self.operation
    }
    pub const fn cpu(self) -> usize {
        self.cpu
    }
    pub const fn cpu_generation(self) -> u64 {
        self.cpu_generation
    }
}
/// All domains are required, including an explicit verified empty-domain event
/// when a CPU has no DMA or reference users. A closed dispatch gate alone is
/// insufficient. Each event producer is a trusted native subsystem adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StopDomain {
    Dispatch,
    Tasks,
    Irq,
    Dma,
    Tlb,
    References,
}
impl StopDomain {
    pub const ALL: [Self; 6] = [
        Self::Dispatch,
        Self::Tasks,
        Self::Irq,
        Self::Dma,
        Self::Tlb,
        Self::References,
    ];
}
#[derive(Clone, Copy)]
enum StopPurpose {
    Transfer(Ticket),
    Quarantine,
}
#[derive(Clone, Copy)]
struct Collector {
    request: StopRequest,
    purpose: StopPurpose,
    completed: u8,
}
/// Cannot be constructed by callers; created only from a complete, live,
/// generation-bound collector. In particular there is no boolean stop API.
struct StopProof {
    request: StopRequest,
}
impl Collector {
    fn proof(self) -> Result<StopProof, Error> {
        if self.completed != 0b11_1111 {
            return Err(Error::MissingProof);
        }
        Ok(StopProof {
            request: self.request,
        })
    }
}
#[derive(Clone, Copy)]
struct Transition {
    ticket: Ticket,
    target: u64,
    moving: u64,
    acked: u64,
    deadline: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadSpec {
    pub thread_id: u64,
    pub budget_milli: u16,
    pub allowed_mask: CoreSet,
    pub assigned_cpu: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadHandle {
    thread_id: u64,
    generation: u64,
}
impl ThreadHandle {
    pub const fn thread_id(self) -> u64 {
        self.thread_id
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub thread_id: u64,
    pub generation: u64,
    pub budget_milli: u16,
    pub allowed_mask: CoreSet,
    pub assigned_cpu: usize,
    pub consumed_milli: u16,
    /// Both assigned and destination CPUs retain the complete reservation.
    pub migration_cpu: Option<usize>,
}

pub struct Cores {
    state: Snapshot,
    cpu_generations: [u64; MAX_CPUS],
    operations: u64,
    thread_generations: u64,
    collectors: [Option<Collector>; MAX_CPUS],
    pending: Option<Transition>,
    threads: [Option<Reservation>; MAX_THREADS],
    budget_window: u64,
    // Persists independently of thread lifetimes, affinity and ownership.
    window_spent: [u16; MAX_CPUS],
    last_normal_proposal_ms: Option<u64>,
}
impl Cores {
    pub fn new(online: CoreSet, control: CoreSet) -> Result<Self, Error> {
        if control.is_empty() || control.0 & !online.0 != 0 || online.0 & !control.0 == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            state: Snapshot {
                online,
                control,
                business: CoreSet(online.0 & !control.0),
                transition: CoreSet(0),
                quarantined: CoreSet(0),
                suspect: CoreSet(0),
                draining: CoreSet(0),
                core_generation: 1,
                ledger_generation: 1,
            },
            cpu_generations: [1; MAX_CPUS],
            operations: 0,
            thread_generations: 0,
            collectors: [None; MAX_CPUS],
            pending: None,
            threads: [None; MAX_THREADS],
            budget_window: 0,
            window_spent: [0; MAX_CPUS],
            last_normal_proposal_ms: None,
        })
    }
    pub const fn snapshot(&self) -> Snapshot {
        self.state
    }
    pub const fn permits(&self, cpu: usize, plane: Plane) -> bool {
        self.state.permits(cpu, plane)
    }
    fn cpu(&self, cpu: usize) -> Result<u64, Error> {
        if !self.state.online.contains(cpu) {
            return Err(Error::UnknownCpu);
        }
        Ok(1u64 << cpu)
    }
    fn next_core(&self) -> Result<u64, Error> {
        self.state
            .core_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)
    }
    fn next_ledger(&self) -> Result<u64, Error> {
        self.state
            .ledger_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)
    }
    fn active(&self, ticket: Ticket) -> Result<Transition, Error> {
        self.pending
            .filter(|p| p.ticket == ticket)
            .ok_or(Error::Stale)
    }
    fn target_valid(&self, target: u64) -> Result<(), Error> {
        self.target_valid_except(target, None)
    }
    fn target_valid_except(
        &self,
        target: u64,
        retiring: Option<ThreadHandle>,
    ) -> Result<(), Error> {
        let owned = self.state.control.0 | self.state.business.0 | self.state.transition.0;
        if target == 0 || target & !owned != 0 || owned & !target == 0 {
            return Err(Error::Invalid);
        }
        let bad = self.state.suspect.0;
        if target & bad != 0
            || self.state.control.0 & target & !bad == 0
            || self.state.business.0 & !target & !bad == 0
        {
            return Err(Error::Unhealthy);
        }
        for r in self.threads.iter().flatten() {
            if retiring.is_some_and(|h| h.thread_id == r.thread_id && h.generation == r.generation)
            {
                continue;
            }
            if target & (1 << r.assigned_cpu) != 0
                || r.migration_cpu.is_some_and(|cpu| target & (1 << cpu) != 0)
            {
                return Err(Error::Capacity);
            }
        }
        Ok(())
    }
    /// Admit one normal add/remove proposal. Successful admission consumes its
    /// 1000 ms slot even if later canceled. Failed validation consumes no slot.
    /// `now_ms` comes from the trusted monotonic boot clock; regression relative
    /// to the last admitted proposal is rejected. Urgent stop paths are separate.
    pub fn begin(
        &mut self,
        target: CoreSet,
        expected_core_gen: u64,
        expected_ledger_gen: u64,
        now_ms: u64,
    ) -> Result<Ticket, Error> {
        self.begin_inner(target, expected_core_gen, expected_ledger_gen, now_ms, None)
    }
    fn begin_inner(
        &mut self,
        target: CoreSet,
        expected_core_gen: u64,
        expected_ledger_gen: u64,
        now_ms: u64,
        retiring: Option<ThreadHandle>,
    ) -> Result<Ticket, Error> {
        if expected_core_gen != self.state.core_generation
            || expected_ledger_gen != self.state.ledger_generation
        {
            return Err(Error::Stale);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.target_valid_except(target.0, retiring)?;
        let moving = self.state.control.0 ^ target.0;
        if moving.count_ones() != 1 {
            return Err(Error::Invalid);
        }
        if moving & (self.state.suspect.0 | self.state.draining.0) != 0 {
            return Err(Error::Unhealthy);
        }
        if let Some(last) = self.last_normal_proposal_ms {
            let elapsed = now_ms.checked_sub(last).ok_or(Error::ClockRegression)?;
            if elapsed < NORMAL_PROPOSAL_INTERVAL_MS {
                return Err(Error::RateLimited);
            }
        }
        // Reserve enough generation space for begin, every ACK, and publish
        // (or cancellation). Never start a handoff that cannot finish.
        self.state
            .core_generation
            .checked_add(u64::from(moving.count_ones()) + 2)
            .ok_or(Error::Exhausted)?;
        let generation = self.next_core()?;
        let operation = self.operations.checked_add(1).ok_or(Error::Exhausted)?;
        let deadline = now_ms.checked_add(TRANSITION_MS).ok_or(Error::Exhausted)?;
        for cpu in 0..MAX_CPUS {
            if moving & (1 << cpu) != 0 {
                self.cpu_generations[cpu]
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?;
            }
        }
        let ticket = Ticket {
            sequence: operation,
        };
        for cpu in 0..MAX_CPUS {
            if moving & (1 << cpu) == 0 {
                continue;
            }
            self.cpu_generations[cpu] += 1;
            self.collectors[cpu] = Some(Collector {
                request: StopRequest {
                    operation,
                    cpu,
                    cpu_generation: self.cpu_generations[cpu],
                },
                purpose: StopPurpose::Transfer(ticket),
                completed: 0,
            });
        }
        self.operations = operation;
        self.last_normal_proposal_ms = Some(now_ms);
        self.state.draining.0 |= moving;
        self.state.core_generation = generation;
        self.pending = Some(Transition {
            ticket,
            target: target.0,
            moving,
            acked: 0,
            deadline,
        });
        Ok(ticket)
    }
    /// Start DRAIN for one explicitly retiring local best-effort workload.
    /// Its reservation remains charged and final PUBLISH still rejects it until
    /// trusted native execution/reference cessation permits `release`.
    /// Guaranteed/remote obligations must be migrated, never retired by this API.
    pub fn begin_retiring(
        &mut self,
        target: CoreSet,
        core: u64,
        ledger: u64,
        now: u64,
        thread: ThreadHandle,
    ) -> Result<Ticket, Error> {
        let reservation = self.reservation(thread)?;
        if reservation.migration_cpu.is_some()
            || self.state.control.0 & (1 << reservation.assigned_cpu) != 0
            || self.state.control.0 ^ target.0 != 1 << reservation.assigned_cpu
        {
            return Err(Error::Invalid);
        }
        self.begin_inner(target, core, ledger, now, Some(thread))
    }
    pub fn stop_request(&self, ticket: Ticket, cpu: usize) -> Result<StopRequest, Error> {
        let bit = self.cpu(cpu)?;
        let p = self.active(ticket)?;
        if p.moving & bit == 0 {
            return Err(Error::Invalid);
        }
        self.collectors[cpu]
            .map(|c| c.request)
            .ok_or(Error::Duplicate)
    }
    /// Trusted EL1 ingress only. The adapter validates source identity and boot,
    /// operation, CPU generation, and actual subsystem completion before calling.
    /// The opaque request is supplied with the original native drain request.
    pub fn record_stop_completion(
        &mut self,
        request: StopRequest,
        domain: StopDomain,
    ) -> Result<(), Error> {
        self.cpu(request.cpu)?;
        let collector = self.collectors[request.cpu].as_mut().ok_or(Error::Stale)?;
        if collector.request != request
            || self.cpu_generations[request.cpu] != request.cpu_generation
        {
            return Err(Error::Stale);
        }
        let bit = 1 << domain as u8;
        if collector.completed & bit != 0 {
            return Err(Error::Duplicate);
        }
        collector.completed |= bit;
        Ok(())
    }
    pub fn ack_quiescent(&mut self, ticket: Ticket, cpu: usize) -> Result<(), Error> {
        let bit = self.cpu(cpu)?;
        let mut p = self.active(ticket)?;
        if p.moving & bit == 0 {
            return Err(Error::Invalid);
        }
        if p.acked & bit != 0 {
            return Err(Error::Duplicate);
        }
        let collector = self.collectors[cpu].ok_or(Error::Stale)?;
        if !matches!(collector.purpose, StopPurpose::Transfer(t) if t == ticket) {
            return Err(Error::Stale);
        }
        let proof = collector.proof()?;
        let generation = self.next_core()?;
        self.apply_stop(proof);
        self.state.transition.0 |= bit;
        p.acked |= bit;
        self.pending = Some(p);
        self.state.core_generation = generation;
        Ok(())
    }
    fn apply_stop(&mut self, proof: StopProof) {
        let bit = 1 << proof.request.cpu;
        self.state.control.0 &= !bit;
        self.state.business.0 &= !bit;
        self.collectors[proof.request.cpu] = None;
    }
    pub fn publish(&mut self, ticket: Ticket, now_ms: u64) -> Result<(), Error> {
        let p = self.active(ticket)?;
        if now_ms >= p.deadline {
            self.expire(now_ms)?;
            return Err(Error::Expired);
        }
        if p.acked != p.moving {
            return Err(Error::MissingProof);
        }
        self.target_valid(p.target)?;
        let generation = self.next_core()?;
        self.state.control = CoreSet(p.target);
        self.state.business.0 = (self.state.business.0 | p.moving) & !p.target;
        self.state.transition.0 &= !p.moving;
        self.state.draining.0 &= !p.moving;
        self.state.core_generation = generation;
        self.pending = None;
        Ok(())
    }
    /// Cancel preserves C/B for every unproven CPU. Already proven T CPUs may
    /// safely enter Q; cancellation never resumes either group automatically.
    fn cancel_pending(&mut self) {
        if let Some(p) = self.pending.take() {
            self.state.quarantined.0 |= p.acked;
            self.state.transition.0 &= !p.acked;
            self.state.suspect.0 |= p.moving & !p.acked;
            self.state.draining.0 &= !p.moving;
            for cpu in 0..MAX_CPUS {
                if p.moving & (1 << cpu) != 0 {
                    self.collectors[cpu] = None;
                }
            }
        }
    }
    pub fn expire(&mut self, now_ms: u64) -> Result<bool, Error> {
        if self.pending.is_none_or(|p| now_ms < p.deadline) {
            return Ok(false);
        }
        let generation = self.next_core()?;
        self.cancel_pending();
        self.state.core_generation = generation;
        Ok(true)
    }
    /// Record suspicion and start a fresh, generation-bound stop collection.
    /// This preserves last ownership. A fault may leave zero healthy control or
    /// business CPUs; the module never invents a healthy CPU to hide that fact.
    pub fn suspect(&mut self, cpu: usize) -> Result<StopRequest, Error> {
        let bit = self.cpu(cpu)?;
        if (self.state.quarantined.0 | self.state.transition.0) & bit != 0 {
            return Err(Error::Invalid);
        }
        let generation = self.next_core()?;
        let cpu_generation = self.cpu_generations[cpu]
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let operation = self.operations.checked_add(1).ok_or(Error::Exhausted)?;
        self.cancel_pending();
        self.state.suspect.0 |= bit;
        self.state.core_generation = generation;
        self.cpu_generations[cpu] = cpu_generation;
        self.operations = operation;
        let request = StopRequest {
            operation,
            cpu,
            cpu_generation,
        };
        self.collectors[cpu] = Some(Collector {
            request,
            purpose: StopPurpose::Quarantine,
            completed: 0,
        });
        Ok(request)
    }
    pub fn confirm_stopped(&mut self, request: StopRequest) -> Result<(), Error> {
        let bit = self.cpu(request.cpu)?;
        let collector = self.collectors[request.cpu].ok_or(Error::Stale)?;
        if collector.request != request || !matches!(collector.purpose, StopPurpose::Quarantine) {
            return Err(Error::Stale);
        }
        let proof = collector.proof()?;
        let generation = self.next_core()?;
        self.apply_stop(proof);
        self.state.transition.0 &= !bit;
        self.state.quarantined.0 |= bit;
        self.state.suspect.0 &= !bit;
        self.state.draining.0 &= !bit;
        self.state.core_generation = generation;
        Ok(())
    }
    /// Two independent bounds: full reservations for future windows, and
    /// already-spent CPU time plus remaining obligations in the current window.
    /// Migration reserves each obligation at both source and destination.
    fn commitments(&self, cpu: usize) -> Result<(u16, u16), Error> {
        self.cpu(cpu)?;
        let mut full = 0;
        let mut current = self.window_spent[cpu];
        for r in self.threads.iter().flatten() {
            if r.assigned_cpu == cpu || r.migration_cpu == Some(cpu) {
                full += r.budget_milli;
                current += r.budget_milli - r.consumed_milli;
            }
        }
        Ok((full, current))
    }
    /// The larger of future full commitments and current spent-plus-remaining
    /// commitments. Retired/migrated CPU spending is retained until window advance.
    pub fn committed_milli(&self, cpu: usize) -> Result<u16, Error> {
        let (full, current) = self.commitments(cpu)?;
        Ok(full.max(current))
    }
    pub fn window_spent_milli(&self, cpu: usize) -> Result<u16, Error> {
        self.cpu(cpu)?;
        Ok(self.window_spent[cpu])
    }
    fn capacity_for(&self, cpu: usize, budget: u16, remaining: u16) -> Result<(), Error> {
        let (full, current) = self.commitments(cpu)?;
        if full + budget > CAPACITY_MILLI || current + remaining > CAPACITY_MILLI {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    fn thread_slot(&self, handle: ThreadHandle) -> Result<usize, Error> {
        self.threads
            .iter()
            .position(|r| {
                r.is_some_and(|r| {
                    r.thread_id == handle.thread_id && r.generation == handle.generation
                })
            })
            .ok_or(Error::Stale)
    }
    pub fn reservation(&self, handle: ThreadHandle) -> Result<Reservation, Error> {
        Ok(self.threads[self.thread_slot(handle)?].unwrap())
    }
    pub fn admit(&mut self, spec: ThreadSpec) -> Result<ThreadHandle, Error> {
        self.cpu(spec.assigned_cpu)?;
        if spec.budget_milli == 0
            || spec.budget_milli > CAPACITY_MILLI
            || spec.allowed_mask.0 & !self.state.online.0 != 0
        {
            return Err(Error::Invalid);
        }
        if !spec.allowed_mask.contains(spec.assigned_cpu) {
            return Err(Error::Affinity);
        }
        if !self.permits(spec.assigned_cpu, Plane::Business) {
            return Err(Error::Unhealthy);
        }
        if self
            .threads
            .iter()
            .flatten()
            .any(|r| r.thread_id == spec.thread_id)
        {
            return Err(Error::Duplicate);
        }
        let slot = self
            .threads
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        self.capacity_for(spec.assigned_cpu, spec.budget_milli, spec.budget_milli)?;
        let ledger_generation = self.next_ledger()?;
        let generation = self
            .thread_generations
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.threads[slot] = Some(Reservation {
            thread_id: spec.thread_id,
            generation,
            budget_milli: spec.budget_milli,
            allowed_mask: spec.allowed_mask,
            assigned_cpu: spec.assigned_cpu,
            consumed_milli: 0,
            migration_cpu: None,
        });
        self.thread_generations = generation;
        self.state.ledger_generation = ledger_generation;
        Ok(ThreadHandle {
            thread_id: spec.thread_id,
            generation,
        })
    }
    /// Trusted scheduler debits a bounded execution slice BEFORE dispatch.
    /// Amounts are milli-CPU in the aligned 100 ms window and must not round down.
    /// Spent/debited CPU time survives migration and release; an unused predebit
    /// may conservatively remain charged. This is not post-overrun enforcement.
    pub fn charge(&mut self, handle: ThreadHandle, amount: u16) -> Result<(), Error> {
        let slot = self.thread_slot(handle)?;
        let mut r = self.threads[slot].unwrap();
        if !self.permits(r.assigned_cpu, Plane::Business) {
            return Err(Error::Unhealthy);
        }
        let consumed = r.consumed_milli.checked_add(amount).ok_or(Error::Budget)?;
        if consumed > r.budget_milli {
            return Err(Error::Budget);
        }
        let cpu_spent = self.window_spent[r.assigned_cpu]
            .checked_add(amount)
            .ok_or(Error::Budget)?;
        if cpu_spent > CAPACITY_MILLI {
            return Err(Error::Budget);
        }
        let generation = self.next_ledger()?;
        self.window_spent[r.assigned_cpu] = cpu_spent;
        r.consumed_milli = consumed;
        self.threads[slot] = Some(r);
        self.state.ledger_generation = generation;
        Ok(())
    }
    pub fn begin_migration(
        &mut self,
        handle: ThreadHandle,
        destination: usize,
    ) -> Result<(), Error> {
        self.cpu(destination)?;
        let slot = self.thread_slot(handle)?;
        let mut r = self.threads[slot].unwrap();
        if r.migration_cpu.is_some() {
            return Err(Error::Busy);
        }
        if destination == r.assigned_cpu {
            return Err(Error::Invalid);
        }
        if !r.allowed_mask.contains(destination) {
            return Err(Error::Affinity);
        }
        if !self.permits(destination, Plane::Business)
            || !self.permits(r.assigned_cpu, Plane::Business)
        {
            return Err(Error::Unhealthy);
        }
        self.capacity_for(
            destination,
            r.budget_milli,
            r.budget_milli - r.consumed_milli,
        )?;
        let generation = self.next_ledger()?;
        r.migration_cpu = Some(destination);
        self.threads[slot] = Some(r);
        self.state.ledger_generation = generation;
        Ok(())
    }
    /// Trusted scheduler bookkeeping: call only after actual thread execution
    /// and references relinquish the source, under the unique dispatch-owner
    /// lock. This is NOT a thread-stop proof or a native migration implementation.
    pub fn commit_migration(&mut self, handle: ThreadHandle) -> Result<(), Error> {
        let slot = self.thread_slot(handle)?;
        let mut r = self.threads[slot].unwrap();
        let destination = r.migration_cpu.ok_or(Error::Invalid)?;
        if !self.permits(destination, Plane::Business)
            || !self.permits(r.assigned_cpu, Plane::Business)
        {
            return Err(Error::Unhealthy);
        }
        let generation = self.next_ledger()?;
        r.assigned_cpu = destination;
        r.migration_cpu = None;
        self.threads[slot] = Some(r);
        self.state.ledger_generation = generation;
        Ok(())
    }
    /// Cancellation is safe only while the scheduler has kept source ownership.
    pub fn cancel_migration(&mut self, handle: ThreadHandle) -> Result<(), Error> {
        let slot = self.thread_slot(handle)?;
        let mut r = self.threads[slot].unwrap();
        if r.migration_cpu.is_none() {
            return Err(Error::Invalid);
        }
        let generation = self.next_ledger()?;
        r.migration_cpu = None;
        self.threads[slot] = Some(r);
        self.state.ledger_generation = generation;
        Ok(())
    }
    /// Native scheduler may release only after the thread is stopped and its
    /// execution references retired. Core quarantine does not release records.
    pub fn release(&mut self, handle: ThreadHandle) -> Result<(), Error> {
        let slot = self.thread_slot(handle)?;
        let generation = self.next_ledger()?;
        self.threads[slot] = None;
        self.state.ledger_generation = generation;
        Ok(())
    }
    /// Trusted aligned index: floor(monotonic_ms / 100), using one boot origin
    /// across controller recovery. Never advance on scheduling/migration events.
    /// Skipped real windows are valid; equal or regressing indices are rejected.
    pub fn advance_window(&mut self, window: u64) -> Result<(), Error> {
        if window <= self.budget_window {
            return Err(Error::Stale);
        }
        let generation = self.next_ledger()?;
        for r in self.threads.iter_mut().flatten() {
            r.consumed_milli = 0;
        }
        self.window_spent = [0; MAX_CPUS];
        self.budget_window = window;
        self.state.ledger_generation = generation;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn begin_requires_generation_headroom_for_ack_and_completion() {
        let mut c = Cores::new(CoreSet(15), CoreSet(1)).unwrap();
        c.state.core_generation = u64::MAX - 1;
        let before = c.snapshot();
        assert_eq!(
            c.begin(
                CoreSet(3),
                before.core_generation,
                before.ledger_generation,
                0
            ),
            Err(Error::Exhausted)
        );
        assert_eq!(c.snapshot(), before);
        c.state.core_generation = u64::MAX - 3;
        let s = c.snapshot();
        let ticket = c
            .begin(CoreSet(3), s.core_generation, s.ledger_generation, 0)
            .unwrap();
        let request = c.stop_request(ticket, 1).unwrap();
        for domain in StopDomain::ALL {
            c.record_stop_completion(request, domain).unwrap();
        }
        c.ack_quiescent(ticket, 1).unwrap();
        c.publish(ticket, 1).unwrap();
        assert_eq!(c.snapshot().core_generation, u64::MAX);
        let stable = c.snapshot();
        assert_eq!(c.suspect(1), Err(Error::Exhausted));
        assert_eq!(c.snapshot(), stable);
    }
    #[test]
    fn generation_exhaustion_never_wraps_or_partially_mutates() {
        for which in 0..3 {
            let mut c = Cores::new(CoreSet(15), CoreSet(1)).unwrap();
            match which {
                0 => c.state.core_generation = u64::MAX,
                1 => c.operations = u64::MAX,
                _ => c.cpu_generations[1] = u64::MAX,
            }
            let s = c.snapshot();
            assert_eq!(
                c.begin(CoreSet(3), s.core_generation, s.ledger_generation, 0),
                Err(Error::Exhausted)
            );
            assert_eq!(c.snapshot(), s);
            assert!(c.pending.is_none());
        }
        let mut c = Cores::new(CoreSet(15), CoreSet(1)).unwrap();
        c.state.ledger_generation = u64::MAX;
        let s = c.snapshot();
        assert_eq!(
            c.admit(ThreadSpec {
                thread_id: 1,
                budget_milli: 1,
                allowed_mask: CoreSet(2),
                assigned_cpu: 1
            }),
            Err(Error::Exhausted)
        );
        assert_eq!(c.snapshot(), s);
        assert_eq!(c.committed_milli(1), Ok(0));
    }
}

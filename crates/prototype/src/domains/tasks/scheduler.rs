use super::{MAX_GROUPS, MAX_THREADS, UNSET, valid_key};
use crate::domains::{Action, Error, ObjectKey, PolicyStamp, WINDOW_NS};

pub const CPU_BUDGET_NS: u64 = WINDOW_NS * 9 / 10;
pub const CONTROL_BUDGET_NS: u64 = WINDOW_NS * 7 / 10;
pub const FAIR_WAIT_NS: u64 = WINDOW_NS;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuLayout {
    pub business_mask: u64,
    pub healthy_mask: u64,
    pub generation: u64,
}
impl CpuLayout {
    fn permits(self, cpu: usize) -> bool {
        cpu < 64
            && self.generation != 0
            && self.business_mask & self.healthy_mask & (1u64 << cpu) != 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadSpec {
    pub key: ObjectKey,
    pub group: ObjectKey,
    pub cpu: u16,
    pub allowed_mask: u64,
    pub minimum_ns: u64,
    pub budget_ns: u64,
}
/// Proof that admission has inserted the exact thread and its budget promise.
/// The owner keeps its scheduler/resource gate held while constructing the
/// corresponding task, and removes this reservation if construction fails.
#[derive(Debug, PartialEq, Eq)]
pub struct ThreadReservation {
    key: ObjectKey,
    cpu: u16,
    core_generation: u64,
    admitted_ns: u64,
}
impl ThreadReservation {
    pub fn key(&self) -> ObjectKey {
        self.key
    }
    pub fn cpu(&self) -> u16 {
        self.cpu
    }
    pub fn core_generation(&self) -> u64 {
        self.core_generation
    }
    pub fn admitted_ns(&self) -> u64 {
        self.admitted_ns
    }
}
enum Admission {
    Reserved(ThreadReservation),
    Deferred(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Runnable,
    Blocked,
    Exited,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchReason {
    Minimum,
    Weighted,
    FairRecovery,
    Service,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub sequence: u64,
    pub thread: ObjectKey,
    pub group: ObjectKey,
    pub cpu: u16,
    pub core_generation: u64,
    pub window: u64,
    pub started_ns: u64,
    pub reserved_ns: u64,
    pub reason: DispatchReason,
    pub waited_ns: u64,
    pub policy_version: u64,
}
/// A real reservation on one current control CPU. It is independent of the
/// business thread table and survives ownership changes until exact settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlCredit {
    pub sequence: u64,
    pub cpu: u16,
    pub core_generation: u64,
    pub window: u64,
    pub started_ns: u64,
    pub reserved_ns: u64,
    pub control_total_ns: u64,
    pub physical_total_ns: u64,
}
#[derive(Clone, Copy)]
struct Group {
    key: ObjectKey,
    weight: u16,
    stamp: PolicyStamp,
    applied_version: u64,
}
#[derive(Clone, Copy)]
struct Thread {
    spec: ThreadSpec,
    group: usize,
    state: RunState,
    ready_since: u64,
    spent: u64,
    carry_window: u64,
    carry_spent: u64,
    actual: u64,
    last_dispatch: u64,
}
#[derive(Clone, Copy)]
struct Cpu {
    window: u64,
    spent: u64,
    groups: [u64; MAX_GROUPS],
    active: Option<Dispatch>,
    control: Option<ControlCredit>,
    control_spent: u64,
    carry_window: u64,
    carry_spent: u64,
    carry_control_spent: u64,
    carry_groups: [u64; MAX_GROUPS],
    quarantine_generation: u64,
    recovery_after: u64,
}
impl Cpu {
    const EMPTY: Self = Self {
        window: u64::MAX,
        spent: 0,
        groups: [0; MAX_GROUPS],
        active: None,
        control: None,
        control_spent: 0,
        carry_window: u64::MAX,
        carry_spent: 0,
        carry_control_spent: 0,
        carry_groups: [0; MAX_GROUPS],
        quarantine_generation: 0,
        recovery_after: 0,
    };
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulerStats {
    pub runnable: u16,
    pub dispatches: u64,
    pub fair_recoveries: u64,
    pub actual_ns: u64,
    pub overruns: u64,
    pub quarantine_mask: u64,
    pub maximum_wait_ns: u64,
}
pub struct Scheduler {
    groups: [Option<Group>; MAX_GROUPS],
    threads: [Option<Thread>; MAX_THREADS],
    cpus: [Cpu; 64],
    sequence: u64,
    last_now: u64,
    stats: SchedulerStats,
}
impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}
impl Scheduler {
    pub const fn new() -> Self {
        Self {
            groups: [None; MAX_GROUPS],
            threads: [None; MAX_THREADS],
            cpus: [Cpu::EMPTY; 64],
            sequence: 0,
            last_now: 0,
            stats: SchedulerStats {
                runnable: 0,
                dispatches: 0,
                fair_recoveries: 0,
                actual_ns: 0,
                overruns: 0,
                quarantine_mask: 0,
                maximum_wait_ns: 0,
            },
        }
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Stale);
        }
        self.last_now = now;
        Ok(())
    }
    fn group(&self, key: ObjectKey) -> Result<usize, Error> {
        self.groups
            .iter()
            .position(|g| g.is_some_and(|g| g.key == key))
            .ok_or(Error::Stale)
    }
    fn thread(&self, key: ObjectKey) -> Result<usize, Error> {
        self.threads
            .iter()
            .position(|t| t.is_some_and(|t| t.spec.key == key))
            .ok_or(Error::Stale)
    }
    fn roll(&mut self, cpu: usize, now: u64) -> Result<(), Error> {
        let window = now / WINDOW_NS;
        if self.cpus[cpu].window == window {
            let c = &mut self.cpus[cpu];
            if c.carry_window == window {
                c.spent = c.spent.saturating_add(c.carry_spent);
                c.control_spent = c.control_spent.saturating_add(c.carry_control_spent);
                for (spent, carry) in c.groups.iter_mut().zip(c.carry_groups) {
                    *spent = spent.saturating_add(carry);
                }
                c.carry_window = u64::MAX;
                c.carry_spent = 0;
                c.carry_control_spent = 0;
                c.carry_groups = [0; MAX_GROUPS];
            }
            for t in self
                .threads
                .iter_mut()
                .flatten()
                .filter(|t| usize::from(t.spec.cpu) == cpu && t.carry_window == window)
            {
                t.spent = t.spent.saturating_add(t.carry_spent);
                t.carry_window = u64::MAX;
                t.carry_spent = 0;
            }
            return Ok(());
        }
        if self.cpus[cpu].active.is_some()
            || self.cpus[cpu].control.is_some()
            || self.cpus.iter().any(|c| {
                c.active.is_some_and(|d| {
                    self.threads
                        .iter()
                        .flatten()
                        .any(|t| t.spec.key == d.thread && usize::from(t.spec.cpu) == cpu)
                })
            })
        {
            return Err(Error::Busy);
        }
        let c = &mut self.cpus[cpu];
        c.window = window;
        if c.carry_window == window {
            c.spent = c.carry_spent;
            c.control_spent = c.carry_control_spent;
            c.groups = c.carry_groups;
        } else {
            c.spent = 0;
            c.control_spent = 0;
            c.groups = [0; MAX_GROUPS];
        }
        if c.carry_window <= window {
            c.carry_window = u64::MAX;
            c.carry_spent = 0;
            c.carry_control_spent = 0;
            c.carry_groups = [0; MAX_GROUPS];
        }
        for t in self
            .threads
            .iter_mut()
            .flatten()
            .filter(|t| usize::from(t.spec.cpu) == cpu)
        {
            t.spent = if t.carry_window == window {
                t.carry_spent
            } else {
                0
            };
            if t.carry_window <= window {
                t.carry_window = u64::MAX;
                t.carry_spent = 0;
            }
        }
        Ok(())
    }
    /// Retain a late receipt in both ledgers. The grant window already paid
    /// for the work; charging the completion window as well is deliberately
    /// conservative and prevents host scheduling latency from releasing new
    /// guest capacity.
    fn carry_business_completion(
        &mut self,
        cpu: usize,
        thread: usize,
        actual_ns: u64,
        finished_ns: u64,
    ) -> Result<(), Error> {
        let window = finished_ns / WINDOW_NS;
        let (source, group, minimum_ns, budget_ns, old_thread_carry, new_thread_carry) = {
            let t = self.threads[thread].as_mut().ok_or(Error::Stale)?;
            if t.carry_window != window {
                t.carry_window = window;
                t.carry_spent = 0;
            }
            let old = t.carry_spent;
            t.carry_spent = t.carry_spent.saturating_add(actual_ns);
            (
                usize::from(t.spec.cpu),
                t.group,
                t.spec.minimum_ns,
                t.spec.budget_ns,
                old,
                t.carry_spent,
            )
        };
        let extra = new_thread_carry
            .saturating_sub(minimum_ns)
            .saturating_sub(old_thread_carry.saturating_sub(minimum_ns));
        let c = &mut self.cpus[cpu];
        if c.carry_window != window {
            c.carry_window = window;
            c.carry_spent = 0;
            c.carry_control_spent = 0;
            c.carry_groups = [0; MAX_GROUPS];
        }
        c.carry_spent = c.carry_spent.saturating_add(actual_ns);
        c.carry_groups[group] = c.carry_groups[group].saturating_add(extra);
        if c.carry_spent > CPU_BUDGET_NS || new_thread_carry > budget_ns {
            return Err(Error::Budget);
        }
        // Applying may be temporarily blocked by another old-window service
        // receipt. In that case the tagged carry remains pending for the next
        // admissible roll and read-only usage still exposes it.
        let _ = self.roll(cpu, finished_ns);
        if source != cpu {
            let _ = self.roll(source, finished_ns);
        }
        Ok(())
    }

    fn carry_control_completion(
        &mut self,
        cpu: usize,
        actual_ns: u64,
        finished_ns: u64,
    ) -> Result<(), Error> {
        let window = finished_ns / WINDOW_NS;
        let c = &mut self.cpus[cpu];
        if c.carry_window != window {
            c.carry_window = window;
            c.carry_spent = 0;
            c.carry_control_spent = 0;
            c.carry_groups = [0; MAX_GROUPS];
        }
        c.carry_spent = c.carry_spent.saturating_add(actual_ns);
        c.carry_control_spent = c.carry_control_spent.saturating_add(actual_ns);
        if c.carry_spent > CPU_BUDGET_NS || c.carry_control_spent > CONTROL_BUDGET_NS {
            return Err(Error::Budget);
        }
        let _ = self.roll(cpu, finished_ns);
        Ok(())
    }
    pub fn register_group(&mut self, key: ObjectKey) -> Result<(), Error> {
        valid_key(key)?;
        if self.groups.iter().flatten().any(|g| g.key.id == key.id) {
            return Err(Error::Exists);
        }
        let slot = self
            .groups
            .iter_mut()
            .find(|g| g.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(Group {
            key,
            weight: 1,
            stamp: UNSET,
            applied_version: 0,
        });
        Ok(())
    }
    pub fn install_weight(
        &mut self,
        key: ObjectKey,
        weight: u16,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        self.time(now)?;
        Action::CpuWeight(weight).validate()?;
        let i = self.group(key)?;
        let g = self.groups[i].as_mut().ok_or(Error::Stale)?;
        g.stamp.accepts(stamp, now)?;
        if stamp.version == g.stamp.version && weight != g.weight {
            return Err(Error::Conflict);
        }
        g.stamp = stamp;
        g.weight = weight;
        Ok(())
    }
    /// Reserve actual scheduling capacity before the owner acquires task,
    /// memory, or capability custody. `None` leaves no thread reservation and
    /// permits the same queued request to wait within its original deadline.
    pub fn prepare_admission(
        &mut self,
        spec: ThreadSpec,
        layout: CpuLayout,
        now: u64,
    ) -> Result<Option<ThreadReservation>, Error> {
        match self.admit_inner(spec, layout, now)? {
            Admission::Reserved(reservation) => Ok(Some(reservation)),
            Admission::Deferred(_) => Ok(None),
        }
    }
    pub fn admit(&mut self, spec: ThreadSpec, layout: CpuLayout, now: u64) -> Result<(), Error> {
        match self.admit_inner(spec, layout, now)? {
            Admission::Reserved(_) => Ok(()),
            Admission::Deferred(error) => Err(error),
        }
    }
    fn admit_inner(
        &mut self,
        spec: ThreadSpec,
        layout: CpuLayout,
        now: u64,
    ) -> Result<Admission, Error> {
        self.time(now)?;
        valid_key(spec.key)?;
        let group = self.group(spec.group)?;
        let cpu = usize::from(spec.cpu);
        if !layout.permits(cpu) || spec.allowed_mask & (1u64 << cpu) == 0 {
            return Err(Error::Auth);
        }
        // Permanent request/identity failures cannot be hidden by temporary
        // pressure on an otherwise usable CPU.
        if spec.budget_ns == 0 || spec.budget_ns > CPU_BUDGET_NS || spec.minimum_ns > spec.budget_ns
        {
            return Err(Error::Budget);
        }
        if self
            .threads
            .iter()
            .flatten()
            .any(|t| t.spec.key.id == spec.key.id)
        {
            return Err(Error::Exists);
        }
        if self.cpus[cpu].quarantine_generation != 0 {
            return Err(Error::NotReady);
        }
        if self.cpus[cpu].control.is_some() {
            return Ok(Admission::Deferred(Error::Busy));
        }
        match self.roll(cpu, now) {
            Ok(()) => {}
            // An outstanding exact credit must be settled by its actual owner.
            Err(Error::Busy) => return Ok(Admission::Deferred(Error::Busy)),
            Err(error) => return Err(error),
        }
        if self.committed_ns(cpu) > CPU_BUDGET_NS - spec.budget_ns {
            // Live thread promises are released only by real removal. Unlike
            // the retained spawn receipt table, this occupancy can clear.
            return Ok(Admission::Deferred(Error::Capacity));
        }
        let remaining: u64 = self
            .threads
            .iter()
            .flatten()
            .filter(|t| t.spec.cpu == spec.cpu)
            .map(|t| t.spec.budget_ns.saturating_sub(t.spent))
            .sum();
        if self.cpus[cpu]
            .spent
            .saturating_add(remaining)
            .saturating_add(spec.budget_ns)
            > CPU_BUDGET_NS
        {
            return Ok(Admission::Deferred(Error::Budget));
        }
        let minimum: u64 = self
            .threads
            .iter()
            .flatten()
            .filter(|t| t.spec.cpu == spec.cpu && t.state == RunState::Runnable)
            .map(|t| t.spec.minimum_ns.saturating_sub(t.spent))
            .sum();
        if minimum.saturating_add(spec.minimum_ns) > WINDOW_NS - now % WINDOW_NS {
            return Ok(Admission::Deferred(Error::Budget));
        }
        let Some(slot) = self.threads.iter_mut().find(|t| t.is_none()) else {
            return Ok(Admission::Deferred(Error::Capacity));
        };
        *slot = Some(Thread {
            spec,
            group,
            state: RunState::Runnable,
            ready_since: now,
            spent: 0,
            carry_window: u64::MAX,
            carry_spent: 0,
            actual: 0,
            last_dispatch: 0,
        });
        Ok(Admission::Reserved(ThreadReservation {
            key: spec.key,
            cpu: spec.cpu,
            core_generation: layout.generation,
            admitted_ns: now,
        }))
    }
    pub fn set_runnable(&mut self, key: ObjectKey, ready: bool, now: u64) -> Result<(), Error> {
        self.time(now)?;
        let i = self.thread(key)?;
        let t = self.threads[i].as_mut().ok_or(Error::Stale)?;
        if self
            .cpus
            .iter()
            .any(|c| c.active.is_some_and(|d| d.thread == key))
        {
            return Err(Error::Busy);
        }
        if t.state == RunState::Exited {
            return Err(Error::Stale);
        }
        if ready && t.state != RunState::Runnable {
            t.ready_since = now;
        }
        t.state = if ready {
            RunState::Runnable
        } else {
            RunState::Blocked
        };
        Ok(())
    }
    pub fn remove(&mut self, key: ObjectKey) -> Result<(), Error> {
        let i = self.thread(key)?;
        if self
            .cpus
            .iter()
            .any(|c| c.active.is_some_and(|d| d.thread == key))
        {
            return Err(Error::Busy);
        }
        // CPU/group spending survives slot reuse. Exit never creates free credit.
        self.threads[i] = None;
        Ok(())
    }
    pub fn dispatch(
        &mut self,
        cpu: usize,
        layout: CpuLayout,
        now: u64,
        maximum_ns: u64,
    ) -> Result<Option<Dispatch>, Error> {
        self.dispatch_with_window_headroom(cpu, layout, now, maximum_ns, 0)
    }
    /// Dispatch only when the current aligned window still contains the
    /// caller's complete wall-time execution envelope. Deferral leaves no
    /// reservation behind; CPU-time credit is still bounded independently by
    /// `maximum_ns` and the admitted thread budget.
    pub fn dispatch_with_window_headroom(
        &mut self,
        cpu: usize,
        layout: CpuLayout,
        now: u64,
        maximum_ns: u64,
        headroom_ns: u64,
    ) -> Result<Option<Dispatch>, Error> {
        self.time(now)?;
        if !layout.permits(cpu) {
            return Err(Error::Auth);
        }
        if maximum_ns == 0 || headroom_ns > WINDOW_NS {
            return Err(Error::Range);
        }
        if self.cpus[cpu].quarantine_generation != 0 {
            return Err(Error::NotReady);
        }
        if self.cpus[cpu].active.is_some() || self.cpus[cpu].control.is_some() {
            return Err(Error::Busy);
        }
        self.roll(cpu, now)?;
        if WINDOW_NS - now % WINDOW_NS < headroom_ns {
            return Ok(None);
        }
        if self.cpus[cpu].spent >= CPU_BUDGET_NS {
            return Ok(None);
        }
        let eligible = |t: &&Thread| {
            usize::from(t.spec.cpu) == cpu
                && t.state == RunState::Runnable
                && t.spent < t.spec.budget_ns
        };
        let minimum = self
            .threads
            .iter()
            .flatten()
            .filter(eligible)
            .any(|t| t.spent < t.spec.minimum_ns);
        let guard = !minimum
            && self
                .threads
                .iter()
                .flatten()
                .filter(eligible)
                .any(|t| now.saturating_sub(t.ready_since) >= FAIR_WAIT_NS);
        let mut chosen: Option<usize> = None;
        for (i, t) in self
            .threads
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.as_ref().map(|t| (i, t)))
        {
            if !eligible(&t)
                || (minimum && t.spent >= t.spec.minimum_ns)
                || (guard && now.saturating_sub(t.ready_since) < FAIR_WAIT_NS)
            {
                continue;
            }
            let Some(previous) = chosen else {
                chosen = Some(i);
                continue;
            };
            let p = self.threads[previous].as_ref().ok_or(Error::Stale)?;
            let prefer = if minimum || guard {
                (t.ready_since, t.last_dispatch, t.spec.key.id)
                    < (p.ready_since, p.last_dispatch, p.spec.key.id)
            } else {
                let weight = |index: usize| {
                    self.groups[index].map_or(1, |g| if g.stamp.live(now) { g.weight } else { 1 })
                };
                let left = u128::from(self.cpus[cpu].groups[t.group]) * u128::from(weight(p.group));
                let right =
                    u128::from(self.cpus[cpu].groups[p.group]) * u128::from(weight(t.group));
                (left, t.last_dispatch, t.spec.key.id) < (right, p.last_dispatch, p.spec.key.id)
            };
            if prefer {
                chosen = Some(i);
            }
        }
        let Some(i) = chosen else {
            return Ok(None);
        };
        let t = self.threads[i].as_mut().ok_or(Error::Stale)?;
        let end = (now / WINDOW_NS)
            .checked_add(1)
            .and_then(|w| w.checked_mul(WINDOW_NS))
            .ok_or(Error::Overflow)?;
        let mut reserved = maximum_ns
            .min(end - now)
            .min(CPU_BUDGET_NS - self.cpus[cpu].spent)
            .min(t.spec.budget_ns - t.spent);
        if minimum {
            reserved = reserved.min(t.spec.minimum_ns - t.spent);
        }
        if reserved == 0 {
            return Ok(None);
        }
        let sequence = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        let dispatch = Dispatch {
            sequence,
            thread: t.spec.key,
            group: t.spec.group,
            cpu: t.spec.cpu,
            core_generation: layout.generation,
            window: now / WINDOW_NS,
            started_ns: now,
            reserved_ns: reserved,
            reason: if minimum {
                DispatchReason::Minimum
            } else if guard {
                DispatchReason::FairRecovery
            } else {
                DispatchReason::Weighted
            },
            waited_ns: now.saturating_sub(t.ready_since),
            policy_version: self.groups[t.group]
                .filter(|g| g.stamp.live(now))
                .map_or(0, |g| g.stamp.version),
        };
        self.stats.maximum_wait_ns = self.stats.maximum_wait_ns.max(dispatch.waited_ns);
        let old_extra = t.spent.saturating_sub(t.spec.minimum_ns);
        t.spent += reserved;
        t.last_dispatch = sequence;
        self.cpus[cpu].spent += reserved;
        self.cpus[cpu].groups[t.group] += t.spent.saturating_sub(t.spec.minimum_ns) - old_extra;
        self.cpus[cpu].active = Some(dispatch);
        self.sequence = sequence;
        self.stats.dispatches = self.stats.dispatches.saturating_add(1);
        if guard {
            self.stats.fair_recoveries = self.stats.fair_recoveries.saturating_add(1);
        }
        Ok(Some(dispatch))
    }
    /// A trusted kernel service may execute a blocked caller's syscall on a
    /// broker CPU without migrating its user context or lending its affinity.
    /// Actual time is charged once to that physical CPU and once to the caller's
    /// thread budget. Existing broker-thread promises retain their full credit.
    pub fn dispatch_service(
        &mut self,
        caller: ObjectKey,
        cpu: usize,
        layout: CpuLayout,
        now: u64,
        maximum_ns: u64,
    ) -> Result<Option<Dispatch>, Error> {
        self.time(now)?;
        let i = self.thread(caller)?;
        let t = self.threads[i].ok_or(Error::Stale)?;
        let source = usize::from(t.spec.cpu);
        if !layout.permits(cpu) || !layout.permits(source) {
            return Err(Error::Auth);
        }
        if t.state != RunState::Blocked {
            return Err(Error::Conflict);
        }
        if maximum_ns == 0 {
            return Err(Error::Range);
        }
        if self.cpus[cpu].quarantine_generation != 0 {
            return Err(Error::NotReady);
        }
        if self.cpus[cpu].active.is_some()
            || self.cpus[cpu].control.is_some()
            || self
                .cpus
                .iter()
                .any(|c| c.active.is_some_and(|d| d.thread == caller))
        {
            return Err(Error::Busy);
        }
        self.roll(source, now)?;
        self.roll(cpu, now)?;
        let protected: u64 = self
            .threads
            .iter()
            .flatten()
            .filter(|t| usize::from(t.spec.cpu) == cpu && t.spec.key != caller)
            .map(|t| t.spec.budget_ns.saturating_sub(t.spent))
            .sum();
        let physical = CPU_BUDGET_NS
            .saturating_sub(self.cpus[cpu].spent)
            .saturating_sub(protected);
        let t = self.threads[i].as_mut().ok_or(Error::Stale)?;
        let end = (now / WINDOW_NS)
            .checked_add(1)
            .and_then(|w| w.checked_mul(WINDOW_NS))
            .ok_or(Error::Overflow)?;
        let reserved = maximum_ns
            .min(physical)
            .min(end - now)
            .min(t.spec.budget_ns.saturating_sub(t.spent));
        if reserved == 0 {
            return Ok(None);
        }
        let sequence = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        let d = Dispatch {
            sequence,
            thread: caller,
            group: t.spec.group,
            cpu: cpu as u16,
            core_generation: layout.generation,
            window: now / WINDOW_NS,
            started_ns: now,
            reserved_ns: reserved,
            reason: DispatchReason::Service,
            waited_ns: 0,
            // Explicit syscall service did not choose an AI group weight.
            policy_version: 0,
        };
        let extra = t.spent.saturating_sub(t.spec.minimum_ns);
        t.spent += reserved;
        t.last_dispatch = sequence;
        self.cpus[cpu].spent += reserved;
        self.cpus[cpu].groups[t.group] += t.spent.saturating_sub(t.spec.minimum_ns) - extra;
        self.cpus[cpu].active = Some(d);
        self.sequence = sequence;
        self.stats.dispatches = self.stats.dispatches.saturating_add(1);
        Ok(Some(d))
    }
    /// Reserve a complete non-preemptible service segment. A partial tail is
    /// refunded before returning and never authorizes execution of the body.
    pub fn dispatch_service_exact(
        &mut self,
        caller: ObjectKey,
        cpu: usize,
        layout: CpuLayout,
        now: u64,
        required_ns: u64,
    ) -> Result<Option<Dispatch>, Error> {
        let i = self.thread(caller)?;
        if self.threads[i].ok_or(Error::Stale)?.spec.budget_ns < required_ns {
            return Err(Error::Budget);
        }
        let Some(d) = self.dispatch_service(caller, cpu, layout, now, required_ns)? else {
            return Ok(None);
        };
        if d.reserved_ns != required_ns {
            self.complete(d, 0, RunState::Blocked, now)?;
            return Ok(None);
        }
        Ok(Some(d))
    }
    pub fn resize_dispatch(&mut self, d: Dispatch, reserved_ns: u64) -> Result<Dispatch, Error> {
        let cpu = usize::from(d.cpu);
        if cpu >= 64 || self.cpus[cpu].active != Some(d) {
            return Err(Error::Stale);
        }
        if reserved_ns == 0 {
            return Err(Error::Range);
        }
        let i = self.thread(d.thread)?;
        let protected = if d.reason == DispatchReason::Service {
            self.threads
                .iter()
                .flatten()
                .filter(|t| usize::from(t.spec.cpu) == cpu && t.spec.key != d.thread)
                .map(|t| t.spec.budget_ns.saturating_sub(t.spent))
                .sum::<u64>()
        } else {
            0
        };
        let t = self.threads[i].as_mut().ok_or(Error::Stale)?;
        let base = t.spent.checked_sub(d.reserved_ns).ok_or(Error::Conflict)?;
        let cpu_base = self.cpus[cpu]
            .spent
            .checked_sub(d.reserved_ns)
            .ok_or(Error::Conflict)?;
        let end = d
            .window
            .checked_add(1)
            .and_then(|w| w.checked_mul(WINDOW_NS))
            .ok_or(Error::Overflow)?;
        if reserved_ns > t.spec.budget_ns.saturating_sub(base)
            || reserved_ns
                > CPU_BUDGET_NS
                    .saturating_sub(cpu_base)
                    .saturating_sub(protected)
            || reserved_ns > end.saturating_sub(d.started_ns)
        {
            return Err(Error::Budget);
        }
        let extra = t
            .spent
            .saturating_sub(t.spec.minimum_ns)
            .saturating_sub(base.saturating_sub(t.spec.minimum_ns));
        t.spent = base + reserved_ns;
        self.cpus[cpu].spent = cpu_base + reserved_ns;
        self.cpus[cpu].groups[t.group] = self.cpus[cpu].groups[t.group]
            .saturating_sub(extra)
            .saturating_add(
                t.spent
                    .saturating_sub(t.spec.minimum_ns)
                    .saturating_sub(base.saturating_sub(t.spec.minimum_ns)),
            );
        let next = Dispatch { reserved_ns, ..d };
        self.cpus[cpu].active = Some(next);
        Ok(next)
    }
    /// Refund a dispatch that was selected but never entered execution. This
    /// is distinct from completion: a vCPU may be descheduled after selection,
    /// so an expired, wholly unused credit must not be reported as executed
    /// across its aligned window. The caller must still own the exact active
    /// dispatch and prove that no task body ran before using this operation.
    pub fn cancel_unstarted(&mut self, d: Dispatch, now: u64) -> Result<(), Error> {
        self.time(now)?;
        let cpu = usize::from(d.cpu);
        if cpu >= 64 || self.cpus[cpu].active != Some(d) {
            return Err(Error::Stale);
        }
        if now < d.started_ns {
            return Err(Error::Range);
        }
        let i = self.thread(d.thread)?;
        let t = self.threads[i].as_mut().ok_or(Error::Stale)?;
        let base = t.spent.checked_sub(d.reserved_ns).ok_or(Error::Conflict)?;
        let cpu_base = self.cpus[cpu]
            .spent
            .checked_sub(d.reserved_ns)
            .ok_or(Error::Conflict)?;
        let extra = t
            .spent
            .saturating_sub(t.spec.minimum_ns)
            .saturating_sub(base.saturating_sub(t.spec.minimum_ns));
        t.spent = base;
        self.cpus[cpu].spent = cpu_base;
        self.cpus[cpu].groups[t.group] = self.cpus[cpu].groups[t.group].saturating_sub(extra);
        self.cpus[cpu].active = None;
        Ok(())
    }
    pub fn complete(
        &mut self,
        d: Dispatch,
        actual_ns: u64,
        state: RunState,
        finished_ns: u64,
    ) -> Result<(), Error> {
        let cpu = usize::from(d.cpu);
        if cpu >= 64 || self.cpus[cpu].active != Some(d) {
            return Err(Error::Stale);
        }
        if finished_ns < d.started_ns || actual_ns > finished_ns - d.started_ns {
            return Err(Error::Range);
        }
        let i = self.thread(d.thread)?;
        let t = self.threads[i].as_mut().ok_or(Error::Stale)?;
        let end = d
            .window
            .checked_add(1)
            .and_then(|w| w.checked_mul(WINDOW_NS))
            .ok_or(Error::Overflow)?;
        self.last_now = self.last_now.max(finished_ns);
        let base = t.spent.saturating_sub(d.reserved_ns);
        let extra = t
            .spent
            .saturating_sub(t.spec.minimum_ns)
            .saturating_sub(base.saturating_sub(t.spec.minimum_ns));
        t.spent = t
            .spent
            .saturating_sub(d.reserved_ns)
            .saturating_add(actual_ns);
        self.cpus[cpu].spent = self.cpus[cpu]
            .spent
            .saturating_sub(d.reserved_ns)
            .saturating_add(actual_ns);
        self.cpus[cpu].groups[t.group] = self.cpus[cpu].groups[t.group]
            .saturating_sub(extra)
            .saturating_add(
                t.spent
                    .saturating_sub(t.spec.minimum_ns)
                    .saturating_sub(base.saturating_sub(t.spec.minimum_ns)),
            );
        t.actual = t.actual.saturating_add(actual_ns);
        t.state = state;
        t.ready_since = finished_ns;
        self.cpus[cpu].active = None;
        self.stats.actual_ns = self.stats.actual_ns.saturating_add(actual_ns);
        if actual_ns > d.reserved_ns {
            self.cpus[cpu].quarantine_generation = d.core_generation;
            self.cpus[cpu].recovery_after =
                if finished_ns > end && !finished_ns.is_multiple_of(WINDOW_NS) {
                    finished_ns.saturating_add(WINDOW_NS - finished_ns % WINDOW_NS)
                } else {
                    finished_ns
                };
            self.stats.overruns = self.stats.overruns.saturating_add(1);
            self.stats.quarantine_mask |= 1u64 << cpu;
            return Err(Error::Budget);
        }
        if actual_ns != 0 {
            let g = self.groups[t.group].as_mut().ok_or(Error::Stale)?;
            g.applied_version = g.applied_version.max(d.policy_version);
        }
        if finished_ns > end
            && self
                .carry_business_completion(cpu, i, actual_ns, finished_ns)
                .is_err()
        {
            self.cpus[cpu].quarantine_generation = d.core_generation;
            self.cpus[cpu].recovery_after = if finished_ns.is_multiple_of(WINDOW_NS) {
                finished_ns
            } else {
                finished_ns.saturating_add(WINDOW_NS - finished_ns % WINDOW_NS)
            };
            self.stats.overruns = self.stats.overruns.saturating_add(1);
            self.stats.quarantine_mask |= 1u64 << cpu;
            return Err(Error::Budget);
        }
        Ok(())
    }
    pub fn recover_cpu(&mut self, cpu: usize, layout: CpuLayout, now: u64) -> Result<(), Error> {
        self.time(now)?;
        if !layout.permits(cpu) {
            return Err(Error::Auth);
        }
        let c = &self.cpus[cpu];
        if c.active.is_some() || c.control.is_some() {
            return Err(Error::Busy);
        }
        if c.quarantine_generation == 0 || layout.generation <= c.quarantine_generation {
            return Err(Error::Stale);
        }
        if now < c.recovery_after {
            return Err(Error::Busy);
        }
        if self.committed_ns(cpu) > CPU_BUDGET_NS {
            return Err(Error::Capacity);
        }
        self.cpus[cpu].quarantine_generation = 0;
        self.stats.quarantine_mask &= !(1u64 << cpu);
        Ok(())
    }
    /// Ordinary callers may narrow their admitted affinity while retaining the
    /// current CPU. Moving the context and its reservations remains relocate's
    /// separate operation; this cannot grant a control or unhealthy CPU.
    pub fn bind_affinity(
        &mut self,
        key: ObjectKey,
        mask: u64,
        layout: CpuLayout,
    ) -> Result<(), Error> {
        let i = self.thread(key)?;
        let old = self.threads[i].ok_or(Error::Stale)?.spec;
        if mask == 0
            || layout.generation == 0
            || mask & !(layout.business_mask & layout.healthy_mask & old.allowed_mask) != 0
        {
            return Err(Error::Auth);
        }
        if mask & (1u64 << old.cpu) == 0 {
            return Err(Error::Busy);
        }
        self.threads[i]
            .as_mut()
            .ok_or(Error::Stale)?
            .spec
            .allowed_mask = mask;
        Ok(())
    }
    pub fn thread_affinity(&self, key: ObjectKey) -> Result<u64, Error> {
        Ok(self.threads[self.thread(key)?]
            .ok_or(Error::Stale)?
            .spec
            .allowed_mask)
    }
    pub fn relocate(
        &mut self,
        key: ObjectKey,
        cpu: usize,
        layout: CpuLayout,
        now: u64,
    ) -> Result<(), Error> {
        self.time(now)?;
        let i = self.thread(key)?;
        let initial = self.threads[i].ok_or(Error::Stale)?;
        let old = usize::from(initial.spec.cpu);
        if old == cpu {
            return Ok(());
        }
        if !layout.permits(cpu) || initial.spec.allowed_mask & (1u64 << cpu) == 0 {
            return Err(Error::Auth);
        }
        if self
            .cpus
            .iter()
            .any(|c| c.active.is_some_and(|d| d.thread == key))
            || self.cpus[cpu].active.is_some()
            || self.cpus[cpu].control.is_some()
        {
            return Err(Error::Busy);
        }
        if self.cpus[cpu].quarantine_generation != 0 {
            return Err(Error::NotReady);
        }
        self.roll(old, now)?;
        self.roll(cpu, now)?;
        let t = self.threads[i].ok_or(Error::Stale)?;
        if self.committed_ns(cpu).saturating_add(t.spec.budget_ns) > CPU_BUDGET_NS {
            return Err(Error::Capacity);
        }
        let outstanding: u64 = self
            .threads
            .iter()
            .flatten()
            .filter(|t| usize::from(t.spec.cpu) == cpu)
            .map(|t| t.spec.budget_ns.saturating_sub(t.spent))
            .sum();
        if self.cpus[cpu]
            .spent
            .saturating_add(outstanding)
            .saturating_add(t.spec.budget_ns)
            > CPU_BUDGET_NS
        {
            return Err(Error::Budget);
        }
        // Destination accounts carried consumption; source debits are retained
        // until its aligned window ends. A move cannot manufacture free credit.
        self.cpus[cpu].spent = self.cpus[cpu].spent.saturating_add(t.spent);
        self.cpus[cpu].groups[t.group] = self.cpus[cpu].groups[t.group]
            .saturating_add(t.spent.saturating_sub(t.spec.minimum_ns));
        self.threads[i].as_mut().ok_or(Error::Stale)?.spec.cpu = cpu as u16;
        Ok(())
    }
    pub fn stats(&self) -> SchedulerStats {
        let mut s = self.stats;
        s.runnable = self
            .threads
            .iter()
            .flatten()
            .filter(|t| t.state == RunState::Runnable)
            .count() as u16;
        s
    }
    pub fn group_at(&self, ordinal: usize) -> Option<ObjectKey> {
        self.groups.iter().flatten().nth(ordinal).map(|g| g.key)
    }
    pub fn weight(&self, key: ObjectKey, now: u64) -> Result<u16, Error> {
        let g = self.groups[self.group(key)?].ok_or(Error::Stale)?;
        Ok(if g.stamp.live(now) { g.weight } else { 1 })
    }
    pub fn policy_receipt(&self, key: ObjectKey) -> Result<u64, Error> {
        Ok(self.groups[self.group(key)?]
            .ok_or(Error::Stale)?
            .applied_version)
    }
    pub fn group_threads(&self, key: ObjectKey) -> Result<(usize, usize), Error> {
        self.group(key)?;
        let mut all = 0;
        let mut ready = 0;
        for t in self
            .threads
            .iter()
            .flatten()
            .filter(|t| t.spec.group == key)
        {
            all += 1;
            ready += usize::from(t.state == RunState::Runnable);
        }
        Ok((all, ready))
    }
    pub fn committed_ns(&self, cpu: usize) -> u64 {
        self.threads
            .iter()
            .flatten()
            .filter(|t| usize::from(t.spec.cpu) == cpu)
            .map(|t| t.spec.budget_ns)
            .sum()
    }
    pub fn minimum_ns(&self, cpu: usize) -> u64 {
        self.threads
            .iter()
            .flatten()
            .filter(|t| usize::from(t.spec.cpu) == cpu)
            .map(|t| t.spec.minimum_ns)
            .sum()
    }
    /// Actual outstanding thread promises in the current scheduler ledger.
    /// Read-only diagnostics do not roll the window or retire active credit.
    pub fn admission_observation(&self, cpu: usize) -> (u64, u64) {
        self.threads
            .iter()
            .flatten()
            .filter(|t| usize::from(t.spec.cpu) == cpu)
            .fold((0u64, 0u64), |(budget, minimum), t| {
                (
                    budget.saturating_add(t.spec.budget_ns.saturating_sub(t.spent)),
                    minimum.saturating_add(if t.state == RunState::Runnable {
                        t.spec.minimum_ns.saturating_sub(t.spent)
                    } else {
                        0
                    }),
                )
            })
    }
    pub fn thread_count(&self) -> usize {
        self.threads.iter().flatten().count()
    }
    pub fn thread_cpu_ns(&self, key: ObjectKey) -> Result<u64, Error> {
        Ok(self.threads[self.thread(key)?].ok_or(Error::Stale)?.actual)
    }
    pub fn cpu_spent_ns(&self, cpu: usize) -> Result<u64, Error> {
        self.cpus.get(cpu).map(|c| c.spent).ok_or(Error::Range)
    }
    /// Physical CPU usage is not reset by a control/business ownership change.
    /// Pending control and business credits remain visible after a clock roll
    /// or ownership change until their exact completion has been accounted.
    pub fn cpu_window_usage(&self, cpu: usize, now: u64) -> Result<(u64, u64), Error> {
        let c = self.cpus.get(cpu).ok_or(Error::Range)?;
        if c.window == u64::MAX {
            return Ok((0, 0));
        }
        if now / WINDOW_NS < c.window {
            return Err(Error::Stale);
        }
        if now / WINDOW_NS > c.window && now / WINDOW_NS == c.carry_window {
            return Ok((c.carry_spent, 0));
        }
        if now / WINDOW_NS > c.window
            && c.active.is_none()
            && c.control.is_none()
            && now >= c.recovery_after
        {
            return Ok((0, 0));
        }
        let reserved =
            c.active.map_or(0, |d| d.reserved_ns) + c.control.map_or(0, |d| d.reserved_ns);
        Ok((c.spent.saturating_sub(reserved), reserved))
    }
    /// Prepay one complete bounded control turn on its actual physical CPU.
    /// Both the 70 ms control ceiling and 90 ms shared physical ceiling use the
    /// same aligned window. Returning None grants no execution rights.
    pub fn reserve_control(
        &mut self,
        cpu: usize,
        layout: CpuLayout,
        now: u64,
        required_ns: u64,
    ) -> Result<Option<ControlCredit>, Error> {
        self.reserve_control_with_window_headroom(cpu, layout, now, required_ns, 0)
    }
    /// Prepay a complete control turn only when its aligned window also has
    /// the caller's full wall-time execution envelope. The CPU-time debit is
    /// still exactly `required_ns`; headroom is admission-only and creates no
    /// additional credit.
    pub fn reserve_control_with_window_headroom(
        &mut self,
        cpu: usize,
        layout: CpuLayout,
        now: u64,
        required_ns: u64,
        headroom_ns: u64,
    ) -> Result<Option<ControlCredit>, Error> {
        if cpu >= 64
            || layout.generation == 0
            || layout.healthy_mask & (1u64 << cpu) == 0
            || layout.business_mask & (1u64 << cpu) != 0
        {
            return Err(Error::Auth);
        }
        if required_ns == 0 || required_ns > CONTROL_BUDGET_NS || headroom_ns > WINDOW_NS {
            return Err(Error::Range);
        }
        self.time(now)?;
        if self.cpus[cpu].active.is_some() || self.cpus[cpu].control.is_some() {
            return Err(Error::Busy);
        }
        if self.cpus[cpu].quarantine_generation != 0 {
            return Err(Error::NotReady);
        }
        self.roll(cpu, now)?;
        if WINDOW_NS - now % WINDOW_NS < headroom_ns {
            return Ok(None);
        }
        let c = self.cpus[cpu];
        if required_ns > CPU_BUDGET_NS.saturating_sub(c.spent)
            || required_ns > CONTROL_BUDGET_NS.saturating_sub(c.control_spent)
            || required_ns > WINDOW_NS - now % WINDOW_NS
        {
            return Ok(None);
        }
        let sequence = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        let credit = ControlCredit {
            sequence,
            cpu: cpu as u16,
            core_generation: layout.generation,
            window: now / WINDOW_NS,
            started_ns: now,
            reserved_ns: required_ns,
            control_total_ns: c.control_spent + required_ns,
            physical_total_ns: c.spent + required_ns,
        };
        self.cpus[cpu].spent += required_ns;
        self.cpus[cpu].control_spent += required_ns;
        self.cpus[cpu].control = Some(credit);
        self.sequence = sequence;
        Ok(Some(credit))
    }
    /// Settle exactly once, even if a later ownership context has been
    /// published. A real CPU-time overrun quarantines this CPU. A wall-late
    /// receipt is conservatively charged again in its completion window;
    /// malformed or stale receipts do not retire the real reservation.
    pub fn complete_control(
        &mut self,
        credit: ControlCredit,
        actual_ns: u64,
        finished_ns: u64,
    ) -> Result<(), Error> {
        let cpu = usize::from(credit.cpu);
        let c = self.cpus.get(cpu).ok_or(Error::Range)?;
        if c.control != Some(credit) {
            return Err(Error::Stale);
        }
        if finished_ns < credit.started_ns
            || actual_ns > finished_ns.saturating_sub(credit.started_ns)
        {
            return Err(Error::Range);
        }
        let end = credit
            .window
            .checked_add(1)
            .and_then(|w| w.checked_mul(WINDOW_NS))
            .ok_or(Error::Overflow)?;
        let c = &mut self.cpus[cpu];
        c.spent = c
            .spent
            .saturating_sub(credit.reserved_ns)
            .saturating_add(actual_ns);
        c.control_spent = c
            .control_spent
            .saturating_sub(credit.reserved_ns)
            .saturating_add(actual_ns);
        c.control = None;
        self.last_now = self.last_now.max(finished_ns);
        if actual_ns > credit.reserved_ns
            || c.spent > CPU_BUDGET_NS
            || c.control_spent > CONTROL_BUDGET_NS
        {
            c.quarantine_generation = c.quarantine_generation.max(credit.core_generation);
            c.recovery_after = if finished_ns.is_multiple_of(WINDOW_NS) {
                finished_ns
            } else {
                finished_ns.saturating_add(WINDOW_NS - finished_ns % WINDOW_NS)
            };
            self.stats.quarantine_mask |= 1u64 << cpu;
            self.stats.overruns = self.stats.overruns.saturating_add(1);
            return Err(Error::Budget);
        }
        if finished_ns > end
            && self
                .carry_control_completion(cpu, actual_ns, finished_ns)
                .is_err()
        {
            let c = &mut self.cpus[cpu];
            c.quarantine_generation = c.quarantine_generation.max(credit.core_generation);
            c.recovery_after = if finished_ns.is_multiple_of(WINDOW_NS) {
                finished_ns
            } else {
                finished_ns.saturating_add(WINDOW_NS - finished_ns % WINDOW_NS)
            };
            self.stats.quarantine_mask |= 1u64 << cpu;
            self.stats.overruns = self.stats.overruns.saturating_add(1);
            return Err(Error::Budget);
        }
        Ok(())
    }
    pub fn control_active(&self, cpu: usize) -> Option<ControlCredit> {
        self.cpus.get(cpu).and_then(|c| c.control)
    }
    /// Record actual isolated-control CPU time after its separate control
    /// budget has prepaid it. The CPU must already be quiescent for business.
    /// Budget errors consume the receipt and quarantine only this physical CPU;
    /// Busy/Range/Stale leave it unconsumed. No task/group is charged twice.
    pub fn record_control_cost(
        &mut self,
        cpu: usize,
        actual: u64,
        finished: u64,
        generation: u64,
    ) -> Result<(), Error> {
        if cpu >= 64 || generation == 0 || actual > finished {
            return Err(Error::Range);
        }
        if self.cpus[cpu].active.is_some() || self.cpus[cpu].control.is_some() {
            return Err(Error::Busy);
        }
        let started = finished - actual;
        if self.cpus[cpu].window != u64::MAX && self.cpus[cpu].window > started / WINDOW_NS {
            return Err(Error::Stale);
        }
        let end = (started / WINDOW_NS)
            .checked_add(1)
            .and_then(|window| window.checked_mul(WINDOW_NS))
            .ok_or(Error::Overflow)?;
        self.roll(cpu, started)?;
        self.last_now = self.last_now.max(finished);
        self.cpus[cpu].spent = self.cpus[cpu].spent.saturating_add(actual);
        self.cpus[cpu].control_spent = self.cpus[cpu].control_spent.saturating_add(actual);
        if self.cpus[cpu].spent > CPU_BUDGET_NS
            || self.cpus[cpu].control_spent > CONTROL_BUDGET_NS
            || finished > end
        {
            self.cpus[cpu].quarantine_generation =
                self.cpus[cpu].quarantine_generation.max(generation);
            self.cpus[cpu].recovery_after = if finished.is_multiple_of(WINDOW_NS) {
                finished
            } else {
                finished.saturating_add(WINDOW_NS - finished % WINDOW_NS)
            };
            self.stats.quarantine_mask |= 1u64 << cpu;
            self.stats.overruns = self.stats.overruns.saturating_add(1);
            return Err(Error::Budget);
        }
        Ok(())
    }
    pub fn active(&self, cpu: usize) -> Option<Dispatch> {
        self.cpus.get(cpu).and_then(|c| c.active)
    }
}

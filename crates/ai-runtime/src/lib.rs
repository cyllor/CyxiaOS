#![no_std]
#![deny(unsafe_code)]
//! Single-owner cooperative kernel resource service, independent of MMIO/architecture.
pub mod accounting;
mod device;
pub mod display_policy;
#[allow(unsafe_code)] // Two audited trusted grant/revocation receipts; no raw page access escapes.
mod memory;
mod model;
pub mod storage_policy;
#[rustfmt::skip]
mod weights;
use cyxia_contracts::DecisionSource;
pub use device::{Device, DeviceInfo, DeviceIo, IoError, RequestInfo, RequestState};
pub use memory::{MemoryId, MemoryStatus, PAGE_BYTES, PAGES};
const TASKS: usize = 8;
const AUDIT: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Capacity,
    AiDenied,
    Owner,
    Stale,
    Bounds,
    Exhausted,
    Invariant,
    Offline,
    Busy,
    State,
    Clock,
    InvalidDecision,
    DeviceFailed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workload {
    Compute,
    Memory,
    Uart,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Waiting,
    Exited,
    Failed,
    Killed,
}
#[derive(Clone, Copy, Debug)]
pub struct TaskInfo {
    pub id: u32,
    pub kind: Workload,
    pub state: TaskState,
    pub paused: bool,
    pub priority: u8,
    pub done: u32,
    pub total: u32,
    pub checksum: u64,
    pub slices: u64,
    pub last_budget: u32,
    pub pages: usize,
    pub error: Option<Error>,
}
#[derive(Clone, Copy)]
struct Task {
    info: TaskInfo,
    memory: Option<MemoryId>,
    request: Option<u64>,
    ready_since: u64,
}
#[derive(Clone, Copy, Debug)]
pub enum Domain {
    Memory,
    Cpu,
    Device,
    Operator,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    Decision,
    Submitted,
    Cancelled,
    Reaped,
    Completed,
    Failed,
    Released,
    TaskExit,
}
#[derive(Clone, Copy, Debug)]
pub struct AuditRecord {
    pub serial: u64,
    pub event: AuditEvent,
    pub request_state: Option<RequestState>,
    pub uncertain: bool,
    pub domain: Domain,
    pub source: DecisionSource,
    pub model: u64,
    pub owner: u32,
    pub object: u64,
    pub amount: u32,
    pub accepted: bool,
}
const EMPTY_AUDIT: AuditRecord = AuditRecord {
    serial: 0,
    event: AuditEvent::Decision,
    request_state: None,
    uncertain: false,
    domain: Domain::Operator,
    source: DecisionSource::Bootstrap,
    model: 0,
    owner: 0,
    object: 0,
    amount: 0,
    accepted: false,
};
#[derive(Clone, Copy, Debug)]
pub struct RuntimeStatus {
    pub tick: u64,
    pub tasks: usize,
    pub dispatches: u64,
    pub guards: u64,
    pub device_decisions: u64,
    pub device_failures: u64,
    pub device_guards: u64,
    pub device_mechanisms: u64,
    pub audit_dropped: u64,
    pub epoch: u64,
}
#[derive(Clone, Copy)]
struct CpuDecision {
    epoch: u64,
    task: u32,
    slot: usize,
    budget: u32,
    guard: bool,
}
pub struct Runtime {
    memory: memory::Memory,
    devices: device::Devices,
    tasks: [Option<Task>; TASKS],
    next_task: u32,
    epoch: u64,
    now: u64,
    bound: bool,
    dispatches: u64,
    guards: u64,
    audit: [AuditRecord; AUDIT],
    audit_next: u64,
}
impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}
impl Runtime {
    pub const fn new() -> Self {
        Self {
            memory: memory::Memory::new(),
            devices: device::Devices::new(),
            tasks: [None; TASKS],
            next_task: 2,
            epoch: 1,
            now: 0,
            bound: false,
            dispatches: 0,
            guards: 0,
            audit: [EMPTY_AUDIT; AUDIT],
            audit_next: 1,
        }
    }
    pub fn bind_devices(&mut self, uart: bool, timer: bool) -> Result<(), Error> {
        if self.bound {
            return Err(Error::State);
        }
        self.devices.bind(uart, timer);
        self.bound = true;
        Ok(())
    }
    fn record(
        &mut self,
        domain: Domain,
        source: DecisionSource,
        owner: u32,
        object: u64,
        amount: u32,
        accepted: bool,
    ) {
        let Some(next) = self.audit_next.checked_add(1) else {
            return;
        };
        let model = if source == DecisionSource::AiDirect {
            match domain {
                Domain::Memory => model::MEMORY_ID,
                Domain::Cpu => model::CPU_ID,
                Domain::Device => model::DEVICE_ID,
                Domain::Operator => 0,
            }
        } else {
            0
        };
        self.audit[(self.audit_next as usize - 1) % AUDIT] = AuditRecord {
            serial: self.audit_next,
            event: AuditEvent::Decision,
            request_state: None,
            uncertain: false,
            domain,
            source,
            model,
            owner,
            object,
            amount,
            accepted,
        };
        self.audit_next = next;
    }
    fn bump(&mut self) -> Result<(), Error> {
        // Each bounded command/tick emits fewer than 64 records; reserve IDs upfront.
        if self.audit_next > u64::MAX - 64 {
            return Err(Error::Exhausted);
        }
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(())
    }
    pub fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            tick: self.now,
            tasks: self.tasks.iter().flatten().count(),
            dispatches: self.dispatches,
            guards: self.guards,
            device_decisions: self.devices.decisions,
            device_failures: self.devices.failures,
            device_guards: self.devices.guards,
            device_mechanisms: self.devices.mechanisms,
            audit_dropped: self.audit_next.saturating_sub(1 + AUDIT as u64),
            epoch: self.epoch,
        }
    }
    pub fn audit(&self) -> impl Iterator<Item = AuditRecord> + '_ {
        let start = self.audit_next.saturating_sub(AUDIT as u64).max(1);
        (start..self.audit_next).map(|id| self.audit[(id as usize - 1) % AUDIT])
    }
    pub fn memory_status(&self) -> MemoryStatus {
        self.memory.status()
    }
    pub fn allocations(&self) -> impl Iterator<Item = (MemoryId, u32, usize, u64)> + '_ {
        self.memory.records()
    }
    pub fn allocate(&mut self, pages: usize) -> Result<MemoryId, Error> {
        self.bump()?;
        let result = self.memory.allocate(1, pages);
        self.record(
            Domain::Memory,
            if matches!(result, Ok(_) | Err(Error::AiDenied)) {
                DecisionSource::AiDirect
            } else {
                DecisionSource::Mechanism
            },
            1,
            result.as_ref().map_or(0, |id| id.0),
            pages.min(u32::MAX as usize) as u32,
            result.is_ok(),
        );
        result
    }
    pub fn free(&mut self, id: MemoryId) -> Result<(), Error> {
        self.bump()?;
        self.memory.release(1, id)?;
        self.record(Domain::Operator, DecisionSource::Operator, 1, id.0, 0, true);
        Ok(())
    }
    pub fn peek(&self, id: MemoryId, offset: usize) -> Result<u8, Error> {
        self.memory.read(1, id, offset)
    }
    pub fn poke(&mut self, id: MemoryId, offset: usize, value: u8) -> Result<(), Error> {
        self.memory.write(1, id, offset, value)
    }
    pub fn tasks(&self) -> impl Iterator<Item = TaskInfo> + '_ {
        self.tasks.iter().flatten().map(|t| t.info)
    }
    fn task_slot(&self, id: u32) -> Result<usize, Error> {
        self.tasks
            .iter()
            .position(|t| t.is_some_and(|t| t.info.id == id))
            .ok_or(Error::Stale)
    }
    pub fn spawn(
        &mut self,
        kind: Workload,
        total: u32,
        priority: u8,
        pages: usize,
    ) -> Result<u32, Error> {
        if total == 0 || total > 1_000_000 || priority > 3 {
            return Err(Error::Invalid);
        }
        let slot = self
            .tasks
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let next = self.next_task.checked_add(1).ok_or(Error::Exhausted)?;
        self.bump()?;
        let id = self.next_task;
        let result = self.memory.allocate(id, pages);
        self.record(
            Domain::Memory,
            if matches!(result, Ok(_) | Err(Error::AiDenied)) {
                DecisionSource::AiDirect
            } else {
                DecisionSource::Mechanism
            },
            id,
            result.as_ref().map_or(0, |m| m.0),
            pages.min(u32::MAX as usize) as u32,
            result.is_ok(),
        );
        let memory = result?;
        self.tasks[slot] = Some(Task {
            info: TaskInfo {
                id,
                kind,
                state: TaskState::Ready,
                paused: false,
                priority,
                done: 0,
                total,
                checksum: 0,
                slices: 0,
                last_budget: 0,
                pages,
                error: None,
            },
            memory: Some(memory),
            request: None,
            ready_since: self.now,
        });
        self.next_task = next;
        self.record(Domain::Operator, DecisionSource::Operator, id, 0, 0, true);
        Ok(id)
    }
    pub fn pause(&mut self, id: u32, paused: bool) -> Result<(), Error> {
        let slot = self.task_slot(id)?;
        let task = self.tasks[slot].as_ref().ok_or(Error::Invariant)?;
        if matches!(
            task.info.state,
            TaskState::Exited | TaskState::Failed | TaskState::Killed
        ) {
            return Err(Error::State);
        }
        self.bump()?;
        let task = self.tasks[slot].as_mut().ok_or(Error::Invariant)?;
        task.info.paused = paused;
        task.ready_since = self.now;
        self.record(
            Domain::Operator,
            DecisionSource::Operator,
            id,
            0,
            u32::from(paused),
            true,
        );
        Ok(())
    }
    fn device_event(
        &mut self,
        event: AuditEvent,
        source: DecisionSource,
        r: RequestInfo,
        amount: usize,
    ) {
        self.record(
            Domain::Device,
            source,
            r.owner,
            r.id,
            amount as u32,
            r.state != RequestState::Failed,
        );
        if self.audit_next > 1 {
            let record = &mut self.audit[(self.audit_next as usize - 2) % AUDIT];
            record.event = event;
            record.request_state = Some(r.state);
            record.uncertain = r.uncertain;
        }
    }
    fn tag_last(&mut self, event: AuditEvent) {
        if self.audit_next > 1 {
            self.audit[(self.audit_next as usize - 2) % AUDIT].event = event;
        }
    }
    fn finish(&mut self, slot: usize, state: TaskState) -> Result<(), Error> {
        let task = self.tasks[slot].ok_or(Error::Invariant)?;
        if let Some(id) = task.request
            && let Ok(mut request) = self.devices.get(id)
            && request.state == RequestState::Queued
        {
            self.devices.cancel(task.info.id, id)?;
            request = self.devices.get(id)?;
            self.device_event(
                AuditEvent::Cancelled,
                DecisionSource::Mechanism,
                request,
                request.done,
            );
        }
        self.devices.cancel_owner(task.info.id);
        if let Some(id) = task.memory {
            self.memory.release(task.info.id, id)?;
            self.record(
                Domain::Memory,
                DecisionSource::Mechanism,
                task.info.id,
                id.0,
                task.info.pages as u32,
                true,
            );
            self.tag_last(AuditEvent::Released);
        }
        let t = self.tasks[slot].as_mut().ok_or(Error::Invariant)?;
        t.request = None;
        t.memory = None;
        t.info.state = state;
        t.info.paused = false;
        t.info.pages = 0;
        self.record(
            Domain::Cpu,
            DecisionSource::Mechanism,
            task.info.id,
            0,
            task.info.done,
            state != TaskState::Failed,
        );
        self.tag_last(AuditEvent::TaskExit);
        Ok(())
    }
    pub fn kill(&mut self, id: u32) -> Result<(), Error> {
        let slot = self.task_slot(id)?;
        if self.tasks[slot].is_some_and(|t| {
            matches!(
                t.info.state,
                TaskState::Exited | TaskState::Failed | TaskState::Killed
            )
        }) {
            return Err(Error::State);
        }
        self.bump()?;
        self.finish(slot, TaskState::Killed)?;
        self.record(Domain::Operator, DecisionSource::Operator, id, 0, 0, true);
        Ok(())
    }
    pub fn reap(&mut self, id: u32) -> Result<(), Error> {
        let slot = self.task_slot(id)?;
        if !self.tasks[slot].is_some_and(|t| {
            matches!(
                t.info.state,
                TaskState::Exited | TaskState::Failed | TaskState::Killed
            )
        }) {
            return Err(Error::Busy);
        }
        self.bump()?;
        self.tasks[slot] = None;
        Ok(())
    }
    pub fn device_info(&self, d: Device) -> DeviceInfo {
        self.devices.info(d)
    }
    pub fn device_enable(&mut self, d: Device, enabled: bool) -> Result<(), Error> {
        self.bump()?;
        self.devices.enable(d, enabled)?;
        self.record(
            Domain::Operator,
            DecisionSource::Operator,
            1,
            d as u64,
            u32::from(enabled),
            true,
        );
        Ok(())
    }
    pub fn device_submit(&mut self, d: Device, data: &[u8]) -> Result<u64, Error> {
        self.bump()?;
        let id = self.devices.submit(1, d, data, 1, self.now)?;
        self.device_event(
            AuditEvent::Submitted,
            DecisionSource::Operator,
            self.devices.get(id)?,
            data.len(),
        );
        Ok(id)
    }
    /// Queue a bounded timer batch with priorities 0..3 to exercise arbitration.
    pub fn device_batch(&mut self, count: usize) -> Result<u64, Error> {
        self.devices.check_batch(Device::Timer, count)?;
        self.bump()?;
        let mut first = 0;
        for i in 0..count {
            let id = self
                .devices
                .submit(1, Device::Timer, b"", (i % 4) as u8, self.now)?;
            if i == 0 {
                first = id;
            }
            self.device_event(
                AuditEvent::Submitted,
                DecisionSource::Operator,
                self.devices.get(id)?,
                0,
            );
        }
        Ok(first)
    }
    pub fn requests(&self) -> impl Iterator<Item = RequestInfo> + '_ {
        self.devices.records()
    }
    pub fn request_cancel(&mut self, id: u64) -> Result<(), Error> {
        self.bump()?;
        self.devices.cancel(1, id)?;
        let r = self.devices.get(id)?;
        self.device_event(AuditEvent::Cancelled, DecisionSource::Operator, r, r.done);
        Ok(())
    }
    pub fn request_reap(&mut self, id: u64) -> Result<RequestInfo, Error> {
        self.bump()?;
        let r = self.devices.reap(1, id)?;
        self.device_event(AuditEvent::Reaped, DecisionSource::Operator, r, r.done);
        Ok(r)
    }
    fn decide(&self) -> Option<CpuDecision> {
        let ready = self
            .tasks
            .iter()
            .flatten()
            .filter(|t| t.info.state == TaskState::Ready && !t.info.paused)
            .count();
        let oldest = self
            .tasks
            .iter()
            .flatten()
            .filter(|t| t.info.state == TaskState::Ready && !t.info.paused)
            .map(|t| t.ready_since)
            .min()?;
        let guard = self.now.saturating_sub(oldest) >= 32;
        let mut best = None;
        for (i, t) in self.tasks.iter().enumerate() {
            if let Some(t) = t
                && t.info.state == TaskState::Ready
                && !t.info.paused
                && (!guard || t.ready_since == oldest)
                && best.is_none_or(|j: usize| {
                    self.tasks[j].is_some_and(|b| {
                        model::cpu(
                            self.now.saturating_sub(t.ready_since),
                            t.info.priority,
                            t.info.total - t.info.done,
                        ) > model::cpu(
                            self.now.saturating_sub(b.ready_since),
                            b.info.priority,
                            b.info.total - b.info.done,
                        )
                    })
                })
            {
                best = Some(i);
            }
        }
        let slot = best?;
        let t = self.tasks[slot]?;
        Some(CpuDecision {
            epoch: self.epoch,
            task: t.info.id,
            slot,
            budget: model::quantum(ready, t.info.total - t.info.done),
            guard,
        })
    }
    fn dispatch(&mut self, d: CpuDecision) -> Result<(), Error> {
        if d.epoch != self.epoch || d.slot >= TASKS || ![32, 256].contains(&d.budget) {
            return Err(Error::InvalidDecision);
        }
        let t = self.tasks[d.slot].as_ref().ok_or(Error::InvalidDecision)?;
        if t.info.id != d.task || t.info.state != TaskState::Ready || t.info.paused {
            return Err(Error::InvalidDecision);
        }
        // Consume this proposal's revision before executing any work.
        self.bump()?;
        self.record(
            Domain::Cpu,
            if d.guard {
                DecisionSource::SafetyGuard
            } else {
                DecisionSource::AiDirect
            },
            d.task,
            0,
            d.budget,
            true,
        );
        if d.guard {
            self.guards = self.guards.saturating_add(1);
        } else {
            self.dispatches = self.dispatches.saturating_add(1);
        }
        let t = self.tasks[d.slot].as_mut().ok_or(Error::Invariant)?;
        t.info.slices = t.info.slices.saturating_add(1);
        t.info.last_budget = d.budget;
        t.ready_since = self.now;
        if t.info.kind == Workload::Uart {
            match self.devices.submit(
                t.info.id,
                Device::Uart,
                b"[CyxiaOS AI task UART]\r\n",
                t.info.priority,
                self.now,
            ) {
                Ok(id) => {
                    t.request = Some(id);
                    t.info.state = TaskState::Waiting;
                    self.device_event(
                        AuditEvent::Submitted,
                        DecisionSource::Mechanism,
                        self.devices.get(id)?,
                        0,
                    );
                }
                Err(error) => {
                    t.info.error = Some(error);
                    self.finish(d.slot, TaskState::Failed)?;
                }
            }
            return Ok(());
        }
        let m = t.memory.ok_or(Error::Invariant)?;
        let count = d.budget.min(t.info.total - t.info.done);
        for _ in 0..count {
            let offset = if t.info.kind == Workload::Memory {
                t.info.done as usize % (t.info.pages * PAGE_BYTES)
            } else {
                0
            };
            let byte = if t.info.kind == Workload::Memory {
                (t.info.done % 251) as u8
            } else {
                t.info
                    .checksum
                    .wrapping_mul(1664525)
                    .wrapping_add(1013904223) as u8
            };
            self.memory.write(t.info.id, m, offset, byte)?;
            let actual = self.memory.read(t.info.id, m, offset)?;
            t.info.checksum = t
                .info
                .checksum
                .rotate_left(5)
                .wrapping_add(u64::from(actual) + 1);
            t.info.done += 1;
        }
        if t.info.done == t.info.total {
            self.finish(d.slot, TaskState::Exited)?;
        }
        Ok(())
    }
    pub fn tick(&mut self, now: u64, io: &mut impl DeviceIo) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Clock);
        }
        if now == self.now {
            return Ok(());
        }
        self.bump()?;
        self.now = now;
        if let Some((_owner, id, source, amount)) = self.devices.step(now, io) {
            let r = self.devices.get(id)?;
            self.device_event(
                match r.state {
                    RequestState::Complete => AuditEvent::Completed,
                    RequestState::Failed => AuditEvent::Failed,
                    _ => AuditEvent::Decision,
                },
                source,
                r,
                amount,
            );
        }
        for slot in 0..TASKS {
            let Some(t) = self.tasks[slot] else {
                continue;
            };
            if t.info.state == TaskState::Waiting {
                let r = self.devices.get(t.request.ok_or(Error::Invariant)?)?;
                if r.state == RequestState::Queued {
                    continue;
                }
                self.devices.reap(t.info.id, r.id)?;
                self.device_event(AuditEvent::Reaped, DecisionSource::Mechanism, r, r.done);
                if r.state != RequestState::Complete {
                    self.tasks[slot]
                        .as_mut()
                        .ok_or(Error::Invariant)?
                        .info
                        .error = Some(Error::DeviceFailed);
                    self.finish(slot, TaskState::Failed)?;
                    continue;
                }
                let task = self.tasks[slot].as_mut().ok_or(Error::Invariant)?;
                task.request = None;
                task.info.done += 1;
                task.info.checksum = task.info.checksum.wrapping_add(r.done as u64);
                if task.info.done == task.info.total {
                    self.finish(slot, TaskState::Exited)?;
                } else {
                    task.info.state = TaskState::Ready;
                    task.ready_since = now;
                }
            }
        }
        if let Some(d) = self.decide() {
            self.dispatch(d)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;

/// Local policy reuse by the isolated user-process service. No authority is conferred.
/// Capacity may reach 64 pages across eight slots. Saturating the observed free
/// pages at the model's trained 32-page maximum is conservative; it does not
/// extrapolate weights or relax the existing low-capacity admission boundary.
pub fn user_memory_policy(free: u32, requested: u32) -> Result<(bool, u64), Error> {
    if free > 64 || requested == 0 || requested > 8 {
        return Err(Error::Invalid);
    }
    Ok((
        model::memory((free as usize).min(PAGES), requested as usize),
        model::MEMORY_ID,
    ))
}

/// Anonymous user memory admission. Features are conservative 16-page units,
/// within the separately trained 0..256 free / 1..128 request domain. This model
/// has no authority to exceed actual capacity or per-process mapping limits.
pub fn anonymous_memory_policy(free: u32, requested: u32) -> Result<(bool, u64), Error> {
    if free > 4096 || requested == 0 || requested > 2048 {
        return Err(Error::Invalid);
    }
    let features = [1, (free / 16) as i32, requested.div_ceil(16) as i32, 0];
    let score: i32 = weights::USER_MEMORY
        .into_iter()
        .zip(features)
        .map(|(w, x)| w * x)
        .sum();
    Ok((score >= 0, 0x2002))
}

/// Executable-image admission, separately trained for a 16 MiB private arena.
/// The kernel still enforces actual page capacity, permissions and ownership.
pub fn executable_memory_policy(free: u32, requested: u32) -> Result<(bool, u64), Error> {
    if free > 4096 || requested == 0 || requested > 4096 {
        return Err(Error::Invalid);
    }
    let features = [1, (free / 16) as i32, requested.div_ceil(16) as i32, 0];
    let score: i32 = weights::EXEC_MEMORY
        .into_iter()
        .zip(features)
        .map(|(w, x)| w * x)
        .sum();
    Ok((score >= 0, 0x2003))
}

/// User dispatch wall-time budget in milliseconds. Safety caps are enforced by the kernel.
pub fn user_cpu_policy(cpu_bound: bool, competing: usize) -> Result<(u64, u64), Error> {
    if competing > 8 {
        return Err(Error::Invalid);
    }
    let x = [1, i32::from(cpu_bound), competing as i32, 0];
    let score: i32 = weights::USER_QUANTUM
        .into_iter()
        .zip(x)
        .map(|(w, v)| w * v)
        .sum();
    Ok((if score >= 0 { 4 } else { 1 }, 0x3002))
}

#[derive(Clone, Copy, Debug)]
pub struct UserCandidate {
    pub waiting_ms: u64,
    pub cpu_bound: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserDispatch {
    pub index: usize,
    pub source: DecisionSource,
    pub model: u64,
}
/// Reuse the local CPU ranking model for bounded native EL0 services. Priority
/// is currently equal; recent IRQ-bound work has an estimated 16 work units,
/// yielding/syscall work one. This is an adaptation, not a desktop-trained model.
pub fn user_dispatch_policy(
    candidates: &[Option<UserCandidate>],
) -> Result<Option<UserDispatch>, Error> {
    if candidates.len() > 8 {
        return Err(Error::Invalid);
    }
    let oldest = candidates.iter().flatten().map(|c| c.waiting_ms).max();
    let guard = oldest.is_some_and(|age| age >= 100);
    let mut best: Option<(usize, i32, u64)> = None;
    for (index, candidate) in candidates.iter().enumerate() {
        let Some(candidate) = candidate else {
            continue;
        };
        if guard && Some(candidate.waiting_ms) != oldest {
            continue;
        }
        let score = model::cpu(
            candidate.waiting_ms,
            1,
            if candidate.cpu_bound { 4096 } else { 256 },
        );
        if best
            .is_none_or(|(_, prior_score, age)| (score, candidate.waiting_ms) > (prior_score, age))
        {
            best = Some((index, score, candidate.waiting_ms));
        }
    }
    Ok(best.map(|(index, _, _)| UserDispatch {
        index,
        source: if guard {
            DecisionSource::SafetyGuard
        } else {
            DecisionSource::AiDirect
        },
        model: model::CPU_ID,
    }))
}

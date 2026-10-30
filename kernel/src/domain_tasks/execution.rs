use super::memory::{Pages, copy_from, copy_to, frame_phys, frame_ptr, prepare, synchronize};
use super::*;
use cyxia_prototype::domains::tasks::ThreadReservation;
#[path = "lifecycle.rs"]
mod lifecycle;

struct Creator<'a> {
    tasks: &'a mut [Task; TASKS],
    launches: &'a [Launch; LAUNCHES],
    memory: &'a mut Memory<PAGES, 512>,
    scheduler: &'a mut Scheduler,
    services: &'a mut ServiceBatch,
    ipc: &'a mut Ipc<IPC_BYTES>,
    background: &'a mut BackgroundBudgets,
    layout: CpuLayout,
    remote: Option<Remote>,
    generation: &'a mut u64,
    local_failure: Option<local_evidence::Failure>,
}
struct BuildTrace {
    enabled: bool,
    stage: u64,
    entered_ns: u64,
}
impl BuildTrace {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            stage: 0,
            entered_ns: 0,
        }
    }
    fn step(&mut self, stage: u64) {
        if self.enabled {
            self.stage = stage;
            self.entered_ns = now_ns();
        }
    }
}
fn thread_spec(request: &SpawnRequest, launch: &Launch, key: ObjectKey) -> ThreadSpec {
    let local = request.caller == CLUSTER_CALLER;
    ThreadSpec {
        key,
        group: request.group,
        cpu: launch.cpu,
        allowed_mask: 12,
        minimum_ns: if local { 10_000_000 } else { 0 },
        budget_ns: if matches!(request.group.id, 15 | 16) && launch.recipe != 0 {
            20_000_000
        } else if request.package == CLIENT_PACKAGE || local {
            10_000_000
        } else {
            1_000_000
        },
    }
}
impl Creator<'_> {
    fn failure_facts(
        &self,
        request: &SpawnRequest,
        task: ObjectKey,
        stage: u64,
        entered_ns: u64,
        error: Error,
    ) -> Option<local_evidence::Failure> {
        let launch = self.launch(request).ok().map(|i| &self.launches[i]);
        if self.tasks.iter().any(|parent| {
            parent.key == request.caller
                && parent.package == CLIENT_PACKAGE
                && parent.life != Life::Free
        }) {
            let memory = self.memory.stats();
            let target_cpu = launch.map_or(3, |l| l.cpu);
            spawn_diagnostics::construction_failure([
                now_ns(),
                stage,
                error as u64 + 1,
                request.request_id,
                request.caller.id,
                request.caller.generation,
                task.id,
                task.generation,
                launch.map_or(0, |l| l.deadline),
                entered_ns,
                u64::from(target_cpu),
                self.scheduler.committed_ns(usize::from(target_cpu)),
                self.scheduler.thread_count() as u64,
                self.tasks[..ORDINARY_TASKS]
                    .iter()
                    .filter(|t| t.life == Life::Free && t.recipe == 0)
                    .count() as u64,
                memory.free_pages as u64,
                memory.progress_free_pages as u64,
                self.scheduler.committed_ns(2),
                self.scheduler.committed_ns(3),
                self.layout.business_mask,
                self.layout.healthy_mask,
            ]);
        }
        if request.caller != CLUSTER_CALLER {
            return None;
        }
        Some(local_evidence::Failure::capture(
            local_evidence::Event {
                stage,
                error,
                observed_ns: now_ns(),
                spawn_id: request.request_id,
                deadline_ns: launch.map_or(0, |l| l.deadline),
                task,
                cpu: launch.map_or(3, |l| l.cpu),
                group: request.group,
                layout: self.layout,
                entered_ns,
            },
            self.scheduler,
        ))
    }
    fn launch(&self, r: &SpawnRequest) -> Result<usize, Error> {
        self.launches
            .iter()
            .position(|l| l.request == Some(*r))
            .ok_or(Error::Stale)
    }
    fn build(
        &mut self,
        r: &SpawnRequest,
        slot: usize,
        key: ObjectKey,
        reservation: Option<ThreadReservation>,
        trace: &mut BuildTrace,
    ) -> Result<(), Error> {
        trace.step(10); // Original immutable launch lookup.
        let launch = &self.launches[self.launch(r)?];
        let client = r.package == CLIENT_PACKAGE;
        let local = r.caller == CLUSTER_CALLER;
        let inherited = task_index(self.tasks, r.caller).map_or(ZERO, |i| self.tasks[i].endpoint);
        self.tasks[slot] = Task {
            key,
            group: r.group,
            parent: r.caller,
            package: r.package,
            spawn_id: r.request_id,
            cpu: launch.cpu,
            life: Life::Ready,
            deadline: launch.deadline,
            optional: matches!(r.group.id, 15 | 16),
            recipe: launch.recipe,
            pending: true,
            ..Task::EMPTY
        };
        self.tasks[slot].caps[0] = inherited;
        // A reserved normal thread already has scheduler custody. Keep its
        // actual parent/request identity before any fallible construction so
        // incomplete rollback can be drained without losing that custody.
        trace.step(11); // Original task deadline.
        if launch.deadline <= now_ns() {
            return Err(Error::Expired);
        }
        if let Some(reserved) = reservation.as_ref() {
            if r.recovery
                || reserved.key() != key
                || reserved.cpu() != launch.cpu
                || reserved.core_generation() != self.layout.generation
            {
                return Err(Error::Conflict);
            }
        } else if !r.recovery {
            return Err(Error::Conflict);
        }
        trace.step(12); // Actual page-table/code-leaf construction.
        unsafe {
            for frame in slot * 3..slot * 3 + 3 {
                core::ptr::write_bytes(frame_ptr(frame)?, 0, 4096);
            }
            frame_ptr(slot * 3)?
                .cast::<u64>()
                .write(frame_phys(slot * 3 + 1)? | 3);
            frame_ptr(slot * 3 + 1)?
                .cast::<u64>()
                .write(frame_phys(slot * 3 + 2)? | 3);
            let (first, count) = if client {
                (CLIENT_CODE_FRAME, 4)
            } else {
                (CODE_FRAME, 1)
            };
            for page in 0..count {
                frame_ptr(slot * 3 + 2)?.cast::<u64>().add(16 + page).write(
                    mmu::encode_user_leaf(PhysAddr(frame_phys(first + page)?), false, true)
                        .map_err(|_| Error::Range)?,
                );
            }
        }
        trace.step(13); // Register the exact memory owner generation.
        let client_pages = if client && crate::storage_fault_capture::PROFILE {
            if launch.len != 40 {
                return Err(Error::Format);
            }
            let mode = u64::from_le_bytes(launch.input[8..16].try_into().unwrap());
            cyxia_prototype::a10_budget::client_memory_pages(mode).ok_or(Error::Format)?
        } else {
            16
        };
        if r.recovery {
            self.memory.register_progress_owner(key, 4)?;
        } else {
            self.memory.register_owner(
                key,
                if client {
                    client_pages
                } else if local {
                    16
                } else {
                    64
                },
            )?;
        }
        trace.step(14); // Commit real backing for LOCAL/recovery.
        if local || r.recovery {
            self.memory.commit_pages(key)?;
        }
        trace.step(15); // Reserve the task's actual virtual regions.
        for (base, pages, write) in [
            (0x20000, 1, false),
            (0x21000, 1, false),
            (0x30000, 1, true),
            (
                if client { 0x39000 } else { 0x40000 },
                if client { 8 } else { 1 },
                true,
            ),
        ] {
            self.memory.reserve(key, base, pages, write)?;
            let t = &mut self.tasks[slot];
            t.regions[t.region_count] = base;
            t.region_count += 1;
        }
        trace.step(16); // Prepare/copy the original task input.
        prepare(self.memory, self.tasks, self.remote, key, 0x20000, 8, false)?;
        trace.step(17);
        prepare(
            self.memory,
            self.tasks,
            self.remote,
            key,
            0x21000,
            launch.len,
            false,
        )?;
        trace.step(18);
        copy_to(
            self.memory,
            key,
            0x20000,
            &(launch.len as u64).to_le_bytes(),
        )?;
        trace.step(19);
        copy_to(self.memory, key, 0x21000, &launch.input[..launch.len])?;
        trace.step(20); // Actual TASK_QUERY capability grant.
        let cap = self.services.grant(key, key, TASK_SERVICE, 2)?;
        self.tasks[slot].own_query_cap = cap;
        if launch.recipe != 0 {
            trace.step(21);
            self.tasks[slot].endpoint = self.ipc.open(key, true)?;
            trace.step(22);
            self.background.set_commitment(r.group, 0, now_ns())?;
        }
        if reservation.is_none() {
            let spec = thread_spec(r, launch, key);
            // Normal creation already owns its exact reservation. Repeating
            // admission here would race the physical window during page
            // construction. Recovery keeps its existing separate path.
            let admission_ns = now_ns();
            if trace.enabled {
                trace.stage = 23;
                trace.entered_ns = admission_ns;
            }
            self.scheduler.admit(spec, self.layout, admission_ns)?;
        }
        trace.step(24); // Final EL0 context/capability initialization.
        unsafe {
            let context = &mut *core::ptr::addr_of_mut!(CONTEXTS)
                .cast::<user::Context>()
                .add(slot);
            *context = user::Context::empty();
            context.pc = 0x10000;
            context.sp = 0x41000;
            if client {
                let file =
                    crate::domain_file_abi::grant(key, crate::domain_file_abi::abi::ALL_RIGHTS)?;
                context.regs[0] = file.id;
                context.regs[1] = file.generation;
            } else {
                context.regs[0] = cap;
                context.regs[1] = inherited.id;
                context.regs[2] = inherited.generation;
            }
        }
        synchronize();
        trace.step(25); // Protected replay membership, when applicable.
        replay::member_created(
            key,
            r.caller,
            r.request_id,
            launch.recipe,
            matches!(r.group.id, 15 | 16),
        )?;
        if client && crate::storage_fault_capture::PROFILE {
            if launch.len != 40 {
                return Err(Error::Format);
            }
            let role = u64::from_le_bytes(launch.input[16..24].try_into().unwrap());
            if !crate::storage_fault_capture::register(role as usize, key) {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
    fn rollback(&mut self, slot: usize, key: ObjectKey) -> Result<(), Error> {
        match self.scheduler.remove(key) {
            Ok(()) | Err(Error::Stale) => {}
            Err(error) => return Err(error),
        }
        crate::domain_file_abi::exit(key)?;
        self.services.revoke_owner(key);
        self.services.revoke_object(key);
        let mut wake = 0;
        self.ipc.exit(
            key,
            &mut abi::Mailbox {
                tasks: self.tasks,
                wake: &mut wake,
                received: &mut [],
                used: 0,
            },
        );
        let mut pages = Pages {
            tasks: self.tasks,
            remote: self.remote,
            load: None,
        };
        for base in self.tasks[slot].regions[..self.tasks[slot].region_count]
            .iter()
            .copied()
        {
            match self.memory.unmap_step(key, base, 64, &mut pages) {
                Ok(progress) if progress.remaining == 0 => {}
                Err(Error::NotFound) => {}
                _ => return Err(Error::Busy),
            }
        }
        match self.memory.unregister_owner(key) {
            Ok(()) | Err(Error::Stale) => {}
            Err(error) => return Err(error),
        }
        unsafe {
            for frame in slot * 3..slot * 3 + 3 {
                core::ptr::write_bytes(frame_ptr(frame)?, 0, 4096);
            }
            *core::ptr::addr_of_mut!(CONTEXTS)
                .cast::<user::Context>()
                .add(slot) = user::Context::empty();
        }
        synchronize();
        replay::member_retired(key);
        self.tasks[slot] = Task::EMPTY;
        Ok(())
    }
}
impl TaskBackend for Creator<'_> {
    fn authorize(&mut self, r: &SpawnRequest) -> Result<(), Error> {
        if r.package != PACKAGE
            && !(r.package == CLIENT_PACKAGE && r.caller == KERNEL_CALLER && SELFTEST_ENABLED)
        {
            return Err(Error::Auth);
        }
        let launch = &self.launches[self.launch(r)?];
        if r.recovery && r.caller != KERNEL_CALLER {
            return Err(Error::Auth);
        }
        if r.caller.id == replay::CALLER_ID {
            replay::authorize_request(
                r,
                &launch.input[..launch.len],
                launch.cpu,
                launch.deadline,
                launch.recipe,
            )?;
        } else if r.caller != KERNEL_CALLER && r.caller != CLUSTER_CALLER {
            let parent = &self.tasks[task_index(self.tasks, r.caller)?];
            if parent.closed || parent.group != r.group {
                return Err(Error::Auth);
            }
        }
        if r.caller == CLUSTER_CALLER
            && (r.group != group(5) || r.recovery || r.package != PACKAGE || launch.cpu != 3)
        {
            return Err(Error::Auth);
        }
        if !(2..=3).contains(&launch.cpu)
            || self.layout.business_mask & self.layout.healthy_mask & (1u64 << launch.cpu) == 0
        {
            return Err(Error::NotReady);
        }
        if launch.deadline <= now_ns() {
            return Err(Error::Expired);
        }
        Ok(())
    }
    fn create(&mut self, r: &SpawnRequest) -> CreateOutcome {
        let recipe = self.launch(r).ok().map_or(0, |i| self.launches[i].recipe);
        // Recovery construction is already inside its executor-action span;
        // synchronous ordinary admission is inside the replay caller's span.
        let source = if recipe == 0 && !replay::work_measured() {
            replay::work_source(r.caller, r.request_id, recipe)
        } else {
            None
        };
        let mut body = || {
            let range = if r.recovery {
                ORDINARY_TASKS..TASKS
            } else {
                0..ORDINARY_TASKS
            };
            let Some(slot) = range
                .into_iter()
                .find(|i| self.tasks[*i].life == Life::Free && self.tasks[*i].recipe == 0)
            else {
                if r.caller == CLUSTER_CALLER {
                    // These slots remain owned by real live/closing tasks. A
                    // queued LOCAL request may wait for their actual cleanup.
                    return CreateOutcome::Deferred;
                }
                self.local_failure = self.failure_facts(r, ZERO, 3, now_ns(), Error::Capacity);
                return CreateOutcome::Rejected(Error::Capacity);
            };
            let Some(generation) = self.generation.checked_add(1) else {
                self.local_failure = self.failure_facts(r, ZERO, 4, now_ns(), Error::Overflow);
                return CreateOutcome::Rejected(Error::Overflow);
            };
            let key = ObjectKey {
                id: 0x1000 + slot as u64,
                generation,
            };
            let mut trace = BuildTrace::new(
                r.caller == CLUSTER_CALLER
                    || self.tasks.iter().any(|parent| {
                        parent.key == r.caller
                            && parent.package == CLIENT_PACKAGE
                            && parent.life != Life::Free
                    }),
            );
            let reservation = if !r.recovery {
                let launch = match self.launch(r) {
                    Ok(index) => &self.launches[index],
                    Err(error) => {
                        self.local_failure = self.failure_facts(r, key, 10, now_ns(), error);
                        return CreateOutcome::Rejected(error);
                    }
                };
                let spec = thread_spec(r, launch, key);
                let admission_ns = now_ns();
                trace.stage = 23;
                trace.entered_ns = admission_ns;
                match self
                    .scheduler
                    .prepare_admission(spec, self.layout, admission_ns)
                {
                    Ok(Some(reserved)) => Some(reserved),
                    // No task, pages, capability, or scheduler thread has been
                    // created. This includes ordinary client children whose
                    // target CPU still owns a live promise awaiting removal.
                    // Preserve the existing queue identity and deadline.
                    Ok(None) => return CreateOutcome::Deferred,
                    Err(error) => {
                        self.local_failure = self.failure_facts(r, key, 23, admission_ns, error);
                        return CreateOutcome::Rejected(error);
                    }
                }
            } else {
                None
            };
            // The task lock covers reservation, construction and rollback. No
            // other CPU can dispatch this reserved key before construction ends.
            *self.generation = generation;
            match self.build(r, slot, key, reservation, &mut trace) {
                Ok(()) => {
                    #[cfg(not(test))]
                    crate::learning_evidence::execution_trace::created(
                        crate::learning_evidence::execution_trace::Child {
                            group: r.group,
                            child: key,
                            parent: r.caller,
                            request_id: r.request_id,
                            at: now_ns(),
                        },
                    );
                    CreateOutcome::Created(key)
                }
                Err(error) => {
                    let failure = self.failure_facts(r, key, trace.stage, trace.entered_ns, error);
                    if self.rollback(slot, key).is_ok() {
                        self.local_failure = failure;
                        CreateOutcome::Rejected(error)
                    } else {
                        self.tasks[slot].life = Life::Exiting;
                        self.tasks[slot].failure = Some(error);
                        CreateOutcome::Uncertain
                    }
                }
            }
        };
        if let Some(source) = source {
            crate::learning_evidence::measure(
                source,
                cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
                body,
            )
        } else {
            body()
        }
    }
}
fn effective_layout(s: &State) -> CpuLayout {
    CpuLayout {
        business_mask: s.layout.business_mask & !s.draining,
        ..s.layout
    }
}
pub(super) fn submit_locked(
    s: &mut State,
    caller: ObjectKey,
    id: u64,
    target: ObjectKey,
    input: &[u8],
    cpu: u16,
    deadline: u64,
    recovery: bool,
    recipe: u16,
) -> Result<SpawnState, Error> {
    s.facts.attempts = s.facts.attempts.saturating_add(1);
    if (1..=16).contains(&target.id) {
        s.facts.spawn[(target.id - 1) as usize].add(now_ns(), 1);
    }
    let result = submit_package(
        s, PACKAGE, caller, id, target, input, cpu, deadline, recovery, recipe,
    );
    if matches!(result, Err(_) | Ok(SpawnState::Failed(_))) {
        s.facts.rejected = s.facts.rejected.saturating_add(1);
    }
    result
}
fn submit_package(
    s: &mut State,
    package: ObjectKey,
    caller: ObjectKey,
    id: u64,
    target: ObjectKey,
    input: &[u8],
    cpu: u16,
    deadline: u64,
    recovery: bool,
    recipe: u16,
) -> Result<SpawnState, Error> {
    if input.is_empty() || input.len() > 4096 || !input.len().is_multiple_of(8) || id == 0 {
        return Err(Error::Format);
    }
    let mut hash = Sha256::new();
    hash.update(input);
    hash.update(cpu.to_le_bytes());
    hash.update(deadline.to_le_bytes());
    hash.update(recipe.to_le_bytes());
    let request = SpawnRequest {
        caller,
        request_id: id,
        package,
        group: target,
        payload_hash: hash.finalize().into(),
        recovery,
    };
    if let Ok(old) = s.admission.request(caller, id) {
        return if old == request {
            s.admission.query(caller, id)
        } else {
            Err(Error::Conflict)
        };
    }
    let now = now_ns();
    let maximum_ns = if package == CLIENT_PACKAGE && crate::storage_fault_capture::PROFILE {
        crate::storage_fault_capture::launch_deadline_ns(input)
            .unwrap_or(super::deadline::ORDINARY_NS)
    } else {
        super::deadline::ORDINARY_NS
    };
    if !super::deadline::valid(now, deadline, recipe, maximum_ns) {
        return Err(Error::Range);
    }
    if cpu >= 64 || s.draining & (1u64 << cpu) != 0 {
        return Err(Error::NotReady);
    }
    let range = if recovery { 64..LAUNCHES } else { 0..64 };
    let slot = range
        .into_iter()
        .find(|i| s.launches[*i].request.is_none())
        .ok_or(Error::Again)?;
    let launch = &mut s.launches[slot];
    launch.request = Some(request);
    launch.cpu = cpu;
    launch.deadline = deadline;
    launch.len = input.len();
    launch.recipe = recipe;
    launch.input[..input.len()].copy_from_slice(input);
    let layout = effective_layout(s);
    let mut backend = Creator {
        tasks: &mut s.tasks,
        launches: &s.launches,
        memory: &mut s.memory,
        scheduler: &mut s.scheduler,
        services: &mut s.services,
        ipc: &mut s.ipc,
        background: &mut s.background,
        layout,
        remote: s.remote,
        generation: &mut s.generation,
        local_failure: None,
    };
    let result = s.admission.submit(request, now_ns(), &mut backend);
    if !matches!(result, Ok(SpawnState::Queued)) {
        s.launches[slot].input.fill(0);
        s.launches[slot].request = None;
    }
    result
}
pub fn submit_spawn(
    caller: ObjectKey,
    id: u64,
    target: ObjectKey,
    input: &[u8],
    cpu: u16,
    deadline: u64,
    recovery: bool,
) -> Result<SpawnState, Error> {
    locked(|s| submit_locked(s, caller, id, target, input, cpu, deadline, recovery, 0))
}
pub fn query_spawn(caller: ObjectKey, id: u64) -> Result<SpawnState, Error> {
    locked(|s| s.admission.query(caller, id))
}
pub fn cancel_spawn(caller: ObjectKey, id: u64) -> Result<SpawnState, Error> {
    locked(|s| s.admission.cancel(caller, id))
}
pub fn submit_local(id: u64, input: &[u8], deadline: u64) -> Result<SpawnState, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let entered_ns = now_ns();
        let result = submit_locked(
            s,
            CLUSTER_CALLER,
            id,
            group(5),
            input,
            3,
            deadline,
            false,
            0,
        );
        if let Err(error) = result {
            // Lock contention and the explicit no-custody retry errors are
            // not terminal receipts and must not consume the first-failure ABI.
            if !matches!(error, Error::Busy | Error::Again | Error::NotReady) {
                local_evidence::retain(local_evidence::Failure::capture(
                    local_evidence::Event {
                        stage: 1,
                        error,
                        observed_ns: now_ns(),
                        spawn_id: id,
                        deadline_ns: deadline,
                        task: ZERO,
                        cpu: 3,
                        group: group(5),
                        layout: effective_layout(s),
                        entered_ns,
                    },
                    &s.scheduler,
                ));
            }
        }
        result
    })
}
pub fn query_local(id: u64) -> Result<SpawnState, Error> {
    locked(|s| s.admission.query(CLUSTER_CALLER, id))
}
/// A LOCAL placement is complete only after its real EL0 result and full
/// task/resource cleanup have produced the retained exit receipt.
pub fn local_result(id: u64) -> Result<Option<(u64, u64)>, Error> {
    locked(|s| match s.admission.query(CLUSTER_CALLER, id)? {
        SpawnState::Created(key) => match s
            .exits
            .iter()
            .flatten()
            .find(|v| v.key == key && v.parent == CLUSTER_CALLER)
        {
            Some(v) if v.code == 0 => Ok(Some((v.value, v.finished_ns))),
            Some(v) if v.code == 110 => Err(Error::Expired),
            Some(_) => Err(Error::Io),
            None => Ok(None),
        },
        SpawnState::Queued | SpawnState::Unknown => Ok(None),
        SpawnState::Failed(e) => Err(e),
        SpawnState::Cancelled => Err(Error::Expired),
    })
}
/// The network owner acknowledges only after retaining this exact completion.
/// Dropping an exit is never used to decide that execution completed.
pub fn acknowledge_local_result(id: u64) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| match s.admission.query(CLUSTER_CALLER, id)? {
        SpawnState::Created(key) => {
            if s.tasks.iter().any(|t| t.key == key && t.life != Life::Free)
                || s.active.iter().flatten().any(|a| a.dispatch.thread == key)
            {
                return Err(Error::Busy);
            }
            if let Some(at) = s
                .exits
                .iter()
                .position(|v| v.is_some_and(|v| v.key == key && v.parent == CLUSTER_CALLER))
            {
                s.exits[at] = None;
            }
            Ok(())
        }
        SpawnState::Failed(_) | SpawnState::Cancelled => Ok(()),
        SpawnState::Queued | SpawnState::Unknown => Err(Error::Busy),
    })
}

pub(super) fn wake_task(s: &mut State, i: usize) {
    let key = s.tasks[i].key;
    if s.throttled.iter().flatten().any(|(k, _)| *k == key) {
        return;
    }
    if s.tasks[i].blocked {
        if let Ok(group) = group_index(s, s.tasks[i].group) {
            s.facts.wakes[group].add(now_ns(), 1);
        }
        s.tasks[i].blocked = false;
    }
    if s.tasks[i].life == Life::Ready {
        let _ = s.scheduler.set_runnable(key, true, now_ns());
    }
    if let Some(active) = s
        .active
        .get_mut(usize::from(s.tasks[i].cpu))
        .and_then(Option::as_mut)
        && active.dispatch.thread == key
    {
        active.state = RunState::Runnable;
    }
}
fn cleanup(s: &mut State, i: usize) -> Result<(), Error> {
    #[cfg(not(test))]
    let traced = replay::drain_task_facts(s, i).map(|facts| (facts, now_ns()));
    let result = if let Some(source) =
        replay::work_source(s.tasks[i].parent, s.tasks[i].spawn_id, s.tasks[i].recipe)
    {
        crate::learning_evidence::measure_paid_task(
            source,
            cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
            |entry| {
                if let Some(entry) = entry {
                    entry.observe(|| capture_task_identity(&s.tasks[i], 2));
                }
                cleanup_inner(s, i)
            },
        )
    } else {
        cleanup_inner(s, i)
    };
    #[cfg(not(test))]
    if let Some((facts, entered)) = traced {
        crate::learning_evidence::execution_trace::drain_cleanup(
            facts,
            result,
            entered,
            now_ns(),
            s.tasks[i].life as u64 + 1,
        );
    }
    result
}
fn cleanup_inner(s: &mut State, i: usize) -> Result<(), Error> {
    let key = s.tasks[i].key;
    if FILE_BUSY[i].load(Ordering::Acquire)
        || s.active.iter().flatten().any(|a| a.dispatch.thread == key)
    {
        return Err(Error::Busy);
    }
    if s.tasks[i].exit_code == 0 && !s.tasks[i].terminal_seen {
        s.tasks[i].exit_code = 5;
    }
    let exit_slot = if s.tasks[i].recipe == 0 && s.tasks[i].failure.is_none() {
        Some(
            s.exits
                .iter()
                .position(|record| record.is_none_or(|record| record.key == key))
                .ok_or(Error::Capacity)?,
        )
    } else {
        None
    };
    crate::domain_file_abi::exit(key)?;
    match s.scheduler.remove(key) {
        Ok(()) | Err(Error::Stale) => {}
        Err(e) => return Err(e),
    }
    s.services.revoke_owner(key);
    s.services.revoke_object(key);
    abi::release_vector_leases(s, i)?;
    s.vectors[i] = None;
    s.ipc.exit(
        key,
        &mut abi::Mailbox {
            tasks: &s.tasks,
            wake: &mut s.wake,
            received: &mut [],
            used: 0,
        },
    );
    let mut pages = Pages {
        tasks: &s.tasks,
        remote: s.remote,
        load: None,
    };
    for base in s.tasks[i].regions[..s.tasks[i].region_count]
        .iter()
        .copied()
    {
        match s.memory.unmap_step(key, base, 64, &mut pages) {
            Ok(p) if p.remaining == 0 => {}
            Err(Error::NotFound) => {}
            _ => return Err(Error::Busy),
        }
    }
    match s.memory.unregister_owner(key) {
        Ok(()) | Err(Error::Stale) => {}
        Err(e) => return Err(e),
    }
    if let Some(error) = s.tasks[i].failure {
        let entered_ns = now_ns();
        let reconciled = s.admission.reconcile(
            s.tasks[i].parent,
            s.tasks[i].spawn_id,
            CreateOutcome::Rejected(error),
        );
        if s.tasks[i].parent == CLUSTER_CALLER && reconciled == Ok(SpawnState::Failed(error)) {
            local_evidence::retain(local_evidence::Failure::capture(
                local_evidence::Event {
                    stage: 30,
                    error,
                    observed_ns: now_ns(),
                    spawn_id: s.tasks[i].spawn_id,
                    deadline_ns: s.tasks[i].deadline,
                    task: key,
                    cpu: s.tasks[i].cpu,
                    group: s.tasks[i].group,
                    layout: effective_layout(s),
                    entered_ns,
                },
                &s.scheduler,
            ));
        }
    } else {
        let _ = s.admission.exited(key);
    }
    if s.tasks[i].optional {
        s.background.set_commitment(s.tasks[i].group, 0, now_ns())?;
    }
    unsafe {
        for frame in i * 3..i * 3 + 3 {
            core::ptr::write_bytes(frame_ptr(frame)?, 0, 4096);
        }
        *core::ptr::addr_of_mut!(CONTEXTS)
            .cast::<user::Context>()
            .add(i) = user::Context::empty();
    }
    synchronize();
    replay::member_retired(key);
    RETURN_PENDING[i].store(false, Ordering::Release);
    FILE_PENDING[i].store(false, Ordering::Release);
    FILE_DONE[i].store(false, Ordering::Release);
    if s.probe_key == Some(key) {
        s.probe_exit = Some(s.tasks[i].exit_code);
    }
    if let Some(slot) = exit_slot {
        s.exits[slot] = Some(ExitRecord {
            key,
            parent: s.tasks[i].parent,
            code: s.tasks[i].exit_code,
            value: s.tasks[i].response,
            finished_ns: now_ns(),
        });
    }
    s.generation = s.generation.checked_add(1).ok_or(Error::Overflow)?;
    if s.tasks[i].recipe == 0 {
        s.tasks[i] = Task::EMPTY;
    } else {
        s.tasks[i].life = Life::Free;
        s.tasks[i].region_count = 0;
        s.tasks[i].endpoint = ZERO;
        s.tasks[i].pending = false;
    }
    Ok(())
}
fn advance_admission(s: &mut State) -> Result<(), Error> {
    advance_admission_bounded(s, 4, LAUNCHES)
}
fn advance_admission_bounded(s: &mut State, maximum: usize, cleanup: usize) -> Result<(), Error> {
    for _ in 0..maximum {
        let layout = effective_layout(s);
        let mut backend = Creator {
            tasks: &mut s.tasks,
            launches: &s.launches,
            memory: &mut s.memory,
            scheduler: &mut s.scheduler,
            services: &mut s.services,
            ipc: &mut s.ipc,
            background: &mut s.background,
            layout,
            remote: s.remote,
            generation: &mut s.generation,
            local_failure: None,
        };
        let entered_ns = now_ns();
        let selected = s.admission.service_one(entered_ns, &mut backend)?;
        #[cfg(not(test))]
        if let Some((request, value)) = &selected {
            crate::learning_evidence::execution_trace::admitted(
                request,
                *value,
                now_ns(),
                s.active[0].map_or(0, |v| v.dispatch.sequence),
            );
        }
        match selected {
            None => break,
            Some((request, SpawnState::Failed(error))) => {
                // The original constructor snapshot becomes visible only
                // after SpawnAdmission has actually retained Failed(error).
                if let Some(failure) = backend
                    .local_failure
                    .take()
                    .or_else(|| backend.failure_facts(&request, ZERO, 2, entered_ns, error))
                {
                    local_evidence::retain(failure);
                }
                s.facts.rejected = s.facts.rejected.saturating_add(1)
            }
            Some(_) => {}
        }
    }
    for _ in 0..cleanup {
        let index = s.launch_cursor;
        s.launch_cursor = (index + 1) % LAUNCHES;
        let launch = &mut s.launches[index];
        if let Some(request) = launch.request
            && matches!(
                s.admission.query(request.caller, request.request_id),
                Ok(SpawnState::Created(_) | SpawnState::Failed(_) | SpawnState::Cancelled)
            )
        {
            launch.input.fill(0);
            launch.request = None;
        }
    }
    Ok(())
}
fn capture_task_identity(task: &Task, site: u64) -> crate::learning_evidence::TaskIdentity {
    crate::learning_evidence::TaskIdentity {
        site,
        caller: task.parent,
        request: task.spawn_id,
        child: task.key,
        recipe: task.recipe,
    }
}
fn recipe_turn(s: &mut State, i: usize) -> Result<(), Error> {
    let warm = if s.tasks[i].recipe == 2
        && crate::domain_services::replay::owns(2)
        && !s.tasks[i].pending
        && s.ipc.stats(s.tasks[i].endpoint).is_ok_and(|v| v.depth != 0)
    {
        service_witness_locked(s)
            .ok()
            .and_then(|paid| crate::learning_prewarm::attempt_paid_service(&paid))
    } else {
        None
    };
    let cpu_started = timer::cpu_ticks();
    let result = if let Some(source) =
        replay::work_source(s.tasks[i].parent, s.tasks[i].spawn_id, s.tasks[i].recipe)
    {
        crate::learning_evidence::measure_paid_task(
            source,
            cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
            |entry| {
                if let Some(entry) = entry {
                    entry.observe(|| capture_task_identity(&s.tasks[i], 3));
                }
                recipe_turn_inner(s, i)
            },
        )
    } else {
        recipe_turn_inner(s, i)
    };
    if let Some(mut warm) = warm {
        let (first_ns, last_ns, _) = finish_cpu_interval(cpu_started);
        let _ = crate::learning_prewarm::finish(&mut warm, first_ns, last_ns);
    }
    result
}
fn recipe_turn_inner(s: &mut State, i: usize) -> Result<(), Error> {
    let task = s.tasks[i];
    if task.recipe == 0
        || task.life != Life::Ready
        || task.pending
        || s.active
            .iter()
            .flatten()
            .any(|a| a.dispatch.thread == task.key)
    {
        return Ok(());
    }
    let mut bytes = [0u8; 40];
    let mut backend = abi::Mailbox {
        tasks: &s.tasks,
        wake: &mut s.wake,
        received: &mut bytes,
        used: 0,
    };
    let count = s
        .ipc
        .receive_batch(task.key, task.endpoint, now_ns(), &mut backend)?;
    if count == 0 {
        return Ok(());
    }
    let sequence = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| Error::Format)?);
    prepare(
        &mut s.memory,
        &s.tasks,
        s.remote,
        task.key,
        0x21000,
        8,
        false,
    )?;
    copy_to(&s.memory, task.key, 0x21000, &bytes[32..40])?;
    unsafe {
        let context = &mut *core::ptr::addr_of_mut!(CONTEXTS)
            .cast::<user::Context>()
            .add(i);
        *context = user::Context::empty();
        context.pc = 0x10000;
        context.sp = 0x41000;
    }
    s.tasks[i].pending = true;
    s.tasks[i].pending_sequence = sequence;
    wake_task(s, i);
    Ok(())
}
#[inline]
fn diagnostic_service_stage(stage: u64) {
    #[cfg(feature = "unified-runtime")]
    crate::unified::service_stage(stage);
    if crate::storage_fault_capture::PROFILE {
        DOMAIN_TASK_EVIDENCE.words[9].store(stage, Ordering::Relaxed);
        DOMAIN_TASK_EVIDENCE.words[10]
            .store(CREDIT_KIND[0].load(Ordering::Acquire), Ordering::Relaxed);
        DOMAIN_TASK_EVIDENCE.words[11].store(
            u64::from(COMPLETE_READY[0].load(Ordering::Acquire)),
            Ordering::Release,
        );
    }
    #[cfg(not(feature = "unified-runtime"))]
    let _ = stage;
}

pub fn service(_now: u64, progress: &mut dyn FnMut()) {
    if !READY.load(Ordering::Acquire) || cpu::slot() != 0 {
        return;
    }
    // Use the current metadata turn for an already-owned 50 ms snapshot
    // before general work can consume it. If general replay creates the first
    // snapshot on this pass, retain its existing after-general opportunity.
    let baseline_was_pending = crate::learning_replay::baseline_activation_pending();
    if baseline_was_pending {
        service_baseline_activation();
    }
    // One bounded owner piece per pass. A deferred piece retains its cursor;
    // file/DMA waits run in service_file's separately billed caller segments.
    diagnostic_service_stage(70);
    let _ = service_segment(|| {
        let external = locked(|s| {
            let phase = s.service_phase;
            s.service_phase = (phase + 1) % 11;
            vector_diagnostics::phase(phase);
            #[cfg(feature = "unified-runtime")]
            crate::unified::service_stage(10 + phase as u64);
            match phase {
                0 => {
                    lifecycle_turn(s);
                }
                1 => {
                    let _ = advance_admission_bounded(s, 1, 1);
                }
                // Vector dispatch has its own prepaid opportunity below, like
                // the file pump, rather than waiting for this phase rotation.
                2 => {}
                3 => ipc_piece(s),
                4 => memory_piece(s),
                5 | 7 | 8 | 9 | 10 => {}
                _ => metrics_piece(s),
            }
            publish_evidence(s);
            Ok(phase)
        });
        if external == Ok(5) {
            // This owner call only evicts clean, unpinned pages. Dirty writeback
            // is progressed by the storage service with its own I/O callbacks.
            let cpu_started = timer::cpu_ticks();
            let _ = crate::domain_storage::cache_reclaim_turn();
            let (_, finished_ns, actual_ns) = finish_cpu_interval(cpu_started);
            let _ = locked(|s| {
                s.facts.reclaim_ns.add(finished_ns, actual_ns);
                record_cache_receipt(s, finished_ns);
                Ok(())
            });
        }
        if external == Ok(7) {
            // Runs with this exact still-live kind-5 service reservation,
            // outside the task gate. Safety work can restore an exact baseline
            // even when the optional C1 worker's extra ledger is faulted.
            // It neither acknowledges unknown numerical work nor frees pins.
            let _ = crate::learning_session::safety_turn();
        }
        if external == Ok(8) {
            // The registered, immutable service boundary consumes actual
            // capture rows under this independently prepaid owner turn.
            // Its cursor and any incomplete window survive a Busy return.
            let _ = crate::service_windows::poll();
        }
        if external == Ok(9) {
            // The replay coordinator is a separate bounded, prepaid owner
            // piece; its frozen arrivals never run on an unpaid timer path.
            let _ = crate::learning_replay::service_step();
        }
        if external == Ok(10) {
            let _ = crate::peer_replay::poll();
        }
    });
    if !baseline_was_pending {
        service_baseline_activation();
    }
    service_vectors();
    diagnostic_service_stage(71);
    service_file(progress);
    diagnostic_service_stage(72);
    crate::learning_workload::service_io(progress);
    diagnostic_service_stage(73);
    crate::learning_replay::service_io(progress);
    diagnostic_service_stage(74);
}
/// Preserve the general owner's settlement order and fair single-item turn.
/// Callers must already hold TaskGuard inside a live paid service piece.
fn lifecycle_turn(s: &mut State) {
    // A completion cannot exist outside the currently owned CPU layout: moves
    // close admission and wait for quiescence before changing these masks.
    let mut owned = s.layout.healthy_mask;
    while owned != 0 {
        let slot = owned.trailing_zeros() as usize;
        owned &= owned - 1;
        if COMPLETE_READY[slot].load(Ordering::Acquire) {
            let _ = complete_locked(s, slot);
        }
    }
    // The original rotating selector includes expired blocked callers and
    // advances even when a particular cleanup must retain its resources.
    let i = lifecycle::select::<TASKS>(s.lifecycle_cursor, now_ns(), |i| lifecycle::View {
        occupied: !matches!(s.tasks[i].life, Life::Free | Life::Exiting),
        exiting: s.tasks[i].life == Life::Exiting,
        deadline_ns: s.tasks[i].deadline,
        return_pending: RETURN_PENDING[i].load(Ordering::Acquire),
        file_done: FILE_DONE[i].load(Ordering::Acquire),
        file_busy: FILE_BUSY[i].load(Ordering::Acquire),
    });
    s.lifecycle_cursor = (i + 1) % TASKS;
    lifecycle_piece(s, i);
}
fn lifecycle_piece(s: &mut State, i: usize) {
    #[cfg(not(test))]
    let traced = replay::drain_task_facts(s, i).map(|facts| (facts, now_ns()));
    if RETURN_PENDING[i].load(Ordering::Acquire)
        && !s
            .active
            .iter()
            .flatten()
            .any(|a| a.dispatch.thread == s.tasks[i].key)
    {
        unsafe {
            process_return(
                s,
                i,
                &mut *core::ptr::addr_of_mut!(CONTEXTS)
                    .cast::<user::Context>()
                    .add(i),
            );
        }
    }
    if FILE_DONE[i].swap(false, Ordering::AcqRel) {
        FILE_BUSY[i].store(false, Ordering::Release);
        if !FILE_PENDING[i].load(Ordering::Acquire) && s.tasks[i].life == Life::Waiting {
            s.tasks[i].life = Life::Ready;
            wake_task(s, i);
        }
    }
    if !matches!(s.tasks[i].life, Life::Free | Life::Exiting)
        && now_ns() >= s.tasks[i].deadline
        && !FILE_BUSY[i].load(Ordering::Acquire)
    {
        s.tasks[i].exit_code = 110;
        s.tasks[i].life = Life::Exiting;
    }
    if s.tasks[i].life == Life::Exiting {
        let _ = cleanup(s, i);
    }
    #[cfg(not(test))]
    if let Some((facts, entered)) = traced {
        crate::learning_evidence::execution_trace::drain_lifecycle(
            facts,
            entered,
            now_ns(),
            s.tasks[i].life as u64 + 1,
        );
    }
}
static BASELINE_RETRY_ACTIVE: AtomicBool = AtomicBool::new(false);
struct BaselineRetryGuard {
    _local: core::marker::PhantomData<*mut ()>,
}
impl Drop for BaselineRetryGuard {
    fn drop(&mut self) {
        BASELINE_RETRY_ACTIVE.store(false, Ordering::Release);
    }
}
fn enter_baseline_retry() -> Option<BaselineRetryGuard> {
    if cpu::slot() != 0 || !READY.load(Ordering::Acquire) {
        return None;
    }
    BASELINE_RETRY_ACTIVE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .ok()
        .map(|_| BaselineRetryGuard {
            _local: core::marker::PhantomData,
        })
}
fn service_baseline_activation() {
    service_baseline_activation_at(1);
}
/// Targeted opportunities after suspended I/O has submitted its old bill.
/// Bounded admission and owned-Drain lifecycle may each follow under separate
/// fresh credit. No old reservation is reused or general I/O pump entered.
pub fn service_baseline_progress() {
    if crate::learning_replay::baseline_activation_pending() {
        service_baseline_activation_at(2);
    }
}
fn service_baseline_activation_at(site: u64) {
    // Main-loop and progress paths share this gate. A nested I/O callback must
    // not overwrite the outer diagnostic ticket or enter another helper body.
    let Some(_entry) = enter_baseline_retry() else {
        return;
    };
    let hint = crate::learning_replay::baseline_activation_pending();
    let ticket = baseline_diagnostics::opportunity(
        hint,
        site,
        CREDIT_KIND[0].load(Ordering::Acquire),
        COMPLETE_READY[0].load(Ordering::Acquire),
    );
    if hint {
        // Only already-owned activation/execution custody gets this retry
        // opportunity. Its original snapshot and deadlines remain authoritative.
        // Each attempt needs fresh physical credit and settles before vectors
        // or file work. General replay phases keep their normal rotation.
        let outcome = service_segment(|| {
            baseline_diagnostics::body_start(
                ticket,
                CREDIT_NS[0].load(Ordering::Acquire),
                CREDIT_KIND[0].load(Ordering::Acquire),
            );
            let started = timer::cpu_ticks();
            let result = crate::learning_replay::service_step();
            baseline_diagnostics::body_finish(ticket, &result, timer::cpu_elapsed_ns(started));
            result
        });
        baseline_diagnostics::finish(
            ticket,
            outcome.is_some(),
            CREDIT_KIND[0].load(Ordering::Acquire),
            COMPLETE_READY[0].load(Ordering::Acquire),
        );
        // Publication alone is not execution. After the replay piece has
        // submitted its bill and released all owner borrows, offer one queued
        // construction a separate reservation. An unsettled prior bill or
        // insufficient fresh credit prevents this body from running. Keep the
        // shared retry guard held across all pieces, including nested progress.
        let root_ok = outcome.is_some_and(|result| result.is_ok());
        // Again can report a full launch cache or admission queue. Those
        // already-owned requests need independently paid progress even though
        // the probe itself could not enter. Other errors retain their rules.
        let root_again = matches!(outcome, Some(Err(Error::Again)));
        let pending = crate::learning_replay::baseline_activation_pending();
        #[cfg(not(test))]
        crate::learning_evidence::execution_trace::admission_opportunity(
            root_ok,
            root_again,
            pending,
            now_ns(),
        );
        if (root_ok || root_again) && pending {
            let admitted = service_segment(|| {
                locked(|s| {
                    #[cfg(not(test))]
                    crate::learning_evidence::execution_trace::admission_body(
                        s.active[0].map_or(0, |v| v.dispatch.sequence),
                        now_ns(),
                    );
                    // One queued construction and one 4 KiB terminal-proven
                    // launch cleanup, both inside this same fresh reservation.
                    advance_admission_bounded(s, 1, 1)
                })
            });
            #[cfg(not(test))]
            crate::learning_evidence::execution_trace::admission_result(
                admitted.is_some(),
                now_ns(),
            );
            let _ = admitted;
        }
        // Measurement delivery can require real task cleanup after Root has
        // completed. Recheck that independent owned-Drain reason, then request
        // another fresh reservation after both earlier pieces have returned.
        // A retained old bill or denied credit prevents this body from running.
        if (root_ok || root_again) && crate::learning_replay::owned_drain_pending() {
            let _ = service_segment(|| {
                locked(|s| {
                    lifecycle_turn(s);
                    Ok(())
                })
            });
        }
    }
}
fn service_vectors() {
    // Like file requests, queued read-only vectors get an independently paid
    // opportunity each pump pass. One opportunity still calls exactly one
    // policy-bounded batch; it cannot enlarge that policy or borrow file credit.
    let _ = service_segment(|| {
        locked(|s| {
            let next = (0..TASKS)
                .map(|n| (s.vector_cursor + n) % TASKS)
                .find(|&i| {
                    !matches!(s.tasks[i].life, Life::Free | Life::Exiting)
                        && (s.vectors[i].as_ref().is_some_and(|v| !v.complete())
                            || s.wake & (1u64 << i) != 0
                            || s.tasks[i].recipe != 0 && !s.tasks[i].pending)
                });
            let i = next.unwrap_or(s.vector_cursor);
            s.vector_cursor = (i + 1) % TASKS;
            vector_piece(s, i);
            publish_evidence(s);
            Ok(())
        })
    });
}
fn vector_piece(s: &mut State, i: usize) {
    if matches!(s.tasks[i].life, Life::Free | Life::Exiting) {
        return;
    }
    let _ = recipe_turn(s, i);
    let leases = if s.vectors[i].as_ref().is_some_and(|v| !v.complete()) {
        abi::prepare_vector_leases(s, i)
    } else {
        Ok(false)
    };
    let mut step_error = 0;
    if let Some(vector) = s.vectors[i].as_mut()
        && !vector.complete()
        && leases.unwrap_or(false)
    {
        let mut transport = abi::Transport {
            tasks: &s.tasks,
            validate: s.validate_file,
            stat: s.stat_file,
            ipc: &mut s.ipc,
            task_endpoint: s.task_endpoint,
            file_endpoint: s.file_endpoint,
            sequence: &mut s.service_sequence,
            lease: &mut s.vector_leases[i],
        };
        if let Err(error) = s.services.step(vector, now_ns(), &mut transport) {
            step_error = error as u64 + 1;
        }
    }
    if let Some(vector) = s.vectors[i].as_ref() {
        let now = now_ns();
        let stats = s.services.stats();
        vector_diagnostics::vector([
            now,
            s.tasks[i].key.id,
            s.tasks[i].key.generation,
            s.vector_ids[i],
            s.facts.vector_started[i],
            s.vector_leases[i].deadline,
            u64::from(s.vector_leases[i].needed),
            u64::from(s.vector_leases[i].ready),
            leases.err().map_or(0, |error| error as u64 + 1),
            step_error,
            vector.results().len() as u64,
            vector
                .results()
                .iter()
                .filter(|result| result.status == ItemStatus::Pending)
                .count() as u64,
            stats.items,
            stats.ipc_calls,
            stats.completed,
            stats.errors,
            u64::from(s.services.policy(now)),
        ]);
    }
    if !s.facts.vector_measured[i] && s.vectors[i].as_ref().is_some_and(SubmitVector::complete) {
        s.facts
            .vector_latency
            .add(now_ns().saturating_sub(s.facts.vector_started[i]));
        s.facts.vector_measured[i] = true;
    }
    if s.vectors[i].as_ref().is_some_and(SubmitVector::complete) {
        let _ = abi::release_vector_leases(s, i);
    }
    if s.wake & (1u64 << i) != 0 {
        s.wake &= !(1u64 << i);
        if s.tasks[i].life == Life::Ready && (!s.tasks[i].optional || s.tasks[i].pending) {
            wake_task(s, i);
        }
    }
}
fn ipc_piece(s: &mut State) {
    // Cancellation can release the only occupied cell without a dequeue.
    // Polling real endpoints independently guarantees pending sender progress.
    for offset in 0..TASKS {
        let i = (s.cursor + offset) % TASKS;
        if s.tasks[i].life == Life::Free || s.tasks[i].endpoint == ZERO {
            continue;
        }
        let endpoint = s.tasks[i].endpoint;
        s.cursor = (i + 1) % TASKS;
        let _ = s.ipc.service_waiters(
            endpoint,
            now_ns(),
            &mut abi::Mailbox {
                tasks: &s.tasks,
                wake: &mut s.wake,
                received: &mut [],
                used: 0,
            },
        );
        break;
    }
    s.ipc.flush_notifications(&mut abi::Mailbox {
        tasks: &s.tasks,
        wake: &mut s.wake,
        received: &mut [],
        used: 0,
    });
}
fn memory_piece(s: &mut State) {
    let cpu_started = timer::cpu_ticks();
    memory::synchronize_cache(s);
    let _ = s.memory.reclaim_step(
        0,
        now_ns(),
        &mut Pages {
            tasks: &s.tasks,
            remote: s.remote,
            load: None,
        },
    );
    let (_, finished_ns, actual_ns) = finish_cpu_interval(cpu_started);
    s.facts.reclaim_ns.add(finished_ns, actual_ns);
    let faults = s.memory.stats().faults;
    s.facts
        .faults
        .add(now_ns(), faults.saturating_sub(s.facts.last_faults));
    s.facts.last_faults = faults;
}
fn metrics_piece(s: &mut State) {
    let ordinal = s.metrics_cursor;
    s.metrics_cursor = (ordinal + 1) % 32;
    if let Some(key) = s.ipc.endpoint_at(ordinal)
        && let Ok(stats) = s.ipc.stats(key)
    {
        let i = (key.id - 1) as usize;
        if s.facts.ipc_generation[i] != key.generation {
            s.facts.ipc_generation[i] = key.generation;
            s.facts.ipc_admitted[i] = 0;
            s.facts.ipc_messages[i] = Rate::EMPTY;
        }
        s.facts.ipc_messages[i].add(
            now_ns(),
            stats.admitted.saturating_sub(s.facts.ipc_admitted[i]),
        );
        s.facts.ipc_admitted[i] = stats.admitted;
    }
}

fn process_return(s: &mut State, i: usize, c: &mut user::Context) {
    // The real C3 credit already includes its direct EL0 return handling.
    // Only a deferred C0 lifecycle return needs a separate service segment.
    if cpu::slot() != 0 {
        process_return_inner(s, i, c);
        return;
    }
    let warm = if s.tasks[i].recipe == 2 && crate::domain_services::replay::owns(2) {
        service_witness_locked(s)
            .ok()
            .and_then(|paid| crate::learning_prewarm::attempt_paid_service(&paid))
    } else {
        None
    };
    let cpu_started = timer::cpu_ticks();
    if let Some(source) =
        replay::work_source(s.tasks[i].parent, s.tasks[i].spawn_id, s.tasks[i].recipe)
    {
        crate::learning_evidence::measure_paid_task(
            source,
            cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
            |entry| {
                if let Some(entry) = entry {
                    entry.observe(|| capture_task_identity(&s.tasks[i], 4));
                }
                process_return_inner(s, i, c)
            },
        );
    } else {
        process_return_inner(s, i, c);
    }
    if let Some(mut warm) = warm {
        let (first_ns, last_ns, _) = finish_cpu_interval(cpu_started);
        let _ = crate::learning_prewarm::finish(&mut warm, first_ns, last_ns);
    }
}
fn process_return_inner(s: &mut State, i: usize, c: &mut user::Context) {
    let key = s.tasks[i].key;
    let mut state = RunState::Runnable;
    if s.tasks[i].life == Life::Exiting {
        state = RunState::Exited;
    } else if now_ns() >= s.tasks[i].deadline {
        s.tasks[i].exit_code = 110;
        s.tasks[i].life = Life::Exiting;
        state = RunState::Exited;
    } else if c.kind == 9 {
        s.tasks[i].life = Life::Ready;
    } else if c.kind == 8 && c.esr >> 26 == 0x15 && c.esr & 0xffff == 0x44 {
        s.tasks[i].terminal_seen = true;
        let mut output = [0u8; 16];
        let result = copy_from(&s.memory, &s.tasks, key, 0x30000, &mut output);
        let status = u64::from_le_bytes(output[..8].try_into().unwrap());
        if s.tasks[i].recipe != 0 && result.is_ok() && status == 0 {
            let task = &mut s.tasks[i];
            task.response = u64::from_le_bytes(output[8..].try_into().unwrap());
            task.completed_sequence = task.pending_sequence;
            task.pending = false;
            task.life = Life::Ready;
            task.heartbeat_ns = now_ns();
            state = RunState::Blocked;
        } else {
            s.tasks[i].exit_code = if result.is_ok() { status } else { 5 };
            s.tasks[i].response = u64::from_le_bytes(output[8..].try_into().unwrap());
            s.tasks[i].life = Life::Exiting;
            state = RunState::Exited;
        }
    } else if c.kind == 8 && c.esr >> 26 == 0x15 && c.esr & 0xffff == 0x45 {
        if c.regs[8] == 0x40 {
            s.tasks[i].life = Life::Waiting;
            state = RunState::Blocked;
            FILE_PENDING[i].store(true, Ordering::Release);
        } else {
            if let Err(error) = abi::syscall_locked(s, i, c) {
                c.regs[0] = error_word(error);
            }
            if s.tasks[i].life == Life::Exiting {
                state = RunState::Exited;
            } else {
                s.tasks[i].life = Life::Ready;
            }
        }
    } else if abi::fault_locked(s, key, c).is_ok() {
        s.tasks[i].life = Life::Ready;
    } else {
        s.tasks[i].life = Life::Exiting;
        s.tasks[i].exit_code = 14;
        state = RunState::Exited;
    }
    if let Some(active) = s
        .active
        .iter_mut()
        .flatten()
        .find(|a| a.dispatch.thread == key)
    {
        active.state = state;
    } else {
        let _ = s
            .scheduler
            .set_runnable(key, state == RunState::Runnable, now_ns());
    }
    s.tasks[i].blocked = state != RunState::Runnable;
    RETURN_PENDING[i].store(false, Ordering::Release);
}
pub fn dispatch(slot: usize) -> bool {
    if slot >= 64 || CREDIT_KIND[slot].load(Ordering::Acquire) != 3 {
        return false;
    }
    let selected = locked(|s| {
        let active = s.active[slot].ok_or(Error::Stale)?;
        let i = task_index(&s.tasks, active.dispatch.thread)?;
        if s.tasks[i].life == Life::Exiting {
            if let Some(a) = s.active[slot].as_mut() {
                a.state = RunState::Exited;
            }
            return Ok(None);
        }
        if RETURN_PENDING[i].load(Ordering::Acquire) || FILE_BUSY[i].load(Ordering::Acquire) {
            return Err(Error::Busy);
        }
        let task = crate::a02_capture::Task {
            id: s.tasks[i].key.id,
            generation: s.tasks[i].key.generation,
            role: 1,
            affinity: s.scheduler.thread_affinity(s.tasks[i].key)?,
        };
        if !s.tasks[i].capture_ready {
            return Ok(Some((i, 0, s.tasks[i].deadline, task, None, false)));
        }
        s.tasks[i].life = Life::Running;
        s.tasks[i].entered = true;
        if let Some(a) = s.active[slot].as_mut() {
            a.state = RunState::Blocked;
        }
        Ok(Some((
            i,
            frame_phys(i * 3)?,
            s.tasks[i].deadline,
            task,
            s.tasks[i].capture_index,
            true,
        )))
    });
    let Ok(Some((i, root, deadline, task, capture_index, capture_ready))) = selected else {
        return true;
    };
    if !capture_ready {
        let capture_index = crate::a02_capture::prepare(task);
        let _ = locked(|s| {
            if s.tasks[i].key.id != task.id || s.tasks[i].key.generation != task.generation {
                return Err(Error::Stale);
            }
            s.tasks[i].capture_index = capture_index;
            s.tasks[i].capture_ready = true;
            Ok(())
        });
        return true;
    }
    unsafe {
        let context = &mut *core::ptr::addr_of_mut!(CONTEXTS)
            .cast::<user::Context>()
            .add(i);
        let end = ((u128::from(deadline) * u128::from(timer::frequency())) / 1_000_000_000)
            .min(u128::from(u64::MAX)) as u64;
        crate::smp::enter_service(
            context,
            root,
            timer::ticks().saturating_add(slice_ticks(slot)).min(end),
            task,
            capture_index,
            true,
            true,
        );
    }
    RETURN_PENDING[i].store(true, Ordering::Release);
    let _ = locked(|s| {
        unsafe {
            process_return(
                s,
                i,
                &mut *core::ptr::addr_of_mut!(CONTEXTS)
                    .cast::<user::Context>()
                    .add(i),
            );
        }
        Ok(())
    });
    true
}
/// One blocking owner operation, divided into actual CPU0 reservations at
/// every device-progress wait. The callback must retain the same operation's
/// custody; neither an unanswered I/O nor its payload may be resubmitted here.
/// Call outside another service_segment. `None` means no operation started.
pub fn service_io_piece<R>(
    source: Option<ObjectKey>,
    progress: &mut dyn FnMut(),
    body: impl FnOnce(&mut dyn FnMut()) -> R,
) -> Option<R> {
    begin_service_segment()?;
    if !revalidate_service_segment() {
        return None;
    }
    let mut cpu_started = timer::cpu_ticks();
    let mut capture = source.and_then(|key| {
        crate::learning_evidence::attempt(
            key,
            cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
        )
        .ok()
        .flatten()
    });
    if let Some(attempt) = capture.as_ref() {
        crate::learning_evidence::observe_service_io(attempt, cpu_started);
    }
    let mut resume = || {
        let (first_ns, finished_ns, actual_ns) = finish_cpu_interval(cpu_started);
        if let Some(mut attempt) = capture.take() {
            let _ = crate::learning_evidence::finish_attempt(&mut attempt, first_ns, finished_ns);
        }
        let _ = complete_service(actual_ns, finished_ns);
        loop {
            progress();
            if begin_service_segment().is_some() && revalidate_service_segment() {
                cpu_started = timer::cpu_ticks();
                capture = source.and_then(|key| {
                    crate::learning_evidence::attempt(
                        key,
                        cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
                    )
                    .ok()
                    .flatten()
                });
                if let Some(attempt) = capture.as_ref() {
                    crate::learning_evidence::observe_service_io(attempt, cpu_started);
                }
                break;
            }
            core::hint::spin_loop();
        }
    };
    let result = body(&mut resume);
    let (first_ns, finished_ns, actual_ns) = finish_cpu_interval(cpu_started);
    if let Some(mut attempt) = capture {
        let _ = crate::learning_evidence::finish_attempt(&mut attempt, first_ns, finished_ns);
    }
    let _ = complete_service(actual_ns, finished_ns);
    Some(result)
}

fn service_file(progress: &mut dyn FnMut()) {
    let Some(next) = service_segment(|| {
        locked(|s| {
            // A completed but undelivered receipt owns the file staging buffer.
            // Deliver it before admitting another caller, regardless of slot order.
            for priority in [true, false] {
                for i in 0..TASKS {
                    if FILE_PENDING[i].load(Ordering::Acquire)
                        && s.tasks[i].life == Life::Waiting
                        && (!priority || crate::domain_file_abi::pending_delivery(s.tasks[i].key))
                        && !s
                            .active
                            .iter()
                            .flatten()
                            .any(|a| a.dispatch.thread == s.tasks[i].key)
                    {
                        FILE_PENDING[i].store(false, Ordering::Release);
                        FILE_BUSY[i].store(true, Ordering::Release);
                        return Ok(Some((i, s.tasks[i].key)));
                    }
                }
            }
            Ok(None)
        })
    }) else {
        return;
    };
    let Ok(Some((i, key))) = next else {
        return;
    };
    let credit = begin_file_credit(key);
    crate::domain_file_abi::record_credit_attempt(
        key,
        credit
            .as_ref()
            .map(|credit| credit.is_some())
            .map_err(|error| *error),
    );
    if let Err(error @ (Error::Budget | Error::Auth | Error::Conflict | Error::Stale)) = credit {
        // A caller whose configured hard budget cannot ever cover a segment
        // is rejected before the file ABI executes any effect.
        unsafe {
            (*core::ptr::addr_of_mut!(CONTEXTS)
                .cast::<user::Context>()
                .add(i))
            .regs[0] = error_word(error);
        }
        FILE_DONE[i].store(true, Ordering::Release);
        return;
    }
    if !matches!(credit, Ok(Some(_))) {
        // No file operation has started. Preserve the captured SVC and its PTEs
        // until the caller and CPU0 both have physical execution credit.
        FILE_PENDING[i].store(true, Ordering::Release);
        FILE_BUSY[i].store(false, Ordering::Release);
        return;
    }
    let mut segment_started = timer::cpu_ticks();
    let mut file_progress = || {
        let (_, finished_ns, actual_ns) = finish_cpu_interval(segment_started);
        let _ = complete_builtin(0, actual_ns, finished_ns);
        // The operation remains in custody across budget windows. Completion,
        // network and policy progress run outside both its credit and Task gate;
        // the same suspended operation resumes only after another real grant.
        loop {
            progress();
            if matches!(begin_file_credit(key), Ok(Some(_))) {
                segment_started = timer::cpu_ticks();
                break;
            }
            core::hint::spin_loop();
        }
    };
    let retry_before_effect = unsafe {
        let context = &mut *core::ptr::addr_of_mut!(CONTEXTS)
            .cast::<user::Context>()
            .add(i);
        let disposition = crate::domain_file_abi::dispatch(key, context, &mut file_progress);
        if disposition == crate::domain_file_abi::DispatchResult::NotHandled {
            context.regs[0] = error_word(Error::Unsupported);
        }
        let retry = disposition == crate::domain_file_abi::DispatchResult::RetryBeforeEffect;
        if retry || crate::domain_file_abi::pending_delivery(key) {
            FILE_PENDING[i].store(true, Ordering::Release);
        }
        retry
    };
    let (_, finished_ns, actual_ns) = finish_cpu_interval(segment_started);
    let _ = complete_builtin(0, actual_ns, finished_ns);
    if retry_before_effect {
        // No operation or receipt was consumed. Keep the original stopped SVC
        // in CPU0 custody, so another bounded owner turn can retry without an
        // EL0 round trip. A delivered EAGAIN is Returned, never this branch.
        FILE_DONE[i].store(false, Ordering::Release);
        FILE_BUSY[i].store(false, Ordering::Release);
    } else {
        FILE_DONE[i].store(true, Ordering::Release);
    }
}

pub fn remote_capacity() -> [u64; 4] {
    locked(|s| {
        let healthy = s.layout.business_mask
            & s.layout.healthy_mask
            & !s.draining
            & !s.scheduler.stats().quarantine_mask;
        let ready = s.remote.is_none()
            && healthy & 8 != 0
            && s.scheduler.thread_count() < 64
            && s.scheduler.committed_ns(3) <= 80_000_000
            && s.memory.progress_free_pages() >= 3;
        Ok([
            if ready { 100 } else { 0 },
            if ready { 16 } else { 0 },
            s.layout.generation,
            s.generation,
        ])
    })
    .unwrap_or([0; 4])
}
pub fn remote_start(token: u64, leaf: u64) -> Result<(), Error> {
    locked(|s| {
        if token == 0 || leaf < crate::HIGH || !leaf.is_multiple_of(4096) {
            return Err(Error::Format);
        }
        let key = ObjectKey {
            id: REMOTE_ID,
            generation: token,
        };
        if let Some(remote) = s.remote {
            return if remote.key == key {
                Ok(())
            } else {
                Err(Error::Busy)
            };
        }
        if s.draining & 8 != 0 || s.memory.progress_free_pages() < 3 {
            return Err(Error::Capacity);
        }
        s.remote = Some(Remote {
            key,
            leaf,
            ended: false,
        });
        let result = (|| {
            s.memory.register_progress_owner(key, 3)?;
            s.memory.commit_pages(key)?;
            s.memory.reserve(key, 0x30000, 1, true)?;
            s.memory.reserve(key, 0x40000, 1, true)?;
            s.scheduler.admit(
                ThreadSpec {
                    key,
                    group: group(3),
                    cpu: 3,
                    allowed_mask: 8,
                    minimum_ns: 10_000_000,
                    budget_ns: 10_000_000,
                },
                s.layout,
                now_ns(),
            )?;
            s.scheduler.set_runnable(key, false, now_ns())?;
            s.generation = s.generation.checked_add(1).ok_or(Error::Overflow)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = s.scheduler.remove(key);
            let mut pages = Pages {
                tasks: &s.tasks,
                remote: s.remote,
                load: None,
            };
            for base in [0x30000, 0x40000] {
                let _ = s.memory.unmap_step(key, base, 2, &mut pages);
            }
            let _ = s.memory.unregister_owner(key);
            s.remote = None;
        }
        result
    })
}
pub fn remote_selected(slot: usize) -> bool {
    slot < 64 && CREDIT_KIND[slot].load(Ordering::Acquire) == 2
}
pub fn remote_activate(token: u64) -> Result<(), Error> {
    locked(|s| {
        let remote = s
            .remote
            .as_mut()
            .filter(|r| r.key.generation == token)
            .ok_or(Error::Stale)?;
        remote.ended = false;
        s.scheduler.set_runnable(remote.key, true, now_ns())
    })
}
pub fn remote_stopped(token: u64) -> Result<(), Error> {
    locked(|s| {
        let remote = s
            .remote
            .as_mut()
            .filter(|r| r.key.generation == token)
            .ok_or(Error::Stale)?;
        remote.ended = true;
        if let Some(active) = s.active[3]
            .as_mut()
            .filter(|a| a.dispatch.thread == remote.key)
        {
            active.state = RunState::Blocked;
            Ok(())
        } else {
            s.scheduler.set_runnable(remote.key, false, now_ns())
        }
    })
}
pub fn remote_release(token: u64) -> Result<(), Error> {
    locked(|s| {
        let remote = s
            .remote
            .filter(|r| r.key.generation == token)
            .ok_or(Error::Stale)?;
        if !remote.ended
            || s.active
                .iter()
                .flatten()
                .any(|a| a.dispatch.thread == remote.key)
        {
            return Err(Error::Busy);
        }
        match s.scheduler.remove(remote.key) {
            Ok(()) | Err(Error::Stale) => {}
            Err(error) => return Err(error),
        }
        let mut pages = Pages {
            tasks: &s.tasks,
            remote: s.remote,
            load: None,
        };
        for base in [0x30000, 0x40000] {
            match s.memory.unmap_step(remote.key, base, 2, &mut pages) {
                Ok(p) if p.remaining == 0 => {}
                Err(Error::NotFound) => {}
                _ => return Err(Error::Busy),
            }
        }
        s.memory.unregister_owner(remote.key)?;
        s.remote = None;
        s.generation = s.generation.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    })
}
pub fn remote_fault(token: u64, context: &user::Context) -> Result<(), Error> {
    locked(|s| {
        let remote = s
            .remote
            .filter(|r| r.key.generation == token && !r.ended)
            .ok_or(Error::Stale)?;
        abi::fault_locked(s, remote.key, context)
    })
}
pub fn remote_word(token: u64, address: u64) -> Result<u64, Error> {
    locked(|s| {
        let remote = s
            .remote
            .filter(|r| r.key.generation == token)
            .ok_or(Error::Stale)?;
        let mut bytes = [0u8; 8];
        copy_from(&s.memory, &s.tasks, remote.key, address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    })
}

pub fn init_recoverable() -> Result<(), Error> {
    locked(|s| {
        for recipe in [1u16, 2] {
            if s.tasks.iter().any(|t| t.recipe == recipe) {
                continue;
            }
            if let SpawnState::Failed(error) = submit_locked(
                s,
                KERNEL_CALLER,
                0xd1400000 + u64::from(recipe),
                group(u64::from(recipe) + 14),
                &0u64.to_le_bytes(),
                3,
                u64::MAX,
                true,
                recipe,
            )? {
                return Err(error);
            }
        }
        advance_admission(s)?;
        for recipe in [1u16, 2] {
            match s
                .admission
                .query(KERNEL_CALLER, 0xd1400000 + u64::from(recipe))?
            {
                SpawnState::Created(_) => {}
                SpawnState::Failed(e) => return Err(e),
                SpawnState::Cancelled => return Err(Error::Conflict),
                _ => return Err(Error::Again),
            }
        }
        Ok(())
    })
}
pub fn recoverable_key(recipe: u16) -> Option<ObjectKey> {
    locked(|s| {
        Ok(s.tasks
            .iter()
            .find(|t| t.recipe == recipe && recipe != 0)
            .map(|t| t.key))
    })
    .ok()
    .flatten()
}
pub fn recoverable_submit(recipe: u16, id: u64, value: u64) -> Result<u64, Error> {
    locked(|s| {
        let i = s
            .tasks
            .iter()
            .position(|t| t.recipe == recipe && t.life != Life::Free && !t.closed)
            .ok_or(Error::NotReady)?;
        let data = if recipe == 1 {
            s.facts
                .cpu
                .iter()
                .map(|r| r.get(now_ns()))
                .fold(0u64, u64::saturating_add)
        } else {
            value
        };
        s.ipc.send(
            KERNEL_CALLER,
            s.tasks[i].endpoint,
            id,
            &data.to_le_bytes(),
            now_ns(),
            &mut abi::Mailbox {
                tasks: &s.tasks,
                wake: &mut s.wake,
                received: &mut [],
                used: 0,
            },
        )
    })
}
pub fn recoverable_result(key: ObjectKey, sequence: u64) -> Result<u64, Error> {
    locked(|s| {
        if sequence == 0 {
            return Err(Error::Range);
        }
        let t = &s.tasks[task_index(&s.tasks, key)?];
        if t.completed_sequence == sequence {
            Ok(t.response)
        } else if t.completed_sequence > sequence {
            Err(Error::Stale)
        } else {
            Err(Error::Again)
        }
    })
}
fn recovery_index(s: &State, key: ObjectKey) -> Result<usize, Error> {
    s.tasks
        .iter()
        .position(|t| t.key == key && t.recipe != 0)
        .ok_or(Error::Auth)
}
pub fn close_admission(key: ObjectKey, apply: ApplyId) -> Result<(), Error> {
    locked(|s| {
        if apply.target != key {
            return Err(Error::Auth);
        }
        let i = recovery_index(s, key)?;
        let t = &mut s.tasks[i];
        if t.stop_apply.is_some_and(|old| old != apply) {
            return Err(Error::Conflict);
        }
        t.closed = true;
        t.stop_apply = Some(apply);
        Ok(())
    })
}
struct RecoveryPredicate {
    method: u64,
    reason: u64,
    known: u64,
    detail: [u64; 5],
    active: Option<Dispatch>,
}
impl RecoveryPredicate {
    fn new(method: u64) -> Self {
        Self {
            method,
            reason: 0,
            known: 0,
            detail: [0; 5],
            active: None,
        }
    }
    fn emit(self, s: &State, i: usize, result: Result<bool, Error>) {
        let t = &s.tasks[i];
        let Some(apply) = (if self.method == 3 {
            t.start_apply
        } else {
            t.stop_apply
        }) else {
            return;
        };
        let mut row = [0; 48];
        let (result_tag, error) = match result {
            Ok(true) => (1, 0),
            Ok(false) => (2, 0),
            Err(e) => (3, e as u64 + 1),
        };
        row[..25].copy_from_slice(&[
            apply.boot_epoch,
            apply.controller_epoch,
            apply.plan_seq,
            u64::from(apply.action_index),
            apply.target.id,
            apply.target.generation,
            t.key.id,
            t.key.generation,
            self.method,
            if result.is_err() && self.reason == 0 {
                8
            } else {
                self.reason
            },
            result_tag,
            error,
            t.life as u64 + 1,
            u64::from(t.pending),
            u64::from(t.closed),
            t.heartbeat_ns,
            t.endpoint.id,
            t.endpoint.generation,
            self.known,
            self.detail[0],
            self.detail[1],
            self.detail[2],
            self.detail[3],
            self.detail[4],
            u64::from(self.active.is_some()),
        ]);
        if let Some(d) = self.active {
            row[25..38].copy_from_slice(&[
                d.sequence,
                d.thread.id,
                d.thread.generation,
                d.group.id,
                d.group.generation,
                u64::from(d.cpu),
                d.core_generation,
                d.window,
                d.started_ns,
                d.reserved_ns,
                d.reason as u64,
                d.waited_ns,
                d.policy_version,
            ]);
        }
        row[38..45].copy_from_slice(&[
            t.deadline,
            u64::from(t.cpu),
            t.group.id,
            t.group.generation,
            u64::from(t.start_apply == Some(apply)),
            u64::from(t.stop_apply == Some(apply)),
            u64::from(t.recipe),
        ]);
        crate::domain_evidence::recovery_predicate(t.recipe, row);
    }
}
pub fn readonly_drained(key: ObjectKey) -> Result<bool, Error> {
    locked(|s| {
        let i = recovery_index(s, key)?;
        let t = &s.tasks[i];
        let mut trace = RecoveryPredicate::new(1);
        let result = (|| {
            if !t.closed {
                trace.reason = 1;
                return Ok(false);
            }
            if t.pending {
                trace.reason = 2;
                return Ok(false);
            }
            trace.known |= 1;
            let busy = FILE_BUSY[i].load(Ordering::Acquire);
            trace.detail[0] = u64::from(busy);
            if busy {
                trace.reason = 3;
                return Ok(false);
            }
            trace.known |= 2;
            let complete = s.vectors[i].as_ref().is_none_or(SubmitVector::complete);
            trace.detail[1] = u64::from(complete);
            if !complete {
                trace.reason = 4;
                return Ok(false);
            }
            if t.endpoint != ZERO {
                trace.known |= 4;
                let depth = s.ipc.stats(t.endpoint)?.depth;
                trace.detail[2] = depth as u64;
                if depth != 0 {
                    trace.reason = 5;
                    return Ok(false);
                }
            }
            trace.known |= 16;
            trace.active = s
                .active
                .iter()
                .flatten()
                .find(|a| a.dispatch.thread == key)
                .map(|a| a.dispatch);
            if trace.active.is_some() {
                trace.reason = 6;
                return Ok(false);
            }
            Ok(true)
        })();
        trace.emit(s, i, result);
        result
    })
}
pub fn request_stop(key: ObjectKey, apply: ApplyId) -> Result<(), Error> {
    locked(|s| {
        let i = recovery_index(s, key)?;
        let t = &mut s.tasks[i];
        if !t.closed || t.stop_apply != Some(apply) {
            return Err(Error::Auth);
        }
        if t.life != Life::Free {
            t.life = Life::Exiting;
        }
        Ok(())
    })
}
pub fn stopped(key: ObjectKey) -> Result<bool, Error> {
    locked(|s| {
        let i = recovery_index(s, key)?;
        let mut trace = RecoveryPredicate::new(2);
        let result = (|| {
            if s.tasks[i].life != Life::Free {
                trace.reason = 1;
                return Ok(false);
            }
            if s.tasks[i].endpoint != ZERO {
                trace.reason = 2;
                return Ok(false);
            }
            trace.known |= 8;
            let pages = s.memory.owner_pages(key);
            trace.detail[3] = if pages.is_ok() { 1 } else { 2 };
            trace.detail[4] = match pages {
                Ok(n) => n as u64,
                Err(e) => e as u64 + 1,
            };
            if pages != Err(Error::Stale) {
                trace.reason = 3;
                return Ok(false);
            }
            trace.known |= 16;
            trace.active = s
                .active
                .iter()
                .flatten()
                .find(|a| a.dispatch.thread == key)
                .map(|a| a.dispatch);
            if trace.active.is_some() {
                trace.reason = 4;
                return Ok(false);
            }
            Ok(true)
        })();
        trace.emit(s, i, result);
        result
    })
}
pub fn start_generation(old: ObjectKey, next: u64, apply: ApplyId) -> Result<(), Error> {
    locked(|s| {
        let expected = ObjectKey {
            id: old.id,
            generation: next,
        };
        if let Some(t) = s
            .tasks
            .iter()
            .find(|t| t.key == expected && t.start_apply == Some(apply))
        {
            return if t.life != Life::Free {
                Ok(())
            } else {
                Err(Error::NotReady)
            };
        }
        let i = recovery_index(s, old)?;
        let prior = s.tasks[i];
        let resource_generation = s.generation.checked_add(1).ok_or(Error::Overflow)?;
        if prior.life != Life::Free
            || prior.stop_apply != Some(apply)
            || old.generation.checked_add(1) != Some(next)
        {
            return Err(Error::Conflict);
        }
        if s.active
            .iter()
            .flatten()
            .any(|a| a.dispatch.group == prior.group)
        {
            return Err(Error::Busy);
        }
        let now = now_ns();
        if s.recovery_window != now / 100_000_000 {
            s.recovery_window = now / 100_000_000;
            s.recovery_started = 0;
        }
        if s.recovery_started >= 8 {
            return Err(Error::Again);
        }
        s.background.recover_stopped(prior.group, now)?;
        let slot = (64..LAUNCHES)
            .find(|j| s.launches[*j].request.is_none())
            .ok_or(Error::Capacity)?;
        let request = SpawnRequest {
            caller: KERNEL_CALLER,
            request_id: next,
            package: PACKAGE,
            group: prior.group,
            payload_hash: [0; 32],
            recovery: true,
        };
        let launch = &mut s.launches[slot];
        launch.request = Some(request);
        launch.cpu = prior.cpu;
        launch.deadline = u64::MAX;
        launch.len = 8;
        launch.input[..8].fill(0);
        launch.recipe = prior.recipe;
        s.recovery_started += 1;
        let layout = effective_layout(s);
        let mut backend = Creator {
            tasks: &mut s.tasks,
            launches: &s.launches,
            memory: &mut s.memory,
            scheduler: &mut s.scheduler,
            services: &mut s.services,
            ipc: &mut s.ipc,
            background: &mut s.background,
            layout,
            remote: s.remote,
            generation: &mut s.generation,
            local_failure: None,
        };
        let result = backend.build(&request, i, expected, None, &mut BuildTrace::new(false));
        if let Err(error) = result {
            if backend.rollback(i, expected).is_ok() {
                backend.tasks[i] = prior;
            } else {
                backend.tasks[i].life = Life::Exiting;
                backend.tasks[i].failure = Some(error);
            }
        }
        s.launches[slot].input.fill(0);
        s.launches[slot].request = None;
        result?;
        s.tasks[i].start_apply = Some(apply);
        s.generation = resource_generation.max(next);
        Ok(())
    })
}
pub fn running(key: ObjectKey) -> Result<bool, Error> {
    locked(|s| {
        let i = recovery_index(s, key)?;
        let t = &s.tasks[i];
        let mut trace = RecoveryPredicate::new(3);
        let result = (|| {
            if !matches!(t.life, Life::Ready | Life::Running) {
                trace.reason = 1;
                return Ok(false);
            }
            if t.heartbeat_ns == 0 {
                trace.reason = 2;
                return Ok(false);
            }
            if t.endpoint == ZERO {
                trace.reason = 3;
                return Ok(false);
            }
            trace.known |= 8;
            let pages = s.memory.owner_pages(key);
            trace.detail[3] = if pages.is_ok() { 1 } else { 2 };
            trace.detail[4] = match pages {
                Ok(n) => n as u64,
                Err(e) => e as u64 + 1,
            };
            if pages.is_err() {
                trace.reason = 4;
                return Ok(false);
            }
            Ok(true)
        })();
        trace.emit(s, i, result);
        result
    })
}
pub fn heartbeat_ns(key: ObjectKey) -> Result<u64, Error> {
    locked(|s| Ok(s.tasks[recovery_index(s, key)?].heartbeat_ns))
}
pub fn start_probe_client() -> Result<ObjectKey, Error> {
    if !SELFTEST_ENABLED {
        return Err(Error::Unsupported);
    }
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        if let Some(key) = s.probe_key {
            return Ok(key);
        }
        let id = 0xd0a10001;
        match s.admission.query(KERNEL_CALLER, id) {
            Ok(SpawnState::Created(key)) => {
                s.probe_key = Some(key);
                return Ok(key);
            }
            Ok(SpawnState::Failed(e)) => return Err(e),
            Ok(SpawnState::Cancelled) => return Err(Error::Conflict),
            Ok(_) => {}
            Err(Error::NotFound) => {
                let deadline = now_ns()
                    .checked_add(60_000_000_000)
                    .ok_or(Error::Overflow)?;
                s.facts.attempts = s.facts.attempts.saturating_add(1);
                s.facts.spawn[3].add(now_ns(), 1);
                if let SpawnState::Failed(e) = submit_package(
                    s,
                    CLIENT_PACKAGE,
                    KERNEL_CALLER,
                    id,
                    group(4),
                    &0u64.to_le_bytes(),
                    3,
                    deadline,
                    false,
                    0,
                )? {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
        advance_admission(s)?;
        match s.admission.query(KERNEL_CALLER, id)? {
            SpawnState::Created(key) => {
                s.probe_key = Some(key);
                Ok(key)
            }
            SpawnState::Failed(e) => Err(e),
            _ => Err(Error::Again),
        }
    })
}
/// Same ordinary admission, file capability and EL0 package path as the probe.
/// The dedicated image supplies a bounded, immutable role input only.
pub fn start_storage_client(role: u64) -> Result<ObjectKey, Error> {
    if !SELFTEST_ENABLED || !crate::storage_fault_capture::PROFILE || !(1..=2).contains(&role) {
        return Err(Error::Unsupported);
    }
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        let id = 0xd0a11000 + role;
        match s.admission.query(KERNEL_CALLER, id) {
            Ok(SpawnState::Created(key)) => return Ok(key),
            Ok(SpawnState::Failed(e)) => return Err(e),
            Ok(SpawnState::Cancelled) => return Err(Error::Conflict),
            Ok(_) => {}
            Err(Error::NotFound) => {
                let launch = crate::storage_fault_capture::launch(role);
                let deadline_ns = crate::storage_fault_capture::launch_deadline_ns(&launch)
                    .ok_or(Error::Format)?;
                let deadline = now_ns().checked_add(deadline_ns).ok_or(Error::Overflow)?;
                s.facts.attempts = s.facts.attempts.saturating_add(1);
                s.facts.spawn[3].add(now_ns(), 1);
                if let SpawnState::Failed(e) = submit_package(
                    s,
                    CLIENT_PACKAGE,
                    KERNEL_CALLER,
                    id,
                    group(4),
                    &launch,
                    3,
                    deadline,
                    false,
                    0,
                )? {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
        advance_admission(s)?;
        match s.admission.query(KERNEL_CALLER, id)? {
            SpawnState::Created(key) => Ok(key),
            SpawnState::Failed(e) => Err(e),
            _ => Err(Error::Again),
        }
    })
}
pub fn probe_status() -> Result<Option<u64>, Error> {
    locked(|s| {
        if s.probe_key.is_none() {
            return Err(Error::NotFound);
        }
        Ok(s.probe_exit)
    })
}

//! Native lifecycle diagnostic under the signed scratch policy.
//!
//! The public fixture signs an empty service allowlist. The eight built-in
//! packages may exercise their private contexts and lifecycle syscalls once
//! the disk's boot/security pair is confirmed. No service capability is
//! installed and protected calls never reach the legacy diagnostic bridge.
//! The locked per-vCPU QEMU PMU provides CPU debits, while the physical
//! timer enforces separate wall deadlines. The default catalog path keeps
//! one continuous CPU0 cursor from early boot through the durable media
//! handoff and the resident roles.

use super::role_loader::{RoleLaunch, pie_syscall_abi};
use super::{
    BootInfo, E_AUTH, Error, ExceptionFrame, IRQS, Identity, NativeRole, NativeRoleManifest,
    Ordering, ROLE_COUNT, ROLES, Role, TIMER_IRQ, bring_up_production, cpu, frames, gic,
    load_role_with_identity, media_staging, now_ns, ns_from_ticks, pie_context, profile, recovery,
    report, report_payload, resident, role_asid, timer, trapped_ttbr0, user,
};
use crate::machine::enqueue_resident_frame;
use core::sync::atomic::AtomicU64;
use cyxia_kernel_core::{
    console::OutputQueue,
    control_plane::{
        role_budget_v0199::{CLASS_LIMITS, Class, Cpu0BudgetLedger, Settlement, Turn, WINDOW_NS},
        role_manifest_v0199::ValidatedLifecycleManifest,
    },
    security::{
        Error as SvcError,
        durable_role_epoch_v0199::ConfirmedBootPolicy,
        syscall::Syscall,
        syscall_v3::{decode_aarch64_lifecycle_svc_v3, preflight_errno},
    },
};

#[path = "signed_budget_trace.rs"]
mod budget_trace;

const CLOCK: u16 = 1;
const YIELD: u16 = 1 << 1;
const SLEEP: u16 = 1 << 2;
const DENIED: u16 = 1 << 3;
const EVIDENCE_WINDOWS: u64 = 4;
const RECOVERY_NS: u64 = CLASS_LIMITS[Class::Recovery as usize];
const CONSOLE_TURN_NS: u64 = 1_000_000;
const CONSOLE_RETRY_NS: u64 = 1_000_000;
const MAX_WALL_NS: u64 = 50_000_000;
#[cfg(cyxia_startup_catalog)]
const STARTUP_OPERATION_MARGIN_NS: u64 = 2_000_000;
const FATAL_ROLE_CONTEXT: u64 = 0x5731_1340;
const NO_MEDIA: &[u8] =
    b"V020_STARTUP state=SECURE_DEGRADED reason=signed_media_unavailable command=status\n";
const FENCED: &[u8] =
    b"V020_STARTUP state=SECURE_DEGRADED reason=signed_roles_fenced command=status\n";
#[cfg(cyxia_lifecycle_package_signature)]
const UNQUALIFIED_PACKAGES: &[u8] =
    b"V020_STARTUP state=SECURE_DEGRADED reason=lifecycle_packages_unqualified command=status\n";
// CPU0 publishes the expected root/ASID for each EL0 entry. The
// vector consumes it once, before the common native capture returns.
static ACTIVE_ROLE_TTBR0: AtomicU64 = AtomicU64::new(0);

pub(super) fn verify_captured_role(frame: &ExceptionFrame, kind: u64) {
    if cpu::slot() == 0 && matches!(kind, 8 | 9) {
        let captured = trapped_ttbr0();
        if captured == 0
            || frame.spsr & 0x1f != 0
            || ACTIVE_ROLE_TTBR0
                .compare_exchange(captured, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            super::fatal(FATAL_ROLE_CONTEXT);
        }
    }
}

struct Task {
    context: user::Context,
    wake_ns: u64,
    activity: u16,
}

enum TaskAction {
    Resume,
    EndTurn,
    Exit(i32),
}

enum Fault {
    Operation(Error),
    Budget {
        actor: u64,
        used: u64,
        prepaid: u64,
    },
    Deadline {
        actor: u64,
        ended: u64,
        deadline: u64,
    },
    Coordination {
        used: u64,
        ended: u64,
        crossed: bool,
    },
    RoleExit {
        actor: Identity,
        status: i32,
    },
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Operation(error)
    }
}

#[derive(Clone, Copy)]
pub(super) struct Sample {
    pub(super) wall: u64,
    cpu_tick: u64,
    before: u64,
}

impl Sample {
    fn now() -> Result<Self, Error> {
        let frequency = timer::frequency();
        if frequency == 0 {
            return Err(Error::Clock);
        }
        let tick_ns = 1_000_000_000u64.div_ceil(frequency);
        // As in the native budget harness, bracket the PMU observation
        // inside one aligned window, including the final timer quantum.
        for _ in 0..8 {
            let before = now_ns();
            let cpu_tick = timer::cpu_ticks();
            let wall = now_ns().checked_add(tick_ns).ok_or(Error::Clock)?;
            if before < wall && before / WINDOW_NS == wall / WINDOW_NS {
                return Ok(Self {
                    wall,
                    cpu_tick,
                    before,
                });
            }
        }
        Err(Error::Clock)
    }

    fn cpu_since(&self, tick: u64) -> Result<u64, Error> {
        self.cpu_tick
            .checked_sub(tick)
            .map(timer::cpu_ns)
            .ok_or(Error::Clock)
    }

    pub(super) fn account_gap(
        &mut self,
        ledger: &mut Cpu0BudgetLedger,
    ) -> Result<Settlement, Error> {
        let end = Self::now()?;
        let actual = end.cpu_since(self.cpu_tick)?;
        let receipt = ledger.account_coordination_gap(cpu::slot(), self.wall, end.wall, actual)?;
        *self = end;
        Ok(receipt)
    }

    pub(super) fn settle(
        &mut self,
        ledger: &mut Cpu0BudgetLedger,
        grant: Turn,
    ) -> Result<Settlement, Error> {
        let end = Self::now()?;
        let actual = end.cpu_since(self.cpu_tick)?;
        let receipt = ledger.settle(cpu::slot(), grant, actual, end.wall)?;
        *self = end;
        Ok(receipt)
    }
}

struct Continuous {
    cursor: Sample,
    initial_tick: u64,
    initial_spent: u64,
    idle_ns: u64,
    trace: budget_trace::Trace,
}

struct Budget {
    ledger: Cpu0BudgetLedger,
    continuous: Option<Continuous>,
}

impl Budget {
    #[cfg(cyxia_startup_catalog)]
    fn begin_boot(&mut self) -> Result<(Sample, Turn), Error> {
        let cursor = Sample::now()?;
        self.ledger
            .start_continuous(cpu::slot(), cursor.wall, || Ok(()))?;
        let grant = self.ledger.reserve_kernel_with_wall(
            cpu::slot(),
            Class::Recovery,
            RECOVERY_NS,
            MAX_WALL_NS,
            cursor.wall,
        )?;
        self.continuous = Some(Continuous {
            cursor,
            initial_tick: cursor.cpu_tick,
            initial_spent: 0,
            idle_ns: 0,
            trace: budget_trace::Trace::new(cursor, 0, 0, 0),
        });
        Ok((cursor, grant))
    }

    #[cfg(not(cyxia_startup_catalog))]
    fn begin_continuous(&mut self, boot_epoch: u64) -> Result<(), Error> {
        let cursor = Sample::now()?;
        let initial_spent = self.ledger.lifetime_total()?;
        let opening_window = self.ledger.aligned_window().ok_or(Error::Clock)?;
        self.ledger
            .start_continuous_after_bootstrap_recovery(cpu::slot(), cursor.wall, || Ok(()))?;
        self.continuous = Some(Continuous {
            cursor,
            initial_tick: cursor.cpu_tick,
            initial_spent,
            idle_ns: 0,
            trace: budget_trace::Trace::new(cursor, boot_epoch, opening_window, initial_spent),
        });
        Ok(())
    }

    fn reserve_recovery(&mut self) -> Result<(Sample, Turn), Fault> {
        loop {
            let start = self.sample_gap()?;
            let next = next_boundary(start.wall)?;
            if next - start.wall < MAX_WALL_NS {
                self.idle_until(next)?;
                continue;
            }
            match self.ledger.reserve_kernel_with_wall(
                cpu::slot(),
                Class::Recovery,
                RECOVERY_NS,
                MAX_WALL_NS,
                start.wall,
            ) {
                Ok(grant) => return Ok((start, grant)),
                Err(Error::Exhausted) => self.idle_until(next)?,
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn sample_gap(&mut self) -> Result<Sample, Fault> {
        let Some(continuous) = self.continuous.as_mut() else {
            return Ok(Sample::now()?);
        };
        let receipt = continuous.cursor.account_gap(&mut self.ledger)?;
        continuous.trace.record(continuous.cursor, None, 0);
        if receipt.overrun {
            return Err(Fault::Coordination {
                used: receipt.actual_ns,
                ended: continuous.cursor.wall,
                crossed: receipt.crossed_window,
            });
        }
        Ok(continuous.cursor)
    }

    fn settle(&mut self, grant: Turn, start: Sample, returned: u64) -> Result<u64, Fault> {
        let mut end = start;
        let receipt = end.settle(&mut self.ledger, grant)?;
        if let Some(continuous) = self.continuous.as_mut() {
            continuous.cursor = end;
            continuous.trace.record(end, Some(grant), returned);
        }
        let actor = || grant.accounting_scope().1.map_or(0, |(_, actor)| actor.id);
        if receipt.actual_ns > grant.reserved_ns() {
            return Err(Fault::Budget {
                actor: actor(),
                used: receipt.actual_ns,
                prepaid: grant.reserved_ns(),
            });
        }
        if receipt.overrun || receipt.crossed_window {
            return Err(Fault::Deadline {
                actor: actor(),
                ended: end.wall,
                deadline: grant.deadline_ns(),
            });
        }
        Ok(receipt.actual_ns)
    }

    fn idle_until(&mut self, deadline_ns: u64) -> Result<(), Fault> {
        let start = self.sample_gap()?;
        if wait_until(deadline_ns)? {
            let end = self.sample_gap()?;
            if let Some(continuous) = self.continuous.as_mut() {
                continuous.idle_ns = continuous
                    .idle_ns
                    .checked_add(end.cpu_since(start.cpu_tick)?)
                    .ok_or(Error::Exhausted)?;
            }
        }
        Ok(())
    }

    fn queue_evidence(&mut self, pending: &mut OutputQueue<128>) -> Result<(), Error> {
        let continuous = self.continuous.as_mut().ok_or(Error::NotReady)?;
        let observed = continuous.cursor.cpu_since(continuous.initial_tick)?;
        let charged = self
            .ledger
            .lifetime_total()?
            .checked_sub(continuous.initial_spent)
            .ok_or(Error::Clock)?;
        if observed != charged {
            return Err(Error::Clock);
        }
        continuous
            .trace
            .maybe_seal(continuous.cursor, &self.ledger, charged, continuous.idle_ns);
        let mut text = [0; 96];
        let payload = report_payload(
            &mut text,
            "V020_SIGNED_RESIDENT_CPU",
            observed,
            charged,
            continuous.idle_ns,
        );
        enqueue_resident_frame(pending, payload).map_err(|_| Error::Denied)
    }
}

/// Prepay each batch before touching startup state. The same grant covers
/// the work between checkpoints, including transport and filesystem work.
#[cfg(cyxia_startup_catalog)]
struct RecoveryBatches<'a> {
    budget: &'a mut Budget,
    active: Option<(Sample, Turn)>,
    fault: Option<Fault>,
    batches: u64,
    charged: u64,
}

#[cfg(cyxia_startup_catalog)]
impl<'a> RecoveryBatches<'a> {
    fn new(budget: &'a mut Budget) -> Self {
        Self {
            budget,
            active: None,
            fault: None,
            batches: 0,
            charged: 0,
        }
    }

    fn settle_batch(&mut self) -> Result<(), Fault> {
        if let Some((start, grant)) = self.active.take() {
            let used = self.budget.settle(grant, start, 0)?;
            self.batches += 1;
            self.charged = self.charged.checked_add(used).ok_or(Error::Exhausted)?;
        }
        Ok(())
    }

    fn next_operation(&mut self) -> Result<(), Fault> {
        if let Some((start, grant)) = self.active {
            let elapsed = timer::cpu_ticks()
                .checked_sub(start.cpu_tick)
                .map(timer::cpu_ns)
                .ok_or(Error::Clock)?;
            if elapsed < grant.reserved_ns() - STARTUP_OPERATION_MARGIN_NS
                && now_ns().saturating_add(STARTUP_OPERATION_MARGIN_NS) < grant.deadline_ns()
            {
                return Ok(());
            }
            self.settle_batch()?;
        }
        self.active = Some(self.budget.reserve_recovery()?);
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<(), SvcError> {
        if self.fault.is_some() {
            return Err(SvcError::Unknown);
        }
        self.next_operation().map_err(|fault| {
            self.fault = Some(fault);
            SvcError::Unknown
        })
    }

    fn finish(mut self) -> Result<(u64, u64), Fault> {
        self.settle_batch()?;
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        Ok((self.batches, self.charged))
    }
}

#[cfg(all(cyxia_startup_catalog, feature = "prototype-memory"))]
fn register_frames(info: &mut BootInfo, budget: &mut Budget) -> Result<(), Fault> {
    budget
        .continuous
        .as_ref()
        .ok_or(Error::NotReady)?
        .trace
        .begin_frames();
    let mut work = RecoveryBatches::new(budget);
    let registration = frames::prepare_signed(info, &mut || work.checkpoint());
    let (batches, used) = work.finish()?;
    let registration = registration.map_err(|_| Error::Denied)?;
    if used == 0 {
        return Err(Error::Clock.into());
    }
    budget
        .continuous
        .as_ref()
        .ok_or(Error::NotReady)?
        .trace
        .finish_frames();
    registration.publish();
    report("V020_SIGNED_FRAME_META_BUDGET", batches, used, RECOVERY_NS);
    Ok(())
}

impl Task {
    fn trap(&mut self, syscall_abi: u16) -> Result<TaskAction, Error> {
        let ctx = &mut self.context;
        if ctx.kind == 9 {
            return Ok(TaskAction::EndTurn);
        }
        if ctx.kind != 8 || ctx.esr >> 26 != 0x15 {
            return Err(Error::Denied);
        }
        let call = match decode_aarch64_lifecycle_svc_v3(syscall_abi, ctx.esr, &ctx.regs) {
            Ok(call) => call,
            Err(error) => {
                if error == SvcError::Unauthorized {
                    self.activity |= DENIED;
                }
                ctx.regs[0] = preflight_errno(error) as u64;
                return Ok(TaskAction::Resume);
            }
        };
        ctx.regs[0] = 0;
        match call.operation {
            Syscall::Clock => {
                let now = i64::try_from(now_ns()).map_err(|_| Error::Clock)?;
                ctx.regs[0] = now as u64;
                self.activity |= CLOCK;
            }
            Syscall::Yield => {
                self.activity |= YIELD;
                return Ok(TaskAction::EndTurn);
            }
            Syscall::Sleep => {
                self.activity |= SLEEP;
                if call.args[0] > now_ns() {
                    self.wake_ns = call.args[0];
                    return Ok(TaskAction::EndTurn);
                }
            }
            Syscall::Exit => return Ok(TaskAction::Exit(call.args[0] as i32)),
            _ => ctx.regs[0] = E_AUTH as u64,
        }
        Ok(TaskAction::Resume)
    }
}

fn reservation(role: Role) -> (Class, u16, u64) {
    match role {
        Role::Operations => (Class::Operations, 1, 2_000_000),
        Role::Security => (Class::Security, 12, 2_000_000),
        Role::DeterministicController | Role::Publisher => (Class::Decision, 1, 250_000),
        Role::ModelManager | Role::Supervisor => (Class::Coordination, 0, 500_000),
        Role::Validator | Role::Learner => (Class::Optional, 0, 500_000),
    }
}

fn startup_work<T>(budget: &mut Budget, step: u64, work: impl FnOnce() -> T) -> Result<T, Fault> {
    let (start, grant) = budget.reserve_recovery()?;
    let result = work();
    let used = budget.settle(grant, start, 0)?;
    if used == 0 {
        return Err(Error::Clock.into());
    }
    report("V020_SIGNED_RESIDENT_RECOVERY", step, used, RECOVERY_NS);
    Ok(result)
}

fn load_signed_roles(
    budget: &mut Budget,
    policy: &ConfirmedBootPolicy<'_>,
    actors: &[Identity; ROLE_COUNT],
) -> Result<[NativeRole; ROLE_COUNT], Fault> {
    startup_work(budget, 2, || {
        #[cfg(cyxia_startup_catalog)]
        if !frames::role_storage_registered() {
            return Err(Error::Denied);
        }
        recovery::init_signed(policy).map_err(|_| Error::Denied)
    })??;

    // Each package owns a separate prepaid Recovery turn. The cohort stays
    // unpublished until every package is loaded and its full inventory passes.
    let mut members = [None; ROLE_COUNT];
    for (index, slot) in members.iter_mut().enumerate() {
        *slot = Some(startup_work(budget, 3 + index as u64, || {
            load_role_with_identity(index, actors[index].generation, RoleLaunch::Lifecycle)
        })??);
    }
    Ok(members.map(|entry| entry.expect("complete signed launch inventory")))
}

fn turn(
    policy: &ConfirmedBootPolicy<'_>,
    manifest: &ValidatedLifecycleManifest<'_>,
    index: usize,
    task: &mut Task,
    budget: &mut Budget,
) -> Result<(), Fault> {
    let start = budget.sample_gap()?;
    if start.wall < task.wake_ns {
        return Ok(());
    }
    let member = manifest.manifest().members[index];
    let (class, domain, quota) = reservation(member.role);
    let grant = match budget.ledger.reserve_indexed_role_with_wall(
        manifest,
        index,
        member.actor,
        0,
        class,
        domain,
        quota,
        MAX_WALL_NS,
        start.wall,
    ) {
        Ok(grant) => grant,
        Err(Error::Exhausted) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    // Recheck the persisted authority inside the prepaid turn. No role is
    // entered using a generation or address space from its own request.
    let mut returned = 0;
    let result = if policy.service_generation(member.role) == Ok(member.actor.generation) {
        run_quantum(member, index, task, grant, &start, &mut returned)
    } else {
        Err(Error::Denied)
    };
    budget.settle(grant, start, returned)?;
    if let Some(status) = result? {
        // The full cohort owns startup readiness. An orderly exit stops its
        // admission after settlement and retains the private backing.
        return Err(Fault::RoleExit {
            actor: member.actor,
            status,
        });
    }
    Ok(())
}

fn run_quantum(
    member: NativeRole,
    index: usize,
    task: &mut Task,
    grant: Turn,
    start: &Sample,
    returned: &mut u64,
) -> Result<Option<i32>, Error> {
    // A separate physical timer forces return before the prepaid bound
    // expires. Reserve exit/settlement margin using the native fixture's
    // role limits. Clock, rejection and waiting cannot refill a grant.
    let decision = grant.accounting_scope().0 == Class::Decision;
    let exit_margin_ns = if decision { 150_000 } else { 100_000 };
    let trap_limit = if decision { 1 } else { 8 };
    let asid = role_asid(index);
    let ttbr0 = member.ttbr0_root | (u64::from(asid) << 48);
    let syscall_abi = pie_syscall_abi(index, member.ttbr0_root).ok_or(Error::Denied)?;
    for _ in 0..trap_limit {
        let wall_ticks = timer::ticks();
        let wall_left = grant
            .deadline_ns()
            .saturating_sub(ns_from_ticks(wall_ticks));
        let cpu_ns = timer::cpu_ticks()
            .checked_sub(start.cpu_tick)
            .map(timer::cpu_ns)
            .ok_or(Error::Clock)?;
        let cpu_left = grant.reserved_ns().saturating_sub(cpu_ns);
        let remaining = cpu_left.min(wall_left).saturating_sub(exit_margin_ns);
        let ticks = (u128::from(remaining) * u128::from(timer::frequency()) / 1_000_000_000) as u64;
        if ticks == 0 {
            break;
        }
        let deadline = wall_ticks.checked_add(ticks).ok_or(Error::Clock)?;
        task.context.kind = 0;
        ACTIVE_ROLE_TTBR0
            .compare_exchange(0, ttbr0, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Denied)?;
        // SAFETY: CPU0 is the sole owner of each verified, pinned root and
        // context. Its ASID is private and its mappings are retained for boot.
        unsafe {
            timer::arm(deadline);
            user::enter_pinned_until_retired(&mut task.context, member.ttbr0_root, asid);
            cpu::disable_timer();
        }
        // Every dispatch needs a newly captured lower-EL trap from the
        // root registered for this entry. No stale trap reaches recovery.
        if ACTIVE_ROLE_TTBR0.swap(0, Ordering::AcqRel) != 0 || task.context.kind == 0 {
            return Err(Error::Denied);
        }
        *returned += 1;
        match task.trap(syscall_abi) {
            Ok(TaskAction::Resume) => {}
            Ok(TaskAction::EndTurn) => break,
            Ok(TaskAction::Exit(status)) => return Ok(Some(status)),
            Err(error) => {
                recovery::record_role_failure(member.actor, task.context.esr, task.context.far)
                    .map_err(|_| Error::Denied)?;
                return Err(error);
            }
        }
    }
    Ok(None)
}

fn run_tasks(
    info: &BootInfo,
    policy: &ConfirmedBootPolicy<'_>,
    manifest: &ValidatedLifecycleManifest<'_>,
    budget: &mut Budget,
    pending: &mut OutputQueue<128>,
) -> Result<core::convert::Infallible, Fault> {
    let mut uart = resident::attach_console(info);
    let mut tasks: [Task; ROLE_COUNT] = core::array::from_fn(|index| Task {
        context: pie_context(index),
        wake_ns: 0,
        activity: 0,
    });
    let mut next_window = now_ns() / WINDOW_NS;
    let mut proof_window = next_window + EVIDENCE_WINDOWS;
    let mut console_window = next_window;
    let mut command = 0;
    let mut budget_frame = false;
    // Finish publishing the authenticated cohort before entering any EL0
    // role. Each console grant prepares at most one frame and drains a
    // bounded number of bytes, including when the UART is busy.
    let mut ready_record = Some(0);
    loop {
        let now = now_ns();
        let window = now / WINDOW_NS;
        let ready_at_start = ready_record.is_none();
        if ready_at_start && window >= next_window {
            next_window = window + 1;
            for (index, task) in tasks.iter_mut().enumerate() {
                turn(policy, manifest, index, task, budget)?;
            }
        }
        let mut wake = next_boundary(now)?;
        if window >= console_window
            || ready_record.is_some()
            || pending.pending() != 0
            || budget_frame
        {
            let start = budget.sample_gap()?;
            match budget.ledger.reserve_kernel_with_wall(
                0,
                Class::Coordination,
                CONSOLE_TURN_NS,
                MAX_WALL_NS,
                start.wall,
            ) {
                Ok(grant) => {
                    console_window = window + 1;
                    let result = if let Some(index) = ready_record {
                        queue_ready(policy.boot_epoch(), manifest, index, pending).map(|()| {
                            resident::drain_console(&mut uart, pending);
                            if pending.pending() == 0 {
                                ready_record = (index < ROLE_COUNT).then_some(index + 1);
                            }
                        })
                    } else {
                        queue_activity(
                            &mut tasks,
                            window,
                            &mut proof_window,
                            &mut budget_frame,
                            budget,
                            pending,
                        )
                        .map(|()| {
                            resident::poll_console(
                                &mut uart,
                                pending,
                                &mut command,
                                IRQS[0].load(Ordering::Acquire),
                            );
                        })
                    };
                    budget.settle(grant, start, 0)?;
                    result?;
                    if !ready_at_start && ready_record.is_none() {
                        proof_window = window + EVIDENCE_WINDOWS;
                        continue;
                    }
                    if ready_record.is_some() || pending.pending() != 0 || budget_frame {
                        wake =
                            wake.min(now_ns().checked_add(CONSOLE_RETRY_NS).ok_or(Error::Clock)?);
                    }
                }
                Err(Error::Exhausted) => {}
                Err(error) => return Err(error.into()),
            }
        }
        // Role dispatch and new console polls are once per aligned window.
        // Recheck sooner only to finish a queued frame with remaining credit.
        budget.idle_until(wake)?;
    }
}

fn queue_ready(
    epoch: u64,
    manifest: &ValidatedLifecycleManifest<'_>,
    index: usize,
    pending: &mut OutputQueue<128>,
) -> Result<(), Error> {
    if pending.pending() != 0 {
        return Ok(());
    }
    let (label, [a, b, c]) = if index == 0 {
        ("V020_SIGNED_RESIDENT_BOOT", [epoch, ROLE_COUNT as u64, 0])
    } else {
        let actor = manifest.manifest().members[index - 1].actor;
        (
            "V020_SIGNED_RESIDENT_ROLE",
            [(index - 1) as u64, actor.id, actor.generation],
        )
    };
    let mut text = [0; 96];
    let payload = report_payload(&mut text, label, a, b, c);
    enqueue_resident_frame(pending, payload).map_err(|_| Error::Denied)
}

fn queue_activity(
    tasks: &mut [Task; ROLE_COUNT],
    window: u64,
    proof_window: &mut u64,
    budget_frame: &mut bool,
    budget: &mut Budget,
    pending: &mut OutputQueue<128>,
) -> Result<(), Error> {
    if pending.pending() == 0 {
        if *budget_frame {
            budget.queue_evidence(pending)?;
            *budget_frame = false;
        } else if window >= *proof_window {
            queue_progress(tasks, window, pending)?;
            *proof_window = window + EVIDENCE_WINDOWS;
            *budget_frame = true;
        }
    }
    Ok(())
}

fn queue_progress(
    tasks: &mut [Task; ROLE_COUNT],
    window: u64,
    pending: &mut OutputQueue<128>,
) -> Result<(), Error> {
    let mut masks = [0u64; 4];
    for (index, task) in tasks.iter_mut().enumerate() {
        for (bit, mask) in masks.iter_mut().enumerate() {
            if task.activity & (1 << bit) != 0 {
                *mask |= 1 << index;
            }
        }
        task.activity = 0;
    }
    let mut text = [0; 96];
    let payload = report_payload(
        &mut text,
        "V020_SIGNED_RESIDENT_PROGRESS",
        window,
        masks[0] | (masks[1] << 8),
        masks[2] | (masks[3] << 8),
    );
    enqueue_resident_frame(pending, payload).map_err(|_| Error::Denied)
}

fn next_boundary(now_ns: u64) -> Result<u64, Error> {
    (now_ns / WINDOW_NS)
        .checked_add(1)
        .and_then(|window| window.checked_mul(WINDOW_NS))
        .ok_or(Error::Clock)
}

fn wait_until(deadline_ns: u64) -> Result<bool, Error> {
    let deadline = u64::try_from(
        (u128::from(deadline_ns) * u128::from(timer::frequency())).div_ceil(1_000_000_000),
    )
    .map_err(|_| Error::Clock)?;
    if timer::ticks() >= deadline {
        return Ok(false);
    }
    // SAFETY: the boot GIC handler rearms CPU0's EL1 timer. This
    // wait leaves the stopped EL0 contexts untouched.
    unsafe {
        timer::arm(deadline);
        timer::enable_irqs();
    }
    timer::idle();
    // Keep the EL1 idle tick out of the next role's quantum. EL0 entry
    // unmasks IRQs in its saved PSTATE after installing the private root.
    unsafe {
        core::arch::asm!(
            "msr daifset, #2",
            "isb",
            options(nomem, nostack, preserves_flags),
        );
        cpu::disable_timer();
    }
    Ok(true)
}

fn identities(policy: &ConfirmedBootPolicy<'_>) -> Result<[Identity; ROLE_COUNT], Error> {
    let mut identities = [Identity {
        id: 0,
        generation: 0,
    }; ROLE_COUNT];
    for (actor, role) in identities.iter_mut().zip(ROLES) {
        *actor = Identity {
            id: u64::from(role.id()),
            generation: policy.service_generation(role).map_err(|_| Error::Denied)?,
        };
    }
    Ok(identities)
}

fn fence(info: &BootInfo, budget: Budget, pending: OutputQueue<128>, fault: Fault) -> ! {
    let witness = match fault {
        Fault::Operation(error) => ("V020_SIGNED_RESIDENT_FAULT", [error as u64, 0, 0]),
        Fault::Budget {
            actor,
            used,
            prepaid,
        } => ("V020_SIGNED_RESIDENT_OVERRUN", [actor, used, prepaid]),
        Fault::Deadline {
            actor,
            ended,
            deadline,
        } => ("V020_SIGNED_RESIDENT_DEADLINE", [actor, ended, deadline]),
        Fault::Coordination {
            used,
            ended,
            crossed,
        } => (
            "V020_SIGNED_RESIDENT_COORD_OVERRUN",
            [used, ended, u64::from(crossed)],
        ),
        Fault::RoleExit { actor, status } => (
            "V020_SIGNED_RESIDENT_EXIT",
            [actor.id, actor.generation, i64::from(status) as u64],
        ),
    };
    // Finish any retained serial suffix before the read-only status banner.
    resident::serve_with_queue(
        info,
        Some(FENCED),
        budget.ledger,
        pending,
        Some(witness),
        budget.continuous.map(|continuous| continuous.cursor),
    )
}

fn degraded(info: &BootInfo, budget: Budget, reason: Option<&'static [u8]>) -> ! {
    resident::serve_with_queue(
        info,
        reason,
        budget.ledger,
        OutputQueue::new(),
        None,
        budget.continuous.map(|continuous| continuous.cursor),
    )
}

pub(super) fn run(info: &BootInfo) -> ! {
    assert_eq!(cpu::slot(), 0);
    // SAFETY: this opt-in diagnostic requires the pinned MTTCG PMU backend.
    // CPU0 owns its counter from EL1 and the verifier checks the host hashes.
    unsafe { timer::init_cpu_accounting() };
    let mut budget = Budget {
        ledger: Cpu0BudgetLedger::new(),
        continuous: None,
    };
    #[cfg(cyxia_startup_catalog)]
    let (early_start, early_grant) = budget.begin_boot().expect("early Recovery budget");
    #[cfg(not(all(cyxia_startup_catalog, feature = "prototype-memory")))]
    frames::register_or_fatal();
    bring_up_production(info);
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 timer PPI");
    #[cfg(cyxia_startup_catalog)]
    match budget.settle(early_grant, early_start, 0) {
        Ok(used) => report("V020_SIGNED_RESIDENT_RECOVERY", 0, used, RECOVERY_NS),
        Err(fault) => fence(info, budget, OutputQueue::new(), fault),
    }
    #[cfg(all(cyxia_startup_catalog, feature = "prototype-memory"))]
    let reserved = {
        let mut reserved = *info;
        if let Err(fault) = register_frames(&mut reserved, &mut budget) {
            fence(info, budget, OutputQueue::new(), fault);
        }
        reserved
    };
    #[cfg(all(cyxia_startup_catalog, feature = "prototype-memory"))]
    let info = &reserved;
    let config = match startup_work(&mut budget, 1, || {
        // An authenticated catalog with unsupported lists can still be
        // inspected by the default read-only diagnostics.
        let fallback = if cfg!(cyxia_startup_catalog) {
            None
        } else {
            Some(FENCED)
        };
        let config = media_staging::verify_scratch_config().map_err(|_| fallback)?;
        #[cfg(cyxia_lifecycle_package_signature)]
        super::startup_catalog::verify_lifecycle_packages(&config)
            .map_err(|_| Some(UNQUALIFIED_PACKAGES))?;
        Ok(config)
    }) {
        Ok(Ok(config)) => config,
        Ok(Err(reason)) => degraded(info, budget, reason),
        Err(fault) => fence(info, budget, OutputQueue::new(), fault),
    };
    #[cfg(cyxia_startup_catalog)]
    let mut staged = {
        budget
            .continuous
            .as_mut()
            .expect("active boot meter")
            .trace
            .begin_media();
        let mut media = RecoveryBatches::new(&mut budget);
        let staged =
            media_staging::stage_with_policy(info, Some(config), &mut || media.checkpoint());
        let confirmed_epoch = staged
            .resident_boot
            .as_ref()
            .map_or(0, |_| staged.confirmed_epoch);
        let (batches, used) = match media.finish() {
            Ok(debit) => debit,
            Err(fault) => fence(info, budget, OutputQueue::new(), fault),
        };
        if confirmed_epoch != 0 {
            budget
                .continuous
                .as_ref()
                .expect("active boot meter")
                .trace
                .finish_media(confirmed_epoch);
            report("V020_SIGNED_MEDIA_BUDGET", batches, used, RECOVERY_NS);
        }
        staged
    };
    #[cfg(not(cyxia_startup_catalog))]
    let mut staged = media_staging::stage_with_policy(info, Some(config));
    let Some(boot) = staged.resident_boot.take() else {
        degraded(info, budget, Some(NO_MEDIA));
    };
    let Ok(policy) = boot.policy() else {
        degraded(info, budget, Some(FENCED));
    };
    if policy.boot_epoch() != staged.confirmed_epoch {
        degraded(info, budget, Some(FENCED));
    }
    #[cfg(not(cyxia_startup_catalog))]
    if let Err(error) = budget.begin_continuous(policy.boot_epoch()) {
        fence(info, budget, OutputQueue::new(), error.into());
    }
    let actors = match identities(&policy) {
        Ok(actors) => actors,
        Err(error) => fence(info, budget, OutputQueue::new(), error.into()),
    };
    let members = match load_signed_roles(&mut budget, &policy, &actors) {
        Ok(members) => members,
        Err(fault) => fence(info, budget, OutputQueue::new(), fault),
    };
    let other_protected_pool_bytes =
        core::mem::size_of::<[super::Tables; ROLE_COUNT]>() + super::COPY + 1024 * 1024;
    #[cfg(feature = "v020-production-diagnostic")]
    let other_protected_pool_bytes = other_protected_pool_bytes + super::PLAN_POOL_BYTES;
    let manifest = NativeRoleManifest {
        online_mask: profile::ONLINE,
        members,
        other_protected_pool_bytes,
        other_control_ns_per_100ms: 10_000_000,
    };
    let manifest = match manifest.validated_lifecycle() {
        Ok(manifest) => manifest,
        Err(error) => fence(info, budget, OutputQueue::new(), error.into()),
    };
    let mut pending = OutputQueue::new();
    let Err(fault) = run_tasks(info, &policy, &manifest, &mut budget, &mut pending);
    fence(info, budget, pending, fault)
}

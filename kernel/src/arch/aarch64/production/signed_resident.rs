//! Native lifecycle diagnostic under the signed scratch policy.
//!
//! The public fixture signs an empty service allowlist. The eight built-in
//! packages may exercise their private contexts and lifecycle syscalls once
//! the disk's boot/security pair is confirmed. No service capability is
//! installed and protected calls never reach the legacy diagnostic bridge.
//! The locked per-vCPU QEMU PMU provides CPU debits, while the physical
//! timer enforces separate wall deadlines.

use super::{
    BootInfo, E_AUTH, E_FORMAT, Error, ExceptionFrame, IRQS, Identity, NativeRole,
    NativeRoleManifest, Ordering, ROLE_COUNT, ROLES, Role, TIMER_IRQ, bring_up_production, cpu,
    frames, gic, load_role_with_identity, media_staging, now_ns, ns_from_ticks, pie_context,
    profile, recovery, report, report_payload, resident, role_asid, timer, trapped_ttbr0, user,
};
use crate::machine::enqueue_resident_frame;
use core::sync::atomic::AtomicU64;
use cyxia_kernel_core::{
    console::OutputQueue,
    control_plane::{
        role_budget_v0199::{CLASS_LIMITS, Class, Cpu0BudgetLedger, Turn, WINDOW_NS},
        role_manifest_v0199::ValidatedRoleManifest,
    },
    security::{
        Error as SvcError,
        durable_role_epoch_v0199::ConfirmedBootPolicy,
        syscall::Syscall,
        syscall_v3::{ABI_VERSION, decode_aarch64_lifecycle_svc_v3},
    },
};

const CLOCK: u16 = 1;
const YIELD: u16 = 1 << 1;
const SLEEP: u16 = 1 << 2;
const DENIED: u16 = 1 << 3;
const EVIDENCE_WINDOWS: u64 = 4;
const RECOVERY_NS: u64 = CLASS_LIMITS[Class::Recovery as usize];
const CONSOLE_TURN_NS: u64 = 1_000_000;
const MAX_WALL_NS: u64 = 50_000_000;
const FATAL_ROLE_CONTEXT: u64 = 0x5731_1340;
const NO_MEDIA: &[u8] =
    b"V020_STARTUP state=SECURE_DEGRADED reason=signed_media_unavailable command=status\n";
const FENCED: &[u8] =
    b"V020_STARTUP state=SECURE_DEGRADED reason=signed_roles_fenced command=status\n";
// CPU0 publishes the expected root/ASID for the exclusive running turn.
// The vector verifies the live EL0 context before handing control back.
static ACTIVE_ROLE_TTBR0: AtomicU64 = AtomicU64::new(0);

pub(super) fn verify_captured_role(frame: &ExceptionFrame, kind: u64) {
    if cpu::slot() == 0 && matches!(kind, 8 | 9) {
        let expected = ACTIVE_ROLE_TTBR0.load(Ordering::Acquire);
        if expected == 0 || frame.spsr & 0x1f != 0 || trapped_ttbr0() != expected {
            super::fatal(FATAL_ROLE_CONTEXT);
        }
    }
}

struct Task {
    context: user::Context,
    wake_ns: u64,
    activity: u16,
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
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Operation(error)
    }
}

struct Sample {
    wall: u64,
    cpu_tick: u64,
}

impl Sample {
    fn now() -> Self {
        Self {
            wall: now_ns(),
            cpu_tick: timer::cpu_ticks(),
        }
    }

    fn cpu_elapsed(&self) -> Result<u64, Error> {
        timer::cpu_ticks()
            .checked_sub(self.cpu_tick)
            .map(timer::cpu_ns)
            .ok_or(Error::Clock)
    }
}

impl Task {
    fn trap(&mut self) -> Result<bool, Error> {
        let ctx = &mut self.context;
        if ctx.kind == 9 {
            return Ok(true);
        }
        if ctx.kind != 8 || ctx.esr >> 26 != 0x15 {
            return Err(Error::Denied);
        }
        let call = match decode_aarch64_lifecycle_svc_v3(ABI_VERSION, ctx.esr, &ctx.regs) {
            Ok(call) => call,
            Err(SvcError::Unauthorized) => {
                ctx.regs[0] = E_AUTH as u64;
                self.activity |= DENIED;
                return Ok(false);
            }
            Err(_) => {
                ctx.regs[0] = E_FORMAT as u64;
                return Ok(false);
            }
        };
        ctx.regs[0] = 0;
        match call.operation {
            Syscall::Clock => {
                let now = i64::try_from(now_ns()).map_err(|_| Error::Clock)?;
                ctx.regs[0] = now as u64;
                self.activity |= CLOCK;
            }
            Syscall::Yield => self.activity |= YIELD,
            Syscall::Sleep => {
                self.wake_ns = call.args[0];
                self.activity |= SLEEP;
            }
            // Retain the pinned private frames and fence this diagnostic
            // cohort on exit or fault. No implicit restart is authorized.
            Syscall::Exit => return Err(Error::Denied),
            _ => ctx.regs[0] = E_AUTH as u64,
        }
        Ok(matches!(call.operation, Syscall::Yield | Syscall::Sleep))
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

fn settle(ledger: &mut Cpu0BudgetLedger, grant: Turn, start: &Sample) -> Result<u64, Fault> {
    let used = start.cpu_elapsed()?;
    let end = now_ns();
    let receipt = ledger.settle(0, grant, used, end)?;
    let actor = || grant.accounting_scope().1.map_or(0, |(_, actor)| actor.id);
    if used > grant.reserved_ns() {
        return Err(Fault::Budget {
            actor: actor(),
            used,
            prepaid: grant.reserved_ns(),
        });
    }
    if receipt.overrun || receipt.crossed_window {
        return Err(Fault::Deadline {
            actor: actor(),
            ended: end,
            deadline: grant.deadline_ns(),
        });
    }
    Ok(used)
}

fn startup_work<T>(
    ledger: &mut Cpu0BudgetLedger,
    step: u64,
    work: impl FnOnce() -> T,
) -> Result<T, Fault> {
    let (start, grant) = loop {
        let start = Sample::now();
        if WINDOW_NS - start.wall % WINDOW_NS < MAX_WALL_NS {
            wait_for_tick();
            continue;
        }
        match ledger.reserve_kernel_with_wall(
            0,
            Class::Recovery,
            RECOVERY_NS,
            MAX_WALL_NS,
            start.wall,
        ) {
            Ok(grant) => break (start, grant),
            Err(Error::Exhausted) => wait_for_tick(),
            Err(error) => return Err(error.into()),
        }
    };
    let result = work();
    let used = settle(ledger, grant, &start)?;
    if used == 0 {
        return Err(Error::Clock.into());
    }
    report("V020_SIGNED_RESIDENT_RECOVERY", step, used, RECOVERY_NS);
    Ok(result)
}

fn turn(
    policy: &ConfirmedBootPolicy<'_>,
    manifest: &ValidatedRoleManifest<'_>,
    index: usize,
    task: &mut Task,
    ledger: &mut Cpu0BudgetLedger,
) -> Result<(), Fault> {
    let start = Sample::now();
    if start.wall < task.wake_ns {
        return Ok(());
    }
    let member = manifest.manifest().members[index];
    let (class, domain, quota) = reservation(member.role);
    let grant = match ledger.reserve_indexed_role_with_wall(
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
    let result = if policy.service_generation(member.role) == Ok(member.actor.generation) {
        run_quantum(member, index, task, grant, &start)
    } else {
        Err(Error::Denied)
    };
    settle(ledger, grant, &start)?;
    result.map_err(Into::into)
}

fn run_quantum(
    member: NativeRole,
    index: usize,
    task: &mut Task,
    grant: Turn,
    start: &Sample,
) -> Result<(), Error> {
    // A separate physical timer forces return before the prepaid bound
    // expires. Reserve exit/settlement margin using the native fixture's
    // role limits. Clock, rejection and waiting cannot refill a grant.
    let decision = grant.accounting_scope().0 == Class::Decision;
    let exit_margin_ns = if decision { 150_000 } else { 100_000 };
    let trap_limit = if decision { 1 } else { 8 };
    let asid = role_asid(index);
    let ttbr0 = member.ttbr0_root | (u64::from(asid) << 48);
    for _ in 0..trap_limit {
        let wall_ticks = timer::ticks();
        let wall_left = grant
            .deadline_ns()
            .saturating_sub(ns_from_ticks(wall_ticks));
        let cpu_left = grant.reserved_ns().saturating_sub(start.cpu_elapsed()?);
        let remaining = cpu_left.min(wall_left).saturating_sub(exit_margin_ns);
        let ticks = (u128::from(remaining) * u128::from(timer::frequency()) / 1_000_000_000) as u64;
        if ticks == 0 {
            break;
        }
        let deadline = wall_ticks.checked_add(ticks).ok_or(Error::Clock)?;
        ACTIVE_ROLE_TTBR0.store(ttbr0, Ordering::Release);
        // SAFETY: CPU0 is the sole owner of each verified, pinned root and
        // context. Its ASID is private and its mappings are retained for boot.
        unsafe {
            timer::arm(deadline);
            user::enter_pinned_until_retired(&mut task.context, member.ttbr0_root, asid);
            cpu::disable_timer();
        }
        ACTIVE_ROLE_TTBR0.store(0, Ordering::Release);
        match task.trap() {
            Ok(false) => {}
            Ok(true) => break,
            Err(error) => {
                recovery::record_role_failure(member.actor, task.context.esr, task.context.far)
                    .map_err(|_| Error::Denied)?;
                return Err(error);
            }
        }
    }
    Ok(())
}

fn run_tasks(
    info: &BootInfo,
    policy: &ConfirmedBootPolicy<'_>,
    manifest: &ValidatedRoleManifest<'_>,
    ledger: &mut Cpu0BudgetLedger,
    pending: &mut OutputQueue<128>,
) -> Result<(), Fault> {
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
    loop {
        let window = now_ns() / WINDOW_NS;
        if window >= next_window {
            next_window = window + 1;
            for (index, task) in tasks.iter_mut().enumerate() {
                turn(policy, manifest, index, task, ledger)?;
            }
        }
        if window >= console_window || pending.pending() != 0 {
            let start = Sample::now();
            match ledger.reserve_kernel_with_wall(
                0,
                Class::Coordination,
                CONSOLE_TURN_NS,
                MAX_WALL_NS,
                start.wall,
            ) {
                Ok(grant) => {
                    console_window = window + 1;
                    let result = if pending.pending() == 0 && window >= proof_window {
                        proof_window = window + EVIDENCE_WINDOWS;
                        queue_progress(&mut tasks, window, pending)
                    } else {
                        Ok(())
                    };
                    if result.is_ok() {
                        resident::poll_console(
                            &mut uart,
                            pending,
                            &mut command,
                            IRQS[0].load(Ordering::Acquire),
                        );
                    }
                    settle(ledger, grant, &start)?;
                    result?;
                }
                Err(Error::Exhausted) => {}
                Err(error) => return Err(error.into()),
            }
        }
        wait_for_tick();
    }
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

fn wait_for_tick() {
    // SAFETY: the boot GIC handler rearms CPU0's EL1 timer. This
    // wait leaves the stopped EL0 contexts untouched.
    unsafe {
        timer::arm(resident::timer_deadline());
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

fn fence(info: &BootInfo, ledger: Cpu0BudgetLedger, pending: OutputQueue<128>, fault: Fault) -> ! {
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
    };
    // Finish any retained serial suffix before the read-only status banner.
    resident::serve_with_queue(info, Some(FENCED), ledger, pending, Some(witness))
}

pub(super) fn run(info: &BootInfo) -> ! {
    assert_eq!(cpu::slot(), 0);
    // SAFETY: this opt-in diagnostic requires the pinned MTTCG PMU backend.
    // CPU0 owns its counter from EL1 and the verifier checks the host hashes.
    unsafe { timer::init_cpu_accounting() };
    frames::register_or_fatal();
    bring_up_production(info);
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 timer PPI");
    let mut ledger = Cpu0BudgetLedger::new();
    let config = match startup_work(&mut ledger, 1, media_staging::verify_scratch_config) {
        Ok(Ok(config)) => config,
        Ok(Err(_)) => resident::serve(info, Some(FENCED), ledger),
        Err(fault) => fence(info, ledger, OutputQueue::new(), fault),
    };
    // This existing scratch formatter and paired BootEpoch transport owns
    // its per-request I/O deadlines. It is a pre-admission diagnostic, with
    // no role or service grant outstanding.
    let mut staged = media_staging::stage_with_policy(info, Some(config));
    let Some(boot) = staged.resident_boot.take() else {
        resident::serve(info, Some(NO_MEDIA), ledger);
    };
    let Ok(policy) = boot.policy() else {
        resident::serve(info, Some(FENCED), ledger);
    };
    if policy.boot_epoch() != staged.confirmed_epoch {
        resident::serve(info, Some(FENCED), ledger);
    }
    let Ok(actors) = identities(&policy) else {
        resident::serve(info, Some(FENCED), ledger);
    };
    if recovery::init_signed(&policy).is_err() {
        resident::serve(info, Some(FENCED), ledger);
    }
    let members = match startup_work(&mut ledger, 2, || {
        core::array::from_fn(|index| load_role_with_identity(index, actors[index].generation, 0, 0))
    }) {
        Ok(members) => members,
        Err(fault) => fence(info, ledger, OutputQueue::new(), fault),
    };
    let manifest = NativeRoleManifest {
        online_mask: profile::ONLINE,
        members,
        other_protected_pool_bytes: core::mem::size_of::<[super::Tables; ROLE_COUNT]>()
            + super::COPY
            + super::PLAN_POOL_BYTES
            + 1024 * 1024,
        other_control_ns_per_100ms: 10_000_000,
    };
    let Ok(manifest) = manifest.validated() else {
        resident::serve(info, Some(FENCED), ledger);
    };
    report(
        "V020_SIGNED_RESIDENT_BOOT",
        policy.boot_epoch(),
        ROLE_COUNT as u64,
        0,
    );
    for (index, actor) in actors.iter().enumerate() {
        report(
            "V020_SIGNED_RESIDENT_ROLE",
            index as u64,
            actor.id,
            actor.generation,
        );
    }
    let mut pending = OutputQueue::new();
    match run_tasks(info, &policy, &manifest, &mut ledger, &mut pending) {
        Err(fault) => fence(info, ledger, pending, fault),
        Ok(()) => resident::serve(info, Some(FENCED), ledger),
    }
}

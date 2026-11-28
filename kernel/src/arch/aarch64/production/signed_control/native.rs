//! CPU0 owns the registered control transaction and D01 target view.
//! The native business scheduler owns observations and policy effects.

mod apply;

use super::super::signed_d01::{self, D01Observation};
use super::{
    Caller, MAX_WAIT_NS, NativeRole, Role, RpcError, RpcTable, SNAPSHOT, SignedCaller, Syscall,
    VerifiedSpan, authorized, now_ns, recovery,
};
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_arch_aarch64::cpu;
use cyxia_control_model::native_v0199::{MAX_AGE_NS, SNAPSHOT_BYTES};
use cyxia_kernel_core::{
    control_plane::{
        Error, Identity,
        action_schema_v2::ActionV2,
        apply_report_v1::{
            APPLY_HEADER_BYTES, ApplyReportV1, ExecutorBindingV1, PlanKey, PlanQueryReplyV3,
        },
        apply_work_v1::WorkFrame,
        candidate_registry_v0199::{CatalogEntry, FrozenCandidates},
        decision_record_v3::{DECISION_BYTES, DecisionRecordV3, DecisionSource},
        desired_plan_v0199::DesiredBank,
        plan_wire_v2::{
            PLAN_HEADER_BYTES, POLICY_ENVELOPE_BYTES, PlanHeaderV2, PolicyActionV2,
            encode_single_action,
        },
        registered_gate_v3::{
            Publication, RegisteredDecisionGate, TERMINAL_HISTORY, TrustedRegistrationScope,
        },
        role_manifest_v0199::{
            AUDIT_READ, DECISION_REGISTER, PUBLISH_PLAN, READ_DECISIONS, ROLE_COUNT, SnapshotView,
        },
        rule_profile_v2::{Candidates, Profile},
        snapshot_store_v3::{SnapshotStore, Target, ViewGrant},
        svc_bridge_v3::{
            FrozenNativePlan, SvcV3Bridge, VerifiedNativeCaller, read_registered_decision_rpc,
        },
    },
    security::{
        Error as SecurityError,
        cap_record_v3::{CapRecordV3, SNAPSHOT_READ},
        startup_catalog_v0199::role_services::RoleServices,
        syscall_v3::ABI_VERSION,
    },
};
use sha2::{Digest, Sha256};

const DOMAIN: u16 = 1;
const PLAN_BYTES: usize = PLAN_HEADER_BYTES + POLICY_ENVELOPE_BYTES + 4;
const REPORT_BYTES: usize = APPLY_HEADER_BYTES + 2;
const APPLY_DEADLINE_NS: u64 = 50_000_000;
const LEASE_NS: u64 = 10_000_000_000;
const NO_HOLDER: Identity = Identity {
    id: 0,
    generation: 0,
};

#[derive(Clone, Copy)]
struct Setup {
    boot_epoch: u64,
    controller_epoch: u64,
    target: Target,
    rules: Profile<'static>,
    rules_hash: [u8; 32],
    catalog_digest: [u8; 32],
}

#[derive(Clone, Copy)]
struct Owners {
    controller: Caller,
    publisher: Caller,
    supervisor: Caller,
}

#[derive(Clone, Copy)]
struct Sample {
    seq: u64,
    at: u64,
    base_version: u64,
    observation: D01Observation,
    weight_hold: bool,
}

enum Stage {
    Prepared,
    Unknown,
    Published,
    Applying(WorkFrame),
    Cancelled([u8; REPORT_BYTES]),
}

struct Plan {
    wire: [u8; PLAN_BYTES],
    decision: [u8; DECISION_BYTES],
    key: PlanKey,
    decision_seq: u64,
    sampled_ns: u64,
    expires_ns: u64,
    weight_before: u16,
    candidates: FrozenCandidates,
    stage: Stage,
}

#[derive(Clone, Copy)]
struct Terminal {
    key: PlanKey,
    decision_seq: u64,
    plan_digest: [u8; 32],
    decision_digest: [u8; 32],
    report: [u8; REPORT_BYTES],
}

struct NativeControl {
    setup: Option<Setup>,
    owners: Option<Owners>,
    supervisor_closed: bool,
    views: [Option<CapRecordV3>; ROLE_COUNT],
    snapshots: SnapshotStore,
    desired: DesiredBank,
    gate: RegisteredDecisionGate<'static>,
    decisions: RpcTable,
    sample: Option<Sample>,
    plan: Option<Plan>,
    terminal: [Option<Terminal>; TERMINAL_HISTORY],
    next_terminal: usize,
    last_weight_change_ns: Option<u64>,
}

impl NativeControl {
    const fn empty() -> Self {
        Self {
            setup: None,
            owners: None,
            supervisor_closed: false,
            views: [None; ROLE_COUNT],
            snapshots: SnapshotStore::empty(),
            desired: DesiredBank::empty(),
            gate: RegisteredDecisionGate::unbound(),
            decisions: RpcTable::new(),
            sample: None,
            plan: None,
            terminal: [None; TERMINAL_HISTORY],
            next_terminal: 0,
            last_weight_change_ns: None,
        }
    }
}

pub(super) const PROTECTED_BYTES: usize = core::mem::size_of::<NativeControl>();

// The initialized kernel data segment contains the table enum sentinels.
// This storage has no EL0 alias and is charged to the control pool above.
static mut NATIVE: NativeControl = NativeControl::empty();
static PUBLICATIONS_FENCED: AtomicBool = AtomicBool::new(false);

pub(crate) fn publications_fenced() -> bool {
    PUBLICATIONS_FENCED.load(Ordering::Acquire)
}

fn with_control<T>(f: impl FnOnce(&mut NativeControl) -> T) -> T {
    assert_eq!(cpu::slot(), 0);
    // SAFETY: startup, foreground coordination and stopped-role SVC handling
    // are serialized on CPU0. None of these calls enters EL0 or calls back into
    // this module, and the IRQ and business CPU paths never access NATIVE.
    f(unsafe { &mut *addr_of_mut!(NATIVE) })
}

fn binding(target: Target) -> ExecutorBindingV1 {
    ExecutorBindingV1 {
        domain: target.domain,
        role: 1,
        active: true,
        target: target.object,
        executor_generation: target.owner.generation,
        holder: NO_HOLDER,
        endpoint_cap_id: 0,
    }
}

fn snapshot_view(role: Role) -> Option<(SnapshotView, u16)> {
    Some(match role {
        Role::Operations => (SnapshotView::Operations, 0x0f7f),
        Role::Security => (SnapshotView::RedactedSecurity, 0x0040),
        Role::DeterministicController => (SnapshotView::ControllerRawEvidence, 0x0f7f),
        _ => return None,
    })
}

impl NativeControl {
    fn bind_view(
        &mut self,
        index: usize,
        member: NativeRole,
        caps: u64,
        selector: u64,
        boot_epoch: u64,
        target: Target,
    ) -> Result<(), Error> {
        if caps & SNAPSHOT == 0 {
            return Ok(());
        }
        if let Some(bound) = self.views[index] {
            return if bound.cap_id == selector && bound.holder == member.actor {
                Ok(())
            } else {
                Err(Error::Denied)
            };
        }
        let (view, allowed_fields) = snapshot_view(member.role).ok_or(Error::Denied)?;
        let cap = CapRecordV3 {
            cap_id: selector,
            holder: member.actor,
            target: target.object,
            parent_cap_id: 0,
            parent_generation: 0,
            deny_generation: 0,
            rights: SNAPSHOT_READ,
            object_kind: 12,
            state: 1,
            depth: 0,
            source_role: u32::from(member.role.id()),
            owner_group: u32::MAX,
            record_generation: boot_epoch,
        };
        let grant = ViewGrant {
            cap: selector,
            holder: member.actor,
            endpoint: selector,
            view,
            selector: target.object.id,
            domain: target.domain,
            target: target.object,
            allowed_fields,
        };
        self.snapshots.register_protected_view(grant, |_| {
            if !authorized(member, caps, selector, Syscall::ReadSnapshot, selector) {
                return Err(Error::Denied);
            }
            cap.check_snapshot_view(member.actor, target.object, boot_epoch, member.role)
                .map_err(capability_error)
        })?;
        self.views[index] = Some(cap);
        Ok(())
    }
}

pub(crate) fn install_native(
    boot_epoch: u64,
    controller_epoch: u64,
    members: &[NativeRole; ROLE_COUNT],
    grants: RoleServices,
    selectors: [u64; ROLE_COUNT],
    catalog_digest: [u8; 32],
    rules: Profile<'static>,
) -> Result<(), SecurityError> {
    if !(0..ROLE_COUNT).any(|index| grants.control_caps(index) & SNAPSHOT != 0) {
        return Ok(());
    }
    with_control(|state| {
        if state.setup.is_some() || catalog_digest == [0; 32] || controller_epoch == 0 {
            return Err(Error::Denied);
        }
        let target = signed_d01::target(boot_epoch);
        let owner = |role, rights| {
            let (i, member) = members.iter().enumerate().find(|(_, m)| m.role == role)?;
            let selector = selectors[i];
            (selector != 0 && grants.control_caps(i) & rights == rights).then_some(Caller {
                boot_epoch,
                holder: member.actor,
                role: member.role.id(),
                endpoint: selector,
                cap: selector,
            })
        };
        let owners = match (
            owner(Role::DeterministicController, SNAPSHOT | DECISION_REGISTER),
            owner(Role::Publisher, PUBLISH_PLAN | READ_DECISIONS),
            owner(Role::Supervisor, AUDIT_READ),
        ) {
            (Some(controller), Some(publisher), Some(supervisor)) => Some(Owners {
                controller,
                publisher,
                supervisor,
            }),
            _ => None,
        };
        // The confirmed boot owner supplies members, profile and actual
        // detached grants. The scheduler proves live target state again at
        // each sample, publication and application boundary.
        state.snapshots.bind_boot(boot_epoch, || Ok(()))?;
        state.snapshots.register_target(target, |t| {
            if t == signed_d01::target(boot_epoch) {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        })?;
        for (index, &member) in members.iter().enumerate() {
            state.bind_view(
                index,
                member,
                grants.control_caps(index),
                selectors[index],
                boot_epoch,
                target,
            )?;
        }
        if let Some(owners) = owners {
            state.gate.bind_terminal_owner(
                owners.controller.holder,
                owners.publisher.holder,
                owners.supervisor.holder,
                boot_epoch,
                controller_epoch,
            )?;
            state.desired.bind_boot(
                boot_epoch,
                controller_epoch,
                owners.publisher.holder,
                || Ok(()),
            )?;
            state.desired.register_target(binding(target), |_| Ok(()))?;
            state
                .decisions
                .bind(owners.publisher, false)
                .map_err(|_| Error::Denied)?;
            state.owners = Some(owners);
        }
        state.setup = Some(Setup {
            boot_epoch,
            controller_epoch,
            target,
            rules,
            rules_hash: sha(rules.canonical_bytes()),
            catalog_digest,
        });
        Ok(())
    })
    .map_err(|e| match e {
        Error::Exhausted => SecurityError::Capacity,
        Error::Busy => SecurityError::Busy,
        _ => SecurityError::Unauthorized,
    })
}

pub(super) fn retire_role(
    index: usize,
    old: NativeRole,
    selector: u64,
) -> Result<(), SecurityError> {
    with_control(|state| {
        if let Some(cap) = state.views[index] {
            if cap.holder != old.actor || cap.cap_id != selector {
                return Err(SecurityError::Unauthorized);
            }
            state
                .snapshots
                .revoke_view(old.actor, selector)
                .map_err(|_| SecurityError::Unauthorized)?;
            state.views[index] = None;
        }
        if old.role == Role::Supervisor
            && let Some(owners) = state.owners
        {
            if owners.supervisor.holder != old.actor || owners.supervisor.cap != selector {
                return Err(SecurityError::Unauthorized);
            }
            state.supervisor_closed = true;
        }
        if let Some(owners) = state.owners {
            let owner = match old.role {
                Role::DeterministicController => Some(owners.controller),
                Role::Publisher => Some(owners.publisher),
                _ => None,
            };
            if let Some(owner) = owner {
                if owner.holder != old.actor || owner.cap != selector {
                    return Err(SecurityError::Unauthorized);
                }
                if publications_fenced() {
                    return Ok(());
                }
                let setup = state.setup.as_mut().ok_or(SecurityError::Unauthorized)?;
                let next_epoch = setup
                    .controller_epoch
                    .checked_add(1)
                    .ok_or(SecurityError::Exhausted)?;
                state
                    .gate
                    .fence(owners.supervisor.holder)
                    .map_err(|_| SecurityError::Unauthorized)?;
                state.desired.fence_publications();
                // Guest registration and query use the advanced epoch. The
                // old bank and gate retain their original keys for EL1
                // reconciliation until a trusted restart can bind both.
                setup.controller_epoch = next_epoch;
                // Secondaries preserve established work while this latch
                // disables new admissions until a trusted handoff.
                PUBLICATIONS_FENCED.store(true, Ordering::Release);
            }
        }
        Ok(())
    })
}

pub(super) fn restore_role(
    index: usize,
    old: NativeRole,
    next: NativeRole,
    capabilities: u64,
    selector: u64,
) -> Result<(), SecurityError> {
    with_control(|state| {
        let Some(setup) = state.setup else {
            return Ok(());
        };
        state
            .bind_view(
                index,
                next,
                capabilities,
                selector,
                setup.boot_epoch(),
                setup.target,
            )
            .map_err(|_| SecurityError::Unauthorized)?;
        if next.role == Role::Supervisor
            && let Some(owners) = state.owners.as_mut()
        {
            if !state.supervisor_closed
                && owners.supervisor.holder == next.actor
                && owners.supervisor.cap == selector
            {
                return Ok(());
            }
            if !state.supervisor_closed
                || selector == owners.supervisor.cap
                || capabilities & AUDIT_READ == 0
                || !authorized(next, capabilities, selector, Syscall::QueryPlan, 0)
            {
                return Err(SecurityError::Unauthorized);
            }
            // The parent adapter checked the durable generation and old
            // root retirement. Preserve the EL1 gate's accepted work.
            state
                .gate
                .replace_terminal_owner(old.actor, next.actor, || Ok(()))
                .map_err(|_| SecurityError::Unauthorized)?;
            owners.supervisor = Caller {
                boot_epoch: setup.boot_epoch(),
                holder: next.actor,
                role: next.role.id(),
                endpoint: selector,
                cap: selector,
            };
            state.supervisor_closed = false;
        }
        Ok(())
    })
}

pub(crate) fn native_active() -> bool {
    with_control(|state| state.owners.is_some())
}

pub(crate) fn native_pending() -> bool {
    with_control(|state| {
        state.plan.as_ref().is_some_and(|plan| {
            matches!(
                plan.stage,
                Stage::Published | Stage::Applying(_) | Stage::Cancelled(_)
            )
        })
    })
}

pub(crate) fn snapshot_due(now: u64) -> bool {
    with_control(|state| state.snapshot_due(now))
}

pub(crate) fn refresh_snapshot(now: u64) -> Result<(), Error> {
    with_control(|state| {
        if !state.snapshot_due(now) {
            return Ok(());
        }
        let setup = state.setup.ok_or(Error::NotReady)?;
        match setup.observe(now) {
            Ok(o) => state.capture_snapshot(setup, o),
            Err(Error::Busy | Error::NotReady | Error::Stale) => Ok(()),
            Err(error) => Err(error),
        }
    })
}

impl NativeControl {
    fn snapshot_due(&self, now: u64) -> bool {
        self.setup.is_some()
            && self
                .plan
                .as_ref()
                .is_none_or(|plan| matches!(plan.stage, Stage::Prepared) && now >= plan.expires_ns)
            && self.sample.is_none_or(|sample| {
                now / MAX_AGE_NS != sample.at / MAX_AGE_NS
                    || sample.base_version != self.desired.version()
            })
    }

    fn capture_snapshot(&mut self, setup: Setup, o: D01Observation) -> Result<(), Error> {
        let seq = self.snapshots.capture(
            o.ledger_generation,
            o.core_generation,
            o.sampled_ns,
            [None; 8],
            &[o.domain],
            |row| {
                if row.target == setup.target {
                    Ok(())
                } else {
                    Err(Error::Stale)
                }
            },
        )?;
        self.sample = Some(Sample {
            seq,
            at: o.sampled_ns,
            base_version: self.desired.version(),
            observation: o,
            weight_hold: self
                .last_weight_change_ns
                .is_some_and(|at| o.sampled_ns.saturating_sub(at) < MAX_AGE_NS),
        });
        Ok(())
    }
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn rpc_error(e: Error) -> RpcError {
    match e {
        Error::Invalid => RpcError::Format,
        Error::Busy => RpcError::Busy,
        Error::Stale => RpcError::Stale,
        Error::Expired => RpcError::Expired,
        Error::Denied => RpcError::Auth,
        Error::Exhausted => RpcError::Capacity,
        Error::NotReady => RpcError::Again,
        Error::Clock => RpcError::Io,
    }
}

fn capability_error(error: SecurityError) -> Error {
    match error {
        SecurityError::Stale => Error::Stale,
        _ => Error::Denied,
    }
}

fn native_caller(caller: &SignedCaller, selector: u64) -> VerifiedNativeCaller {
    VerifiedNativeCaller {
        identity: caller.member.actor,
        package_abi: ABI_VERSION,
        endpoint_cap: selector,
        cpu: cpu::slot(),
    }
}

fn copy_out(output: VerifiedSpan<'_>, bytes: &[u8]) -> Result<(), RpcError> {
    if output
        .copy_out_and_check(bytes)
        .map_err(|_| RpcError::Fault)?
    {
        Ok(())
    } else {
        Err(RpcError::Fault)
    }
}

impl Setup {
    fn boot_epoch(self) -> u64 {
        self.boot_epoch
    }

    fn observe(self, now: u64) -> Result<D01Observation, Error> {
        let o = signed_d01::observe(self.boot_epoch(), now)?;
        if o.domain.target != self.target {
            return Err(Error::Stale);
        }
        Ok(o)
    }

    fn key(self, record: DecisionRecordV3) -> Result<PlanKey, Error> {
        if record.boot_epoch != self.boot_epoch()
            || record.controller_epoch != self.controller_epoch
        {
            return Err(Error::Stale);
        }
        Ok(PlanKey {
            boot_epoch: record.boot_epoch,
            controller_epoch: record.controller_epoch,
            plan_seq: record.plan_seq,
        })
    }
}

impl Sample {
    fn matches(self, o: D01Observation) -> bool {
        self.observation.ledger_generation == o.ledger_generation
            && self.observation.core_generation == o.core_generation
            && self.observation.domain.target == o.domain.target
            && self.observation.current_weight == o.current_weight
    }

    fn context(self, setup: Setup, now: u64) -> TrustedRegistrationScope {
        TrustedRegistrationScope {
            boot_epoch: setup.boot_epoch(),
            controller_epoch: setup.controller_epoch,
            rules_generation: setup.rules.generation,
            rules_hash: setup.rules_hash,
            base_plan_version: self.base_version,
            ledger_generation: self.observation.ledger_generation,
            core_generation: self.observation.core_generation,
            snapshot_seq: self.seq,
            sampled_ns: self.at,
            now_ns: now,
        }
    }
}

pub(super) fn read_snapshot(
    caller: &SignedCaller,
    selector: u64,
    args: [u64; 6],
) -> Result<(), RpcError> {
    let bytes = with_control(|state| {
        let setup = state.setup.ok_or(RpcError::Again)?;
        if args[1] != u64::from(setup.target.domain) || args[2] != setup.target.object.id {
            return Err(RpcError::Auth);
        }
        let role = caller.member.role;
        let (view, mask) = snapshot_view(role).ok_or(RpcError::Auth)?;
        let cap = state.views[caller.index]
            .filter(|cap| cap.cap_id == selector)
            .ok_or(RpcError::Auth)?;
        cap.check_snapshot_view(
            caller.member.actor,
            setup.target.object,
            setup.boot_epoch(),
            role,
        )
        .map_err(super::security_error)?;
        let output = VerifiedSpan::verify_signed(caller, args[3], args[4] as usize, true)
            .map_err(|_| RpcError::Fault)?;
        let sample = state.sample.ok_or(RpcError::Again)?;
        signed_d01::check_scope(setup.boot_epoch()).map_err(rpc_error)?;
        let (ledger, cores) = (
            sample.observation.ledger_generation,
            sample.observation.core_generation,
        );
        let now = now_ns();
        let bytes: [u8; SNAPSHOT_BYTES] = state
            .snapshots
            .read_protected(
                caller.member.actor,
                cpu::slot(),
                selector,
                setup.target.domain,
                args[2],
                ledger,
                cores,
                now,
                |grant| {
                    if grant.view == view
                        && grant.allowed_fields == mask
                        && grant.endpoint == selector
                        && grant.target == setup.target.object
                    {
                        Ok(())
                    } else {
                        Err(Error::Denied)
                    }
                },
            )
            .map_err(rpc_error)?;
        Ok((output, bytes))
    })?;
    copy_out(bytes.0, &bytes.1)
}

fn candidates(
    state: &NativeControl,
    setup: Setup,
    sample: Sample,
    now: u64,
) -> Result<FrozenCandidates, Error> {
    let o = sample.observation;
    let snapshot = state.snapshots.frozen_for_owner(
        setup.target,
        o.ledger_generation,
        o.core_generation,
        now,
        |target| {
            if target == o.domain.target {
                Ok(())
            } else {
                Err(Error::Stale)
            }
        },
    )?;
    let current = ActionV2::GroupWeight(o.current_weight);
    let values = ActionV2::values(DOMAIN)?;
    let current_index = values
        .iter()
        .position(|v| *v == current)
        .ok_or(Error::Stale)?;
    let catalog: [CatalogEntry; 4] = core::array::from_fn(|i| CatalogEntry {
        ordinal: i as u16,
        value: values[i],
    });
    // ActionSchema fixes the compiled ordinals. The signed startup catalog
    // digest binds them to this deployment's authenticated rule inputs.
    FrozenCandidates::capture(
        snapshot,
        &catalog,
        setup.catalog_digest,
        current,
        None,
        Some(true),
        false,
        |entries, digest| {
            if entries == catalog && digest == setup.catalog_digest {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        },
        |value| {
            Ok(values.iter().position(|v| *v == value).is_some_and(|i| {
                i == current_index || (!sample.weight_hold && current_index.abs_diff(i) == 1)
            }))
        },
    )
}

impl Plan {
    fn matches(&self, wire: &[u8; PLAN_BYTES], decision: &[u8; DECISION_BYTES]) -> bool {
        &self.wire == wire && &self.decision == decision
    }
}

pub(super) fn register(
    caller: &SignedCaller,
    args: [u64; 6],
    decision: &[u8; DECISION_BYTES],
    record: DecisionRecordV3,
    output: VerifiedSpan<'_>,
) -> Result<(), RpcError> {
    with_control(|state| {
        let setup = state.setup.ok_or(RpcError::Again)?;
        let owners = state.owners.ok_or(RpcError::Again)?;
        if owners.controller.holder != caller.member.actor || owners.controller.cap != args[0] {
            return Err(RpcError::Auth);
        }
        let key = setup.key(record).map_err(rpc_error)?;
        if (record.domain_id, record.target_id, record.target_generation)
            != (
                setup.target.domain,
                setup.target.object.id,
                setup.target.object.generation,
            )
        {
            return Err(RpcError::Stale);
        }
        if record.source != DecisionSource::RuleOnly || record.mode != 0 {
            return Err(RpcError::Auth);
        }
        let now = now_ns();
        if state.gate.has_unpublished()
            && state
                .gate
                .expire_unpublished(owners.controller.holder, now)
                .map_err(rpc_error)?
        {
            state.plan = None;
        }
        if let Some(t) = state
            .terminal
            .iter()
            .flatten()
            .find(|t| t.key == key || t.decision_seq == record.decision_seq)
        {
            return if t.decision_digest == sha(decision) {
                Ok(())
            } else {
                Err(RpcError::Conflict)
            };
        }
        if let Some(plan) = &state.plan {
            if plan.key != key && plan.decision_seq != record.decision_seq {
                return Err(RpcError::Busy);
            }
            if &plan.decision != decision {
                return Err(RpcError::Conflict);
            }
            match plan.stage {
                Stage::Prepared => (),
                Stage::Unknown => return Err(RpcError::Again),
                _ => return Ok(()),
            }
        }
        if recovery::audit_degraded() {
            return Err(RpcError::Again);
        }
        register_prepared(
            state, setup, owners, record, key, decision, caller, args, now,
        )
        .map_err(rpc_error)
    })?;
    copy_out(output, &record.decision_seq.to_le_bytes())
}

#[allow(clippy::too_many_arguments)]
fn register_prepared(
    state: &mut NativeControl,
    setup: Setup,
    owners: Owners,
    record: DecisionRecordV3,
    key: PlanKey,
    decision: &[u8; DECISION_BYTES],
    caller: &SignedCaller,
    args: [u64; 6],
    now: u64,
) -> Result<(), Error> {
    let sample = state.sample.ok_or(Error::NotReady)?;
    if sample.seq != record.snapshot_seq
        || sample.base_version != state.desired.version()
        || !sample.matches(setup.observe(now)?)
    {
        return Err(Error::Stale);
    }
    let candidates = candidates(state, setup, sample, now)?;
    let rule = setup
        .rules
        .match_candidates(
            DOMAIN,
            setup.target.object.id,
            candidates.rule_fields(),
            Candidates {
                static_ordinals: candidates.ordinals(),
            },
        )?
        .ok_or(Error::Denied)?;
    let view = candidates.view();
    let local = view.selected(rule.fallback_index)?;
    let selected = ActionV2::decode(DOMAIN, 1, local.action_payload)?;
    let reason_valid = match record.reason_code {
        1 => selected == ActionV2::GroupWeight(sample.observation.current_weight),
        2 => selected == ActionV2::GroupWeight(1),
        3 => true,
        _ => false,
    };
    if !record.matches_rule(rule)
        || record.selected_index != rule.fallback_index
        || record.candidate_set_hash != candidates.digest()
        || !reason_valid
    {
        return Err(Error::Denied);
    }
    let context = sample.context(setup, now);
    let mut wire = [0; PLAN_BYTES];
    let expires_ns = sample.at.checked_add(MAX_AGE_NS).ok_or(Error::Clock)?;
    if record.decision_expires_ns > expires_ns || record.decision_expires_ns <= now {
        return Err(Error::Expired);
    }
    encode_single_action(
        PlanHeaderV2 {
            plan_seq: key.plan_seq,
            base_plan_version: context.base_plan_version,
            active_model_generation: 0,
            controller_epoch: context.controller_epoch,
            snapshot_seq: context.snapshot_seq,
            active_until_local_ns: sample.at.checked_add(LEASE_NS).ok_or(Error::Clock)?,
            action_count: 1,
            flags: 0,
        },
        PolicyActionV2 {
            domain_id: DOMAIN,
            action_kind: 1,
            controller_epoch: context.controller_epoch,
            decision_seq: record.decision_seq,
            snapshot_seq: context.snapshot_seq,
            target_id: setup.target.object.id,
            target_generation: setup.target.object.generation,
            ledger_generation: context.ledger_generation,
            core_generation: context.core_generation,
            expires_local_ns: record.decision_expires_ns,
            model_hash: [0; 32],
            candidate_set_hash: candidates.digest(),
            candidate_index: rule.fallback_index,
            action_payload: local.action_payload,
        },
        &mut wire,
    )?;
    let frozen = FrozenNativePlan {
        bytes: &wire,
        sidecars: core::slice::from_ref(decision),
        rules: &setup.rules,
        actions: &[local],
        context,
    };
    let mut bridge = SvcV3Bridge {
        gate: &mut state.gate,
        decision_endpoint_cap: owners.controller.cap,
        publisher_cap: owners.publisher.cap,
    };
    bridge.register_rule_only(native_caller(caller, args[0]), args, decision, &frozen)?;
    state.plan = Some(Plan {
        wire,
        decision: *decision,
        key,
        decision_seq: record.decision_seq,
        sampled_ns: sample.at,
        expires_ns: record.decision_expires_ns,
        weight_before: sample.observation.current_weight,
        candidates,
        stage: Stage::Prepared,
    });
    Ok(())
}

pub(super) fn read_decision(
    caller: &SignedCaller,
    args: [u64; 6],
    request: &[u8],
    output: VerifiedSpan<'_>,
) -> Result<(), RpcError> {
    let reply = with_control(|state| {
        let owner = state.owners.ok_or(RpcError::Again)?.publisher;
        let now = now_ns();
        read_registered_decision_rpc(
            &state.gate,
            &mut state.decisions,
            owner,
            native_caller(caller, args[0]),
            args,
            request,
            now,
            now.saturating_add(MAX_WAIT_NS),
        )
    })?;
    copy_out(output, reply.bytes())
}

pub(super) fn publish(
    caller: &SignedCaller,
    selector: u64,
    args: [u64; 6],
) -> Result<(), RpcError> {
    with_control(|state| {
        let setup = state.setup.ok_or(RpcError::Again)?;
        let owners = state.owners.ok_or(RpcError::Again)?;
        if caller.member.actor != owners.publisher.holder || selector != owners.publisher.cap {
            return Err(RpcError::Auth);
        }
        if args[1] != PLAN_BYTES as u64 || args[3] != 1 {
            return Err(RpcError::Format);
        }
        let mut wire = [0; PLAN_BYTES];
        let mut decision = [0; DECISION_BYTES];
        for (address, dest) in [
            (args[0], wire.as_mut_slice()),
            (args[2], decision.as_mut_slice()),
        ] {
            VerifiedSpan::verify_signed(caller, address, dest.len(), false)
                .and_then(|span| span.copy_in(dest))
                .map_err(|_| RpcError::Fault)?;
        }
        let record = DecisionRecordV3::decode(&decision).map_err(rpc_error)?;
        let key = setup.key(record).map_err(rpc_error)?;
        if let Some(t) = state
            .terminal
            .iter()
            .flatten()
            .find(|t| t.key == key || t.decision_seq == record.decision_seq)
        {
            return if t.plan_digest == sha(&wire) && t.decision_digest == sha(&decision) {
                Ok(())
            } else {
                Err(RpcError::Conflict)
            };
        }
        let plan = state.plan.as_ref().ok_or(RpcError::Stale)?;
        if key != plan.key && record.decision_seq != plan.decision_seq {
            return Err(RpcError::Stale);
        }
        if !plan.matches(&wire, &decision) {
            return Err(RpcError::Conflict);
        }
        match plan.stage {
            Stage::Published | Stage::Applying(_) | Stage::Cancelled(_) => return Ok(()),
            Stage::Unknown => return Err(RpcError::Again),
            Stage::Prepared => (),
        }
        // Audit backpressure fences the first publication. Retained
        // results and the foreground's accepted work remain reachable.
        if recovery::audit_degraded() {
            return Err(RpcError::Again);
        }
        let now = now_ns();
        if now >= plan.expires_ns {
            return Err(RpcError::Expired);
        }
        let sample = state.sample.ok_or(RpcError::Again)?;
        if sample.seq != record.snapshot_seq
            || sample.base_version != state.desired.version()
            || !sample.matches(setup.observe(now).map_err(rpc_error)?)
        {
            return Err(RpcError::Stale);
        }
        // Reuse the decoded candidate evidence only while the exact frozen
        // snapshot and resource generations still match the native owner.
        let view = plan.candidates.view();
        let local = view.selected(record.selected_index).map_err(rpc_error)?;
        let context = sample.context(setup, now);
        let frozen = FrozenNativePlan {
            bytes: &plan.wire,
            sidecars: core::slice::from_ref(&plan.decision),
            rules: &setup.rules,
            actions: &[local],
            context,
        };
        let mut bridge = SvcV3Bridge {
            gate: &mut state.gate,
            decision_endpoint_cap: owners.controller.cap,
            publisher_cap: owners.publisher.cap,
        };
        let mut entered_owner = false;
        let result = bridge.publish_plan(
            native_caller(caller, selector),
            args,
            &wire,
            core::slice::from_ref(&decision),
            &frozen,
            || {
                entered_owner = true;
                state
                    .desired
                    .publish_registered(
                        owners.publisher.holder,
                        cpu::slot(),
                        &wire,
                        context,
                        |actions| {
                            if actions.len() != 1
                                || actions[0].is_none_or(|a| a.binding != binding(setup.target))
                            {
                                return Err(Error::Denied);
                            }
                            Ok(())
                        },
                    )
                    .map(|_| ())
            },
        );
        let plan = state.plan.as_mut().unwrap();
        match result {
            Ok(Publication::AdapterAccepted) => plan.stage = Stage::Published,
            Ok(Publication::ReplayNoEffect) => (),
            Err(_) if entered_owner => plan.stage = Stage::Unknown,
            Err(_) => (),
        }
        result.map(|_| ()).map_err(rpc_error)
    })
}

pub(super) fn query(caller: &SignedCaller, selector: u64, args: [u64; 6]) -> Result<(), RpcError> {
    let (output, response) = with_control(|state| {
        let setup = state.setup.ok_or(RpcError::Auth)?;
        let owners = state.owners.ok_or(RpcError::Auth)?;
        if caller.member.role == Role::Supervisor && state.supervisor_closed {
            return Err(RpcError::Auth);
        }
        if ![owners.controller, owners.publisher, owners.supervisor]
            .iter()
            .any(|owner| owner.holder == caller.member.actor && owner.cap == selector)
        {
            return Err(RpcError::Auth);
        }
        let mut raw = [0; 24];
        VerifiedSpan::verify_signed(caller, args[0], raw.len(), false)
            .and_then(|span| span.copy_in(&mut raw))
            .map_err(|_| RpcError::Fault)?;
        let output = VerifiedSpan::verify_signed(caller, args[2], args[3] as usize, true)
            .map_err(|_| RpcError::Fault)?;
        let key = PlanKey::decode(&raw).map_err(rpc_error)?;
        if (key.boot_epoch, key.controller_epoch) != (setup.boot_epoch(), setup.controller_epoch) {
            return Err(RpcError::Stale);
        }
        Ok((
            output,
            state
                .query_plan(setup, key, now_ns())
                .and_then(PlanQueryReplyV3::encode)
                .map_err(rpc_error)?,
        ))
    })?;
    copy_out(output, &response)
}

impl NativeControl {
    fn query_plan(&self, setup: Setup, key: PlanKey, now: u64) -> Result<PlanQueryReplyV3, Error> {
        let mut reply = PlanQueryReplyV3 {
            key,
            plan_version: 0,
            state: 1,
            result: 0,
            action_count: 1,
            terminal_count: 0,
        };
        if let Some(t) = self.terminal.iter().flatten().find(|t| t.key == key) {
            let report = ApplyReportV1::decode(&t.report)?;
            reply.plan_version = report.plan_version;
            reply.state = 4;
            reply.result = report.result;
            reply.terminal_count = 1;
            return Ok(reply);
        }
        let plan = self
            .plan
            .as_ref()
            .filter(|p| p.key == key)
            .ok_or(Error::Stale)?;
        reply.state = match plan.stage {
            Stage::Prepared if now >= plan.expires_ns => return Err(Error::Stale),
            Stage::Prepared => 1,
            Stage::Published => 2,
            Stage::Applying(_) => 3,
            Stage::Unknown => {
                reply.result = RpcError::Io as i32;
                5
            }
            Stage::Cancelled(_) => 5,
        };
        if let Some(a) = self.desired.pending(DOMAIN, setup.target.object)? {
            if a.key != key {
                return Err(Error::Stale);
            }
            reply.plan_version = a.version;
            if now.saturating_sub(a.published_ns) >= APPLY_DEADLINE_NS {
                reply.state = 5;
                reply.result = RpcError::Timeout as i32;
            }
        }
        Ok(reply)
    }
}

pub(crate) use apply::tick_native;

//! V0.19.9 eight-role *native EL0 launch contract* (G0/G1).
//!
//! Validation is a necessary boot-time check, NOT proof that eight page tables
//! or threads have actually been constructed or that the CPU0 migration is
//! complete. EL1 must supply VERIFIED TTBR roots, distinct page ownership,
//! actual task IDs and privileged capability table. No role number in a wire
//! message confers authority. Unverified roles fail closed; no fallback to
//! hosted agents or CPU1 controllers.
use super::{Error, Identity};

pub const CONTROL_CPU: usize = 0;
pub const CONTROL_MASK: u64 = 1u64 << CONTROL_CPU;
pub const BUSINESS_MASK: u64 = 0b1110;
pub const REQUIRED_ONLINE_MASK: u64 = 0b1111;
pub const ROLE_COUNT: usize = 8;
pub const CONTROL_POOL_LIMIT: usize = 8 * 1024 * 1024;
pub const CONTROL_NS_PER_100MS: u64 = 70_000_000;
pub const OPERATIONS_MAX_NS: u64 = 30_000_000;
pub const SECURITY_MAX_NS: u64 = 8_000_000;
pub const PAGE_SIZE: u64 = 4096;

pub const SNAPSHOT: u64 = 1 << 0;
pub const SEND_ADVICE: u64 = 1 << 1;
pub const SEND_FINDING: u64 = 1 << 2;
pub const READ_RULES: u64 = 1 << 3;
pub const DECISION_REGISTER: u64 = 1 << 4;
pub const READ_DECISIONS: u64 = 1 << 5;
pub const PUBLISH_PLAN: u64 = 1 << 6;
pub const CANDIDATE_READ: u64 = 1 << 7;
pub const VALIDATION_REGISTER: u64 = 1 << 8;
pub const MODEL_MANAGE: u64 = 1 << 9;
pub const TRIAL_D15: u64 = 1 << 10;
pub const LEARNING_FEEDBACK: u64 = 1 << 11;
pub const CANDIDATE_SUBMIT: u64 = 1 << 12;
pub const AUDIT_READ: u64 = 1 << 13;
pub const FINDING_REVIEW: u64 = 1 << 14;
// Abstract manifest permissions, not the on-wire CapabilityRights bit numbers.
pub const TRIAL_NORMAL: u64 = 1 << 15;
pub const ADVICE_DISPOSITION: u64 = 1 << 16;
pub const EPOCH_ALLOC: u64 = 1 << 17;
pub const AUDIT_ACK: u64 = 1 << 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotView {
    Operations,
    RedactedSecurity,
    ControllerRawEvidence,
    RedactedValidation,
    RedactedSupervision,
}
/// Classification after EL1 capability lookup and canonical RPC decoding.
/// Trial domain comes from a frozen offline template, not message claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuxOperation {
    AuditRead,
    AuditAck,
    ModelPromote,
    ModelRollback,
    EpochAllocate { target: Role },
    TrialInstantiate { template_domain: u16 },
    ValidationRegister,
    CandidateSubmit,
    DecisionRead,
    AdviceDisposition,
    Ack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Operations,
    Security,
    DeterministicController,
    Publisher,
    Validator,
    ModelManager,
    Learner,
    Supervisor,
}
impl Role {
    pub const fn id(self) -> u16 {
        match self {
            Self::Operations => 6,
            Self::Security => 7,
            Self::DeterministicController => 2,
            Self::Publisher => 8,
            Self::Validator => 9,
            Self::ModelManager => 3,
            Self::Learner => 10,
            Self::Supervisor => 11,
        }
    }
    pub const fn allowed_caps(self) -> u64 {
        match self {
            Self::Operations => SNAPSHOT | SEND_ADVICE,
            Self::Security => SNAPSHOT | SEND_FINDING,
            Self::DeterministicController => {
                SNAPSHOT | READ_RULES | DECISION_REGISTER | TRIAL_NORMAL | ADVICE_DISPOSITION
            }
            Self::Publisher => READ_DECISIONS | PUBLISH_PLAN,
            Self::Validator => CANDIDATE_READ | VALIDATION_REGISTER,
            Self::ModelManager => MODEL_MANAGE | TRIAL_D15,
            Self::Learner => LEARNING_FEEDBACK | CANDIDATE_SUBMIT,
            Self::Supervisor => AUDIT_READ | AUDIT_ACK | EPOCH_ALLOC | FINDING_REVIEW,
        }
    }
}
pub const ROLES: [Role; ROLE_COUNT] = [
    Role::Operations,
    Role::Security,
    Role::DeterministicController,
    Role::Publisher,
    Role::Validator,
    Role::ModelManager,
    Role::Learner,
    Role::Supervisor,
];

/// Region is derived from EL1 owned-page metadata, not a naked model VA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateRegion {
    pub base: u64,
    pub bytes: u64,
}
impl PrivateRegion {
    fn valid(self) -> bool {
        self.base != 0
            && self.base.is_multiple_of(PAGE_SIZE)
            && self.bytes >= PAGE_SIZE
            && self.bytes.is_multiple_of(PAGE_SIZE)
            && self.base.checked_add(self.bytes).is_some()
    }
    fn overlaps(self, other: Self) -> bool {
        // Safe because caller first validates both intervals.
        self.base < other.base + other.bytes && other.base < self.base + self.bytes
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRole {
    pub role: Role,
    pub actor: Identity,
    /// Actual, EL1-verified nonzero physical TTBR0 root, private per-role.
    pub ttbr0_root: u64,
    /// EL1-owned contiguous PHYSICAL span backing private user writable pages.
    /// Must not overlap any role's page-table root. Native registry still
    /// proves the ownership of every lower-level table and all other pages.
    pub private_rw: PrivateRegion,
    pub caps: u64,
    /// Genuine protected per-role CPU budget debit, all on CPU0.
    pub control_ns_per_100ms: u64,
    pub cpu_mask: u64,
    pub thread_count: u16,
    /// Distinct EL1 endpoint selector; cannot be self-reported by EL0.
    pub endpoint_id: u64,
}
impl NativeRole {
    fn lifecycle_only(&self) -> bool {
        self.endpoint_id == 0 && self.caps == 0 && self.actor.id == u64::from(self.role.id())
    }
}

/// EL1's live ABI registration for a signed CPU0 lifecycle task. It binds
/// this exact holder generation to the staged root and hardware ASID.
#[derive(Clone, Copy)]
pub struct LifecycleBinding {
    member: NativeRole,
    ttbr0_asid: u64,
    abi: u16,
}
impl LifecycleBinding {
    pub fn new(member: NativeRole, asid: u8, abi: u16) -> Result<Self, Error> {
        if !member.lifecycle_only()
            || !member.actor.valid()
            || member.cpu_mask != CONTROL_MASK
            || member.thread_count != 1
            || member.ttbr0_root == 0
            || member.ttbr0_root >= 1 << 48
            || !member.ttbr0_root.is_multiple_of(PAGE_SIZE)
            || asid == 0
            || abi != crate::security::syscall_v3::ABI_VERSION
        {
            return Err(Error::Denied);
        }
        Ok(Self {
            member,
            ttbr0_asid: member.ttbr0_root | (u64::from(asid) << 48),
            abi,
        })
    }

    pub fn authenticate(&self, member: NativeRole, captured_ttbr0: u64, cpu: usize) -> Option<u16> {
        (cpu == CONTROL_CPU && self.member == member && self.ttbr0_asid == captured_ttbr0)
            .then_some(self.abi)
    }
}

#[derive(Clone, Copy)]
pub struct NativeRoleManifest {
    pub online_mask: u64,
    pub members: [NativeRole; ROLE_COUNT],
    pub other_protected_pool_bytes: usize,
    pub other_control_ns_per_100ms: u64,
}
/// An immutable, fully validated manifest borrow. A replacement must
/// finish using this borrow before changing any registered role. Admission
/// may then avoid repeating the complete eight-role overlap scan on each
/// individual SVC without accepting unvalidated or stale manifest fields.
pub struct ValidatedRoleManifest<'a, const SERVICES: bool = true>(&'a NativeRoleManifest);

/// A signed bootstrap cohort owns private contexts and CPU turns. This
/// validation supplies no service endpoint or capability authorization.
pub type ValidatedLifecycleManifest<'a> = ValidatedRoleManifest<'a, false>;

impl<'a, const SERVICES: bool> ValidatedRoleManifest<'a, SERVICES> {
    pub fn manifest(&self) -> &'a NativeRoleManifest {
        self.0
    }
}
impl ValidatedRoleManifest<'_> {
    pub fn can_act(&self, role: Role, actor: Identity, cap: u64, cpu: usize) -> Result<(), Error> {
        self.0.can_act_validated(role, actor, cap, cpu)
    }
    pub fn check_snapshot_view(
        &self,
        actor: Identity,
        endpoint: u64,
        cpu: usize,
        view: SnapshotView,
    ) -> Result<(), Error> {
        self.0
            .check_snapshot_view_validated(actor, endpoint, cpu, view)
    }
    pub fn check_aux(
        &self,
        actor: Identity,
        endpoint: u64,
        cpu: usize,
        op: AuxOperation,
    ) -> Result<Role, Error> {
        self.0.check_aux_validated(actor, endpoint, cpu, op)
    }
}
impl NativeRoleManifest {
    pub fn validated(&self) -> Result<ValidatedRoleManifest<'_>, Error> {
        self.validate()?;
        Ok(ValidatedRoleManifest(self))
    }
    pub fn validated_lifecycle(&self) -> Result<ValidatedLifecycleManifest<'_>, Error> {
        self.validate_inventory(false)?;
        Ok(ValidatedRoleManifest(self))
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_inventory(true)
    }
    fn validate_inventory(&self, services: bool) -> Result<(), Error> {
        if self.online_mask != REQUIRED_ONLINE_MASK
            || self.other_control_ns_per_100ms >= CONTROL_NS_PER_100MS
            || self.other_protected_pool_bytes >= CONTROL_POOL_LIMIT
        {
            return Err(Error::Denied);
        }
        let mut charge_ns = self.other_control_ns_per_100ms;
        let mut pool = self.other_protected_pool_bytes;
        for (index, entry) in self.members.iter().enumerate() {
            let authority_valid = if services {
                entry.endpoint_id != 0 && entry.caps == entry.role.allowed_caps()
            } else {
                entry.lifecycle_only()
            };
            if entry.role != ROLES[index]
                || !entry.actor.valid()
                || entry.ttbr0_root == 0
                || entry.ttbr0_root % PAGE_SIZE != 0
                || entry.ttbr0_root.checked_add(PAGE_SIZE).is_none()
                || entry.cpu_mask != CONTROL_MASK
                || entry.thread_count != 1
                || !entry.private_rw.valid()
                || !authority_valid
                || entry.control_ns_per_100ms == 0
                || (entry.role == Role::Operations
                    && entry.control_ns_per_100ms > OPERATIONS_MAX_NS)
                || (entry.role == Role::Security && entry.control_ns_per_100ms > SECURITY_MAX_NS)
            {
                return Err(Error::Denied);
            }
            let root = PrivateRegion {
                base: entry.ttbr0_root,
                bytes: PAGE_SIZE,
            };
            if root.overlaps(entry.private_rw) {
                return Err(Error::Denied);
            }
            charge_ns = charge_ns
                .checked_add(entry.control_ns_per_100ms)
                .ok_or(Error::Exhausted)?;
            pool = pool
                .checked_add(usize::try_from(entry.private_rw.bytes).map_err(|_| Error::Exhausted)?)
                .ok_or(Error::Exhausted)?;
            for prior in &self.members[..index] {
                let prior_root = PrivateRegion {
                    base: prior.ttbr0_root,
                    bytes: PAGE_SIZE,
                };
                // Two simultaneously live roles cannot be generations of the
                // same registry identity, or map each other's TTBR root RW.
                if prior.actor.id == entry.actor.id
                    || prior.ttbr0_root == entry.ttbr0_root
                    || (services && prior.endpoint_id == entry.endpoint_id)
                    || prior.private_rw.overlaps(entry.private_rw)
                    || root.overlaps(prior.private_rw)
                    || prior_root.overlaps(entry.private_rw)
                {
                    return Err(Error::Denied);
                }
            }
        }
        if charge_ns > CONTROL_NS_PER_100MS || pool > CONTROL_POOL_LIMIT {
            return Err(Error::Exhausted);
        }
        Ok(())
    }

    /// Resolve an authenticated holder against its registered endpoint.
    fn endpoint_holder(
        &self,
        actor: Identity,
        registered_endpoint: u64,
        cpu: usize,
    ) -> Result<NativeRole, Error> {
        // Called only through validated paths below.
        if cpu != CONTROL_CPU || !actor.valid() || registered_endpoint == 0 {
            return Err(Error::Denied);
        }
        self.members
            .iter()
            .copied()
            .find(|m| m.actor == actor && m.endpoint_id == registered_endpoint)
            .ok_or(Error::Denied)
    }

    /// CONTROL_AUX v1 preflight. EL1 must ALSO validate actual cap type/label,
    /// holder generation, sequence, completion credit and protected operands.
    /// A successful preflight is not execution authority or an ACK receipt.
    pub fn check_aux(
        &self,
        actor: Identity,
        registered_endpoint: u64,
        cpu: usize,
        op: AuxOperation,
    ) -> Result<Role, Error> {
        self.validated()?
            .check_aux(actor, registered_endpoint, cpu, op)
    }
    fn check_aux_validated(
        &self,
        actor: Identity,
        registered_endpoint: u64,
        cpu: usize,
        op: AuxOperation,
    ) -> Result<Role, Error> {
        let entry = self.endpoint_holder(actor, registered_endpoint, cpu)?;
        use AuxOperation::*;
        let required = match op {
            AuditRead => AUDIT_READ,
            AuditAck => AUDIT_ACK,
            ModelPromote | ModelRollback => MODEL_MANAGE,
            EpochAllocate { target } if target != Role::Supervisor => EPOCH_ALLOC,
            EpochAllocate { .. } => return Err(Error::Denied),
            TrialInstantiate {
                template_domain: 15,
            } if entry.role == Role::ModelManager => TRIAL_D15,
            TrialInstantiate {
                template_domain: 1..=14,
            } => TRIAL_NORMAL,
            TrialInstantiate { .. } => return Err(Error::Denied),
            ValidationRegister => VALIDATION_REGISTER,
            CandidateSubmit => CANDIDATE_SUBMIT,
            DecisionRead => READ_DECISIONS,
            AdviceDisposition => ADVICE_DISPOSITION,
            // ACK still needs the actual holder's existing terminal slot.
            Ack if !matches!(entry.role, Role::Operations | Role::Security) => 0,
            Ack => return Err(Error::Denied),
        };
        if required != 0 && entry.caps & required != required {
            return Err(Error::Denied);
        }
        Ok(entry.role)
    }

    /// Mandatory views only. Optional redacted validator/supervisor views
    /// require a separately registered per-view cap.
    pub fn check_snapshot_view(
        &self,
        actor: Identity,
        registered_endpoint: u64,
        cpu: usize,
        view: SnapshotView,
    ) -> Result<(), Error> {
        self.validated()?
            .check_snapshot_view(actor, registered_endpoint, cpu, view)
    }
    fn check_snapshot_view_validated(
        &self,
        actor: Identity,
        registered_endpoint: u64,
        cpu: usize,
        view: SnapshotView,
    ) -> Result<(), Error> {
        let e = self.endpoint_holder(actor, registered_endpoint, cpu)?;
        let allowed = matches!(
            (e.role, view),
            (Role::Operations, SnapshotView::Operations)
                | (Role::Security, SnapshotView::RedactedSecurity)
                | (
                    Role::DeterministicController,
                    SnapshotView::ControllerRawEvidence
                )
        );
        if !allowed || e.caps & SNAPSHOT == 0 {
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// No independent role manifests may remap the sole control CPU to a
    /// business core or grant publishers to either advisory brain.
    pub fn can_act(&self, role: Role, actor: Identity, cap: u64, cpu: usize) -> Result<(), Error> {
        self.validated()?.can_act(role, actor, cap, cpu)
    }

    fn can_act_validated(
        &self,
        role: Role,
        actor: Identity,
        cap: u64,
        cpu: usize,
    ) -> Result<(), Error> {
        if cpu != CONTROL_CPU || cap == 0 || cap.count_ones() != 1 {
            return Err(Error::Denied);
        }
        let entry = self
            .members
            .iter()
            .find(|m| m.role == role)
            .ok_or(Error::Denied)?;
        if entry.actor != actor || entry.caps & cap == 0 {
            return Err(Error::Denied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_registration_binds_a_live_holder_to_its_root_asid_and_cpu() {
        let mut member = manifest().members[0];
        member.actor.id = u64::from(member.role.id());
        member.actor.generation = 19;
        member.caps = 0;
        member.endpoint_id = 0;
        let binding = LifecycleBinding::new(member, 0xa0, 3).unwrap();
        let captured = member.ttbr0_root | (0xa0u64 << 48);
        assert_eq!(binding.authenticate(member, captured, 0), Some(3));
        assert_eq!(binding.authenticate(member, captured, 1), None);
        assert_eq!(binding.authenticate(member, captured ^ (1 << 48), 0), None);
        assert_eq!(binding.authenticate(member, captured ^ 4096, 0), None);

        let mut stale = member;
        stale.actor.generation -= 1;
        assert_eq!(binding.authenticate(stale, captured, 0), None);
        let mut altered = member;
        altered.caps = SNAPSHOT;
        assert_eq!(binding.authenticate(altered, captured, 0), None);
        assert!(LifecycleBinding::new(altered, 0xa0, 3).is_err());
        assert!(LifecycleBinding::new(member, 0xa0, 2).is_err());
    }
    fn manifest() -> NativeRoleManifest {
        let members = core::array::from_fn(|i| NativeRole {
            role: ROLES[i],
            actor: Identity {
                id: i as u64 + 1,
                generation: 1,
            },
            ttbr0_root: 0x100000 + i as u64 * PAGE_SIZE,
            private_rw: PrivateRegion {
                base: 0x200000 + i as u64 * PAGE_SIZE * 16,
                bytes: PAGE_SIZE * 16,
            },
            caps: ROLES[i].allowed_caps(),
            control_ns_per_100ms: 2_000_000,
            cpu_mask: CONTROL_MASK,
            thread_count: 1,
            endpoint_id: i as u64 + 10,
        });
        NativeRoleManifest {
            online_mask: REQUIRED_ONLINE_MASK,
            members,
            other_protected_pool_bytes: 5 * 1024 * 1024,
            other_control_ns_per_100ms: 45_000_000,
        }
    }
    #[test]
    fn validated_borrow_checks_exact_holder_view_and_endpoint() {
        let mut m = manifest();
        let ops = m.members[0];
        let ctl = m.members[2];
        let checked = m.validated().unwrap();
        assert_eq!(
            checked.check_snapshot_view(ops.actor, ops.endpoint_id, 0, SnapshotView::Operations),
            Ok(())
        );
        assert_eq!(
            checked.check_snapshot_view(ops.actor, ctl.endpoint_id, 0, SnapshotView::Operations),
            Err(Error::Denied)
        );
        assert_eq!(
            checked.check_snapshot_view(ops.actor, ops.endpoint_id, 1, SnapshotView::Operations),
            Err(Error::Denied)
        );
        assert_eq!(
            checked.check_snapshot_view(
                ops.actor,
                ops.endpoint_id,
                0,
                SnapshotView::ControllerRawEvidence
            ),
            Err(Error::Denied)
        );
        assert_eq!(
            checked.check_aux(ops.actor, ops.endpoint_id, 0, AuxOperation::DecisionRead),
            Err(Error::Denied)
        );
        // A generation/physical inventory update requires a new proof.
        m.members[2].ttbr0_root = m.members[0].ttbr0_root;
        assert!(m.validated().is_err());
    }
    #[test]
    fn v0199_requires_eight_distinct_native_el0_roles_on_cpu0() {
        let m = manifest();
        m.validate().unwrap();
        for role in ROLES {
            let entry = m.members.iter().find(|e| e.role == role).unwrap();
            m.can_act(role, entry.actor, entry.caps & (!entry.caps + 1), 0)
                .unwrap();
            assert_eq!(
                m.can_act(role, entry.actor, entry.caps & (!entry.caps + 1), 1),
                Err(Error::Denied)
            );
            assert_eq!(entry.cpu_mask, 1);
        }
        let ops = m.members[0];
        assert_eq!(
            m.can_act(Role::Operations, ops.actor, PUBLISH_PLAN, 0),
            Err(Error::Denied)
        );
        let security = m.members[1];
        assert_eq!(
            m.can_act(Role::Security, security.actor, DECISION_REGISTER, 0),
            Err(Error::Denied)
        );
        assert_eq!(
            m.can_act(Role::Publisher, ops.actor, PUBLISH_PLAN, 0),
            Err(Error::Denied)
        );
    }
    #[test]
    fn repeated_ttbr_identity_endpoint_or_rw_pages_fail_closed() {
        let m = manifest();
        let mut bad = m;
        bad.members[1].ttbr0_root = m.members[0].ttbr0_root;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[1].actor = m.members[0].actor;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[1].endpoint_id = m.members[0].endpoint_id;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[1].private_rw = m.members[0].private_rw;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[1].cpu_mask = 0b10;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[1].caps |= PUBLISH_PLAN;
        assert_eq!(bad.validate(), Err(Error::Denied));
    }
    #[test]
    fn native_role_manifest_rejects_cross_generation_and_page_table_aliases() {
        let m = manifest();
        let mut bad = m;
        bad.online_mask = 0b1_1111;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[1].actor.id = m.members[0].actor.id;
        bad.members[1].actor.generation = 2;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[0].ttbr0_root = m.members[0].private_rw.base;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[0].ttbr0_root = m.members[1].private_rw.base;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[1].ttbr0_root = m.members[0].private_rw.base + PAGE_SIZE;
        assert_eq!(bad.validate(), Err(Error::Denied));
        bad = m;
        bad.members[0].ttbr0_root = u64::MAX - (PAGE_SIZE - 1);
        assert_eq!(bad.validate(), Err(Error::Denied));
        assert!(m.validate().is_ok());
    }
    #[test]
    fn single_control_ledger_and_pool_fail_closed_on_overcommit() {
        let mut m = manifest();
        m.other_control_ns_per_100ms = 69_000_000;
        assert_eq!(m.validate(), Err(Error::Exhausted));
        m = manifest();
        m.other_protected_pool_bytes = 8 * 1024 * 1024 - 4096;
        assert_eq!(m.validate(), Err(Error::Exhausted));
        m = manifest();
        m.members[1].control_ns_per_100ms = 8_000_001;
        assert_eq!(m.validate(), Err(Error::Denied));
        m = manifest();
        m.online_mask = 0b0111;
        assert_eq!(m.validate(), Err(Error::Denied));
    }
    #[test]
    fn actual_holder_aux_matrix_keeps_brains_out_of_privileged_operations() {
        use AuxOperation::*;
        let m = manifest();
        let cases = [
            (AuditRead, Role::Supervisor),
            (AuditAck, Role::Supervisor),
            (ModelPromote, Role::ModelManager),
            (ModelRollback, Role::ModelManager),
            (
                EpochAllocate {
                    target: Role::Publisher,
                },
                Role::Supervisor,
            ),
            (
                TrialInstantiate { template_domain: 1 },
                Role::DeterministicController,
            ),
            (
                TrialInstantiate {
                    template_domain: 15,
                },
                Role::ModelManager,
            ),
            (ValidationRegister, Role::Validator),
            (CandidateSubmit, Role::Learner),
            (DecisionRead, Role::Publisher),
            (AdviceDisposition, Role::DeterministicController),
        ];
        for (op, owner) in cases {
            for member in m.members {
                assert_eq!(
                    m.check_aux(member.actor, member.endpoint_id, 0, op).is_ok(),
                    member.role == owner,
                    "{:?} {:?}",
                    member.role,
                    op
                );
                assert_eq!(
                    m.check_aux(member.actor, member.endpoint_id, 1, op),
                    Err(Error::Denied)
                );
                assert_eq!(
                    m.check_aux(
                        Identity {
                            id: member.actor.id,
                            generation: 2
                        },
                        member.endpoint_id,
                        0,
                        op
                    ),
                    Err(Error::Denied)
                );
            }
        }
        let s = m.members[7];
        assert_eq!(
            m.check_aux(
                s.actor,
                s.endpoint_id,
                0,
                EpochAllocate {
                    target: Role::Supervisor
                }
            ),
            Err(Error::Denied)
        );
        let ops = m.members[0];
        let controller = m.members[2];
        assert_eq!(
            m.check_aux(ops.actor, controller.endpoint_id, 0, AdviceDisposition),
            Err(Error::Denied)
        );
        assert_eq!(
            m.check_aux(ops.actor, ops.endpoint_id, 0, Ack),
            Err(Error::Denied)
        );
    }

    #[test]
    fn mandatory_snapshot_views_are_not_interchangeable() {
        let m = manifest();
        for (view, role) in [
            (SnapshotView::Operations, Role::Operations),
            (SnapshotView::RedactedSecurity, Role::Security),
            (
                SnapshotView::ControllerRawEvidence,
                Role::DeterministicController,
            ),
        ] {
            for member in m.members {
                assert_eq!(
                    m.check_snapshot_view(member.actor, member.endpoint_id, 0, view)
                        .is_ok(),
                    member.role == role
                );
            }
        }
        let v = m.members[4];
        assert_eq!(
            m.check_snapshot_view(v.actor, v.endpoint_id, 0, SnapshotView::RedactedValidation),
            Err(Error::Denied)
        );
    }
}

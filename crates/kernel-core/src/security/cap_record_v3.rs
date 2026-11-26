//! Canonical CapRecord v3 and protected static-control capability registry.
//! No user can manufacture a record/handle by changing wire fields. Root
//! issuance requires a confirmed durable boot, actual role registry and
//! the independently signed startup catalog. This module covers static
//! control roots, not general business object creation/derived-cap graph.
use super::{Error, durable_role_epoch_v0199::ConfirmedBootPolicy};
use crate::control_plane::{
    Identity,
    role_manifest_v0199::{self as rm, NativeRoleManifest, Role, ValidatedRoleManifest},
};
pub const RECORD_BYTES: usize = 128;
pub const IPC_SEND: u64 = 1 << 16;
pub const IPC_RECV: u64 = 1 << 17;
pub const PLAN_PUBLISH: u64 = 1 << 26;
pub const CONTROL_DECISION: u64 = 1 << 27;
pub const SNAPSHOT_READ: u64 = 1 << 28;
fn u16at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn put16(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], i: usize, v: u64) {
    b[i..i + 8].copy_from_slice(&v.to_le_bytes());
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapRecordV3 {
    pub cap_id: u64,
    pub holder: Identity,
    pub target: Identity,
    pub parent_cap_id: u64,
    pub parent_generation: u64,
    pub deny_generation: u64,
    pub rights: u64,
    pub object_kind: u16,
    pub state: u16,
    pub depth: u16,
    pub source_role: u32,
    pub owner_group: u32,
    pub record_generation: u64,
}
impl CapRecordV3 {
    fn valid(self) -> bool {
        if self.cap_id == 0
            || !self.holder.valid()
            || self.target.generation == 0
            || self.record_generation == 0
            || !(1..=3).contains(&self.state)
            || self.depth > 8
            || !(1..=15).contains(&self.source_role)
            || !(self.owner_group <= 15 || self.owner_group == u32::MAX)
        {
            return false;
        }
        if if self.depth == 0 {
            self.parent_cap_id != 0 || self.parent_generation != 0
        } else {
            self.parent_cap_id == 0
                || self.parent_generation == 0
                || self.parent_cap_id == self.cap_id
        } {
            return false;
        }
        let mask = match self.object_kind {
            1 => 0b1110,
            2 => (1 << 8) | (1 << 9) | (1 << 13),
            3 => (1 << 10) | (1 << 11) | (1 << 12) | (1 << 14),
            4 => IPC_SEND | IPC_RECV,
            5 => 1 << 24,
            6 => 1 << 25,
            7 => PLAN_PUBLISH,
            8 => {
                if self.rights & CONTROL_DECISION != 0 {
                    CONTROL_DECISION
                } else {
                    IPC_SEND | IPC_RECV
                }
            }
            9 | 10 => 0,
            11 => 1,
            12 => SNAPSHOT_READ,
            _ => return false,
        };
        self.rights & !mask == 0
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 128
            || u32at(b, 0) != 0x43594350
            || u16at(b, 4) != 3
            || u16at(b, 6) != 128
            || u16at(b, 86) != 0
            || b[104..].iter().any(|&v| v != 0)
        {
            return Err(Error::Invalid);
        }
        let r = Self {
            cap_id: u64at(b, 8),
            holder: Identity {
                id: u64at(b, 16),
                generation: u64at(b, 24),
            },
            target: Identity {
                id: u64at(b, 32),
                generation: u64at(b, 40),
            },
            parent_cap_id: u64at(b, 48),
            parent_generation: u64at(b, 56),
            deny_generation: u64at(b, 64),
            rights: u64at(b, 72),
            object_kind: u16at(b, 80),
            state: u16at(b, 82),
            depth: u16at(b, 84),
            source_role: u32at(b, 88),
            owner_group: u32at(b, 92),
            record_generation: u64at(b, 96),
        };
        if !r.valid() {
            return Err(Error::Invalid);
        }
        Ok(r)
    }
    pub fn encode(self) -> Result<[u8; 128], Error> {
        if !self.valid() {
            return Err(Error::Invalid);
        }
        let mut b = [0; 128];
        put32(&mut b, 0, 0x43594350);
        put16(&mut b, 4, 3);
        put16(&mut b, 6, 128);
        for (at, v) in [
            (8, self.cap_id),
            (16, self.holder.id),
            (24, self.holder.generation),
            (32, self.target.id),
            (40, self.target.generation),
            (48, self.parent_cap_id),
            (56, self.parent_generation),
            (64, self.deny_generation),
            (72, self.rights),
            (96, self.record_generation),
        ] {
            put64(&mut b, at, v);
        }
        put16(&mut b, 80, self.object_kind);
        put16(&mut b, 82, self.state);
        put16(&mut b, 84, self.depth);
        put32(&mut b, 88, self.source_role);
        put32(&mut b, 92, self.owner_group);
        Ok(b)
    }
}
/// Internal protected labels, NOT additional wire ABI or new cap bits.
/// Distinct actual endpoint objects are allocated by the boot registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Label {
    OperationsView,
    SecurityView,
    ControllerView,
    AdviceSend,
    FindingSend,
    DecisionRegister,
    ControlAux,
    Publish,
    FindingReceive,
    AdviceReceive,
    DecisionSend,
    DecisionReceive,
}
impl Label {
    fn requirement(self, source_role: u32) -> Result<(Role, u64, u16, u64), Error> {
        use Label::*;
        Ok(match self {
            OperationsView => (Role::Operations, rm::SNAPSHOT, 12, SNAPSHOT_READ),
            SecurityView => (Role::Security, rm::SNAPSHOT, 12, SNAPSHOT_READ),
            ControllerView => (
                Role::DeterministicController,
                rm::SNAPSHOT,
                12,
                SNAPSHOT_READ,
            ),
            AdviceSend => (Role::Operations, rm::SEND_ADVICE, 4, IPC_SEND),
            // These are the existing directional IPC flows in §2.0/6.1,
            // not new privilege bits. The signed endpoint catalog must
            // bind the exact receiver/sender object and generation.
            AdviceReceive => (
                Role::DeterministicController,
                rm::DECISION_REGISTER,
                4,
                IPC_RECV,
            ),
            DecisionSend => (
                Role::DeterministicController,
                rm::DECISION_REGISTER,
                4,
                IPC_SEND,
            ),
            DecisionReceive => (Role::Publisher, rm::READ_DECISIONS, 4, IPC_RECV),
            FindingSend => (Role::Security, rm::SEND_FINDING, 4, IPC_SEND),
            DecisionRegister => (
                Role::DeterministicController,
                rm::DECISION_REGISTER,
                8,
                CONTROL_DECISION,
            ),
            Publish => (Role::Publisher, rm::PUBLISH_PLAN, 7, PLAN_PUBLISH),
            FindingReceive => (Role::Supervisor, rm::FINDING_REVIEW, 4, IPC_RECV),
            // One canonical CONTROL_AUX label; individual ops remain
            // restricted by the real manifest and ControlRPC whitelist.
            ControlAux => match source_role {
                2 => (
                    Role::DeterministicController,
                    rm::ADVICE_DISPOSITION,
                    8,
                    IPC_SEND,
                ),
                3 => (Role::ModelManager, rm::MODEL_MANAGE, 8, IPC_SEND),
                8 => (Role::Publisher, rm::READ_DECISIONS, 8, IPC_SEND),
                9 => (Role::Validator, rm::VALIDATION_REGISTER, 8, IPC_SEND),
                10 => (Role::Learner, rm::CANDIDATE_SUBMIT, 8, IPC_SEND),
                11 => (Role::Supervisor, rm::AUDIT_READ, 8, IPC_SEND),
                _ => return Err(Error::Unauthorized),
            },
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    label: Label,
    record: CapRecordV3,
}
/// Preallocated table. Retired records are tombstones until boot ends;
/// no slot reuse or old-generation handle resurrection.
pub struct StaticControlCaps<const N: usize> {
    boot: u64,
    config_digest: [u8; 32],
    rows: [Option<Entry>; N],
    // Fixed role identities, independent of whether a root was ever issued.
    fenced: [Option<Identity>; rm::ROLE_COUNT],
}
impl<const N: usize> StaticControlCaps<N> {
    pub fn new(policy: &ConfirmedBootPolicy<'_>) -> Self {
        Self {
            boot: policy.boot_epoch(),
            config_digest: policy.config_digest(),
            rows: [None; N],
            fenced: [None; rm::ROLE_COUNT],
        }
    }
    fn check_policy(&self, policy: &ConfirmedBootPolicy<'_>) -> Result<(), Error> {
        if self.boot != policy.boot_epoch() || self.config_digest != policy.config_digest() {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn issue_checked(
        &mut self,
        manifest: &NativeRoleManifest,
        label: Label,
        r: CapRecordV3,
        verify_catalog_and_object: impl FnOnce(Label, &CapRecordV3) -> Result<(), Error>,
    ) -> Result<u64, Error> {
        let (role, authority, kind, rights) = label.requirement(r.source_role)?;
        // Issued slots, including retired tombstones, are never removed.
        let at = self.rows.partition_point(Option::is_some);
        if !r.valid()
            || !r.target.valid()
            || r.state != 1
            || r.depth != 0
            || r.object_kind != kind
            || r.rights != rights
            || r.source_role != u32::from(role.id())
            || r.owner_group != u32::MAX
            || r.record_generation != 1
            || self
                .fenced
                .iter()
                .flatten()
                .any(|a| a.id == r.holder.id && a.generation >= r.holder.generation)
            || self.rows[..at].iter().flatten().any(|e| {
                e.record.cap_id==r.cap_id
                // A fenced or retired holder generation may never gain
                // a new root, even under a previously unused cap_id.
                ||e.record.holder==r.holder&&e.record.state!=1
                // Also prevent an old generation being reintroduced
                // after a replacement has obtained any root.
                ||e.record.holder.id==r.holder.id&&(e.record.holder.generation>r.holder.generation
                    ||e.record.holder.generation<r.holder.generation&&e.record.state!=3)
            })
        {
            return Err(Error::Unauthorized);
        }
        manifest
            .can_act(role, r.holder, authority, 0)
            .map_err(|_| Error::Unauthorized)?;
        if at == N {
            return Err(Error::Capacity);
        }
        let index = u32::try_from(at).map_err(|_| Error::Capacity)?;
        verify_catalog_and_object(label, &r)?;
        self.rows[at] = Some(Entry { label, record: r });
        Ok((1u64 << 32) | u64::from(index))
    }
    /// Actual catalog/target owner validates the exact root grant and object
    /// lifetime. Manifest permission masks alone are not an issued cap.
    pub fn issue_root(
        &mut self,
        policy: &ConfirmedBootPolicy<'_>,
        manifest: &NativeRoleManifest,
        label: Label,
        r: CapRecordV3,
        verify_catalog_and_object: impl FnOnce(Label, &CapRecordV3) -> Result<(), Error>,
    ) -> Result<u64, Error> {
        self.check_policy(policy)?;
        let role = label.requirement(r.source_role)?.0;
        if policy.service_generation(role)? != r.holder.generation {
            return Err(Error::Stale);
        }
        self.issue_checked(manifest, label, r, verify_catalog_and_object)
    }
    /// Recheck the authenticated task, cap handle, static label and exact
    /// object generation at every use. Source-role wire fields confer nothing.
    // Stable wide cap-lookup API; regrouping arguments would change the public contract.
    #[allow(clippy::too_many_arguments)]
    fn lookup(
        &self,
        holder: Identity,
        cpu: usize,
        handle: u64,
        label: Label,
        target: Identity,
        verify_live: impl FnOnce(&CapRecordV3) -> Result<(), Error>,
    ) -> Result<CapRecordV3, Error> {
        if cpu != rm::CONTROL_CPU || !holder.valid() {
            return Err(Error::Unauthorized);
        }
        let entry = self
            .rows
            .get(handle as u32 as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::Unauthorized)?;
        let r = entry.record;
        if holder.id != r.holder.id {
            return Err(Error::Unauthorized);
        }
        if holder != r.holder
            || handle >> 32 != r.record_generation
            || r.state != 1
            || target != r.target
        {
            return Err(Error::Stale);
        }
        if entry.label != label {
            return Err(Error::Unauthorized);
        }
        verify_live(&r)?;
        Ok(r)
    }
    /// Production lookup also checks the current confirmed durable epoch,
    /// signed configuration, and actual manifest. A stale in-memory root
    /// or a transaction whose outcome is UNKNOWN cannot reopen authority.
    #[allow(clippy::too_many_arguments)]
    pub fn lookup_current(
        &self,
        policy: &ConfirmedBootPolicy<'_>,
        manifest: &ValidatedRoleManifest<'_>,
        holder: Identity,
        cpu: usize,
        handle: u64,
        label: Label,
        target: Identity,
        verify_live: impl FnOnce(&CapRecordV3) -> Result<(), Error>,
    ) -> Result<CapRecordV3, Error> {
        self.check_policy(policy)?;
        self.lookup(holder, cpu, handle, label, target, |r| {
            let (role, authority, _, _) = label.requirement(r.source_role)?;
            if policy.service_generation(role)? != holder.generation {
                return Err(Error::Stale);
            }
            manifest
                .can_act(role, holder, authority, cpu)
                .map_err(|_| Error::Unauthorized)?;
            verify_live(r)
        })
    }
    /// Fence the authenticated manifest holder even before its first root
    /// issuance. No authority derives from an untrusted numeric role ID.
    pub fn fence_registered(
        &mut self,
        manifest: &NativeRoleManifest,
        holder: Identity,
        verify_close: impl FnOnce(Identity) -> Result<(), Error>,
    ) -> Result<(), Error> {
        manifest.validate().map_err(|_| Error::Unauthorized)?;
        let i = manifest
            .members
            .iter()
            .position(|m| m.actor == holder)
            .ok_or(Error::Stale)?;
        if self.fenced[i]
            .is_some_and(|old| old.id != holder.id || old.generation > holder.generation)
        {
            return Err(Error::Stale);
        }
        if self.fenced[i] == Some(holder) {
            return Ok(());
        }
        verify_close(holder)?;
        self.fenced[i] = Some(holder);
        for e in self.rows.iter_mut().flatten() {
            if e.record.holder == holder && e.record.state == 1 {
                e.record.state = 2;
            }
        }
        Ok(())
    }
    /// Seal new use before stopping/draining the role. Retirement requires
    /// independent native reference/DMA/IPC/accepted-work evidence.
    pub fn fence_holder(&mut self, holder: Identity) -> Result<(), Error> {
        let mut found = false;
        for e in self.rows.iter_mut().flatten() {
            if e.record.holder == holder && e.record.state == 1 {
                e.record.state = 2;
                found = true;
            }
        }
        if found { Ok(()) } else { Err(Error::Stale) }
    }
    pub fn retire_holder(
        &mut self,
        holder: Identity,
        mut verify_stop: impl FnMut(&CapRecordV3) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut found = false;
        for e in self
            .rows
            .iter()
            .flatten()
            .filter(|e| e.record.holder == holder)
        {
            if e.record.state == 1 {
                return Err(Error::Busy);
            }
            if e.record.state == 2 {
                verify_stop(&e.record)?;
                found = true;
            }
        }
        if !found {
            return Err(Error::Stale);
        }
        for e in self
            .rows
            .iter_mut()
            .flatten()
            .filter(|e| e.record.holder == holder && e.record.state == 2)
        {
            e.record.state = 3;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::role_manifest_v0199::{NativeRole, PrivateRegion, ROLES};
    fn manifest() -> NativeRoleManifest {
        NativeRoleManifest {
            online_mask: 15,
            other_protected_pool_bytes: 1024,
            other_control_ns_per_100ms: 1,
            members: core::array::from_fn(|i| NativeRole {
                role: ROLES[i],
                actor: Identity {
                    id: u64::from(ROLES[i].id()),
                    generation: 1,
                },
                ttbr0_root: 0x100000 + i as u64 * 4096,
                private_rw: PrivateRegion {
                    base: 0x200000 + i as u64 * 4096,
                    bytes: 4096,
                },
                caps: ROLES[i].allowed_caps(),
                control_ns_per_100ms: 1,
                cpu_mask: 1,
                thread_count: 1,
                endpoint_id: 10 + i as u64,
            }),
        }
    }
    fn publisher() -> CapRecordV3 {
        CapRecordV3 {
            cap_id: 17,
            holder: Identity {
                id: 8,
                generation: 1,
            },
            target: Identity {
                id: 90,
                generation: 3,
            },
            parent_cap_id: 0,
            parent_generation: 0,
            deny_generation: 1,
            rights: PLAN_PUBLISH,
            object_kind: 7,
            state: 1,
            depth: 0,
            source_role: 8,
            owner_group: u32::MAX,
            record_generation: 1,
        }
    }
    #[test]
    fn preissuance_fence_survives_empty_cap_table() {
        let m = manifest();
        let r = publisher();
        let mut table = StaticControlCaps::<2> {
            boot: 1,
            config_digest: [0; 32],
            rows: [None; 2],
            fenced: [None; rm::ROLE_COUNT],
        };
        assert_eq!(
            table.fence_registered(&m, r.holder, |_| Err(Error::Unknown)),
            Err(Error::Unknown)
        );
        table
            .fence_registered(&m, r.holder, |a| {
                assert_eq!(a, r.holder);
                Ok(())
            })
            .unwrap();
        table.fence_registered(&m, r.holder, |_| panic!()).unwrap();
        assert_eq!(
            table.issue_checked(&m, Label::Publish, r, |_, _| panic!()),
            Err(Error::Unauthorized)
        );
        let mut next = m;
        next.members[3].actor.generation = 2;
        let replacement = CapRecordV3 {
            holder: next.members[3].actor,
            ..r
        };
        table
            .issue_checked(&next, Label::Publish, replacement, |_, _| Ok(()))
            .unwrap();
        assert_eq!(
            table.issue_checked(
                &m,
                Label::Publish,
                CapRecordV3 { cap_id: 18, ..r },
                |_, _| panic!()
            ),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn full_static_table_keeps_exact_handles_and_duplicate_rejection() {
        let m = manifest();
        let r = publisher();
        let mut table = StaticControlCaps::<3> {
            boot: 1,
            config_digest: [0; 32],
            rows: [None; 3],
            fenced: [None; rm::ROLE_COUNT],
        };
        for i in 0..3u64 {
            let record = CapRecordV3 {
                cap_id: r.cap_id + i,
                ..r
            };
            assert_eq!(
                table.issue_checked(&m, Label::Publish, record, |_, _| Ok(())),
                Ok((1u64 << 32) | i)
            );
        }
        assert_eq!(
            table.issue_checked(&m, Label::Publish, r, |_, _| panic!()),
            Err(Error::Unauthorized)
        );
        let extra = CapRecordV3 { cap_id: 100, ..r };
        assert_eq!(
            table.issue_checked(&m, Label::Publish, extra, |_, _| panic!()),
            Err(Error::Capacity)
        );
        table.fence_holder(r.holder).unwrap();
        table.retire_holder(r.holder, |_| Ok(())).unwrap();
        assert_eq!(
            table.issue_checked(&m, Label::Publish, extra, |_, _| panic!()),
            Err(Error::Unauthorized)
        );
        for i in 0..3u64 {
            assert_eq!(
                table.lookup(
                    r.holder,
                    0,
                    (1u64 << 32) | i,
                    Label::Publish,
                    r.target,
                    |_| panic!()
                ),
                Err(Error::Stale)
            );
        }
    }

    #[test]
    fn record_type_rights_and_exact_holder_cap_lookup() {
        let m = manifest();
        let r = publisher();
        let b = r.encode().unwrap();
        assert_eq!(CapRecordV3::decode(&b), Ok(r));
        let mut bad = b;
        bad[104] = 1;
        assert_eq!(CapRecordV3::decode(&bad), Err(Error::Invalid));
        assert!(
            CapRecordV3 {
                rights: PLAN_PUBLISH | SNAPSHOT_READ,
                ..r
            }
            .encode()
            .is_err()
        );
        // Private helper exercises the table only; no test signature or
        // durable generation is issued as a real production credential.
        let mut table = StaticControlCaps::<2> {
            boot: 1,
            config_digest: [0; 32],
            rows: [None; 2],
            fenced: [None; rm::ROLE_COUNT],
        };
        let wrong = CapRecordV3 {
            holder: m.members[0].actor,
            source_role: 6,
            ..r
        };
        assert_eq!(
            table.issue_checked(&m, Label::Publish, wrong, |_, _| panic!()),
            Err(Error::Unauthorized)
        );
        let h = table
            .issue_checked(&m, Label::Publish, r, |_, _| Ok(()))
            .unwrap();
        assert_eq!(
            table.lookup(r.holder, 0, h, Label::Publish, r.target, |_| Ok(())),
            Ok(r)
        );
        assert_eq!(
            table.lookup(
                m.members[0].actor,
                0,
                h,
                Label::Publish,
                r.target,
                |_| panic!()
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            table.lookup(r.holder, 1, h, Label::Publish, r.target, |_| panic!()),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            table.lookup(
                r.holder,
                0,
                h,
                Label::DecisionRegister,
                r.target,
                |_| panic!()
            ),
            Err(Error::Unauthorized)
        );
        let mut replacement_manifest = m;
        replacement_manifest.members[3].actor.generation = 2;
        let early = CapRecordV3 {
            cap_id: 18,
            holder: replacement_manifest.members[3].actor,
            ..r
        };
        assert_eq!(
            table.issue_checked(
                &replacement_manifest,
                Label::Publish,
                early,
                |_, _| panic!()
            ),
            Err(Error::Unauthorized)
        );
        table.fence_holder(r.holder).unwrap();
        assert_eq!(
            table.issue_checked(
                &replacement_manifest,
                Label::Publish,
                early,
                |_, _| panic!()
            ),
            Err(Error::Unauthorized)
        );
        let fresh = CapRecordV3 { cap_id: 18, ..r };
        assert_eq!(
            table.issue_checked(&m, Label::Publish, fresh, |_, _| panic!()),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            table.lookup(r.holder, 0, h, Label::Publish, r.target, |_| panic!()),
            Err(Error::Stale)
        );
        assert_eq!(
            table.retire_holder(r.holder, |_| Err(Error::Unknown)),
            Err(Error::Unknown)
        );
        table.retire_holder(r.holder, |_| Ok(())).unwrap();
        assert_eq!(
            table.issue_checked(&m, Label::Publish, r, |_, _| panic!()),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            table.issue_checked(&m, Label::Publish, fresh, |_, _| panic!()),
            Err(Error::Unauthorized)
        );
        let mut next = m;
        next.members[3].actor.generation = 2;
        let replacement = CapRecordV3 {
            holder: next.members[3].actor,
            ..fresh
        };
        let new_handle = table
            .issue_checked(&next, Label::Publish, replacement, |_, _| Ok(()))
            .unwrap();
        assert_ne!(h, new_handle);
        assert_eq!(
            table.lookup(r.holder, 0, h, Label::Publish, r.target, |_| panic!()),
            Err(Error::Stale)
        );
        assert_eq!(
            table.lookup(
                replacement.holder,
                0,
                new_handle,
                Label::Publish,
                r.target,
                |_| Ok(())
            ),
            Ok(replacement)
        );
    }
}

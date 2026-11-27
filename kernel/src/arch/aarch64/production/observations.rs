//! CPU0 snapshots and volatile audit custody for the staged production fixture. One D01
//! executor is bound to its actual installed target. The view discloses the
//! sampling timestamp and field 22 (age); other telemetry has no native source
//! here. Three volatile recovery-class SecurityAudit v2 slots retain the writer
//! handoff records until their full delivery to, and exact acknowledgment by, role 11.
//!
//! CPU0 exclusively initializes or accesses the stores between PIE turns or
//! synchronously inside the stopped caller's SVC. No references cross a turn.
//! User addresses are translated through stack_span before bounded copies.

use super::*;
use core::ptr::{addr_of, addr_of_mut};
use cyxia_control_model::native_v0199::SnapshotReplyV3;
use cyxia_kernel_core::control_plane::{
    control_rpc_v1::{Admission, Caller, Error as RpcError, Op, Request, RpcTable, State},
    role_manifest_v0199::{AuxOperation, SnapshotView},
    snapshot_store_v3::{DomainObservation, SnapshotStore, Target, ViewGrant},
    svc_bridge_v3::read_snapshot_rpc,
};
#[path = "observations/audit_record.rs"]
mod audit_record;
use audit_record::Custody;
#[path = "observations/audit_rpc.rs"]
mod audit_rpc;

const AGE: u16 = 1 << 6;

const FATAL_OBSERVATION: u64 = 0x5732_1640;
static mut STORE: SnapshotStore = SnapshotStore::empty();
static mut RPC: RpcTable = RpcTable::new();
static mut MANIFEST: Option<NativeRoleManifest> = None;
static mut CUSTODY: Custody = Custody::empty();
static EARLY: AtomicU64 = AtomicU64::new(0);
static SNAP_ROLES: AtomicU64 = AtomicU64::new(0);
static SNAP_SEQ: AtomicU64 = AtomicU64::new(0);
static AUDIT_SEEN: AtomicU64 = AtomicU64::new(0);
static REPLAYS: AtomicU64 = AtomicU64::new(0);
static EMPTY_RESCAN: AtomicU64 = AtomicU64::new(0);

pub(super) const fn protected_bytes() -> usize {
    size_of::<SnapshotStore>()
        + size_of::<RpcTable>()
        + size_of::<Option<NativeRoleManifest>>()
        + size_of::<Custody>()
        + 6 * size_of::<AtomicU64>()
}

fn view(role: Role) -> Option<SnapshotView> {
    match role {
        Role::Operations => Some(SnapshotView::Operations),
        Role::DeterministicController => Some(SnapshotView::ControllerRawEvidence),
        _ => None,
    }
}

pub(super) fn selector(role: Role) -> u64 {
    if role == Role::Supervisor {
        BOOT
    } else if view(role).is_some() {
        TARGET.id
    } else {
        0
    }
}

fn target() -> Target {
    let b = binding();
    Target {
        domain: b.domain,
        object: b.target,
        owner: Identity {
            id: u64::from(b.role),
            generation: b.executor_generation,
        },
    }
}

fn verify_target(t: Target) -> Result<(), Error> {
    // The fixture executor has one protected target. Settlement independently
    // checked the actual installed weight before retaining the terminal record.
    let b = binding();
    if !b.active || t != target() || EXEC_TARGET.installed_weight(PLAN_VERSION) != Some(4) {
        return Err(Error::NotReady);
    }
    let terminal = unsafe { (&*gate_ptr()).terminal_summary(SUPER, PLAN_SEQ) }?;
    if !terminal.is_some_and(|s| s.plan_seq == PLAN_SEQ && s.action_count == 1) {
        return Err(Error::NotReady);
    }
    Ok(())
}

fn grant(index: usize, m: NativeRole) -> Result<ViewGrant, Error> {
    let cap = PIE_CAP[index].load(Ordering::Acquire);
    if m.ttbr0_root != root_pa(index)
        || m.role != ROLES[index]
        || cap == 0
        || cap != pie_cap_selector(index)
    {
        return Err(Error::Denied);
    }
    Ok(ViewGrant {
        cap,
        holder: m.actor,
        endpoint: m.endpoint_id,
        view: view(m.role).ok_or(Error::Denied)?,
        selector: selector(m.role),
        domain: 1,
        target: TARGET,
        allowed_fields: AGE,
    })
}

fn caller(index: usize, m: NativeRole) -> Result<Caller, RpcError> {
    let cap = PIE_CAP[index].load(Ordering::Acquire);
    if m.role != Role::Supervisor
        || m.role != ROLES[index]
        || m.ttbr0_root != root_pa(index)
        || cap == 0
        || cap != pie_cap_selector(index)
    {
        return Err(RpcError::Auth);
    }
    Ok(Caller {
        boot_epoch: BOOT,
        holder: m.actor,
        role: m.role.id(),
        endpoint: m.endpoint_id,
        cap,
    })
}

fn manifest() -> Option<&'static NativeRoleManifest> {
    // MANIFEST is installed once on CPU0, never changed after publication.
    unsafe { (&*addr_of!(MANIFEST)).as_ref() }
}

/// Copy to the already translated private stack, then read it back before
/// reporting evidence. The role cannot run concurrently with its handler.
fn copy_reply(address: u64, wire: &[u8]) -> bool {
    let ptr = address as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(wire.as_ptr(), ptr, wire.len()) };
    wire.iter()
        .enumerate()
        .all(|(i, &v)| unsafe { ptr.add(i).read_volatile() } == v)
}

pub(super) fn snapshot(index: usize, m: NativeRole, args: [u64; 6]) -> Option<u64> {
    let cap = match trapped_pie_cap(index, m) {
        Ok(cap) => cap,
        Err(error) => return Some(error as u64),
    };
    if args[0] != cap || args[2] != selector(m.role) {
        return Some(E_AUTH as u64);
    }
    let Some(manifest) = manifest() else {
        EARLY.fetch_or(1, Ordering::Relaxed);
        return None;
    };
    if view(m.role).is_none() {
        return Some(EAGAIN as u64);
    }
    let Some(dst) = usize::try_from(args[4])
        .ok()
        .and_then(|n| stack_span(index, args[3], n, true))
    else {
        return Some(EFAULT as u64);
    };
    let native = VerifiedNativeCaller {
        identity: m.actor,
        cpu: cpu::slot(),
        package_abi: 3,
        endpoint_cap: cap,
    };
    let sampled = read_snapshot_rpc(
        unsafe { &*addr_of!(STORE) },
        manifest,
        native,
        args,
        epochs().resources,
        epochs().cores,
        now_ns(),
        |g| {
            if g == grant(index, m)? && manifest.members[index] == m {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        },
    );
    let wire = match sampled {
        Ok(wire) => wire,
        Err(Error::Stale | Error::NotReady) => return Some(EAGAIN as u64),
        Err(_) => return Some(E_AUTH as u64),
    };
    let Ok(reply) = SnapshotReplyV3::decode(&wire) else {
        return Some(E_FORMAT as u64);
    };
    if !copy_reply(dst, &wire) {
        return Some(EFAULT as u64);
    }
    if reply.target_id == TARGET.id && reply.fields[6].is_some() {
        SNAP_SEQ.store(reply.snapshot_seq, Ordering::Relaxed);
        SNAP_ROLES.fetch_or(1 << index, Ordering::Relaxed);
    }
    Some(0)
}

pub(super) fn audit(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    audit_rpc::dispatch(index, member, args).map_or_else(|e| e as i32 as i64 as u64, |()| 0)
}

fn prepare(manifest: &NativeRoleManifest) -> Result<(), Error> {
    if cpu::slot() != 0 || self::manifest().is_some() {
        return Err(Error::Denied);
    }
    let proofs = recovery::handed_off_proofs().ok_or(Error::NotReady)?;
    let custody = Custody::from_handoffs(BOOT, &proofs).ok_or(Error::Invalid)?;
    manifest.validate()?;
    let store = unsafe { &mut *addr_of_mut!(STORE) };
    store.bind_boot(BOOT, || verify_target(target()))?;
    store.register_target(target(), verify_target)?;
    for (i, &member) in manifest.members.iter().enumerate() {
        if view(member.role).is_some() {
            let g = grant(i, member)?;
            store.register_view(manifest, g, |registered| {
                if registered == grant(i, member)? {
                    Ok(())
                } else {
                    Err(Error::Denied)
                }
            })?;
        } else if member.role == Role::Supervisor {
            let c = caller(i, member).map_err(|_| Error::Denied)?;
            manifest.check_aux(c.holder, c.endpoint, 0, AuxOperation::AuditRead)?;
            manifest.check_aux(c.holder, c.endpoint, 0, AuxOperation::AuditAck)?;
            unsafe { (&mut *addr_of_mut!(RPC)).bind(c, false) }.map_err(|_| Error::Denied)?;
        }
    }
    unsafe {
        addr_of_mut!(CUSTODY).write(custody);
        addr_of_mut!(MANIFEST).write(Some(*manifest));
    }
    Ok(())
}

fn capture() -> Result<u64, Error> {
    let o = DomainObservation {
        target: target(),
        fields: [None; 4],
    };
    unsafe {
        (&mut *addr_of_mut!(STORE)).capture(
            epochs().resources,
            epochs().cores,
            now_ns(),
            [None; 8],
            &[o],
            |o| verify_target(o.target),
        )
    }
}

pub(super) fn drive(contexts: &mut [user::Context; ROLE_COUNT], manifest: &NativeRoleManifest) {
    if prepare(manifest).is_err() {
        fatal(FATAL_OBSERVATION);
    }
    let deadline = timer::ticks().saturating_add(timer::frequency().saturating_mul(5));
    loop {
        for (index, (ctx, member)) in contexts.iter_mut().zip(manifest.members.iter()).enumerate() {
            if view(member.role).is_some() && SNAP_ROLES.load(Ordering::Relaxed) & (1 << index) == 0
            {
                if capture().is_err() {
                    fatal(FATAL_OBSERVATION + 1);
                }
                pie_turn(index, ctx);
            } else if member.role == Role::Supervisor && EMPTY_RESCAN.load(Ordering::Relaxed) == 0 {
                pie_turn(index, ctx);
            }
        }
        let mask = SNAP_ROLES.load(Ordering::Relaxed);
        let seq = SNAP_SEQ.load(Ordering::Relaxed);
        let audit = AUDIT_SEEN.load(Ordering::Relaxed);
        let early = EARLY.load(Ordering::Relaxed);
        let released = unsafe { (&*addr_of!(CUSTODY)).released };
        let replays = REPLAYS.load(Ordering::Relaxed);
        if mask == 5
            && seq != 0
            && early == 3
            && audit == 3
            && released == 3
            && replays == 1
            && EMPTY_RESCAN.load(Ordering::Relaxed) == 1
        {
            evidence::put(evidence::W13_AUDIT_EL0_SEQUENCE, audit);
            evidence::put(evidence::W13_AUDIT_RELEASED, released);
            evidence::put(evidence::W13_AUDIT_REPLAYS, replays);
            report("V020_W13_AUDIT_SESSION", audit, released, replays);
            evidence::put(evidence::W12_SNAPSHOT_ROLES, mask);
            evidence::put(evidence::W12_SNAPSHOT_SEQUENCE, seq);
            evidence::put(evidence::W12_CONTROL_EARLY_REFUSALS, early);
            report("V020_W12_LIVE_SNAPSHOT", mask, seq, TARGET.id);
            report("V020_W12_CONTROL_UNREADY", early, 0, 0);
            break;
        }
        if timer::ticks() >= deadline {
            fatal(FATAL_OBSERVATION + 2);
        }
    }
}

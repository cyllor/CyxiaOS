//! Control calls for authenticated CPU0 roles in the authorized boot profile.

#[cfg(cyxia_business_package)]
mod native;
#[cfg(cyxia_business_package)]
pub(super) use native::{
    install_native, native_active, native_pending, publications_fenced, refresh_snapshot,
    snapshot_due, tick_native,
};

use super::{copy_window::VerifiedSpan, now_ns, recovery, signed_resident::SignedCaller};
use core::ptr::addr_of_mut;
use cyxia_arch_aarch64::cpu;
use cyxia_kernel_core::{
    control_plane::{
        advice_disposition_v1::{AdviceDispositionV1, DISPOSITION_BYTES},
        control_rpc_v1::{
            Admission, Caller, Error as RpcError, FRAME_BYTES, Frame, HEADER_BYTES, MAX_WAIT_NS,
            Op, Request, RpcTable, State, Ticket,
        },
        decision_record_v3::{DECISION_BYTES, DecisionRecordV3},
        role_manifest_v0199::{
            AUDIT_ACK, AUDIT_READ, CANDIDATE_SUBMIT, CONTROL_MASK, DECISION_REGISTER, EPOCH_ALLOC,
            MODEL_MANAGE, NativeRole, PUBLISH_PLAN, READ_DECISIONS, ROLES, Role, SNAPSHOT,
            TRIAL_D15, VALIDATION_REGISTER,
        },
    },
    security::{
        Error, durable_role_epoch_v0199::ConfirmedBootPolicy, syscall::Syscall,
        syscall_v3::ValidatedCall,
    },
};

const AUDIT_RIGHTS: u64 = AUDIT_READ | AUDIT_ACK;
const ASSISTED_BYTES: usize = DECISION_BYTES + DISPOSITION_BYTES;

const fn service_rights(role: Role) -> u64 {
    match role {
        Role::DeterministicController => DECISION_REGISTER,
        Role::Publisher => READ_DECISIONS,
        Role::Validator => VALIDATION_REGISTER,
        Role::ModelManager => MODEL_MANAGE | TRIAL_D15,
        Role::Learner => CANDIDATE_SUBMIT,
        Role::Supervisor => AUDIT_RIGHTS | EPOCH_ALLOC,
        Role::Operations | Role::Security => 0,
    }
}

/// Coarse admission before inspecting pointer arguments. The scheduler must
/// authenticate the original lifecycle binding before supplying a grant.
pub(super) fn authorized(
    member: NativeRole,
    capabilities: u64,
    selector: u64,
    operation: Syscall,
    first_arg: u64,
) -> bool {
    if selector == 0
        || capabilities & !member.role.allowed_caps() != 0
        || !member.actor.valid()
        || member.actor.id != u64::from(member.role.id())
        || member.cpu_mask != CONTROL_MASK
        || member.caps != 0
        || member.endpoint_id != 0
    {
        return false;
    }
    #[cfg(cyxia_business_package)]
    if publications_fenced()
        && matches!(member.role, Role::DeterministicController | Role::Publisher)
        && matches!(operation, Syscall::ServiceCall | Syscall::SubmitPlan)
    {
        return false;
    }
    match operation {
        Syscall::ReadSnapshot => first_arg == selector && capabilities & SNAPSHOT != 0,
        Syscall::SubmitPlan => member.role == Role::Publisher && capabilities & PUBLISH_PLAN != 0,
        Syscall::ServiceCall => {
            first_arg == selector && capabilities & service_rights(member.role) != 0
        }
        Syscall::QueryPlan if cfg!(cyxia_business_package) => match member.role {
            Role::DeterministicController => capabilities & DECISION_REGISTER != 0,
            Role::Publisher => capabilities & PUBLISH_PLAN != 0,
            Role::Supervisor => capabilities & AUDIT_READ != 0,
            _ => false,
        },
        _ => false,
    }
}

struct AuditTransport {
    caller: Option<Caller>,
    table: RpcTable,
    closed: bool,
    pending_ack: Option<PendingAck>,
}

#[derive(Clone, Copy)]
struct PendingAck {
    ticket: Ticket,
    seq: u64,
    digest: [u8; 32],
}

impl AuditTransport {
    const fn new() -> Self {
        Self {
            caller: None,
            table: RpcTable::new(),
            closed: false,
            pending_ack: None,
        }
    }
}

pub(super) const PROTECTED_BYTES: usize = core::mem::size_of::<AuditTransport>() + {
    #[cfg(cyxia_business_package)]
    {
        native::PROTECTED_BYTES
    }
    #[cfg(not(cyxia_business_package))]
    {
        0
    }
};

// CPU0 alone binds, serves, retires and replaces the Supervisor transport.
// Its disk owner settles admitted ACKs separately. IRQs never use either.
#[unsafe(link_section = ".bss.sec_n")]
static mut AUDIT_TRANSPORT: AuditTransport = AuditTransport::new();

pub(super) fn bind_audit(
    member: NativeRole,
    capabilities: u64,
    selector: u64,
    boot_epoch: u64,
) -> Result<(), Error> {
    if capabilities & AUDIT_RIGHTS == 0 {
        if member.role == Role::Supervisor {
            return recovery::audit_transport_online(member, false);
        }
        return Ok(());
    }
    if cpu::slot() != 0
        || member.role != Role::Supervisor
        || !authorized(
            member,
            capabilities,
            selector,
            Syscall::ServiceCall,
            selector,
        )
    {
        return Err(Error::Unauthorized);
    }
    let caller = Caller {
        boot_epoch,
        holder: member.actor,
        role: member.role.id(),
        endpoint: selector,
        cap: selector,
    };
    // SAFETY: This startup call is serialized with all CPU0 transport users.
    let transport = unsafe { &mut *addr_of_mut!(AUDIT_TRANSPORT) };
    transport
        .table
        .bind(caller, false)
        .map_err(|_| Error::Unauthorized)?;
    transport.caller = Some(caller);
    recovery::audit_transport_online(member, capabilities & AUDIT_RIGHTS == AUDIT_RIGHTS)
}

pub(super) fn retire_role(index: usize, member: NativeRole, selector: u64) -> Result<(), Error> {
    if cpu::slot() != 0 || ROLES.get(index) != Some(&member.role) {
        return Err(Error::Unauthorized);
    }
    if member.role == Role::Supervisor {
        // SAFETY: the root has stopped this exact TTBR0 and CPU0 serializes
        // retirement with the synchronous transport and audit owner.
        let transport = unsafe { &mut *addr_of_mut!(AUDIT_TRANSPORT) };
        if let Some(caller) = transport.caller {
            if caller.holder != member.actor || caller.cap != selector {
                return Err(Error::Unauthorized);
            }
            transport.table.close(caller).map_err(transport_error)?;
            transport.closed = true;
        }
        recovery::close_audit_reader(member)?;
    }
    #[cfg(cyxia_business_package)]
    native::retire_role(index, member, selector)?;
    Ok(())
}

pub(super) fn restore_role(
    index: usize,
    old: NativeRole,
    next: NativeRole,
    capabilities: u64,
    selector: u64,
    policy: &ConfirmedBootPolicy<'_>,
) -> Result<(), Error> {
    if cpu::slot() != 0
        || ROLES.get(index) != Some(&old.role)
        || old.role != next.role
        || old.actor.id != next.actor.id
        || old.actor.generation.checked_add(1) != Some(next.actor.generation)
        || policy.service_generation(next.role)? != next.actor.generation
    {
        return Err(Error::Unauthorized);
    }
    if next.role == Role::Supervisor {
        restore_audit(old, next, capabilities, selector, policy)?;
    }
    #[cfg(cyxia_business_package)]
    native::restore_role(index, old, next, capabilities, selector)?;
    Ok(())
}

fn restore_audit(
    old_member: NativeRole,
    next: NativeRole,
    capabilities: u64,
    selector: u64,
    policy: &ConfirmedBootPolicy<'_>,
) -> Result<(), Error> {
    // An optional carrier can exist without an EL0 transport grant.
    if capabilities & AUDIT_RIGHTS == 0 {
        recovery::replace_audit_reader(old_member, policy)?;
        return recovery::audit_transport_online(next, false);
    }
    if !authorized(next, capabilities, selector, Syscall::ServiceCall, selector) {
        return Err(Error::Unauthorized);
    }
    let replacement = Caller {
        boot_epoch: policy.boot_epoch(),
        holder: next.actor,
        role: next.role.id(),
        endpoint: selector,
        cap: selector,
    };
    // SAFETY: the new root has not entered EL0. Only CPU0 runs these
    // serialized callbacks and the audit disk borrow is non-reentrant.
    let transport = unsafe { &mut *addr_of_mut!(AUDIT_TRANSPORT) };
    let old = transport.caller.ok_or(Error::Unauthorized)?;
    if old == replacement && !transport.closed {
        return recovery::audit_transport_online(next, capabilities & AUDIT_RIGHTS == AUDIT_RIGHTS);
    }
    if old.holder != old_member.actor || !transport.closed {
        return Err(Error::Unauthorized);
    }
    if let Some(pending) = transport.pending_ack {
        transport
            .table
            .reconcile(
                pending.ticket,
                0,
                old.holder.generation,
                &[],
                |caller, wire, _, _| {
                    let request = Request::decode(wire)?;
                    if caller != old
                        || request.op != Op::AuditAck
                        || u64_at(request.payload, 8) != pending.seq
                        || request.payload[16..48] != pending.digest
                    {
                        return Err(RpcError::Auth);
                    }
                    recovery::verify_retired_ack(old_member, pending.seq, pending.digest)
                        .map_err(security_error)
                },
            )
            .map_err(transport_error)?;
        transport.pending_ack = None;
    }
    transport
        .table
        .retire_closed(old, |_| {
            // All terminal ACKs were established by independent durable
            // read-back. Read caches are mere copies of retained audit records.
            Ok(())
        })
        .map_err(transport_error)?;
    transport
        .table
        .replace_closed(old, replacement, || {
            recovery::replace_audit_reader(old_member, policy).map_err(security_error)
        })
        .map_err(transport_error)?;
    transport.caller = Some(replacement);
    transport.closed = false;
    recovery::audit_transport_online(next, capabilities & AUDIT_RIGHTS == AUDIT_RIGHTS)
}

fn transport_error(error: RpcError) -> Error {
    match error {
        RpcError::Busy | RpcError::Again => Error::Busy,
        RpcError::Stale => Error::Stale,
        RpcError::Conflict => Error::Conflict,
        RpcError::Capacity => Error::Capacity,
        RpcError::Io => Error::Unknown,
        _ => Error::Unauthorized,
    }
}

fn fixed_rpc_rights(role: Role, operation: Op) -> u64 {
    if !operation.permits_role(role.id()) {
        return 0;
    }
    match operation {
        Op::AuditRead => AUDIT_READ,
        Op::AuditAck => AUDIT_ACK,
        Op::Promote | Op::Rollback => MODEL_MANAGE,
        Op::EpochAllocate => EPOCH_ALLOC,
        Op::TrialInstantiate if role == Role::ModelManager => TRIAL_D15,
        Op::ValidationRegister => VALIDATION_REGISTER,
        Op::CandidateSubmit => CANDIDATE_SUBMIT,
        Op::DecisionRead => READ_DECISIONS,
        Op::Ack if role == Role::Supervisor => AUDIT_RIGHTS,
        Op::Ack => service_rights(role),
        _ => 0,
    }
}

pub(super) fn dispatch(
    caller: &SignedCaller,
    capabilities: u64,
    selector: u64,
    call: ValidatedCall,
) -> i64 {
    if !caller.registered()
        || !authorized(
            caller.member,
            capabilities,
            selector,
            call.operation,
            call.args[0],
        )
    {
        return RpcError::Auth as i64;
    }
    let result = match call.operation {
        #[cfg(cyxia_business_package)]
        Syscall::ReadSnapshot => native::read_snapshot(caller, selector, call.args),
        #[cfg(cyxia_business_package)]
        Syscall::SubmitPlan => native::publish(caller, selector, call.args),
        #[cfg(cyxia_business_package)]
        Syscall::QueryPlan => native::query(caller, selector, call.args),
        #[cfg(not(cyxia_business_package))]
        Syscall::ReadSnapshot | Syscall::SubmitPlan => Err(RpcError::Again),
        Syscall::ServiceCall => service_call(caller, capabilities, call.args),
        _ => Err(RpcError::Auth),
    };
    result.map_or_else(|error| error as i64, |()| 0)
}

fn service_call(caller: &SignedCaller, capabilities: u64, args: [u64; 6]) -> Result<(), RpcError> {
    let member = caller.member;
    if args[3] != 0 {
        return Err(RpcError::Auth);
    }
    let len = usize::try_from(args[2]).map_err(|_| RpcError::Format)?;
    let cap = usize::try_from(args[5]).map_err(|_| RpcError::Fault)?;
    let max_len = if member.role == Role::DeterministicController {
        if len != DECISION_BYTES && len != ASSISTED_BYTES {
            return Err(RpcError::Format);
        }
        ASSISTED_BYTES
    } else {
        FRAME_BYTES
    };
    if len > max_len {
        return Err(RpcError::Format);
    }
    let source =
        VerifiedSpan::verify_signed(caller, args[1], len, false).map_err(|_| RpcError::Fault)?;
    let mut storage = [0; FRAME_BYTES];
    let wire = &mut storage[..len];
    source.copy_in(wire).map_err(|_| RpcError::Fault)?;
    if member.role == Role::DeterministicController {
        let decision =
            DecisionRecordV3::decode(&wire[..DECISION_BYTES]).map_err(|_| RpcError::Format)?;
        if len == ASSISTED_BYTES {
            AdviceDispositionV1::decode(&wire[DECISION_BYTES..]).map_err(|_| RpcError::Format)?;
        }
        if cap < 8 {
            return Err(RpcError::Fault);
        }
        let output =
            VerifiedSpan::verify_signed(caller, args[4], cap, true).map_err(|_| RpcError::Fault)?;
        #[cfg(cyxia_business_package)]
        if len == DECISION_BYTES {
            return native::register(caller, args, (&*wire).try_into().unwrap(), decision, output);
        }
        let _ = decision;
        let _ = output;
        return Err(RpcError::Again);
    }
    let request = Request::decode(wire)?;
    if capabilities & fixed_rpc_rights(member.role, request.op) == 0 {
        return Err(RpcError::Auth);
    }
    if recovery::audit_degraded() && matches!(request.op, Op::Promote | Op::TrialInstantiate) {
        return Err(RpcError::Again);
    }
    if cap < request.op.max_reply_len() {
        return Err(RpcError::Fault);
    }
    let output =
        VerifiedSpan::verify_signed(caller, args[4], cap, true).map_err(|_| RpcError::Fault)?;
    #[cfg(cyxia_business_package)]
    if member.role == Role::Publisher && matches!(request.op, Op::DecisionRead | Op::Ack) {
        return native::read_decision(caller, args, wire, output);
    }
    if member.role != Role::Supervisor
        || !matches!(request.op, Op::AuditRead | Op::AuditAck | Op::Ack)
    {
        return Err(RpcError::Again);
    }
    audit(member, args[0], wire, request, cap, output)
}

fn security_error(error: Error) -> RpcError {
    match error {
        Error::Unauthorized => RpcError::Auth,
        Error::Invalid => RpcError::Format,
        Error::Stale => RpcError::Stale,
        Error::Conflict => RpcError::Conflict,
        Error::Capacity | Error::Exhausted => RpcError::Capacity,
        Error::Busy => RpcError::Again,
        Error::Unknown => RpcError::Io,
    }
}

fn audit(
    member: NativeRole,
    selector: u64,
    wire: &[u8],
    request: Request<'_>,
    cap: usize,
    output: VerifiedSpan<'_>,
) -> Result<(), RpcError> {
    // SAFETY: The signed task is stopped and CPU0 is serialized. No callback
    // below can enter EL0 or invoke this module again.
    let transport = unsafe { &mut *addr_of_mut!(AUDIT_TRANSPORT) };
    let caller = transport.caller.ok_or(RpcError::Auth)?;
    if transport.closed || caller.holder != member.actor || caller.cap != selector {
        return Err(RpcError::Auth);
    }
    if request.expected_generation != caller.holder.generation {
        return Err(RpcError::Stale);
    }
    if !recovery::durable_available(member) {
        return Err(RpcError::Again);
    }
    let generation = caller.holder.generation;
    let now = now_ns();
    let table = &mut transport.table;
    let audit_ack = (request.op == Op::AuditAck).then(|| {
        (
            u64_at(request.payload, 8),
            request.payload[16..48].try_into().unwrap(),
        )
    });
    let admitted = table.admit(
        caller,
        wire,
        cap,
        now,
        now.saturating_add(MAX_WAIT_NS),
        generation,
        |_| {
            if let Some((seq, digest)) = audit_ack {
                recovery::check_durable_ack(member, seq, digest).map_err(security_error)?;
            }
            Ok(())
        },
    )?;
    let reply = match admitted {
        Admission::Execute(ticket) if request.op == Op::AuditRead => {
            let cursor = u64_at(request.payload, 8);
            let payload = recovery::read_durable(member, cursor).map_err(security_error);
            match payload {
                Ok(payload) => {
                    table.complete(ticket, State::Done, 0, generation, &payload, || Ok(()))?
                }
                Err(error) => table.complete(
                    ticket,
                    State::Done,
                    error as i32,
                    generation,
                    &[],
                    || Ok(()),
                )?,
            }
        }
        Admission::Execute(ticket) => {
            let (seq, digest) = audit_ack.ok_or(RpcError::Auth)?;
            let pending = PendingAck {
                ticket,
                seq,
                digest,
            };
            transport.pending_ack = Some(pending);
            complete_ack(transport, member, pending)?
        }
        Admission::Replay(reply) if reply.state() == State::Pending => {
            let pending = transport.pending_ack.ok_or(RpcError::Stale)?;
            if audit_ack != Some((pending.seq, pending.digest)) {
                return Err(RpcError::Conflict);
            }
            complete_ack(transport, member, pending)?
        }
        Admission::Replay(reply) | Admission::Acknowledged(reply) => reply,
    };
    let out = reply.bytes();
    if !output
        .copy_out_and_check(out)
        .map_err(|_| RpcError::Fault)?
    {
        return Err(RpcError::Fault);
    }
    if request.op == Op::AuditRead
        && out.len() == Op::AuditRead.max_reply_len()
        && out[HEADER_BYTES..HEADER_BYTES + 2] == 1u16.to_le_bytes()
    {
        let payload = &out[HEADER_BYTES..];
        let seq = u64_at(payload, 8);
        let digest = payload[112..144].try_into().unwrap();
        recovery::confirm_delivery(member, seq, digest).map_err(security_error)?;
    }
    Ok(())
}

fn complete_ack(
    transport: &mut AuditTransport,
    member: NativeRole,
    pending: PendingAck,
) -> Result<Frame, RpcError> {
    let (status, code) = match recovery::ack_durable(member, pending.seq, pending.digest) {
        Ok(()) => (State::Done, 0),
        // The 0x50 caller retries its original bytes. The admitted ticket
        // keeps the request and completion credit while foreground flush runs.
        Err(Error::Busy) => return Err(RpcError::Again),
        Err(Error::Unknown) => (State::Unknown, RpcError::Io as i32),
        Err(error) => (State::Done, security_error(error) as i32),
    };
    let frame = transport.table.complete(
        pending.ticket,
        status,
        code,
        member.actor.generation,
        &[],
        || Ok(()),
    )?;
    if status == State::Done {
        transport.pending_ack = None;
    }
    Ok(frame)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

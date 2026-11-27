//! Control calls for authenticated CPU0 roles in the authorized boot profile.
//! The detached grant selects a real holder. It cannot install an observation
//! producer, a decision scope, a plan owner or an executor.

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
            MODEL_MANAGE, NativeRole, PUBLISH_PLAN, READ_DECISIONS, Role, SNAPSHOT, TRIAL_D15,
            VALIDATION_REGISTER,
        },
    },
    security::{Error, syscall::Syscall, syscall_v3::ValidatedCall},
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
    match operation {
        Syscall::ReadSnapshot => first_arg == selector && capabilities & SNAPSHOT != 0,
        Syscall::SubmitPlan => member.role == Role::Publisher && capabilities & PUBLISH_PLAN != 0,
        Syscall::ServiceCall => {
            first_arg == selector && capabilities & service_rights(member.role) != 0
        }
        // A plan-owner view or a role-12 D04 executor requires its own live
        // binding. The eight CPU0 lifecycle roles do not hold those endpoints.
        _ => false,
    }
}

struct AuditTransport {
    caller: Option<Caller>,
    table: RpcTable,
    pending_ack: Option<Ticket>,
}

impl AuditTransport {
    const fn new() -> Self {
        Self {
            caller: None,
            table: RpcTable::new(),
            pending_ack: None,
        }
    }
}

pub(super) const PROTECTED_BYTES: usize = core::mem::size_of::<AuditTransport>();

// CPU0 binds the sole actual Supervisor once before EL0 entry. Only the
// serialized signed CPU0 syscall adapter uses it thereafter. IRQs, other
// CPUs, and recovery foreground I/O do not access the transport directly.
#[unsafe(link_section = ".bss.sec_n")]
static mut AUDIT_TRANSPORT: AuditTransport = AuditTransport::new();

pub(super) fn bind_audit(
    member: NativeRole,
    capabilities: u64,
    selector: u64,
    boot_epoch: u64,
) -> Result<(), Error> {
    if capabilities & AUDIT_RIGHTS == 0 {
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
    Ok(())
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
    match call.operation {
        // The signed startup catalog does not provision a SnapshotStore view
        // or frozen registered decision/plan scope. Stop before copying data
        // that cannot be matched to a protected target or registered receipt.
        Syscall::ReadSnapshot | Syscall::SubmitPlan => RpcError::Again as i64,
        Syscall::ServiceCall => match service_call(caller, capabilities, call.args) {
            Ok(()) => 0,
            Err(error) => error as i64,
        },
        _ => RpcError::Auth as i64,
    }
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
        DecisionRecordV3::decode(&wire[..DECISION_BYTES]).map_err(|_| RpcError::Format)?;
        if len == ASSISTED_BYTES {
            AdviceDispositionV1::decode(&wire[DECISION_BYTES..]).map_err(|_| RpcError::Format)?;
        }
        if cap < 8 {
            return Err(RpcError::Fault);
        }
        VerifiedSpan::verify_signed(caller, args[4], cap, true).map_err(|_| RpcError::Fault)?;
        return Err(RpcError::Again);
    }
    let request = Request::decode(wire)?;
    if capabilities & fixed_rpc_rights(member.role, request.op) == 0 {
        return Err(RpcError::Auth);
    }
    if cap < request.op.max_reply_len() {
        return Err(RpcError::Fault);
    }
    let output =
        VerifiedSpan::verify_signed(caller, args[4], cap, true).map_err(|_| RpcError::Fault)?;
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
    if !recovery::durable_available(member) {
        return Err(RpcError::Again);
    }
    // SAFETY: The signed task is stopped and CPU0 is serialized. No callback
    // below can enter EL0 or invoke this module again.
    let transport = unsafe { &mut *addr_of_mut!(AUDIT_TRANSPORT) };
    let caller = transport.caller.ok_or(RpcError::Auth)?;
    if caller.holder != member.actor || caller.cap != selector {
        return Err(RpcError::Auth);
    }
    if request.expected_generation != caller.holder.generation {
        return Err(RpcError::Stale);
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
            transport.pending_ack = Some(ticket);
            let (seq, digest) = audit_ack.ok_or(RpcError::Auth)?;
            complete_ack(transport, member, ticket, seq, digest)?
        }
        Admission::Replay(reply) if reply.state() == State::Pending => {
            let ticket = transport.pending_ack.ok_or(RpcError::Stale)?;
            let (seq, digest) = audit_ack.ok_or(RpcError::Auth)?;
            complete_ack(transport, member, ticket, seq, digest)?
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
    ticket: Ticket,
    seq: u64,
    digest: [u8; 32],
) -> Result<Frame, RpcError> {
    let (status, code) = match recovery::ack_durable(member, seq, digest) {
        Ok(()) => (State::Done, 0),
        // The 0x50 caller retries its original bytes. The admitted ticket
        // keeps the request and completion credit while foreground flush runs.
        Err(Error::Busy) => return Err(RpcError::Again),
        Err(Error::Unknown) => (State::Unknown, RpcError::Io as i32),
        Err(error) => (State::Done, security_error(error) as i32),
    };
    let frame = transport.table.complete(
        ticket,
        status,
        code,
        member.actor.generation,
        &[],
        || Ok(()),
    )?;
    transport.pending_ack = None;
    Ok(frame)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

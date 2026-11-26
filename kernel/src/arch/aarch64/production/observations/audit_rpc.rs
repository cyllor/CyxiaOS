//! Serialized CPU0 endpoint. The transport ACK retires the previous RPC;
//! only an authenticated AUDIT_ACK retires a delivered recovery record.
use super::*;

pub(super) fn dispatch(index: usize, m: NativeRole, args: [u64; 6]) -> Result<(), RpcError> {
    let c = caller(index, m)?;
    if cpu::slot() != 0 || args[0] != c.cap || args[3] != 0 {
        return Err(RpcError::Auth);
    }
    let len = match args[2] {
        64 => 64,
        96 => 96,
        _ => return Err(RpcError::Format),
    };
    let n = usize::try_from(args[5]).map_err(|_| RpcError::Fault)?;
    let src = stack_span(index, args[1], len, false).ok_or(RpcError::Fault)?;
    let dst = stack_span(index, args[4], n, true).ok_or(RpcError::Fault)?;
    let mut buf = [0; 96];
    let request = &mut buf[..len];
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, request.as_mut_ptr(), len) };
    let req = Request::decode(request)?;
    let permission = match req.op {
        Op::AuditRead => AuxOperation::AuditRead,
        Op::AuditAck => AuxOperation::AuditAck,
        _ => return Err(RpcError::Auth),
    };
    if n < req.op.max_reply_len() {
        return Err(RpcError::Fault);
    }
    if c.holder.generation != req.expected_generation {
        return Err(RpcError::Stale);
    }
    let Some(manifest) = manifest() else {
        if req.op == Op::AuditRead {
            EARLY.fetch_or(2, Ordering::Relaxed);
        }
        return Err(RpcError::Again);
    };
    if manifest.members[index] != m
        || manifest.check_aux(c.holder, c.endpoint, 0, permission) != Ok(Role::Supervisor)
    {
        return Err(RpcError::Auth);
    }
    let audit_seq = u64::from_le_bytes(req.payload[8..16].try_into().unwrap());
    let digest = &req.payload[16..];
    let now = now_ns();
    let table = unsafe { &mut *addr_of_mut!(RPC) };
    let custody = unsafe { &mut *addr_of_mut!(CUSTODY) };
    let op = table.admit(
        c,
        request,
        n,
        now,
        now.saturating_add(cyxia_kernel_core::control_plane::control_rpc_v1::MAX_WAIT_NS),
        c.holder.generation,
        |_| {
            if req.op == Op::AuditAck {
                custody.check_ack(c, audit_seq, digest)?;
            }
            Ok(())
        },
    )?;
    let frame = match op {
        Admission::Execute(ticket) if req.op == Op::AuditRead => {
            let payload = custody.read(audit_seq);
            table.complete(
                ticket,
                State::Done,
                0,
                c.holder.generation,
                &payload,
                || Ok(()),
            )?
        }
        Admission::Execute(ticket) => {
            table.complete(ticket, State::Done, 0, c.holder.generation, &[], || {
                custody.release(c, audit_seq, digest)
            })?
        }
        Admission::Replay(frame) => frame,
        Admission::Acknowledged(_) => return Err(RpcError::Auth),
    };
    let wire = frame.bytes();
    if !copy_reply(dst, wire) {
        return Err(RpcError::Fault);
    }
    if req.op == Op::AuditRead && wire.len() == Op::AuditRead.max_reply_len() {
        if wire[48..50] == 1u16.to_le_bytes() {
            let seq = u64::from_le_bytes(wire[56..64].try_into().unwrap());
            custody.delivered(c, seq, &wire[64..])?;
            let previous = AUDIT_SEEN.fetch_max(seq, Ordering::Relaxed);
            if previous == 0 && seq == 1 {
                evidence::put(evidence::W12_AUDIT_READ_SEQUENCE, seq);
                report("V020_W12_VOLATILE_AUDIT", c.role.into(), seq, 1);
            }
            if matches!(op, Admission::Replay(_)) {
                REPLAYS.fetch_add(1, Ordering::Relaxed);
            }
        } else if req.seq == 8 && audit_seq == 0 && wire[48..].iter().all(|&v| v == 0) {
            // The independently linked consumer requests this rescan only after validating
            // all three ACK replies and the terminal empty scan at cursor 3.
            EMPTY_RESCAN.store(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

//! Native read-only FILE_QUERY_RESULT for the signed FSYNC scratch reopen.
//! CPU0 owns the grant. The backing receipt view was read from the replayed
//! disk and sealed only after the current durable BootEpoch was confirmed.

use super::*;
use core::ptr::{addr_of, addr_of_mut, copy_nonoverlapping};
use cyxia_kernel_core::security::{
    Error as SecurityError,
    file_read_v4::{ENDPOINT, MAX_REPLY},
    file_receipt_query_v4::{FILE_QUERY_RESULT, RECEIPT_KEY_BYTES},
    file_service_v4::{REPLY_HEADER, REQUEST_HEADER, Reply, Request},
    recovery_proof_v2::EIO,
};
use media_staging::StagedReceiptQuery;

const FRAME_BYTES: usize = REQUEST_HEADER + RECEIPT_KEY_BYTES;
const E_STALE: i64 = -4;
const FATAL: u64 = 0x5732_2350;

struct Grant {
    holder: NativeRole,
    pie_cap: u64,
    mount: Option<StagedReceiptQuery>,
}

#[derive(Clone, Copy)]
struct Checks {
    pending: bool,
    recovered: Option<(u64, u64, u64)>,
    revoked: bool,
}

struct State {
    grant: Option<Grant>,
    checks: Checks,
}

static mut STATE: State = State {
    grant: None,
    checks: Checks {
        pending: false,
        recovered: None,
        revoked: false,
    },
};

pub(super) const fn protected_bytes() -> usize {
    size_of::<State>()
}

fn caller(index: usize, member: NativeRole, args: [u64; 6]) -> Result<u64, i64> {
    if member.role != Role::Supervisor || args[0] != ENDPOINT || args[3] != 0 {
        return Err(E_AUTH);
    }
    trapped_pie_cap(index, member)
}

fn buffers(index: usize, args: [u64; 6]) -> Result<(u64, u64), i64> {
    if args[2] != FRAME_BYTES as u64 {
        return Err(E_FORMAT);
    }
    let capacity = usize::try_from(args[5]).map_err(|_| EFAULT)?;
    if !(REPLY_HEADER..=MAX_REPLY).contains(&capacity) {
        return Err(EFAULT);
    }
    let source = stack_span(index, args[1], FRAME_BYTES, false).ok_or(EFAULT)?;
    let dest = stack_span(index, args[4], capacity, true).ok_or(EFAULT)?;
    // stack_span has checked that both additions stay within the private span.
    if args[1] < args[4] + args[5] && args[4] < args[1] + args[2] {
        return Err(EFAULT);
    }
    Ok((source, dest))
}

pub(super) fn reject_preflight(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    caller(index, member, args)
        .and_then(|_| buffers(index, args))
        .err()
        .unwrap_or(EFAULT) as u64
}

pub(super) fn dispatch(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    serve(index, member, args).map_or_else(|error| error as u64, |()| 0)
}

fn errno(error: SecurityError) -> i64 {
    match error {
        SecurityError::Unauthorized => E_AUTH,
        SecurityError::Invalid => E_FORMAT,
        SecurityError::Stale => E_STALE,
        SecurityError::Capacity => EFAULT,
        _ => i64::from(EIO),
    }
}

fn serve(index: usize, member: NativeRole, args: [u64; 6]) -> Result<(), i64> {
    let cap = caller(index, member, args)?;
    let (source, dest) = buffers(index, args)?;
    // SAFETY: only the trapped, registered CPU0 role reaches this point.
    // The foreground driver holds no STATE borrow while running the role.
    let state = unsafe { &mut *addr_of_mut!(STATE) };
    let mut request = [0; FRAME_BYTES];
    // SAFETY: the checked EL1 alias covers the stopped role's complete input.
    unsafe { copy_nonoverlapping(source as *const u8, request.as_mut_ptr(), FRAME_BYTES) };
    if Request::decode(&request, 0).map_err(errno)?.op != FILE_QUERY_RESULT {
        return Err(E_FORMAT);
    }
    if let Some(error) = media_staging::ordinary_file_refusal() {
        return Err(error);
    }
    let Some(grant) = &state.grant else {
        state.checks.pending = true;
        return Err(EAGAIN);
    };
    if grant.holder != member || grant.pie_cap != cap {
        return Err(E_AUTH);
    }
    let Some(mount) = &grant.mount else {
        state.checks.revoked = true;
        return Err(E_STALE);
    };
    let mut reply = [0; REPLY_HEADER];
    let len = mount
        .view
        .serve(mount.caller, 0, &request, &mut reply)
        .map_err(errno)?;
    let reply = &reply[..len];
    let parsed = Reply::decode(reply).map_err(errno)?;
    // SAFETY: buffers() checked the independent writable reply span.
    unsafe { copy_nonoverlapping(reply.as_ptr(), dest as *mut u8, len) };
    if parsed.state == mount.expected.status
        && parsed.commit_lsn == mount.expected.commit_lsn
        && parsed.write_seq == mount.expected.write_seq
        && parsed.completed_prefix == mount.expected.completed_prefix
        && parsed.result_digest == mount.expected.output_digest
    {
        state.checks.recovered =
            Some((mount.caller.boot_epoch, parsed.commit_lsn, parsed.write_seq));
    }
    Ok(())
}

fn checks() -> Checks {
    // Only the CPU0 foreground calls this while the role is stopped.
    unsafe { addr_of!(STATE.checks).read() }
}

pub(super) fn drive(
    contexts: &mut [user::Context; ROLE_COUNT],
    manifest: &NativeRoleManifest,
    mount: StagedReceiptQuery,
) {
    if cpu::slot() != 0 || manifest.validate().is_err() {
        fatal(FATAL);
    }
    let index = ROLES
        .iter()
        .position(|&role| role == Role::Supervisor)
        .expect("registered fixture receipt sender");
    let holder = manifest.members[index];
    let Some(pie_cap) = registered_pie_cap(index, holder) else {
        fatal(FATAL);
    };
    let boot = mount.caller.boot_epoch;
    let service = mount.caller.service_generation;
    let ctx = &mut contexts[index];
    let until = deadline();
    wait_for_role_yield(index, ctx, until, FATAL + 1, || checks().pending);
    // SAFETY: CPU0 owns the grant and all the PIE roles are currently stopped.
    unsafe {
        *addr_of_mut!(STATE.grant) = Some(Grant {
            holder,
            pie_cap,
            mount: Some(mount),
        });
    }
    wait_for_role_yield(index, ctx, until, FATAL + 2, || {
        checks().recovered.is_some()
    });
    // Keep the holder binding so its next authenticated query observes ESTALE.
    unsafe { (*addr_of_mut!(STATE.grant)).as_mut().unwrap().mount = None };
    wait_for_role_yield(index, ctx, until, FATAL + 3, || checks().revoked);
    let (epoch, lsn, write_seq) = checks().recovered.expect("checked native receipt result");
    report("V020_FSYNC_RECOVERED", epoch, lsn, write_seq);
    report("V020_FSYNC_RECEIPT_ABI", boot, holder.actor.id, service);
}

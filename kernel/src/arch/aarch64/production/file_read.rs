//! The signed scratch view serves one Supervisor on CPU0. Only the staging
//! run touches the disk. Synchronous traps and stopped-role turns serialize
//! the grant and the volatile reply slots.

use super::*;
use core::ptr::{addr_of, addr_of_mut, copy_nonoverlapping};
use cyxia_kernel_core::security::{
    file_read_v4::{FileReadService, MAX_FRAME, MAX_REPLY, ROOT_SELECTOR, StagedFile},
    file_service_v4::{REPLY_HEADER, REQUEST_HEADER, Request},
    offline_config_v1::Principal,
};

#[cfg(feature = "v020-production-file-sessions")]
#[path = "file_read/sessions.rs"]
mod sessions;
#[cfg(feature = "v020-production-file-volatile-write")]
#[path = "file_read/volatile_write.rs"]
mod volatile_write;

const E_STALE: i64 = -4;
const E_CONFLICT: i64 = -5;
const E_UNSUPPORTED: i64 = -11;
const READ_ONLY_WRITE_STATUS: i64 = if cfg!(feature = "v020-production-file-volatile-write") {
    E_AUTH
} else {
    E_UNSUPPORTED
};
const FATAL: u64 = 0x5732_1850;

const WRONG_ROLE: u8 = 1 << 0;
const UNREADY: u8 = 1 << 1;
const CHANGED_REPLAY: u8 = 1 << 2;
const CLOSED_HANDLE: u8 = 1 << 3;
const FORGED_CONTEXT: u8 = 1 << 4;
const WRITE_REFUSED: u8 = 1 << 5;
const OVERLAP: u8 = 1 << 6;
const REVOKED: u8 = 1 << 7;
const ACTIVE_REFUSALS: u8 = u8::MAX ^ REVOKED;

const OPEN: u16 = 2;
const READ: u16 = 3;
const WRITE: u16 = 4;
const CLOSE: u16 = 6;
const READDIR: u16 = 8;
const QUERY_VOLATILE: u16 = 14;
const ACK_VOLATILE: u16 = 15;
const REQUIRED_OPS: u16 = (1 << OPEN)
    | (1 << READ)
    | (1 << CLOSE)
    | (1 << READDIR)
    | (1 << QUERY_VOLATILE)
    | (1 << ACK_VOLATILE);

struct Grant {
    holder: NativeRole,
    pie_cap: u64,
    service: Option<FileReadService>,
}

#[derive(Clone, Copy)]
struct Checks {
    refusals: u8,
    operations: u16,
    reads: u64,
    replays: u64,
    acks: u64,
}

struct State {
    grant: Option<Grant>,
    checks: Checks,
    #[cfg(feature = "v020-production-file-sessions")]
    sessions: Option<sessions::SessionChecks>,
    #[cfg(feature = "v020-production-file-volatile-write")]
    write_probe: Option<volatile_write::WriteChecks>,
}

static mut STATE: State = State {
    grant: None,
    checks: Checks {
        refusals: 0,
        operations: 0,
        reads: 0,
        replays: 0,
        acks: 0,
    },
    #[cfg(feature = "v020-production-file-sessions")]
    sessions: None,
    #[cfg(feature = "v020-production-file-volatile-write")]
    write_probe: None,
};

pub(super) const fn protected_bytes() -> usize {
    size_of::<State>()
}

fn authorize(state: &mut State, member: NativeRole, cap: u64, selector: u64) -> Result<(), i64> {
    if member.role != Role::Supervisor {
        if member.role == Role::Operations && selector == ROOT_SELECTOR {
            state.checks.refusals |= WRONG_ROLE;
        }
        return Err(E_AUTH);
    }
    if state
        .grant
        .as_ref()
        .is_some_and(|grant| grant.holder != member || grant.pie_cap != cap)
    {
        return Err(E_AUTH);
    }
    Ok(())
}

struct Buffers {
    source: u64,
    dest: u64,
    request_len: usize,
    reply_cap: usize,
    overlap: bool,
}

fn checked_buffers(index: usize, args: [u64; 6]) -> Result<Buffers, i64> {
    let request_len = usize::try_from(args[2]).map_err(|_| E_FORMAT)?;
    if !(REQUEST_HEADER..=MAX_FRAME).contains(&request_len) {
        return Err(E_FORMAT);
    }
    let reply_cap = usize::try_from(args[5]).map_err(|_| EFAULT)?;
    if !(REPLY_HEADER..=MAX_REPLY).contains(&reply_cap) {
        return Err(EFAULT);
    }
    let source = stack_span(index, args[1], request_len, false).ok_or(EFAULT)?;
    let dest = stack_span(index, args[4], reply_cap, true).ok_or(EFAULT)?;
    // stack_span proved both checked half-open ends and the role's page ownership.
    let overlap = args[1] < args[4] + args[5] && args[4] < args[1] + args[2];
    Ok(Buffers {
        source,
        dest,
        request_len,
        reply_cap,
        overlap,
    })
}

fn reject_overlap(state: &mut State, buffers: &Buffers) -> Result<(), i64> {
    if buffers.overlap {
        if state
            .grant
            .as_ref()
            .is_some_and(|grant| grant.service.is_some())
        {
            state.checks.refusals |= OVERLAP;
        }
        return Err(EFAULT);
    }
    Ok(())
}

pub(super) fn reject_preflight(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    match (|| -> Result<(), i64> {
        let cap = trapped_pie_cap(index, member)?;
        // Only CPU0 can call either entry point, from the trapped role's turn.
        let state = unsafe { &mut *addr_of_mut!(STATE) };
        authorize(state, member, cap, args[3])?;
        let buffers = checked_buffers(index, args)?;
        reject_overlap(state, &buffers)
    })() {
        Err(error) => error as u64,
        Ok(()) => EFAULT as u64,
    }
}

pub(super) fn dispatch(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    serve(index, member, args).map_or_else(|error| error as u64, |()| 0)
}

fn serve(index: usize, member: NativeRole, args: [u64; 6]) -> Result<(), i64> {
    let cap = trapped_pie_cap(index, member)?;
    let state = unsafe { &mut *addr_of_mut!(STATE) };
    authorize(state, member, cap, args[3])?;
    let buffers = checked_buffers(index, args)?;
    reject_overlap(state, &buffers)?;
    let mut frame = [0; MAX_FRAME];
    // The role is stopped and both spans are private. No user reference escapes this trap.
    unsafe {
        copy_nonoverlapping(
            buffers.source as *const u8,
            frame.as_mut_ptr(),
            buffers.request_len,
        )
    };
    let frame = &frame[..buffers.request_len];
    let parsed = Request::decode(frame, args[3]);
    let Some(grant) = &mut state.grant else {
        if args[3] == ROOT_SELECTOR
            && parsed.is_ok_and(|request| request.op == READDIR && request.request_id == 1)
        {
            state.checks.refusals |= UNREADY;
        }
        return Err(EAGAIN);
    };
    let Some(service) = &mut grant.service else {
        if args[3] == ROOT_SELECTOR
            && parsed.is_ok_and(|request| request.op == READDIR && request.request_id == 100)
        {
            state.checks.refusals |= REVOKED;
        }
        #[cfg(feature = "v020-production-file-sessions")]
        if let (Some(checks), Ok(request)) = (&mut state.sessions, parsed) {
            checks.record_revocation(request, args[3]);
        }
        return Err(E_STALE);
    };
    let mut reply = [0; MAX_REPLY];
    let served = match service.serve(args[3], frame, &mut reply[..buffers.reply_cap]) {
        Ok(served) => served,
        Err(error) => {
            let errno = error.errno();
            #[cfg(feature = "v020-production-file-volatile-write")]
            if let Some(checks) = &mut state.write_probe {
                if let Ok(request) = parsed {
                    checks.record_denial(request, errno);
                }
                return Err(errno);
            }
            #[cfg(feature = "v020-production-file-sessions")]
            if let Some(checks) = &mut state.sessions {
                if let Ok(request) = parsed {
                    checks.record_denial(request, errno);
                }
                return Err(errno);
            }
            state.checks.refusals |= match (errno, parsed) {
                (E_CONFLICT, Ok(request)) if request.op == READ && request.request_id == 3 => {
                    CHANGED_REPLAY
                }
                (E_STALE, Ok(request)) if request.op == READ && request.request_id == 7 => {
                    CLOSED_HANDLE
                }
                (E_FORMAT, Err(_)) if frame[24..32].iter().any(|&byte| byte != 0) => FORGED_CONTEXT,
                (READ_ONLY_WRITE_STATUS, Ok(request)) if request.op == WRITE => WRITE_REFUSED,
                _ => 0,
            };
            return Err(errno);
        }
    };
    let wire = &reply[..served.len];
    let dest = buffers.dest as *mut u8;
    unsafe { copy_nonoverlapping(wire.as_ptr(), dest, wire.len()) };
    if !wire
        .iter()
        .enumerate()
        .all(|(i, &byte)| unsafe { dest.add(i).read_volatile() } == byte)
    {
        fatal(FATAL + 5);
    }
    let op = parsed.expect("successful file operation was decoded").op;
    #[cfg(feature = "v020-production-file-volatile-write")]
    if let Some(checks) = &mut state.write_probe {
        checks.record_success(op, served.replay);
        return Ok(());
    }
    #[cfg(feature = "v020-production-file-sessions")]
    if let Some(checks) = &mut state.sessions {
        checks.record_success(op, served.replay, service.live_handles());
        return Ok(());
    }
    if served.replay {
        state.checks.replays = state.checks.replays.saturating_add(1);
    } else {
        state.checks.operations |= 1 << op;
        state.checks.reads += u64::from(op == READ);
        state.checks.acks += u64::from(op == ACK_VOLATILE);
    }
    Ok(())
}

fn checks() -> Checks {
    // The driver only reads while no role is running.
    unsafe { addr_of!(STATE.checks).read() }
}

pub(super) fn drive(
    contexts: &mut [user::Context; ROLE_COUNT],
    manifest: &NativeRoleManifest,
    view: StagedFile,
) {
    let owner = view.owner();
    if cpu::slot() != 0
        || manifest.validate().is_err()
        || owner
            != (Principal {
                id: 1,
                generation: 1,
            })
    {
        fatal(FATAL);
    }
    let ops = ROLES
        .iter()
        .position(|&role| role == Role::Operations)
        .unwrap();
    let supervisor = ROLES
        .iter()
        .position(|&role| role == Role::Supervisor)
        .unwrap();
    let holder = manifest.members[supervisor];
    let Some(pie_cap) = registered_pie_cap(supervisor, holder) else {
        fatal(FATAL)
    };
    let until = deadline();
    wait_for_role_yield(ops, &mut contexts[ops], until, FATAL + 1, || {
        checks().refusals & WRONG_ROLE != 0
    });
    let ctx = &mut contexts[supervisor];
    wait_for_role_yield(supervisor, ctx, until, FATAL + 2, || {
        checks().refusals & UNREADY != 0
    });
    {
        let slot = unsafe { &mut *addr_of_mut!(STATE.grant) };
        if slot.is_some() {
            fatal(FATAL);
        }
        #[cfg(feature = "v020-production-file-sessions")]
        let service = FileReadService::with_multiple_handles(view);
        #[cfg(not(feature = "v020-production-file-sessions"))]
        let service = FileReadService::new(view);
        *slot = Some(Grant {
            holder,
            pie_cap,
            service: Some(service),
        });
    }
    wait_for_role_yield(supervisor, ctx, until, FATAL + 3, || {
        let checks = checks();
        checks.operations == REQUIRED_OPS
            && checks.refusals == ACTIVE_REFUSALS
            && checks.reads == 3
            && checks.replays == 1
            && checks.acks == 3
    });
    #[cfg(feature = "v020-production-file-volatile-write")]
    {
        unsafe { *addr_of_mut!(STATE.write_probe) = Some(volatile_write::WriteChecks::default()) };
        wait_for_role_yield(supervisor, ctx, until, FATAL + 7, || {
            // The observer reads CPU0 state only when the PIE is stopped.
            let state = unsafe { &*addr_of!(STATE) };
            let service = state.grant.as_ref().unwrap().service.as_ref().unwrap();
            state.write_probe.as_ref().unwrap().turn_complete(service)
        });
        let state = unsafe { &mut *addr_of_mut!(STATE) };
        let service = state.grant.as_ref().unwrap().service.as_ref().unwrap();
        let checks = state.write_probe.take().unwrap();
        checks.publish(
            view.boot_epoch(),
            view.owner_rights(),
            service.write_sequence(),
        );
    }
    #[cfg(feature = "v020-production-file-sessions")]
    {
        // The next turn starts after any volatile overwrite checks.
        unsafe { *addr_of_mut!(STATE.sessions) = Some(sessions::SessionChecks::default()) };
        wait_for_role_yield(supervisor, ctx, until, FATAL + 6, || {
            // CPU0 owns STATE, and the PIE is stopped at the yield.
            let state = unsafe { &*addr_of!(STATE) };
            let checks = state.sessions.as_ref().unwrap();
            let service = state.grant.as_ref().unwrap().service.as_ref().unwrap();
            checks.turn_complete(service.live_handles(), service.retained_count())
        });
    }
    {
        let state = unsafe { &mut *addr_of_mut!(STATE) };
        let grant = state.grant.as_mut().unwrap();
        #[cfg(feature = "v020-production-file-sessions")]
        state
            .sessions
            .as_mut()
            .unwrap()
            .retire(grant.service.as_ref().unwrap().live_handle_selectors());
        grant.service = None;
    }
    wait_for_role_yield(supervisor, ctx, until, FATAL + 4, || {
        #[cfg(feature = "v020-production-file-sessions")]
        if !unsafe { addr_of!(STATE.sessions).read() }
            .is_some_and(|checks| checks.retirement_confirmed())
        {
            return false;
        }
        checks().refusals == u8::MAX
    });

    let checks = checks();
    let boot = view.boot_epoch();
    let operations = u64::from(checks.operations);
    let refusals = u64::from(checks.refusals);
    evidence::put(evidence::W18_FILE_BOOT, boot);
    evidence::put(evidence::W18_FILE_OWNER, owner.id);
    evidence::put(evidence::W18_FILE_OWNER_GENERATION, owner.generation);
    evidence::put(evidence::W18_FILE_READS, checks.reads);
    evidence::put(evidence::W18_FILE_OPS, operations);
    evidence::put(evidence::W18_FILE_REPLAYS, checks.replays);
    evidence::put(evidence::W18_FILE_REFUSALS, refusals);
    evidence::put(evidence::W18_FILE_ACKS, checks.acks);
    for (i, bytes) in view.content_digest().chunks_exact(8).enumerate() {
        evidence::put(
            evidence::W18_FILE_DIGEST + i,
            u64::from_le_bytes(bytes.try_into().unwrap()),
        );
    }
    report("V020_W18_FILE_READ", boot, checks.reads, operations);
    report(
        "V020_W18_FILE_CHECKS",
        refusals,
        checks.replays,
        checks.acks,
    );
    report(
        "V020_W18_FILE_OWNER",
        owner.id,
        owner.generation,
        u64::from(holder.role.id()),
    );
    #[cfg(feature = "v020-production-file-sessions")]
    unsafe { addr_of!(STATE.sessions).read() }
        .unwrap()
        .publish(boot);
}

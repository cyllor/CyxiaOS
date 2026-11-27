//! Native client adapter for the signed scratch file. The vector authenticates
//! and copies requests. The exclusive foreground mount owner performs the
//! journal work and publishes a result for exact replay.

use super::*;
use core::ptr::{addr_of_mut, copy_nonoverlapping};
use cyxia_kernel_core::security::{
    Error as SecurityError,
    file_index_v0199::BLOCK_BYTES,
    file_read_v4::{ENDPOINT, FileReadService, MAX_FRAME, MAX_REPLY, ReadError, StagedFile},
    file_receipt_query_v4::{RECEIPT_KEY_BYTES, ReceiptKey},
    file_service_v4::{REPLY_HEADER, REQUEST_HEADER, Request},
};

pub(super) const ALLOC: usize = 0;
pub(super) const FSYNC: usize = 1;
const FATAL: u64 = 0x5732_2450;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Frame {
    pub(super) selector: u64,
    len: usize,
    bytes: [u8; MAX_FRAME],
}

impl Frame {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

struct Job {
    frame: Frame,
    reply: [u8; MAX_REPLY],
    len: usize,
    deliveries: u8,
}

struct Grant {
    holder: NativeRole,
    pie_cap: u64,
    service: FileReadService,
    key: ReceiptKey,
    write_seq: u64,
    jobs: [Option<Job>; 2],
}

struct State {
    grant: Option<Grant>,
    pending_open: bool,
}

static mut STATE: State = State {
    grant: None,
    pending_open: false,
};

pub(super) const fn protected_bytes() -> usize {
    size_of::<State>()
}

fn authenticate(index: usize, member: NativeRole, endpoint: u64) -> Result<u64, i64> {
    if member.role != Role::Supervisor || endpoint != ENDPOINT {
        return Err(E_AUTH);
    }
    trapped_pie_cap(index, member)
}

fn buffers(index: usize, args: [u64; 6]) -> Result<(u64, u64, usize, usize), i64> {
    let len = usize::try_from(args[2]).map_err(|_| E_FORMAT)?;
    if !(REQUEST_HEADER..=MAX_FRAME).contains(&len) {
        return Err(E_FORMAT);
    }
    let capacity = usize::try_from(args[5]).map_err(|_| EFAULT)?;
    if !(REPLY_HEADER..=MAX_REPLY).contains(&capacity) {
        return Err(EFAULT);
    }
    let source = stack_span(index, args[1], len, false).ok_or(EFAULT)?;
    let dest = stack_span(index, args[4], capacity, true).ok_or(EFAULT)?;
    if args[1] < args[4] + args[5] && args[4] < args[1] + args[2] {
        return Err(EFAULT);
    }
    Ok((source, dest, len, capacity))
}

pub(super) fn reject_preflight(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    authenticate(index, member, args[0])
        .and_then(|_| buffers(index, args))
        .err()
        .unwrap_or(EFAULT) as u64
}

pub(super) fn dispatch(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    serve(index, member, args).map_or_else(|error| error as u64, |()| 0)
}

fn serve(index: usize, member: NativeRole, args: [u64; 6]) -> Result<(), i64> {
    let cap = authenticate(index, member, args[0])?;
    let (source, dest, len, capacity) = buffers(index, args)?;
    let mut frame = Frame {
        selector: args[3],
        len,
        bytes: [0; MAX_FRAME],
    };
    // SAFETY: source and destination were independently checked against the
    // current holder's writable page tables. EL0 is stopped in this trap.
    unsafe { copy_nonoverlapping(source as *const u8, frame.bytes.as_mut_ptr(), len) };
    let request = Request::decode(frame.bytes(), frame.selector).map_err(|e| {
        if e == SecurityError::Unauthorized {
            E_AUTH
        } else {
            E_FORMAT
        }
    })?;
    if let Some(error) = media_staging::ordinary_file_refusal() {
        return Err(error);
    }
    // SAFETY: only the CPU0 trap or its stopped-role foreground uses STATE.
    let state = unsafe { &mut *addr_of_mut!(STATE) };
    let Some(grant) = &mut state.grant else {
        if request.op == 2 {
            state.pending_open = true;
        }
        return Err(EAGAIN);
    };
    if grant.holder != member || grant.pie_cap != cap {
        return Err(E_AUTH);
    }
    let slot = match request.op {
        10 => ALLOC,
        5 => FSYNC,
        _ => {
            // Serialize volatile operations behind the frozen write version
            // until its last segment and receipt are independently confirmed.
            if grant.jobs[FSYNC].is_some() {
                return Err(EAGAIN);
            }
            let mut reply = [0; MAX_REPLY];
            let served = grant
                .service
                .serve(frame.selector, frame.bytes(), &mut reply[..capacity])
                .map_err(ReadError::errno)?;
            unsafe { copy_nonoverlapping(reply.as_ptr(), dest as *mut u8, served.len) };
            return Ok(());
        }
    };
    let required_reply = REPLY_HEADER + if slot == ALLOC { RECEIPT_KEY_BYTES } else { 0 };
    if capacity < required_reply {
        return Err(EFAULT);
    }
    if let Some(job) = &mut grant.jobs[slot] {
        if job.frame != frame {
            return Err(-5); // E_CONFLICT
        }
        if job.len == 0 {
            return Err(EAGAIN);
        }
        unsafe { copy_nonoverlapping(job.reply.as_ptr(), dest as *mut u8, job.len) };
        job.deliveries = job.deliveries.saturating_add(1);
        return Ok(());
    }
    if slot == ALLOC {
        let stream = u64::from(request.payload[0]);
        let sequence = u64::from_le_bytes(request.payload[8..].try_into().unwrap());
        if (stream, sequence) != (grant.key.stream_slot, grant.key.request_seq) {
            return Err(E_AUTH);
        }
    } else {
        if !grant.jobs[ALLOC]
            .as_ref()
            .is_some_and(|job| job.deliveries > 0)
        {
            return Err(EAGAIN);
        }
        let sequence = u64::from_le_bytes(request.payload.try_into().unwrap());
        if grant.key.request_id() != Some(request.request_id) || sequence != grant.write_seq {
            return Err(E_AUTH);
        }
        grant
            .service
            .check_fsync(frame.selector, sequence)
            .map_err(ReadError::errno)?;
    }

    grant.jobs[slot] = Some(Job {
        frame,
        reply: [0; MAX_REPLY],
        len: 0,
        deliveries: 0,
    });
    Err(EAGAIN)
}

pub(super) struct Client<'a> {
    ctx: &'a mut user::Context,
    holder: NativeRole,
    index: usize,
    pie_cap: u64,
    granted: bool,
}

impl<'a> Client<'a> {
    pub(super) fn new(
        contexts: &'a mut [user::Context; ROLE_COUNT],
        manifest: &NativeRoleManifest,
    ) -> Result<Self, SecurityError> {
        if cpu::slot() != 0 || manifest.validate().is_err() {
            return Err(SecurityError::Unauthorized);
        }
        let index = ROLES.iter().position(|&r| r == Role::Supervisor).unwrap();
        let holder = manifest.members[index];
        let pie_cap = registered_pie_cap(index, holder).ok_or(SecurityError::Unauthorized)?;
        Ok(Self {
            ctx: &mut contexts[index],
            holder,
            index,
            pie_cap,
            granted: false,
        })
    }

    pub(super) fn start(&mut self, file: StagedFile, key: ReceiptKey, write_seq: u64) {
        self.wait(FATAL + 1, |state| state.pending_open);
        // SAFETY: the CPU0 owner writes this slot while the role is stopped.
        unsafe {
            *addr_of_mut!(STATE.grant) = Some(Grant {
                holder: self.holder,
                pie_cap: self.pie_cap,
                service: FileReadService::new(file),
                key,
                write_seq,
                jobs: [None, None],
            });
        }
        self.granted = true;
    }

    fn wait(&mut self, failure: u64, done: impl Fn(&State) -> bool) {
        wait_for_role_yield(self.index, self.ctx, deadline(), failure, || {
            // SAFETY: wait_for_role_yield checks only while the holder stops.
            done(unsafe { &*addr_of_mut!(STATE) })
        });
    }

    pub(super) fn request(&mut self, slot: usize) -> Frame {
        self.wait(FATAL + 2 + slot as u64, |s| {
            s.grant.as_ref().unwrap().jobs[slot].is_some()
        });
        unsafe {
            (*addr_of_mut!(STATE)).grant.as_ref().unwrap().jobs[slot]
                .as_ref()
                .unwrap()
                .frame
        }
    }

    pub(super) fn freeze(
        &self,
        frame: Frame,
        sequence: u64,
        out: &mut [u8; BLOCK_BYTES],
    ) -> Result<(), SecurityError> {
        // SAFETY: a queued FSYNC prevents the stopped holder's mutations.
        let grant = unsafe { (*addr_of_mut!(STATE)).grant.as_ref().unwrap() };
        grant
            .service
            .freeze_fsync(frame.selector, sequence, out)
            .map_err(|_| SecurityError::Unauthorized)
    }

    pub(super) fn publish(&mut self, slot: usize, reply: &[u8]) {
        // SAFETY: no role is running; the completed owner publishes once.
        let grant = unsafe { (*addr_of_mut!(STATE)).grant.as_mut().unwrap() };
        let job = grant.jobs[slot].as_mut().unwrap();
        assert_eq!(job.len, 0);
        job.reply[..reply.len()].copy_from_slice(reply);
        job.len = reply.len();
    }

    pub(super) fn finish(&mut self) -> u64 {
        self.wait(FATAL + 4, |s| {
            s.grant.as_ref().unwrap().jobs[FSYNC]
                .as_ref()
                .is_some_and(|job| job.deliveries >= 2)
        });
        self.holder.actor.id
    }
}

impl Drop for Client<'_> {
    fn drop(&mut self) {
        if self.granted {
            // SAFETY: the CPU0 foreground still owns the stopped caller.
            unsafe { *addr_of_mut!(STATE.grant) = None };
        }
    }
}

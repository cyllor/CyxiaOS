//! Boot-qualified volatile FILE_SERVICE operations for the enrolled CPU3 task.
//! CPU0 stages the signed grant and immutable mounted view once. After CPU3
//! publication each borrow is serialized by the two stopped-role turns.
//!
//! The private IPC v3 work payload starts with the 44 B request prefix stamped
//! with its EL1 context ID. At byte 44 is the copied data length (LE32),
//! followed by inode, inode generation, ACL generation and service generation
//! (LE64 each), then the staged READ output or WRITE source. WRITE appends its
//! new volatile sequence (LE64) to the source bytes. Only enrolled role12
//! receives this work and can complete its admission.

use super::durable::{self, ACK_BYTES, ALLOC_BYTES, FSYNC_BYTES, QUERY_BYTES};
use super::{CPU, Error, Identity, StoppedStack, now_ns, startup_catalog};
use core::{
    mem::MaybeUninit,
    ptr::addr_of_mut,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use cyxia_arch_aarch64::timer;
use cyxia_kernel_core::{
    control_plane::control_rpc_v1::Error as IpcError,
    security::{
        Error as SecurityError,
        epoch_redo_v0199::EpochBlockIo,
        file_admission_flow_v1::FileAdmissionFlowV1,
        file_auth_context_v1::{
            AdmissionLedgerV1, AuthContextIssuerV1, AuthContextV1, AuthorityFacts, LedgerKey,
            RegisterOutcome,
        },
        file_auth_v3::{
            ADMIT_REQUEST_BYTES, AdmitReplyV3, AdmitRequestV3, COMPLETE_REQUEST_BYTES,
            CompleteRequestV1, FILE_SERVICE_ROLE, FILE_SERVICE_SLOT, StepThree, TerminalState,
            Verdict, operation_digest,
        },
        file_fsync_v1::FsyncAuthorization,
        file_index_v0199::SecurityStateStoreV2,
        file_media_unified_v1::CANONICAL_BUSINESS_START,
        file_media_v0199::{FileReceiptV4, INODE_START},
        file_mount_v1::{Acl, MountEvidence},
        file_receipt_query_v4::{ReceiptKey, ReceiptQueryCaller, encode_receipt_reply},
        file_service_v4::{REPLY_HEADER, REPLY_MAGIC, REPLY_VERSION, REQUEST_HEADER, Request},
        file_structure_v1::{BLOCK, INODE_BYTES, Inode},
        ipc_receive_v3::{DirectionalEndpoint, Endpoint, FRAME_BYTES, PAYLOAD_BYTES},
        offline_config_v1::VerifiedOfflineConfig,
        startup_catalog_v0199::{
            FILE_ALLOC_GROUP_PER_SECOND, FILE_FSYNC_TASK_PER_SECOND, FILE_RETIRE_GROUP_PER_SECOND,
            file_owner::FileClientGrant,
        },
        syscall::Syscall,
        syscall_v3::{ABI_VERSION, decode_aarch64_authorized_svc_v3, preflight_errno},
    },
};
use sha2::{Digest, Sha256};

use super::super::super::{E_AUTH, EFAULT};

const E_FORMAT: i64 = IpcError::Format as i64;
const EAGAIN: i64 = IpcError::Again as i64;
const E_STALE: i64 = -4;
const E_CONFLICT: i64 = -5;
const FILE_READ: u64 = 1 << 8;
const FILE_WRITE: u64 = 1 << 9;
const FILE_FSYNC: u64 = 1 << 13;
const READ: u16 = 3;
const WRITE: u16 = 4;
const FSYNC: u16 = 5;
const FILE_ALLOC: u16 = 10;
const FILE_QUERY_RESULT: u16 = 11;
const FILE_ACK_RESULT: u16 = 12;
const QUERY_VOLATILE: u16 = 14;
const ACK_VOLATILE: u16 = 15;
const WORK_TAG: u64 = 0xf201;
const ENDPOINT_TAG: u64 = 0xf210;
const CAP_TAG: u64 = 0xf211;
const READ_BYTES: usize = 256;
const IO_PREFIX: usize = REQUEST_HEADER + 12;
const INPUT_BYTES: usize = IO_PREFIX + READ_BYTES;
const REPLY_BYTES: usize = REPLY_HEADER + READ_BYTES;
const WORK_HEADER: usize = 80;
const _: () = assert!(WORK_HEADER + READ_BYTES + 8 <= PAYLOAD_BYTES);
const DURABLE_COMPLETION: &[u8; 8] = b"CYXFSYNC";

struct ReadView {
    grant: FileClientGrant,
    bytes: [u8; BLOCK],
    len: usize,
    home: u32,
    write_seq: u64,
    durable_write_seq: u64,
}

struct Job {
    context: AuthContextV1,
    frame: [u8; INPUT_BYTES],
    frame_len: usize,
    operation: u16,
    frozen: [u8; 32],
    request_id: u64,
    dispatch: u64,
    response: [u8; REPLY_BYTES],
    response_len: usize,
    delivered: bool,
    admission: Option<(u64, [u8; 32])>,
    durable_evidence: Option<[u8; 32]>,
    durable_error: Option<SecurityError>,
    receipt: Option<FileReceiptV4>,
    terminal_evidence: Option<[u8; 32]>,
}

struct ReadState {
    epoch: u64,
    owner: Identity,
    client: Option<StoppedStack>,
    view: ReadView,
    issuer: AuthContextIssuerV1,
    ledger: AdmissionLedgerV1,
    queue: Option<DirectionalEndpoint<1>>,
    work_credit: bool,
    fenced: bool,
    last_prepared: u64,
    dispatch_hi: u64,
    issue: Option<[u8; ALLOC_BYTES]>,
    ticket: Option<ReceiptKey>,
    query: Option<[u8; QUERY_BYTES]>,
    acknowledging: Option<[u8; ACK_BYTES]>,
    acknowledged: Option<([u8; ACK_BYTES], [u8; REPLY_HEADER])>,
    next_issue_ns: u64,
    next_fsync_ns: u64,
    next_retire_ns: u64,
    retired: Option<(u64, [u8; 32])>,
    job: Option<Job>,
}

static mut GRANT: Option<FileClientGrant> = None;
#[unsafe(link_section = ".bss.sec_n")]
static mut STATE: MaybeUninit<ReadState> = MaybeUninit::uninit();
static STAGED: AtomicBool = AtomicBool::new(false);
const _: () = assert!(core::mem::size_of::<ReadState>() <= 3 * BLOCK);

/// Lifetime peak EL1 PMU nanoseconds for client, IPC receive, ADMIT, COMPLETE.
/// These samples are a subset of existing CPU3 scheduler-charged turns.
#[unsafe(export_name = "V020_SIGNED_FILE_READ_CPU_NS")]
static COST_NS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
/// Fresh contexts, actual admissions, verified terminals and exact client ACKs.
#[unsafe(export_name = "V020_SIGNED_FILE_READ_CUSTODY")]
static CUSTODY: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
/// Latest receipt ID copied successfully by ALLOC, FSYNC, QUERY and ACK.
#[unsafe(export_name = "V020_G1_FILE_RUNTIME_RECEIPTS")]
#[used]
static DURABLE_COPIES: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

pub(in super::super) fn settled_custody() -> [u64; 4] {
    core::array::from_fn(|index| CUSTODY[index].load(Ordering::Relaxed))
}

fn measure(index: usize, started: u64) {
    COST_NS[index].fetch_max(timer::cpu_elapsed_ns(started), Ordering::Release);
}

pub(super) fn meter_auth(frame_bytes: u64, started: u64) {
    match frame_bytes as usize {
        ADMIT_REQUEST_BYTES => measure(2, started),
        COMPLETE_REQUEST_BYTES => measure(3, started),
        _ => {}
    }
}

pub(super) fn meter_work(started: u64) {
    measure(1, started);
}

pub(in super::super) fn qualify(
    config: &VerifiedOfflineConfig<'_>,
    business: [u8; 32],
    owner: [u8; 32],
) -> Result<(), Error> {
    if super::cpu::registered_slot() != Some(0) {
        return Err(Error::Denied);
    }
    let grant =
        startup_catalog::qualify_file_client(config, business, owner).map_err(|_| Error::Denied)?;
    // SAFETY: only the serial boot owner uses GRANT; it never crosses CPUs.
    unsafe { addr_of_mut!(GRANT).write(Some(grant)) };
    Ok(())
}

pub(in super::super::super) fn writable() -> bool {
    // Only CPU0 consults the authenticated grant during boot staging.
    super::cpu::registered_slot() == Some(0)
        && unsafe { addr_of_mut!(GRANT).read() }.is_some_and(|grant| grant.writable)
}

pub(in super::super::super) fn stage(
    disk: &mut impl EpochBlockIo,
    mounted: &MountEvidence,
    committed: &SecurityStateStoreV2,
    acl_home: u32,
    recovery_inode: Option<u32>,
) -> Result<(), SecurityError> {
    if super::cpu::registered_slot() != Some(0) {
        return Err(SecurityError::Unauthorized);
    }
    // SAFETY: only CPU0 reads the already authenticated boot grant.
    let grant = unsafe { addr_of_mut!(GRANT).read() }.ok_or(SecurityError::Unauthorized)?;
    let epoch = committed.last_boot_epoch;
    let generation = committed.service_generations[FILE_SERVICE_SLOT];
    if mounted.boot.fs_uuid != grant.fs_uuid
        || committed.fs_uuid != grant.fs_uuid
        || mounted.boot.boot_epoch.checked_add(1) != Some(epoch)
        || generation == 0
    {
        return Err(SecurityError::Stale);
    }
    let mut page = [0; BLOCK];
    let acl_bytes = 64;
    let offset = grant.inode as usize * acl_bytes;
    disk.read(acl_home + (offset / BLOCK) as u32, &mut page)?;
    let offset = offset % BLOCK;
    let acl = Acl::decode(&page[offset..offset + acl_bytes])?;
    if acl.inode_id != grant.inode
        || acl.state != 1
        || acl.principal != grant.principal
        || acl.inode_generation != grant.inode_generation
        || acl.acl_generation != grant.acl_generation
        || u64::from(acl.owner_rights) & FILE_READ == 0
    {
        return Err(SecurityError::Unauthorized);
    }
    if grant.writable
        && (mounted.snapshot.is_some()
            || !mounted.may_overwrite_in_place()
            || recovery_inode == Some(grant.inode)
            || u64::from(acl.owner_rights) & (FILE_WRITE | FILE_FSYNC) != (FILE_WRITE | FILE_FSYNC))
    {
        return Err(SecurityError::Unauthorized);
    }
    let offset = grant.inode as usize * INODE_BYTES;
    disk.read(INODE_START + (offset / BLOCK) as u32, &mut page)?;
    let offset = offset % BLOCK;
    let inode = Inode::decode(&page[offset..offset + INODE_BYTES])?;
    if inode.kind != 1
        || inode.generation != grant.inode_generation
        || inode.parent != acl.parent
        || inode.size > BLOCK as u64
        || grant.writable && inode.size == 0
    {
        return Err(SecurityError::Unauthorized);
    }
    page.fill(0);
    let len = inode.size as usize;
    if len != 0 {
        let run = inode.runs[0];
        if inode.extents != 1 || run.count != 1 || run.physical < CANONICAL_BUSINESS_START {
            return Err(SecurityError::Invalid);
        }
        disk.read(run.physical, &mut page)?;
        page[len..].fill(0);
    }
    let state = ReadState {
        epoch,
        owner: Identity {
            id: FILE_SERVICE_ROLE,
            generation,
        },
        client: None,
        view: ReadView {
            grant,
            bytes: page,
            len,
            home: inode.runs[0].physical,
            write_seq: inode.durable_write_seq,
            durable_write_seq: inode.durable_write_seq,
        },
        issuer: AuthContextIssuerV1::new(epoch)?,
        ledger: AdmissionLedgerV1::new(epoch)?,
        queue: None,
        work_credit: false,
        fenced: false,
        last_prepared: 0,
        dispatch_hi: 0,
        issue: None,
        ticket: None,
        query: None,
        acknowledging: None,
        acknowledged: None,
        next_issue_ns: 0,
        next_fsync_ns: 0,
        next_retire_ns: 0,
        retired: None,
        job: None,
    };
    // SAFETY: no business task has been published. The only subsequent
    // writer is B3 after the acquire of its signed business epoch.
    if STAGED.load(Ordering::Relaxed) {
        return Err(SecurityError::Conflict);
    }
    unsafe { (*addr_of_mut!(STATE)).write(state) };
    STAGED.store(true, Ordering::Release);
    Ok(())
}

fn selector(epoch: u64, tag: u64) -> Result<u64, Error> {
    Ok(epoch.checked_mul(1 << 16).ok_or(Error::Exhausted)? | tag)
}

pub(super) fn work_selector(epoch: u64) -> Result<u64, Error> {
    selector(epoch, WORK_TAG)
}

pub(in super::super) fn bootstrap(epoch: u64) -> Result<[u8; 24], Error> {
    let mut bytes = [0; 24];
    for (word, value) in bytes.chunks_exact_mut(8).zip([
        epoch,
        selector(epoch, ENDPOINT_TAG)?,
        selector(epoch, CAP_TAG)?,
    ]) {
        word.copy_from_slice(&value.to_le_bytes());
    }
    Ok(bytes)
}

pub(in super::super) fn bind_client(epoch: u64, stack: StoppedStack) -> Result<(), Error> {
    if super::cpu::registered_slot() != Some(0) {
        return Err(Error::Denied);
    }
    // SAFETY: binding runs on the same boot owner before business publication.
    if !STAGED.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let state = unsafe { (*addr_of_mut!(STATE)).assume_init_mut() };
    if state.epoch != epoch || state.client.is_some() || stack.actor.generation != epoch {
        return Err(Error::Denied);
    }
    state.queue = Some(
        DirectionalEndpoint::new(
            Endpoint {
                id: work_selector(epoch)?,
                generation: epoch,
                receiver: state.owner,
            },
            stack.actor,
        )
        .map_err(|_| Error::Denied)?,
    );
    state.client = Some(stack);
    Ok(())
}

pub(super) fn bind_owner(epoch: u64, owner: Identity) -> Result<(), Error> {
    if super::cpu::registered_slot() != Some(0) {
        return Err(Error::Denied);
    }
    // SAFETY: read after bind_client on CPU0, before publishing the roster.
    if !STAGED.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let state = unsafe { (*addr_of_mut!(STATE)).assume_init_ref() };
    if state.epoch != epoch || state.owner != owner || state.queue.is_none() {
        return Err(Error::Denied);
    }
    Ok(())
}

fn with_state<T>(
    epoch: u64,
    action: impl FnOnce(&mut ReadState) -> Result<T, i64>,
) -> Result<T, i64> {
    if super::cpu::registered_slot() != Some(CPU) || !super::super::is_live_epoch(epoch) {
        return Err(E_STALE);
    }
    // SAFETY: CPU3 alone reads or mutates after the business epoch publication.
    // No IRQ enters this path; both interacting EL0 actors share this core.
    if !STAGED.load(Ordering::Acquire) {
        return Err(E_STALE);
    }
    let state = unsafe { (*addr_of_mut!(STATE)).assume_init_mut() };
    if state.epoch != epoch || state.fenced {
        return Err(E_STALE);
    }
    action(state)
}

pub(super) fn fence(epoch: u64, generation: u64) {
    if super::cpu::registered_slot() == Some(CPU) && STAGED.load(Ordering::Acquire) {
        // SAFETY: the scheduler on CPU3 stopped this exact owner and keeps
        // admitted/UNKNOWN custody in place until the boot terminates.
        let state = unsafe { (*addr_of_mut!(STATE)).assume_init_mut() };
        if (state.epoch, state.owner.generation) == (epoch, generation) {
            state.fenced = true;
            if state.view.grant.writable {
                durable::fence();
            }
            state.ledger.close_gate();
            if let Some(queue) = &mut state.queue {
                queue.fence();
            }
        }
    }
}

pub(super) fn errno(error: SecurityError) -> i64 {
    match error {
        SecurityError::Unauthorized => E_AUTH,
        SecurityError::Stale => E_STALE,
        SecurityError::Conflict => E_CONFLICT,
        SecurityError::Invalid => E_FORMAT,
        _ => EAGAIN,
    }
}

pub(in super::super) fn client_syscall(
    epoch: u64,
    actor: Identity,
    context: &mut super::user::Context,
) -> bool {
    if super::cpu::registered_slot() != Some(CPU) || context.regs[8] != 0x50 {
        return false;
    }
    let started = timer::cpu_ticks();
    let result = with_state(epoch, |state| {
        let stack = state
            .client
            .filter(|stack| stack.actor == actor)
            .ok_or(E_AUTH)?;
        let endpoint = selector(epoch, ENDPOINT_TAG).map_err(|_| E_STALE)?;
        let call = decode_aarch64_authorized_svc_v3(
            ABI_VERSION,
            context.esr,
            &context.regs,
            |operation, first| operation == Syscall::ServiceCall && first == endpoint,
        )
        .map_err(preflight_errno)?;
        state.serve_client(stack, call.args)
    });
    measure(0, started);
    context.regs[0] = result.err().unwrap_or(0) as u64;
    true
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn next_rate_slot(earliest: u64, limit: u8) -> Result<u64, i64> {
    let now = now_ns();
    if now < earliest {
        return Err(EAGAIN);
    }
    now.checked_add(1_000_000_000 / u64::from(limit))
        .ok_or(E_STALE)
}

fn reply_header(id: u64, generation: u64, result: i32) -> [u8; REPLY_HEADER] {
    let mut reply = [0; REPLY_HEADER];
    reply[..4].copy_from_slice(&REPLY_MAGIC.to_le_bytes());
    reply[4..6].copy_from_slice(&REPLY_VERSION.to_le_bytes());
    reply[6..8].copy_from_slice(&(REPLY_HEADER as u16).to_le_bytes());
    reply[8..16].copy_from_slice(&id.to_le_bytes());
    reply[16..24].copy_from_slice(&generation.to_le_bytes());
    reply[28..32].copy_from_slice(&result.to_le_bytes());
    reply
}

impl ReadState {
    fn receipt_caller(&self) -> ReceiptQueryCaller {
        ReceiptQueryCaller {
            principal_id: self.view.grant.principal.id,
            boot_epoch: self.epoch,
            service_generation: self.owner.generation,
        }
    }

    fn serve_client(&mut self, stack: StoppedStack, args: [u64; 6]) -> Result<(), i64> {
        let [_, input, length, cap, output, reply] = args;
        if !(REQUEST_HEADER as u64..=INPUT_BYTES as u64).contains(&length) {
            return Err(E_FORMAT);
        }
        if !(REPLY_HEADER as u64..=REPLY_BYTES as u64).contains(&reply) {
            return Err(EFAULT);
        }
        stack.visit_stack(output, reply as usize, |_, _, _| Ok(()))?;
        let mut storage = [0; INPUT_BYTES];
        let frame = &mut storage[..length as usize];
        stack.copy_in(input, frame)?;
        let request = Request::decode(frame, cap).map_err(errno)?;
        match request.op {
            READ | WRITE | FSYNC => {
                if cap != selector(self.epoch, CAP_TAG).map_err(|_| E_STALE)? {
                    return Err(E_AUTH);
                }
                if request.op != READ && !self.view.grant.writable {
                    return Err(E_AUTH);
                }
                if let Some(job) = &self.job {
                    return self.replay(job, stack, output, reply as usize, request, frame);
                }
                if request.op == FSYNC {
                    return self.fsync(stack, request, frame);
                }
                self.start_volatile(stack, reply as usize, request, frame)
            }
            FILE_ALLOC if self.view.grant.writable => {
                self.allocate(stack, output, reply as usize, request, frame)
            }
            FILE_QUERY_RESULT if self.view.grant.writable => {
                self.query_result(stack, output, frame)
            }
            FILE_ACK_RESULT if self.view.grant.writable => self.ack_result(stack, output, frame),
            QUERY_VOLATILE | ACK_VOLATILE => {
                if word(request.payload, 0) != self.epoch
                    || word(request.payload, 8) != self.owner.generation
                {
                    return Err(E_STALE);
                }
                self.custody(stack, output, request)
            }
            _ => Err(E_AUTH),
        }
    }

    fn allocate(
        &mut self,
        stack: StoppedStack,
        output: u64,
        reply_cap: usize,
        request: Request<'_>,
        frame: &[u8],
    ) -> Result<(), i64> {
        if request.payload[0] != 0 || reply_cap < REPLY_HEADER + 56 {
            return Err(E_FORMAT);
        }
        if self.job.is_some() {
            return Err(EAGAIN);
        }
        if let Some(pending) = self.issue {
            if pending != frame {
                return Err(E_CONFLICT);
            }
            let result = durable::receive().ok_or(EAGAIN)?;
            self.issue = None;
            let durable::ResultBody::Ticket(key) = result.map_err(errno)? else {
                return Err(E_CONFLICT);
            };
            self.ticket = Some(key);
        }
        if let Some(key) = self.ticket {
            if key.request_seq != word(request.payload, 8) {
                return Err(EAGAIN);
            }
            let request_id = key.request_id().ok_or(E_CONFLICT)?;
            let mut reply = [0; REPLY_HEADER + 56];
            reply[..REPLY_HEADER].copy_from_slice(&reply_header(
                request_id,
                self.owner.generation,
                0,
            ));
            reply[24..26].copy_from_slice(&1u16.to_le_bytes());
            reply[36..40].copy_from_slice(&56u32.to_le_bytes());
            reply[112..120].copy_from_slice(&request_id.to_le_bytes());
            reply[REPLY_HEADER..].copy_from_slice(&key.encode());
            stack.copy_out(output, &reply)?;
            DURABLE_COPIES[0].store(request_id, Ordering::Release);
            return Ok(());
        }
        let frame: [u8; ALLOC_BYTES] = frame.try_into().map_err(|_| E_FORMAT)?;
        let next = next_rate_slot(self.next_issue_ns, FILE_ALLOC_GROUP_PER_SECOND)?;
        durable::send(durable::Command::Allocate {
            caller: self.receipt_caller(),
            frame,
            stream_ready: false,
        })
        .map_err(errno)?;
        self.issue = Some(frame);
        self.next_issue_ns = next;
        Err(EAGAIN)
    }

    fn query_result(&mut self, stack: StoppedStack, output: u64, frame: &[u8]) -> Result<(), i64> {
        if self.issue.is_some() || self.acknowledging.is_some() {
            return Err(EAGAIN);
        }
        let frame: [u8; QUERY_BYTES] = frame.try_into().map_err(|_| E_FORMAT)?;
        if let Some(job) = &self.job {
            if job.operation != FSYNC || job.terminal_evidence.is_none() {
                return Err(EAGAIN);
            }
        }
        if let Some(pending) = self.query {
            if pending != frame {
                return Err(E_CONFLICT);
            }
            let result = durable::receive().ok_or(EAGAIN)?;
            self.query = None;
            let durable::ResultBody::Query(reply) = result.map_err(errno)? else {
                return Err(E_CONFLICT);
            };
            stack.copy_out(output, &reply)?;
            DURABLE_COPIES[2].store(word(&reply, 8), Ordering::Release);
            return Ok(());
        }
        durable::send(durable::Command::Query {
            caller: self.receipt_caller(),
            frame,
        })
        .map_err(errno)?;
        self.query = Some(frame);
        Err(EAGAIN)
    }

    fn ack_result(&mut self, stack: StoppedStack, output: u64, frame: &[u8]) -> Result<(), i64> {
        let frame: [u8; ACK_BYTES] = frame.try_into().map_err(|_| E_FORMAT)?;
        if let Some((done, reply)) = &self.acknowledged {
            if word(done, 16) == word(&frame, 16) {
                if done != &frame {
                    return Err(E_CONFLICT);
                }
                return stack.copy_out(output, reply);
            }
        }
        if self.work_credit || self.query.is_some() {
            return Err(EAGAIN);
        }
        let job = self
            .job
            .as_ref()
            .filter(|job| job.operation == FSYNC)
            .ok_or(E_STALE)?;
        let receipt = job.receipt.ok_or(EAGAIN)?;
        let evidence = job.terminal_evidence.ok_or(EAGAIN)?;
        let key = self.ticket.ok_or(E_STALE)?;
        if frame[REQUEST_HEADER..QUERY_BYTES] != key.encode()
            || word(&frame, 16) != job.request_id
            || frame[QUERY_BYTES..] != receipt.output_digest
        {
            return Err(E_CONFLICT);
        }
        if let Some(pending) = self.acknowledging {
            if pending != frame {
                return Err(E_CONFLICT);
            }
            let result = durable::receive().ok_or(EAGAIN)?;
            self.acknowledging = None;
            if !matches!(result.map_err(errno)?, durable::ResultBody::Ack) {
                return Err(E_CONFLICT);
            }
            let (admission, _) = job.admission.ok_or(E_STALE)?;
            self.ledger
                .retire_terminal(
                    admission,
                    LedgerKey {
                        auth_context_id: job.context.auth_context_id,
                        request_seq: key.request_seq,
                    },
                    evidence,
                )
                .map_err(errno)?;
            let reply: [u8; REPLY_HEADER] = job.response[..REPLY_HEADER].try_into().unwrap();
            self.acknowledged = Some((frame, reply));
            self.job = None;
            self.ticket = None;
            CUSTODY[3].fetch_add(1, Ordering::Release);
            stack.copy_out(output, &reply)?;
            DURABLE_COPIES[3].store(word(&reply, 8), Ordering::Release);
            return Ok(());
        }
        let next = next_rate_slot(self.next_retire_ns, FILE_RETIRE_GROUP_PER_SECOND)?;
        durable::send(durable::Command::Ack {
            caller: self.receipt_caller(),
            frame,
            receipt,
            home: self.view.home,
        })
        .map_err(errno)?;
        self.acknowledging = Some(frame);
        self.next_retire_ns = next;
        Err(EAGAIN)
    }

    fn replay(
        &self,
        job: &Job,
        stack: StoppedStack,
        output: u64,
        reply_cap: usize,
        request: Request<'_>,
        frame: &[u8],
    ) -> Result<(), i64> {
        if job.request_id != request.request_id {
            return Err(if request.request_id < job.request_id {
                E_STALE
            } else {
                EAGAIN
            });
        }
        if job.frame[..job.frame_len] != *frame {
            return Err(E_CONFLICT);
        }
        if job.response_len > reply_cap {
            return Err(EFAULT);
        }
        if let Some(error) = job.durable_error {
            return Err(errno(error));
        }
        if job.terminal_evidence.is_none() {
            return Err(EAGAIN);
        }
        stack.copy_out(output, &job.response[..job.response_len])?;
        if job.operation == FSYNC {
            DURABLE_COPIES[1].store(job.request_id, Ordering::Release);
        }
        Ok(())
    }

    fn fsync(
        &mut self,
        stack: StoppedStack,
        request: Request<'_>,
        frame: &[u8],
    ) -> Result<(), i64> {
        let key = self.ticket.ok_or(E_STALE)?;
        let through = word(request.payload, 0);
        if key.request_id() != Some(request.request_id)
            || through != self.view.write_seq
            || through <= self.view.durable_write_seq
        {
            return Err(E_STALE);
        }
        if self.issue.is_some() || !durable::available() {
            return Err(EAGAIN);
        }
        let dispatch = self.dispatch_hi.checked_add(1).ok_or(E_STALE)?;
        let context = self
            .issuer
            .issue(self.view.grant.principal.id, self.owner.id)
            .map_err(errno)?;
        let frozen: [u8; 32] = Sha256::digest(self.view.bytes).into();
        let mut work = [0; WORK_HEADER + 32];
        work[..FSYNC_BYTES].copy_from_slice(frame);
        work[24..32].copy_from_slice(&context.auth_context_id.to_le_bytes());
        work[44..48].copy_from_slice(&32u32.to_le_bytes());
        self.work_target(&mut work);
        work[WORK_HEADER..].copy_from_slice(&frozen);
        self.queue
            .as_mut()
            .ok_or(E_STALE)?
            .send(stack.actor, self.epoch, dispatch, &work)
            .map_err(|error| error as i64)?;
        self.dispatch_hi = dispatch;
        let mut retained = [0; INPUT_BYTES];
        retained[..frame.len()].copy_from_slice(frame);
        self.job = Some(Job {
            context,
            frame: retained,
            frame_len: frame.len(),
            operation: FSYNC,
            frozen,
            request_id: request.request_id,
            dispatch,
            response: [0; REPLY_BYTES],
            response_len: REPLY_HEADER,
            delivered: false,
            admission: None,
            durable_evidence: None,
            durable_error: None,
            receipt: None,
            terminal_evidence: None,
        });
        CUSTODY[0].fetch_add(1, Ordering::Release);
        Err(EAGAIN)
    }

    fn work_target(&self, work: &mut [u8]) {
        work[48..56].copy_from_slice(&u64::from(self.view.grant.inode).to_le_bytes());
        work[56..64].copy_from_slice(&self.view.grant.inode_generation.to_le_bytes());
        work[64..72].copy_from_slice(&self.view.grant.acl_generation.to_le_bytes());
        work[72..80].copy_from_slice(&self.owner.generation.to_le_bytes());
    }

    fn start_volatile(
        &mut self,
        stack: StoppedStack,
        reply_cap: usize,
        request: Request<'_>,
        frame: &[u8],
    ) -> Result<(), i64> {
        let id = request.request_id;
        if self.retired.is_some_and(|(retired, _)| id <= retired) {
            return Err(E_STALE);
        }
        let dispatch = if self.view.grant.writable {
            self.dispatch_hi.checked_add(1).ok_or(E_STALE)?
        } else {
            id
        };
        let offset = word(request.payload, 0);
        let len = u32::from_le_bytes(request.payload[8..12].try_into().unwrap()) as usize;
        if len > READ_BYTES {
            return Err(E_FORMAT);
        }
        let (data, sequence, frozen) = if request.op == WRITE {
            // This grant permits overwrites of already allocated file bytes.
            if len == 0
                || offset
                    .checked_add(len as u64)
                    .is_none_or(|end| end > self.view.len as u64)
            {
                return Err(E_FORMAT);
            }
            let source = &request.payload[12..];
            let sequence = self.view.write_seq.checked_add(1).ok_or(E_STALE)?;
            (source, Some(sequence), Sha256::digest(source).into())
        } else {
            let offset = offset.min(self.view.len as u64) as usize;
            (
                &self.view.bytes[offset..offset + len.min(self.view.len - offset)],
                None,
                [0; 32],
            )
        };
        if sequence.is_none() && reply_cap < REPLY_HEADER + data.len() {
            return Err(EFAULT);
        }
        let context = self
            .issuer
            .issue(self.view.grant.principal.id, self.owner.id)
            .map_err(errno)?;
        let mut work = [0; WORK_HEADER + READ_BYTES + 8];
        work[..IO_PREFIX].copy_from_slice(&frame[..IO_PREFIX]);
        work[24..32].copy_from_slice(&context.auth_context_id.to_le_bytes());
        work[44..48].copy_from_slice(&(data.len() as u32).to_le_bytes());
        self.work_target(&mut work);
        work[WORK_HEADER..WORK_HEADER + data.len()].copy_from_slice(data);
        let mut work_len = WORK_HEADER + data.len();
        if let Some(sequence) = sequence {
            work[work_len..work_len + 8].copy_from_slice(&sequence.to_le_bytes());
            work_len += 8;
        }
        self.queue
            .as_mut()
            .ok_or(E_STALE)?
            .send(stack.actor, self.epoch, dispatch, &work[..work_len])
            .map_err(|error| error as i64)?;
        self.dispatch_hi = dispatch;
        let mut response = [0; REPLY_BYTES];
        response[..REPLY_HEADER].copy_from_slice(&reply_header(id, self.owner.generation, 0));
        response[72..80].copy_from_slice(&self.view.grant.inode_generation.to_le_bytes());
        let response_len = if let Some(sequence) = sequence {
            response[120..128].copy_from_slice(&sequence.to_le_bytes());
            REPLY_HEADER
        } else {
            response[36..40].copy_from_slice(&(data.len() as u32).to_le_bytes());
            let response_len = REPLY_HEADER + data.len();
            response[REPLY_HEADER..response_len].copy_from_slice(data);
            response_len
        };
        let digest = Sha256::digest(&response[..response_len]);
        response[80..112].copy_from_slice(&digest);
        let mut retained = [0; INPUT_BYTES];
        retained[..frame.len()].copy_from_slice(frame);
        self.job = Some(Job {
            context,
            frame: retained,
            frame_len: frame.len(),
            operation: request.op,
            frozen,
            request_id: id,
            dispatch,
            response,
            response_len,
            delivered: false,
            admission: None,
            durable_evidence: None,
            durable_error: None,
            receipt: None,
            terminal_evidence: None,
        });
        CUSTODY[0].fetch_add(1, Ordering::Release);
        Err(EAGAIN)
    }

    fn custody(
        &mut self,
        stack: StoppedStack,
        output: u64,
        request: Request<'_>,
    ) -> Result<(), i64> {
        let id = request.request_id;
        let supplied = &request.payload[24..];
        let mut reply = reply_header(id, self.owner.generation, 0);
        if request.op == ACK_VOLATILE && self.retired.is_some_and(|(old, _)| old == id) {
            let (_, digest) = self.retired.ok_or(E_STALE)?;
            if supplied != digest {
                return Err(E_CONFLICT);
            }
            reply[80..112].copy_from_slice(&digest);
            return stack.copy_out(output, &reply);
        }
        let job = self
            .job
            .as_ref()
            .filter(|job| job.request_id == id && job.operation != FSYNC)
            .ok_or(E_STALE)?;
        let Some(evidence) = job.terminal_evidence else {
            if request.op == ACK_VOLATILE {
                return Err(EAGAIN);
            }
            reply[28..32].copy_from_slice(&(E_STALE as i32).to_le_bytes());
            return stack.copy_out(output, &reply);
        };
        let digest: [u8; 32] = job.response[80..112].try_into().unwrap();
        reply[80..112].copy_from_slice(&digest);
        if request.op == QUERY_VOLATILE {
            return stack.copy_out(output, &reply);
        }
        if supplied != digest {
            return Err(E_CONFLICT);
        }
        if self.work_credit {
            return Err(EAGAIN);
        }
        let (id_admission, _) = job.admission.ok_or(E_STALE)?;
        let key = LedgerKey {
            auth_context_id: job.context.auth_context_id,
            request_seq: id,
        };
        stack.copy_out(output, &reply)?;
        self.ledger
            .retire_terminal(id_admission, key, evidence)
            .map_err(errno)?;
        self.retired = Some((id, digest));
        self.job = None;
        CUSTODY[3].fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn offer_durable_terminal(&mut self) -> Result<(), i64> {
        if self.work_credit {
            return Ok(());
        }
        let caller = self.receipt_caller();
        let Some(job) = self.job.as_mut().filter(|job| {
            job.operation == FSYNC && job.admission.is_some() && job.durable_evidence.is_none()
        }) else {
            return Ok(());
        };
        let Some(result) = durable::receive() else {
            return Ok(());
        };
        let (receipt, evidence) = match result {
            Ok(durable::ResultBody::Synced { receipt, evidence }) => (receipt, evidence),
            Ok(_) => return Err(E_CONFLICT),
            Err(error) => {
                job.durable_error = Some(error);
                return Err(errno(error));
            }
        };
        let key = self.ticket.ok_or(E_STALE)?;
        let (admission, operation) = job.admission.ok_or(E_STALE)?;
        if receipt.request_id != job.request_id
            || operation != receipt.operation_digest
            || receipt.write_seq != self.view.write_seq
            || receipt.issued_boot_epoch != caller.boot_epoch
            || receipt.owner_principal_id != caller.principal_id
            || receipt.fs_uuid != key.fs_uuid
            || receipt.group_id != key.group_id
            || receipt.group_generation != key.group_generation
            || receipt.stream_slot != key.stream_slot
            || receipt.stream_generation != key.stream_generation
            || receipt.request_seq != key.request_seq
        {
            job.durable_error = Some(SecurityError::Unknown);
            return Err(E_CONFLICT);
        }
        let wire = encode_receipt_reply(caller, receipt);
        let mut work = [0; 48 + REPLY_HEADER];
        work[..8].copy_from_slice(DURABLE_COMPLETION);
        work[8..16].copy_from_slice(&admission.to_le_bytes());
        work[16..48].copy_from_slice(&evidence);
        work[48..].copy_from_slice(&wire);
        let dispatch = self.dispatch_hi.checked_add(1).ok_or(E_STALE)?;
        let sender = self.client.ok_or(E_AUTH)?.actor;
        // Its earlier receive was acknowledged before taking the result.
        // Egress capacity therefore remains reserved for this terminal.
        self.queue
            .as_mut()
            .ok_or(E_STALE)?
            .send(sender, self.epoch, dispatch, &work)
            .map_err(|error| {
                job.durable_error = Some(SecurityError::Unknown);
                error as i64
            })?;
        self.dispatch_hi = dispatch;
        job.dispatch = dispatch;
        job.delivered = false;
        job.response[..REPLY_HEADER].copy_from_slice(&wire);
        job.durable_evidence = Some(evidence);
        job.receipt = Some(receipt);
        Ok(())
    }
}

pub(super) fn receive(epoch: u64, stack: StoppedStack, args: [u64; 6]) -> Result<i64, i64> {
    with_state(epoch, |state| {
        if stack.actor != state.owner {
            return Err(E_AUTH);
        }
        let [_, dest, len, _, flags, seq] = args;
        if flags == 1 && len as usize == FRAME_BYTES {
            state.offer_durable_terminal()?;
        }
        let queue = state.queue.as_mut().ok_or(E_STALE)?;
        let credit = &mut state.work_credit;
        if flags == 2 {
            queue
                .ack(stack.actor, epoch, seq, || {
                    if !*credit {
                        return Err(IpcError::Conflict);
                    }
                    *credit = false;
                    Ok(())
                })
                .map_err(|error| error as i64)?;
            return Ok(0);
        }
        if flags != 1 || len as usize != FRAME_BYTES {
            return Err(E_FORMAT);
        }
        stack.visit_stack(dest, FRAME_BYTES, |_, _, _| Ok(()))?;
        let ticket = queue
            .reserve_receive(
                stack.actor,
                epoch,
                seq,
                FRAME_BYTES,
                true,
                0,
                now_ns(),
                || {
                    if *credit {
                        return Err(IpcError::Capacity);
                    }
                    *credit = true;
                    Ok(())
                },
            )
            .map_err(|error| error as i64)?;
        let copied = stack.copy_out(dest, ticket.message().bytes()).is_ok();
        let len = queue
            .finish_copy(ticket, copied)
            .map_err(|error| error as i64)?;
        let job = state
            .job
            .as_mut()
            .filter(|job| job.dispatch == ticket.message().request_id())
            .ok_or(E_CONFLICT)?;
        job.delivered = true;
        Ok(len as i64)
    })
}

pub(super) fn admit(
    epoch: u64,
    actor: Identity,
    request: &AdmitRequestV3,
) -> Result<AdmitReplyV3, i64> {
    with_state(epoch, |state| {
        if actor != state.owner {
            return Err(E_AUTH);
        }
        let caller = state.receipt_caller();
        let job = state
            .job
            .as_mut()
            .filter(|job| {
                job.delivered
                    && job.context.auth_context_id == request.auth_context_id
                    && if job.operation == FSYNC {
                        state
                            .ticket
                            .is_some_and(|key| key.request_seq == request.request_seq)
                    } else {
                        job.request_id == request.request_seq
                    }
            })
            .ok_or(E_STALE)?;
        let digest =
            operation_digest(epoch, &job.frame[..job.frame_len], request).map_err(errno)?;
        if digest != request.operation_digest
            || job
                .admission
                .is_some_and(|(_, admitted)| admitted != digest)
        {
            return Err(E_CONFLICT);
        }
        let grant = state.view.grant;
        let required_rights = match job.operation {
            WRITE if grant.writable => FILE_WRITE,
            FSYNC if grant.writable => FILE_FSYNC,
            READ => FILE_READ,
            _ => return Err(E_AUTH),
        };
        let verdict = if request.target_id != u64::from(grant.inode)
            || request.required_rights != required_rights
            || request.frozen_data_digest != job.frozen
        {
            Verdict::Deny
        } else if request.target_generation != grant.inode_generation
            || request.acl_generation != grant.acl_generation
            || (job.admission.is_none() && request.prepared_version <= state.last_prepared)
        {
            Verdict::Stale
        } else {
            Verdict::Admitted
        };
        let facts = AuthorityFacts {
            current_generation: state
                .issuer
                .current_generation(grant.principal.id)
                .ok_or(E_STALE)?,
            verdict,
            deny_generation: grant.acl_generation,
            accepted_local_ns: now_ns(),
        };
        let outcome =
            if job.operation == FSYNC && job.admission.is_none() && verdict == Verdict::Admitted {
                if !durable::available() {
                    return Err(EAGAIN);
                }
                let next = next_rate_slot(state.next_fsync_ns, FILE_FSYNC_TASK_PER_SECOND)?;
                let key = state.ticket.ok_or(E_STALE)?;
                let cap = selector(epoch, CAP_TAG).map_err(|_| E_STALE)?;
                let frame: [u8; FSYNC_BYTES] = job.frame[..job.frame_len]
                    .try_into()
                    .map_err(|_| E_FORMAT)?;
                let mut flow = FileAdmissionFlowV1::freeze(
                    job.context,
                    &frame,
                    cap,
                    *request,
                    state.last_prepared,
                    &state.view.bytes,
                )
                .map_err(errno)?;
                if flow.request() != *request {
                    return Err(E_CONFLICT);
                }
                let outcome = flow.admit(&mut state.ledger, &facts).map_err(errno)?;
                if matches!(outcome, RegisterOutcome::Admitted { .. }) {
                    if flow
                        .execute(&mut state.ledger, request.prepared_version, true)
                        .map_err(errno)?
                        != StepThree::Execute
                    {
                        return Err(E_CONFLICT);
                    }
                    let authorization =
                        FsyncAuthorization::from_execution(&flow, &state.ledger).map_err(errno)?;
                    durable::send(durable::Command::Fsync(durable::Fsync {
                        caller,
                        key,
                        frame,
                        cap,
                        inode: grant.inode as u16,
                        home: state.view.home,
                        authorization,
                        page: state.view.bytes,
                        bound: false,
                    }))
                    .map_err(errno)?;
                    state.next_fsync_ns = next;
                }
                outcome
            } else {
                state
                    .ledger
                    .register(&job.context, request, &facts)
                    .map_err(errno)?
            };
        let mut reply = AdmitReplyV3 {
            auth_context_id: request.auth_context_id,
            verdict,
            deny_generation: grant.acl_generation,
            admission_id: 0,
            accepted_local_ns: 0,
        };
        match outcome {
            RegisterOutcome::NotAdmitted {
                verdict,
                deny_generation,
            } => {
                reply.verdict = verdict;
                reply.deny_generation = deny_generation;
            }
            RegisterOutcome::Admitted {
                admission_id,
                accepted_local_ns,
            }
            | RegisterOutcome::Replay {
                admission_id,
                accepted_local_ns,
            } => {
                if job.admission.is_none() {
                    state.last_prepared = request.prepared_version;
                    job.admission = Some((admission_id, digest));
                    CUSTODY[1].fetch_add(1, Ordering::Release);
                }
                reply.admission_id = admission_id;
                reply.accepted_local_ns = accepted_local_ns;
                reply.deny_generation = 0;
            }
        }
        Ok(reply)
    })
}

pub(super) fn complete(
    epoch: u64,
    actor: Identity,
    request: &CompleteRequestV1,
) -> Result<(), i64> {
    with_state(epoch, |state| {
        if actor != state.owner {
            return Err(E_AUTH);
        }
        let job = state.job.as_mut().ok_or(E_STALE)?;
        let (id, operation) = job
            .admission
            .filter(|(id, _)| *id == request.admission_id)
            .ok_or(E_STALE)?;
        if job.operation == FSYNC {
            if !job.delivered || job.durable_evidence.is_none() {
                return Err(EAGAIN);
            }
            if request.terminal_state != TerminalState::Done
                || job.durable_evidence != Some(request.evidence_digest)
            {
                return Err(E_CONFLICT);
            }
        } else if request.terminal_state != TerminalState::Unknown {
            let mut expected = Sha256::new();
            match job.operation {
                READ => expected.update(b"CYX/FILE-READ-EFFECT/v1"),
                WRITE => expected.update(b"CYX/FILE-WRITE-EFFECT/v1"),
                _ => return Err(E_CONFLICT),
            }
            for value in [epoch, actor.generation, id] {
                expected.update(value.to_le_bytes());
            }
            expected.update(operation);
            expected.update(&job.response[80..112]);
            let expected: [u8; 32] = expected.finalize().into();
            if request.terminal_state != TerminalState::Done || request.evidence_digest != expected
            {
                return Err(E_CONFLICT);
            }
        }
        state
            .ledger
            .complete(actor.id, false, request)
            .map_err(errno)?;
        if request.terminal_state == TerminalState::Done && job.terminal_evidence.is_none() {
            if job.operation == WRITE {
                let offset = word(&job.frame, REQUEST_HEADER) as usize;
                let bytes = &job.frame[IO_PREFIX..job.frame_len];
                state.view.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
                state.view.write_seq = word(&job.response, 120);
            } else if job.operation == FSYNC {
                state.view.durable_write_seq = word(&job.response, 120);
            }
            job.terminal_evidence = Some(request.evidence_digest);
            CUSTODY[2].fetch_add(1, Ordering::Release);
        }
        Ok(())
    })
}

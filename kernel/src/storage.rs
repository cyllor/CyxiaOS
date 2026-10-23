//! CPU0-owned bounded durable RAMFS checkpoints on a dedicated VirtIO disk.
//! No DMA points into the snapshot buffer; only the permanent queue is shared
//! with the device. Polling completes at most one sector per foreground turn.
use super::virtio_platform::Board;
use core::fmt::Write;
use cyxia_ai_fs::{FileSystem, checkpoint::MAX_BYTES};
use cyxia_ai_runtime::storage_policy::{self, Window};
use cyxia_contracts::{Generation, PageCount, RedemptionId, TaskId};
use cyxia_driver_virtio::{
    Error, Platform, QueueMemory, Transport,
    block::{Block, Operation},
    snapshot::{self, Commit, Header, SLOT_SECTORS, Step},
};
use cyxia_kernel_core::grants::{
    AuthorizedGrantRequest, BoundedGrantLedger, Owner, ReleaseReceipt,
};

const BUFFER_PAGES: u32 = 128;
const LEASE_PAGES: u32 = MAX_BYTES.div_ceil(4096) as u32;
const OWNER: Owner = Owner {
    task: match TaskId::new(0xfffffff0) {
        Ok(value) => value,
        Err(_) => panic!("storage owner"),
    },
    generation: match Generation::new(1) {
        Ok(value) => value,
        Err(_) => panic!("storage generation"),
    },
};
const _: () = assert!(MAX_BYTES <= snapshot::MAX_PAYLOAD && LEASE_PAGES < BUFFER_PAGES);
#[repr(C, align(4096))]
struct Buffer([u8; BUFFER_PAGES as usize * 4096]);
static mut BUFFER: Buffer = Buffer([0; BUFFER_PAGES as usize * 4096]);
static mut QUEUE: QueueMemory = QueueMemory::zeroed();
static mut SERVICE: Service = Service::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Absent,
    Header(usize),
    Choose,
    Payload(usize, usize),
    Ready,
    Commit,
    Failed,
}

struct Service {
    block: Option<Block>,
    phase: Phase,
    pending: bool,
    headers: [Option<Header>; 2],
    blank: [bool; 2],
    active: Option<(usize, Header)>,
    commit: Option<Commit>,
    ledger: BoundedGrantLedger<2>,
    lease: Option<RedemptionId>,
    grants: u64,
    allowance: Window,
    logged_quota: u8,
    checkpoint_started: u64,
    checkpoint_rejected: u64,
    memory_denied: u64,
    failures: u64,
    reads: u64,
    writes: u64,
    flushes: u64,
}
impl Service {
    const fn new() -> Self {
        Self {
            block: None,
            phase: Phase::Absent,
            pending: false,
            headers: [None; 2],
            blank: [false; 2],
            active: None,
            commit: None,
            ledger: BoundedGrantLedger::new(PageCount(BUFFER_PAGES)),
            lease: None,
            grants: 0,
            allowance: Window::new(),
            logged_quota: 0,
            checkpoint_started: 0,
            checkpoint_rejected: 0,
            memory_denied: 0,
            failures: 0,
            reads: 0,
            writes: 0,
            flushes: 0,
        }
    }
    fn acquire(&mut self, bootstrap: bool) -> Result<(), Error> {
        if self.lease.is_some() {
            return Err(Error::Busy);
        }
        let request = if bootstrap {
            // Recovery uses already-reserved pinned boot memory before any user
            // input. It does not re-admit or modify previously committed files.
            unsafe { AuthorizedGrantRequest::bootstrap(OWNER, PageCount(LEASE_PAGES)) }
        } else {
            let (admitted, model) =
                cyxia_ai_runtime::anonymous_memory_policy(self.ledger.snapshot().free, LEASE_PAGES)
                    .map_err(|_| Error::Features)?;
            if !admitted {
                self.memory_denied = self.memory_denied.saturating_add(1);
                return Err(Error::Busy);
            }
            // Authenticated local model, actual staging capacity, fixed owner.
            unsafe { AuthorizedGrantRequest::validated_ai(OWNER, PageCount(LEASE_PAGES), model) }
                .map_err(|_| Error::Features)?
        };
        self.lease = Some(
            self.ledger
                .commit_and_redeem(request)
                .map_err(|_| Error::Busy)?,
        );
        if !bootstrap {
            self.grants = self.grants.saturating_add(1);
        }
        Ok(())
    }
    fn release(&mut self, buffer: &mut [u8]) {
        if let Some(lease) = self.lease.take() {
            buffer[..LEASE_PAGES as usize * 4096].fill(0);
            // No users or DMA ever alias this CPU-owned staging buffer. Queue
            // request copies retain their separate pinned backing on failure.
            self.ledger
                .release_completed(unsafe {
                    ReleaseReceipt::after_revoke(lease, OWNER, PageCount(LEASE_PAGES))
                })
                .expect("owned checkpoint staging grant");
        }
    }
    fn fail(&mut self, buffer: &mut [u8], out: &mut impl Write, error: Error) {
        self.failures = self.failures.saturating_add(1);
        self.allowance.invalidate();
        self.phase = Phase::Failed;
        self.commit = None;
        self.release(buffer);
        let _ = writeln!(
            out,
            "STORAGE_ERROR {error:?} MECHANISM; disk retained; restart required\r"
        );
    }
    fn checkpoint(&mut self, fs: &FileSystem, buffer: &mut [u8], out: &mut impl Write) {
        if self.phase != Phase::Ready {
            self.checkpoint_rejected = self.checkpoint_rejected.saturating_add(1);
            let _ = writeln!(out, "STORAGE_CHECKPOINT_REJECT {:?}\r", self.phase);
            return;
        }
        if self.block.as_ref().is_none_or(Block::read_only) {
            self.checkpoint_rejected = self.checkpoint_rejected.saturating_add(1);
            let _ = writeln!(out, "STORAGE_CHECKPOINT_REJECT read-only or absent\r");
            return;
        }
        let result = (|| {
            self.acquire(false)?;
            let size = fs.write_snapshot(buffer).map_err(|_| Error::Response)?;
            let commit = Commit::new(self.active, &buffer[..size]).map_err(|_| Error::Exhausted)?;
            let _ = writeln!(
                out,
                "STORAGE_CHECKPOINT_BEGIN generation={} bytes={} memory_model=8194 pages={} io_model=20481 trigger=OPERATOR memory_source=AI_DIRECT budget_unit=new_operations_per_8ms\r",
                commit.header.generation, size, LEASE_PAGES
            );
            self.commit = Some(commit);
            self.phase = Phase::Commit;
            self.checkpoint_started = self.checkpoint_started.saturating_add(1);
            Ok::<(), Error>(())
        })();
        if let Err(error) = result {
            self.checkpoint_rejected = self.checkpoint_rejected.saturating_add(1);
            self.release(buffer);
            let _ = writeln!(out, "STORAGE_CHECKPOINT_REJECT {error:?}\r");
        }
    }
    fn step(
        &mut self,
        fs: &mut FileSystem,
        buffer: &mut [u8],
        out: &mut impl Write,
        runnable: usize,
    ) -> Result<(), Error> {
        if matches!(self.phase, Phase::Absent | Phase::Ready | Phase::Failed) {
            return Ok(());
        }
        let mut sector = [0; 512];
        if self.pending {
            let Some(operation) = self
                .block
                .as_mut()
                .ok_or(Error::Device)?
                .poll(&mut sector, &Board)?
            else {
                return Ok(());
            };
            self.pending = false;
            match operation {
                Operation::Read(_) => self.reads = self.reads.saturating_add(1),
                Operation::Write(_) => self.writes = self.writes.saturating_add(1),
                Operation::Flush => self.flushes = self.flushes.saturating_add(1),
            }
            match self.phase {
                Phase::Header(slot) => {
                    self.blank[slot] = sector.iter().all(|b| *b == 0);
                    self.headers[slot] = Header::decode(&sector)
                        .ok()
                        .filter(|h| h.length <= MAX_BYTES);
                    self.phase = if slot == 0 {
                        Phase::Header(1)
                    } else {
                        Phase::Choose
                    };
                }
                Phase::Payload(slot, offset) => {
                    let header = self.headers[slot].ok_or(Error::Response)?;
                    let n = (header.length - offset).min(512);
                    buffer[offset..offset + n].copy_from_slice(&sector[..n]);
                    if offset + n == header.length {
                        if header.verify(&buffer[..header.length]).is_ok()
                            && fs.restore_snapshot(&buffer[..header.length]).is_ok()
                        {
                            self.active = Some((slot, header));
                            self.phase = Phase::Ready;
                            self.release(buffer);
                            let _ = writeln!(
                                out,
                                "STORAGE_RECOVERED generation={} slot={} BOOTSTRAP\r",
                                header.generation, slot
                            );
                        } else {
                            self.headers[slot] = None;
                            self.phase = Phase::Choose;
                            let _ =
                                writeln!(out, "STORAGE_SNAPSHOT_INVALID slot={slot} MECHANISM\r");
                        }
                    } else {
                        self.phase = Phase::Payload(slot, offset + n);
                    }
                }
                Phase::Commit => {
                    let commit = self.commit.as_mut().ok_or(Error::Response)?;
                    let step = commit.step();
                    commit.complete(step).map_err(|_| Error::Response)?;
                    if commit.step() == Step::Done {
                        let current = (commit.slot, commit.header);
                        self.active = Some(current);
                        self.commit = None;
                        self.phase = Phase::Ready;
                        self.release(buffer);
                        let _ = writeln!(
                            out,
                            "STORAGE_DURABLE generation={} slot={} bytes={} flushes={} MECHANISM\r",
                            current.1.generation, current.0, current.1.length, self.flushes
                        );
                    }
                }
                _ => return Err(Error::Response),
            }
            return Ok(());
        }
        if self.phase == Phase::Choose {
            if let Some(slot) = snapshot::preferred(self.headers) {
                self.phase = Phase::Payload(slot, 0);
            } else if self.blank == [true, true] {
                self.phase = Phase::Ready;
                self.release(buffer);
                let _ = writeln!(
                    out,
                    "STORAGE_EMPTY BOOTSTRAP; explicit checkpoint required\r"
                );
                return Ok(());
            } else {
                return Err(Error::Response);
            }
        }
        let operation = match self.phase {
            Phase::Header(slot) => Operation::Read(slot as u64 * SLOT_SECTORS),
            Phase::Payload(slot, offset) => {
                Operation::Read(slot as u64 * SLOT_SECTORS + 1 + (offset / 512) as u64)
            }
            Phase::Commit => {
                // Only a NEW request consumes the model's finite I/O allowance.
                // In-flight completions above always progress, even when this
                // window is exhausted. Snapshot/CRC cost is a separate bounded
                // synchronous mechanism, not a claimed CPU-time budget.
                let ready = self
                    .allowance
                    .prepare(Board.now_ms(), runnable)
                    .map_err(|_| Error::Features)?;
                if !ready {
                    return Ok(());
                }
                let c = self.commit.as_ref().ok_or(Error::Response)?;
                match c.step() {
                    Step::Payload {
                        sector: destination,
                        offset,
                    } => {
                        let n = (c.header.length - offset).min(512);
                        sector[..n].copy_from_slice(&buffer[offset..offset + n]);
                        Operation::Write(destination)
                    }
                    Step::Header {
                        sector: destination,
                    } => {
                        sector = c.header.encode();
                        Operation::Write(destination)
                    }
                    Step::PayloadFlush | Step::HeaderFlush => Operation::Flush,
                    Step::Done => return Err(Error::Response),
                }
            }
            _ => return Ok(()),
        };
        self.block
            .as_mut()
            .ok_or(Error::Device)?
            .begin(operation, &sector, &Board)?;
        self.pending = true;
        if self.phase == Phase::Commit {
            // begin accepted the request; redeem exactly once. Completion on a
            // later poll does not spend another operation or consult the model.
            self.allowance.consume().map_err(|_| Error::Features)?;
            // UART output follows submission, so diagnostic transport cannot
            // consume a plan's short lifetime before the authorized action.
            let current = self.allowance.status();
            if self.logged_quota != current.quota {
                self.logged_quota = current.quota;
                let _ = writeln!(
                    out,
                    "STORAGE_BUDGET model={} plan={} runnable={} operations={} window_ms={} AI_DIRECT\r",
                    storage_policy::MODEL_ID,
                    current.decisions,
                    current.runnable,
                    current.quota,
                    storage_policy::WINDOW_MS
                );
            }
        }
        Ok(())
    }
}

pub fn init(info: &cyxia_contracts::BootInfo) {
    // Sole foreground boot owner. IRQ handlers never access this service.
    let service = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE) };
    for resource in &info.virtio[..info.virtio_count] {
        if resource.base.0 < 0x0a000000
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|e| e > 0x0a200000)
        {
            continue;
        }
        let Ok(transport) = (unsafe {
            Transport::attach(
                (super::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        }) else {
            continue;
        };
        if transport.device_id() != 2 {
            continue;
        }
        let memory = unsafe { &mut *core::ptr::addr_of_mut!(QUEUE) };
        match Block::attach(transport, memory, &Board) {
            Ok(block) if block.sectors() >= snapshot::REQUIRED_SECTORS => {
                service.block = Some(block);
                if service.acquire(true).is_ok() {
                    service.phase = Phase::Header(0);
                    super::log(b"STORAGE_READY VIRTIO_BLOCK FLUSH BOOTSTRAP\n");
                } else {
                    service.phase = Phase::Failed;
                }
            }
            _ => {
                service.phase = Phase::Failed;
                super::log(b"STORAGE_ATTACH_ERROR BOOTSTRAP\n");
            }
        }
        return;
    }
    super::log(b"STORAGE_UNAVAILABLE BOOTSTRAP\n");
}

pub fn recovering() -> bool {
    // CPU0 foreground only, shared read ends before poll mutates SERVICE.
    matches!(
        unsafe { &*core::ptr::addr_of!(SERVICE) }.phase,
        Phase::Header(_) | Phase::Choose | Phase::Payload(_, _)
    )
}

#[cfg(feature = "ported")]
struct Audit;
#[cfg(feature = "ported")]
impl Write for Audit {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        super::log(value.as_bytes());
        Ok(())
    }
}

/// The explicit guest save command uses the same AI-admitted checkpoint path
/// as the serial shell. Returning a generation acknowledges staging only.
#[cfg(feature = "ported")]
pub fn start_checkpoint(fs: &FileSystem) -> Result<u64, cyxia_posix::Errno> {
    use cyxia_posix::Errno;
    // SAFETY: the syscall runs only in CPU0 foreground; poll is not reentrant.
    let service = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE) };
    match service.phase {
        Phase::Absent => return Err(Errno::Nodev),
        Phase::Failed => return Err(Errno::Io),
        Phase::Ready => {}
        _ => return Err(Errno::Busy),
    }
    if service.block.as_ref().is_none_or(Block::read_only) {
        return Err(Errno::Rofs);
    }
    // SAFETY: CPU0 owns this pinned buffer and no DMA references it.
    let buffer = unsafe { &mut (*core::ptr::addr_of_mut!(BUFFER)).0 };
    service.checkpoint(fs, buffer, &mut Audit);
    service
        .commit
        .as_ref()
        .map(|commit| commit.header.generation)
        .ok_or(Errno::Io)
}

/// Only the successful second device FLUSH advances `active`. A caller must
/// observe this result before displaying a durable-save acknowledgement.
#[cfg(feature = "ported")]
pub fn checkpoint_complete(generation: u64) -> Result<u64, cyxia_posix::Errno> {
    use cyxia_posix::Errno;
    // SAFETY: CPU0 foreground serialized read, no mutable borrow escapes.
    let service = unsafe { &*core::ptr::addr_of!(SERVICE) };
    if generation == 0 {
        return Err(Errno::Inval);
    }
    if service.phase == Phase::Absent {
        return Err(Errno::Nodev);
    }
    if service.phase == Phase::Failed {
        return Err(Errno::Io);
    }
    let durable = service.active.map_or(0, |(_, header)| header.generation);
    if durable >= generation {
        return Ok(durable);
    }
    if service
        .commit
        .as_ref()
        .is_some_and(|commit| commit.header.generation == generation)
    {
        return Err(Errno::Again);
    }
    Err(Errno::Inval)
}

pub fn poll(shell: &mut cyxia_shell::Shell, out: &mut impl Write) {
    // CPU0 foreground owns all three mutable objects, no IRQ or DMA alias.
    let service = unsafe { &mut *core::ptr::addr_of_mut!(SERVICE) };
    let buffer = unsafe { &mut (*core::ptr::addr_of_mut!(BUFFER)).0 };
    match shell.take_storage_request() {
        Some(cyxia_shell::StorageRequest::Checkpoint) => {
            service.checkpoint(shell.fs_mut(), buffer, out)
        }
        Some(cyxia_shell::StorageRequest::Status) => {
            let _ = writeln!(
                out,
                "STORAGE_STATUS state={:?} generation={} free_pages={} ai_grants={} io_plan_decisions={} io_submitted={} deferred_polls={} reads={} writes={} flushes={} budget_unit=new_operations_per_8ms\r",
                service.phase,
                service.active.map_or(0, |(_, h)| h.generation),
                service.ledger.snapshot().free,
                service.grants,
                service.allowance.status().decisions,
                service.allowance.status().submitted,
                service.allowance.status().deferred_polls,
                service.reads,
                service.writes,
                service.flushes
            );
        }
        None => {}
    }
    let runnable = shell.runnable_work();
    if let Err(error) = service.step(shell.fs_mut(), buffer, out, runnable) {
        service.fail(buffer, out, error);
    }
}

/// Unified system audit entry. Static reservation/recovery and synchronous
/// snapshot serialization remain explicit mechanisms; no online storage trainer.
pub fn ai_status(out: &mut impl Write) {
    // SAFETY: CPU0 foreground read; no reference escapes this call.
    let service = unsafe { &*core::ptr::addr_of!(SERVICE) };
    let allowance = service.allowance.status();
    let _ = writeln!(
        out,
        "AI_DOMAIN name=storage state={:?} scope=checkpoint_memory_and_io_allowance memory_model=8194 io_model={} ai_direct={} ai_plan_steps={} denied={} deferred_polls={} operator_checkpoints={} checkpoint_rejected={} failures={} quota={} used={} runnable={} window_ms={} learning=none snapshot_cpu=bounded_mechanism recovery=BOOTSTRAP\r",
        service.phase,
        storage_policy::MODEL_ID,
        service.grants.saturating_add(allowance.decisions),
        allowance.submitted,
        service.memory_denied,
        allowance.deferred_polls,
        service.checkpoint_started,
        service.checkpoint_rejected,
        service.failures,
        allowance.quota,
        allowance.used,
        allowance.runnable,
        storage_policy::WINDOW_MS
    );
}

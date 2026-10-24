//! Unique CPU0 journal/device owner. Real completion releases DMA and credits.
use crate::virtio_platform::Board;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{
    Error, Platform, Transport,
    block::{BatchedBlock, Operation},
    queue::{BatchMemory, Token},
};
use cyxia_prototype::{
    boot::{BootIdentity, BootSession},
    domains::{
        Action, Error as DomainError, ObjectKey, PolicyStamp,
        io::{Admission, BytePermit, Class, Request, Scheduler, Submission, Ticket},
    },
    journal::{BlockDevice, Journal},
    storage::{BLOCK_SIZE, TOTAL_BLOCKS},
};
static CLAIMED: AtomicBool = AtomicBool::new(false);
static BORROWED: AtomicBool = AtomicBool::new(false);
static mut QUEUE: BatchMemory = BatchMemory::zeroed();
static mut DISK: Option<NativeDisk> = None;
static mut SCHEDULER: Scheduler = Scheduler::new(16, 16);
static mut JOURNAL: Journal = Journal::new();
static mut SCRATCH: [u8; 8192] = [0; 8192];
static mut WORK: [[u8; BLOCK_SIZE]; 4] = [[0; BLOCK_SIZE]; 4];
static FACTS: [AtomicU64; 38] = [const { AtomicU64::new(0) }; 38];
static mut IDENTITY: Option<BootIdentity> = None;
#[repr(C, align(4096))]
pub struct Evidence {
    words: [AtomicU64; 512],
}
#[used]
#[unsafe(no_mangle)]
pub static STORAGE_V13_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};
pub struct NativeDisk {
    device: BatchedBlock,
    scheduler: &'static mut Scheduler,
    object: ObjectKey,
    irq: u32,
    irq_enabled: bool,
    class: Class,
    recovery_from: Option<Class>,
    permit: Option<BytePermit>,
    background: Option<Admission>,
    first_admission: Option<Admission>,
    failed: bool,
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
    last_io_version: u64,
    errors: u64,
    window: u64,
    busy_ns: u64,
    busy_at: Option<u64>,
    doorbell_base: u64,
    latencies: [u64; 64],
}
fn driver_error(e: DomainError) -> Error {
    match e {
        DomainError::Busy | DomainError::Again | DomainError::Budget => Error::Busy,
        DomainError::Capacity => Error::Exhausted,
        _ => Error::Response,
    }
}
impl NativeDisk {
    fn publish(&mut self, now: u64) {
        self.meter(now);
        let u = self.scheduler.usage();
        let n = self.device.notify_stats();
        let total = self.latencies.iter().copied().sum::<u64>();
        let mut sum = 0;
        let mut p99 = 0;
        if total != 0 {
            for (i, c) in self.latencies.iter().enumerate() {
                sum += c;
                if u128::from(sum) * 100 >= u128::from(total) * 99 {
                    p99 = (1u64 << i).div_ceil(1000);
                    break;
                }
            }
        }
        let share = match self.scheduler.current_action(now) {
            Action::IoShare(v) => v,
            _ => 250,
        };
        let v = [
            self.object.id,
            self.object.generation,
            self.device.capacity() as u64,
            u64::from(self.irq),
            self.reads,
            self.writes,
            self.flushes,
            u64::from(u.queued),
            u64::from(u.inflight),
            u64::from(u.completed),
            u.foreground_bytes,
            u.background_bytes,
            u.recovery_bytes,
            u.borrowed_foreground_bytes,
            u.borrowed_background_bytes,
            self.last_io_version,
            u64::from(share),
            u64::from(self.device.current_batch(now)),
            n.published,
            n.completed,
            n.doorbells,
            u64::from(n.pending),
            u64::from(n.descriptors),
            n.last_completed_version,
            self.errors,
            p99,
            ((u128::from(
                self.busy_ns
                    .saturating_add(self.busy_at.map_or(0, |at| now.saturating_sub(at))),
            ) * 1000)
                / 100_000_000)
                .min(1000) as u64,
            self.scheduler.reserved_bytes(),
            now,
            u64::from(u.pages),
            u64::from(u.descriptors),
            u64::from(self.failed),
            n.pending_version,
            n.doorbells
                .saturating_sub(self.doorbell_base)
                .saturating_mul(10),
            self.background.map_or(0, |g| g.policy_version),
            self.background.map_or(0, |g| g.bytes),
            self.background.map_or(0, |g| u64::from(g.ticket.slot) + 1),
            self.scheduler.reserved_slots() as u64,
        ];
        for (i, value) in v.into_iter().enumerate() {
            FACTS[i].store(value, Ordering::Relaxed);
        }
        FACTS[28].store(now, Ordering::Release);
    }
    fn clock(&mut self, now: u64) {
        if now / 100_000_000 != self.window {
            self.window = now / 100_000_000;
            self.busy_ns = 0;
            if self.busy_at.is_some() {
                self.busy_at = Some(self.window * 100_000_000);
            }
            self.doorbell_base = self.device.notify_stats().doorbells;
            self.latencies.fill(0);
        }
    }
    fn meter(&mut self, now: u64) {
        self.clock(now);
        let active = self.device.notify_stats().inflight != 0;
        match (self.busy_at, active) {
            (None, true) => self.busy_at = Some(now),
            (Some(at), false) => {
                self.busy_ns = self.busy_ns.saturating_add(now.saturating_sub(at));
                self.busy_at = None;
            }
            _ => {}
        }
    }
    fn transaction(&mut self, bytes: u64, progress: &mut dyn FnMut()) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Device);
        }
        if self.class == Class::Recovery {
            return Ok(());
        }
        if self.permit.is_some() {
            return Err(Error::Busy);
        }
        if self.class == Class::Background
            && let Some(grant) = self.background
        {
            self.scheduler
                .begin_admission(grant, bytes)
                .map_err(driver_error)?;
            self.background = None;
            self.permit = Some(grant.permit);
            self.first_admission = Some(grant);
            self.publish(Board.now_ns());
            return Ok(());
        }
        let start = Board.now_ns();
        loop {
            let now = Board.now_ns();
            match self.scheduler.reserve_transaction(self.class, bytes, now) {
                Ok(p) => {
                    self.permit = Some(p);
                    self.publish(now);
                    return Ok(());
                }
                Err(DomainError::Budget | DomainError::Busy) => {
                    if now.saturating_sub(start) >= 250_000_000 {
                        return Err(Error::Busy);
                    }
                    progress();
                }
                Err(e) => return Err(driver_error(e)),
            }
        }
    }
    fn end_transaction(&mut self, success: bool) {
        if let Some(p) = self.permit {
            if success && self.scheduler.finish_transaction(p).is_ok() {
                self.permit = None;
            } else {
                self.failed = true;
            }
        }
        self.publish(Board.now_ns());
    }
    fn perform(
        &mut self,
        operations: &[Operation],
        input: &[[u8; 512]; 8],
        output: &mut [[u8; 512]; 8],
        progress: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Device);
        }
        let start = Board.now_ns();
        self.clock(start);
        let cap = if self.class == Class::Recovery {
            self.device.capacity()
        } else {
            self.device.capacity().saturating_sub(1)
        };
        let owned = self.scheduler.reserved_slots();
        let consumed_here =
            usize::from(self.first_admission.is_some() && self.class != Class::Recovery);
        let cap = cap.saturating_sub(owned.saturating_sub(consumed_here));
        if cap == 0 {
            return Err(Error::Exhausted);
        }
        let mut base = 0;
        while base < operations.len() {
            let count = cap.min(operations.len() - base);
            let mut tickets: [Option<Ticket>; 8] = [None; 8];
            let mut dma: [Option<Token>; 8] = [None; 8];
            let mut done = [false; 8];
            for (i, ticket) in tickets[..count].iter_mut().enumerate() {
                let req = Request {
                    object: self.object,
                    class: self.class,
                    bytes: if operations[base + i] == Operation::Flush {
                        0
                    } else {
                        512
                    },
                    pages: 2,
                    descriptors: 2,
                };
                *ticket = Some(if let Some(grant) = self.first_admission {
                    let ticket = self
                        .scheduler
                        .activate_admission(grant, req, Board.now_ns())
                        .map_err(driver_error)?;
                    self.first_admission = None;
                    ticket
                } else {
                    match self.permit {
                        Some(p) => self.scheduler.enqueue_transaction(req, p, Board.now_ns()),
                        None => self.scheduler.enqueue(req, Board.now_ns()),
                    }
                    .map_err(driver_error)?
                });
            }
            let mut remaining = count;
            while remaining != 0 {
                let now = Board.now_ns();
                self.clock(now);
                let mut failure = None;
                for _ in 0..count {
                    let device = &mut self.device;
                    let result = self.scheduler.dispatch(
                        now,
                        |t, _| tickets[..count].contains(&Some(t)),
                        |t, _| {
                            let i = tickets[..count].iter().position(|v| *v == Some(t)).unwrap();
                            match device.begin(
                                operations[base + i],
                                &input[base + i],
                                operations[base + i] == Operation::Flush,
                                count == 1,
                                &Board,
                            ) {
                                Ok(token) => {
                                    dma[i] = Some(token);
                                    Submission::Accepted
                                }
                                Err(Error::Busy) => Submission::Deferred,
                                Err(e) => {
                                    failure = Some(e);
                                    Submission::Unknown
                                }
                            }
                        },
                    );
                    if result.map_err(driver_error)?.is_none() {
                        break;
                    }
                    if failure.is_some() {
                        break;
                    }
                }
                if let Some(e) = failure {
                    self.failed = true;
                    self.errors = self.errors.saturating_add(1);
                    self.publish(now);
                    return Err(e);
                }
                self.device.drain(&Board)?;
                self.meter(Board.now_ns());
                for _ in 0..count {
                    let mut bytes = [0; 512];
                    match self.device.poll(&mut bytes, &Board) {
                        Ok(Some(c)) => {
                            let i = dma[..count]
                                .iter()
                                .position(|v| *v == Some(c.token))
                                .ok_or(Error::Response)?;
                            if done[i] || c.operation != operations[base + i] {
                                self.failed = true;
                                return Err(Error::Response);
                            }
                            output[base + i] = bytes;
                            let ticket = tickets[i].unwrap();
                            let finished = Board.now_ns();
                            self.scheduler
                                .complete(ticket, Ok(()), finished)
                                .map_err(driver_error)?;
                            self.device.acknowledge(c.token)?;
                            let receipt =
                                self.scheduler.acknowledge(ticket).map_err(driver_error)?;
                            if receipt.policy_version != 0 {
                                self.last_io_version =
                                    self.last_io_version.max(receipt.policy_version);
                            }
                            let bin = if receipt.latency_ns == 0 {
                                0
                            } else {
                                (64 - receipt.latency_ns.leading_zeros()).min(63) as usize
                            };
                            self.latencies[bin] = self.latencies[bin].saturating_add(1);
                            done[i] = true;
                            remaining -= 1;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            self.failed = true;
                            self.errors = self.errors.saturating_add(1);
                            self.publish(Board.now_ns());
                            return Err(e);
                        }
                    }
                }
                #[cfg(feature = "unified-runtime")]
                if self.irq_enabled {
                    let _ = crate::domain_platform::device_polled(self.irq);
                }
                self.publish(Board.now_ns());
                if remaining != 0 {
                    progress();
                    core::hint::spin_loop();
                }
            }
            base += count;
            // Settle the caller's bounded CPU segment even when DMA completes
            // immediately. The callback may run other owners; our journal,
            // descriptor and file custody remain exclusive until return.
            progress();
        }
        self.publish(Board.now_ns());
        Ok(())
    }
    fn read(
        &mut self,
        block: u32,
        out: &mut [u8; BLOCK_SIZE],
        p: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        if block >= TOTAL_BLOCKS {
            return Err(Error::Address);
        }
        let ops =
            core::array::from_fn::<_, 8, _>(|i| Operation::Read(u64::from(block) * 8 + i as u64));
        let mut result = [[0; 512]; 8];
        self.perform(&ops, &[[0; 512]; 8], &mut result, p)?;
        for (i, b) in result.iter().enumerate() {
            out[i * 512..i * 512 + 512].copy_from_slice(b);
        }
        self.reads += 1;
        self.publish(Board.now_ns());
        Ok(())
    }
    fn write(
        &mut self,
        block: u32,
        data: &[u8; BLOCK_SIZE],
        p: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        if block >= TOTAL_BLOCKS {
            return Err(Error::Address);
        }
        let ops =
            core::array::from_fn::<_, 8, _>(|i| Operation::Write(u64::from(block) * 8 + i as u64));
        let mut input = [[0; 512]; 8];
        for (i, b) in input.iter_mut().enumerate() {
            b.copy_from_slice(&data[i * 512..i * 512 + 512]);
        }
        self.perform(&ops, &input, &mut [[0; 512]; 8], p)?;
        self.writes += 1;
        self.publish(Board.now_ns());
        Ok(())
    }
    fn barrier(&mut self, p: &mut dyn FnMut()) -> Result<(), Error> {
        self.perform(&[Operation::Flush], &[[0; 512]; 8], &mut [[0; 512]; 8], p)?;
        self.flushes += 1;
        self.publish(Board.now_ns());
        Ok(())
    }
    fn recovery_enter(&mut self) {
        if self.recovery_from.is_none() {
            self.recovery_from = Some(self.class);
            self.class = Class::Recovery;
        }
    }
    fn recovery_exit(&mut self) {
        if let Some(class) = self.recovery_from.take() {
            self.class = class;
        }
    }
}
impl BlockDevice for NativeDisk {
    type Error = Error;
    fn block_count(&self) -> u32 {
        (self.device.sectors() / 8) as u32
    }
    fn read_block(&mut self, b: u32, o: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.read(b, o, &mut || {})
    }
    fn write_block(&mut self, b: u32, d: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.write(b, d, &mut || {})
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.barrier(&mut || {})
    }
    fn recovery_enter(&mut self) {
        NativeDisk::recovery_enter(self)
    }
    fn recovery_exit(&mut self) {
        NativeDisk::recovery_exit(self)
    }
    fn transaction_begin(&mut self, b: u64) -> Result<(), Error> {
        self.transaction(b, &mut || {})
    }
    fn transaction_end(&mut self, s: bool) {
        self.end_transaction(s)
    }
}
fn attach(info: &BootInfo) -> NativeDisk {
    let mut selected = None;
    for resource in info
        .virtio
        .get(..info.virtio_count)
        .expect("DTB virtio count")
    {
        if resource.base.0 < 0x0a000000
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|end| end > 0x0a200000)
        {
            continue;
        }
        let Ok(t) = (unsafe {
            Transport::attach(
                (crate::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        }) else {
            continue;
        };
        if t.device_id() == 2 {
            assert!(selected.is_none(), "exactly one boot disk required");
            selected = Some((t, resource.base.0, resource.irq));
        }
    }
    let (t, base, irq) = selected.expect("512 MiB boot disk required");
    let device = BatchedBlock::attach(t, unsafe { &mut *core::ptr::addr_of_mut!(QUEUE) }, &Board)
        .expect("native block FLUSH support");
    assert_eq!(device.sectors(), u64::from(TOTAL_BLOCKS) * 8);
    assert!(!device.read_only());
    let scheduler = unsafe { &mut *core::ptr::addr_of_mut!(SCHEDULER) };
    scheduler
        .configure_capacity(device.capacity() as u32 * 2, device.capacity() as u32 * 2)
        .expect("pinned device pool");
    scheduler
        .recovery_reserve(2, 2)
        .expect("recovery descriptors");
    NativeDisk {
        device,
        scheduler,
        object: ObjectKey {
            id: base,
            generation: 1,
        },
        irq,
        irq_enabled: false,
        class: Class::Recovery,
        recovery_from: None,
        permit: None,
        background: None,
        first_admission: None,
        failed: false,
        reads: 0,
        writes: 0,
        flushes: 0,
        last_io_version: 0,
        errors: 0,
        window: Board.now_ns() / 100_000_000,
        busy_ns: 0,
        busy_at: None,
        doorbell_base: 0,
        latencies: [0; 64],
    }
}
pub fn boot(info: &BootInfo) -> BootIdentity {
    assert!(
        !CLAIMED.swap(true, Ordering::AcqRel),
        "boot epoch already attempted"
    );
    crate::log(b"STORAGE_V13_MOUNT_BEGIN\n");
    let start = Board.now_ms();
    let mut disk = attach(info);
    let (journal, scratch, work) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(JOURNAL),
            &mut *core::ptr::addr_of_mut!(SCRATCH),
            &mut *core::ptr::addr_of_mut!(WORK),
        )
    };
    let recovery = journal
        .mount(&mut disk, scratch)
        .expect("journal recovery; no automatic formatting");
    let identity = BootSession::new()
        .allocate(journal, &mut disk, scratch, work)
        .expect("durable BootEpoch required");
    disk.object.generation = identity.epoch;
    disk.publish(Board.now_ns());
    let words = [
        1,
        identity.epoch,
        u64::from_le_bytes(identity.filesystem[..8].try_into().unwrap()),
        u64::from_le_bytes(identity.filesystem[8..].try_into().unwrap()),
        recovery.committed_transactions as u64,
        recovery.replayed_blocks as u64,
        recovery.discarded_tail as u64,
        journal.last_commit_lsn(),
        journal.superblock().generation,
        journal.superblock().log_epoch,
        disk.reads,
        disk.writes,
        disk.flushes,
        Board.now_ms() - start,
    ];
    for (i, w) in words.into_iter().enumerate() {
        STORAGE_V13_EVIDENCE.words[i + 1].store(w, Ordering::Relaxed);
    }
    STORAGE_V13_EVIDENCE.words[0].store(0x43595853544f3133, Ordering::Release);
    unsafe {
        *core::ptr::addr_of_mut!(DISK) = Some(disk);
        *core::ptr::addr_of_mut!(IDENTITY) = Some(identity);
    }
    crate::log(b"STORAGE_V13_BOOT_DURABLE\n");
    identity
}
#[cfg(feature = "storage-v13-selftest")]
pub fn run(info: &BootInfo) -> ! {
    let _ = boot(info);
    crate::log(b"STORAGE_V13_READY\n");
    crate::halt()
}
fn acquire() -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    if !CLAIMED.load(Ordering::Acquire) {
        return Err(DomainError::NotReady);
    }
    BORROWED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|_| DomainError::Busy)
}
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}
pub fn try_with_journal<R>(
    f: impl FnOnce(&mut Journal, &mut NativeDisk, &mut [u8; 8192]) -> R,
) -> Result<R, DomainError> {
    acquire()?;
    let _guard = Guard;
    unsafe {
        let disk = (&mut *core::ptr::addr_of_mut!(DISK))
            .as_mut()
            .ok_or(DomainError::NotReady)?;
        Ok(f(
            &mut *core::ptr::addr_of_mut!(JOURNAL),
            disk,
            &mut *core::ptr::addr_of_mut!(SCRATCH),
        ))
    }
}
pub fn with_journal<R>(f: impl FnOnce(&mut Journal, &mut NativeDisk, &mut [u8; 8192]) -> R) -> R {
    try_with_journal(f).expect("serialized journal owner")
}
pub struct ProgressDisk<'a> {
    disk: &'a mut NativeDisk,
    progress: &'a mut dyn FnMut(),
}
impl BlockDevice for ProgressDisk<'_> {
    type Error = Error;
    fn block_count(&self) -> u32 {
        self.disk.block_count()
    }
    fn read_block(&mut self, b: u32, o: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.disk.read(b, o, self.progress)
    }
    fn write_block(&mut self, b: u32, d: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.disk.write(b, d, self.progress)
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.disk.barrier(self.progress)
    }
    fn recovery_enter(&mut self) {
        self.disk.recovery_enter()
    }
    fn recovery_exit(&mut self) {
        self.disk.recovery_exit()
    }
    fn transaction_begin(&mut self, b: u64) -> Result<(), Error> {
        self.disk.transaction(b, self.progress)
    }
    fn transaction_end(&mut self, s: bool) {
        self.disk.end_transaction(s)
    }
}
pub fn try_with_class<R>(
    class: Class,
    progress: &mut dyn FnMut(),
    f: impl FnOnce(&mut Journal, &mut ProgressDisk<'_>, &mut [u8; 8192]) -> R,
) -> Result<R, DomainError> {
    try_with_journal(|j, d, s| {
        let previous = d.class;
        d.class = class;
        let result = f(j, &mut ProgressDisk { disk: d, progress }, s);
        d.class = previous;
        result
    })
}
pub fn with_progress<R>(
    progress: &mut dyn FnMut(),
    f: impl FnOnce(&mut Journal, &mut ProgressDisk<'_>, &mut [u8; 8192]) -> R,
) -> R {
    try_with_class(Class::Recovery, progress, f).expect("serialized progress owner")
}
pub fn facts() -> [u64; 38] {
    core::array::from_fn(|i| FACTS[i].load(Ordering::Acquire))
}
pub fn identity() -> Option<BootIdentity> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return None;
    }
    unsafe { *core::ptr::addr_of!(IDENTITY) }
}
pub fn install_io(action: Action, stamp: PolicyStamp, now: u64) -> Result<(), DomainError> {
    try_with_journal(|_, d, _| {
        d.scheduler.validate_apply(action, stamp, now)?;
        if let Some(grant) = d.background {
            // A newer resource policy can retire only a never-started grant.
            // Already bound/unknown transactions keep the journal owner.
            d.scheduler.cancel_admission(grant)?;
            d.background = None;
        }
        d.scheduler.apply(action, stamp, now)?;
        d.publish(now);
        Ok(())
    })?
}
pub fn prepare_background(bytes: u64, expected_version: u64, now: u64) -> Result<u64, DomainError> {
    try_with_journal(|_, d, _| {
        if d.failed {
            return Err(DomainError::Io);
        }
        if let Some(grant) = d.background {
            if grant.policy_version == expected_version && grant.bytes == bytes {
                return Ok(grant.policy_version);
            }
            d.scheduler.cancel_admission(grant)?;
            d.background = None;
        }
        let grant = d.scheduler.reserve_admission(
            Request {
                object: d.object,
                class: Class::Background,
                bytes: 512,
                pages: 2,
                descriptors: 2,
            },
            bytes,
            expected_version,
            now,
        )?;
        d.background = Some(grant);
        d.last_io_version = d.last_io_version.max(grant.policy_version);
        d.publish(now);
        Ok(grant.policy_version)
    })?
}
pub fn cancel_background() -> Result<(), DomainError> {
    try_with_journal(|_, d, _| {
        if let Some(grant) = d.background {
            d.scheduler.cancel_admission(grant)?;
            d.background = None;
            d.publish(Board.now_ns());
        }
        Ok(())
    })?
}
pub fn current_io_action(now: u64) -> Result<Action, DomainError> {
    try_with_journal(|_, d, _| d.scheduler.current_action(now))
}
pub fn current_notify_batch(now: u64) -> Result<u8, DomainError> {
    try_with_journal(|_, d, _| d.device.current_batch(now))
}
pub fn install_notify(batch: u8, stamp: PolicyStamp, now: u64) -> Result<(), DomainError> {
    try_with_journal(|_, d, _| {
        d.device
            .set_notify_policy(batch, stamp.version, stamp.installed_until_ns, now)
            .map_err(|_| DomainError::Capacity)?;
        d.publish(now);
        Ok(())
    })?
}
#[cfg(feature = "unified-runtime")]
pub fn enable_block_interrupts() -> Result<(), DomainError> {
    try_with_journal(|_, d, _| {
        if d.irq == 0 {
            return Err(DomainError::NotReady);
        }
        d.device.set_completion_interrupts(true, &Board);
        crate::domain_platform::enable_device_irq(d.irq)?;
        d.irq_enabled = true;
        Ok(())
    })?
}

pub fn borrowed() -> bool {
    BORROWED.load(Ordering::Acquire)
}

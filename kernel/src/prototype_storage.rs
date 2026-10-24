//! CPU0-owned native journal/boot identity adapter. DMA pools stay pinned.
use crate::virtio_platform::Board;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{
    Error, Platform, QueueMemory, Transport,
    block::{Block, Operation},
};
use cyxia_prototype::{
    boot::{BootIdentity, BootSession},
    journal::{BlockDevice, Journal},
    storage::{BLOCK_SIZE, TOTAL_BLOCKS},
};

static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut QUEUE: QueueMemory = QueueMemory::zeroed();
static mut DISK: Option<NativeDisk> = None;
static mut JOURNAL: Journal = Journal::new();
static mut SCRATCH: [u8; 8192] = [0; 8192];
static mut WORK: [[u8; BLOCK_SIZE]; 4] = [[0; BLOCK_SIZE]; 4];

#[repr(C, align(4096))]
pub struct Evidence {
    words: [AtomicU64; 512],
}
#[used]
#[unsafe(no_mangle)]
pub static STORAGE_V13_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};

/// 4 KiB journal operations are eight completed VirtIO sectors. Torn sectors
/// are not made atomic here: journal CRC/digest/FLUSH recovery owns that rule.
pub struct NativeDisk {
    device: Block,
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
}
impl NativeDisk {
    fn transfer(&mut self, op: Operation, bytes: &mut [u8; 512]) -> Result<(), Error> {
        self.device.begin(op, bytes, &Board)?;
        loop {
            if let Some(completed) = self.device.poll(bytes, &Board)? {
                if completed != op {
                    return Err(Error::Response);
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }
    }
}
impl BlockDevice for NativeDisk {
    type Error = Error;
    fn block_count(&self) -> u32 {
        (self.device.sectors() / 8) as u32
    }
    fn read_block(&mut self, block: u32, out: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        if block >= TOTAL_BLOCKS {
            return Err(Error::Address);
        }
        for (index, part) in out.chunks_exact_mut(512).enumerate() {
            self.transfer(
                Operation::Read(u64::from(block) * 8 + index as u64),
                part.try_into().unwrap(),
            )?;
        }
        self.reads += 1;
        Ok(())
    }
    fn write_block(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        if block >= TOTAL_BLOCKS {
            return Err(Error::Address);
        }
        for (index, part) in data.chunks_exact(512).enumerate() {
            let mut bytes = [0; 512];
            bytes.copy_from_slice(part);
            self.transfer(
                Operation::Write(u64::from(block) * 8 + index as u64),
                &mut bytes,
            )?;
        }
        self.writes += 1;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.transfer(Operation::Flush, &mut [0; 512])?;
        self.flushes += 1;
        Ok(())
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
        // SAFETY: boot CPU uniquely probes MMIO in the mapped DTB device range.
        let Ok(transport) = (unsafe {
            Transport::attach(
                (crate::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        }) else {
            continue;
        };
        if transport.device_id() == 2 {
            assert!(selected.is_none(), "exactly one boot disk required");
            selected = Some(transport);
        }
    }
    // SAFETY: CLAIMED permits one CPU0 boot owner; IRQs/other CPUs never access
    // the statically pinned DMA pages and failures never reclaim these pages.
    let memory = unsafe { &mut *core::ptr::addr_of_mut!(QUEUE) };
    let device = Block::attach(
        selected.expect("512 MiB boot disk required"),
        memory,
        &Board,
    )
    .expect("native block attach/FLUSH support");
    assert_eq!(
        device.sectors(),
        u64::from(TOTAL_BLOCKS) * 8,
        "boot disk must be exactly 512 MiB"
    );
    assert!(!device.read_only(), "boot disk must be writable");
    NativeDisk {
        device,
        reads: 0,
        writes: 0,
        flushes: 0,
    }
}

/// Boot orchestrator only, before any AI request or network grant. A service
/// restart receives this immutable identity instead of calling this function.
pub fn boot(info: &BootInfo) -> BootIdentity {
    assert!(
        !CLAIMED.swap(true, Ordering::AcqRel),
        "boot epoch already attempted"
    );
    crate::log(b"STORAGE_V13_MOUNT_BEGIN\n");
    let start = Board.now_ms();
    let mut disk = attach(info);
    // SAFETY: CPU0 boot ownership is claimed once above; no references escape.
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
    for (index, word) in words.into_iter().enumerate() {
        STORAGE_V13_EVIDENCE.words[index + 1].store(word, Ordering::Relaxed);
    }
    STORAGE_V13_EVIDENCE.words[0].store(0x43595853544f3133, Ordering::Release);
    // Retain the unique DMA/device owner for the ongoing cluster broker.
    unsafe {
        *core::ptr::addr_of_mut!(DISK) = Some(disk);
    }
    crate::log(b"STORAGE_V13_BOOT_DURABLE\n");
    identity
}

#[cfg(feature = "storage-v13-selftest")]
pub fn run(info: &BootInfo) -> ! {
    let _identity = boot(info);
    // Deliberately no checkpoint: next boot must recover the committed counter
    // from the REDO log, not from a home block incidentally written at shutdown.
    crate::log(b"STORAGE_V13_READY\n");
    crate::halt()
}

/// Serialized CPU0 foreground journal access. No references escape and neither
/// interrupts nor model workers can invoke this broker. Errors leave the journal
/// poisoned; callers must never turn an unknown commit into a successful reply.
#[cfg(feature = "unified-runtime")]
pub fn with_journal<R>(f: impl FnOnce(&mut Journal, &mut NativeDisk, &mut [u8; 8192]) -> R) -> R {
    assert_eq!(cyxia_arch_aarch64::cpu::slot(), 0);
    assert!(CLAIMED.load(Ordering::Acquire));
    // SAFETY: CPU0-only non-reentrant foreground owner; no references escape f.
    unsafe {
        f(
            &mut *core::ptr::addr_of_mut!(JOURNAL),
            (&mut *core::ptr::addr_of_mut!(DISK))
                .as_mut()
                .expect("durable boot first"),
            &mut *core::ptr::addr_of_mut!(SCRATCH),
        )
    }
}

/// The disk mechanism advances the independent control/business coordinator
/// between actual sector completion polls. Journal code owns no scheduler lock.
#[cfg(feature = "unified-runtime")]
pub struct ProgressDisk<'a> {
    disk: &'a mut NativeDisk,
    progress: &'a mut dyn FnMut(),
}
#[cfg(feature = "unified-runtime")]
impl ProgressDisk<'_> {
    fn transfer(&mut self, op: Operation, bytes: &mut [u8; 512]) -> Result<(), Error> {
        self.disk.device.begin(op, bytes, &Board)?;
        loop {
            (self.progress)();
            if let Some(done) = self.disk.device.poll(bytes, &Board)? {
                return if done == op {
                    Ok(())
                } else {
                    Err(Error::Response)
                };
            }
            core::hint::spin_loop();
        }
    }
}
#[cfg(feature = "unified-runtime")]
impl BlockDevice for ProgressDisk<'_> {
    type Error = Error;
    fn block_count(&self) -> u32 {
        self.disk.block_count()
    }
    fn read_block(&mut self, block: u32, out: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        if block >= TOTAL_BLOCKS {
            return Err(Error::Address);
        }
        for (index, part) in out.chunks_exact_mut(512).enumerate() {
            self.transfer(
                Operation::Read(u64::from(block) * 8 + index as u64),
                part.try_into().unwrap(),
            )?;
        }
        self.disk.reads += 1;
        Ok(())
    }
    fn write_block(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        if block >= TOTAL_BLOCKS {
            return Err(Error::Address);
        }
        for (index, part) in data.chunks_exact(512).enumerate() {
            let mut bytes = [0; 512];
            bytes.copy_from_slice(part);
            self.transfer(
                Operation::Write(u64::from(block) * 8 + index as u64),
                &mut bytes,
            )?;
        }
        self.disk.writes += 1;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.transfer(Operation::Flush, &mut [0; 512])?;
        self.disk.flushes += 1;
        Ok(())
    }
}
#[cfg(feature = "unified-runtime")]
pub fn with_progress<R>(
    progress: &mut dyn FnMut(),
    f: impl FnOnce(&mut Journal, &mut ProgressDisk<'_>, &mut [u8; 8192]) -> R,
) -> R {
    with_journal(|journal, disk, scratch| f(journal, &mut ProgressDisk { disk, progress }, scratch))
}

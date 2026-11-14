//! A10's completed WRITE backpressure at an all-dirty cache boundary.
//! Uses the real filesystem, redo journal, dependency table and I/O credits;
//! this host seam creates no native acceptance or optional policy receipt.
#[allow(dead_code)]
#[path = "../../../kernel/src/runtime/control/domain_control/dependencies.rs"]
mod dependencies;

use cyxia_prototype::{
    boot::BootSession,
    domains::{
        Error, ObjectKey,
        filesystem::{FileSystem, OpenMode, cache_writeback_required},
        io::{COMPLETION_CREDITS, Class, Request, Scheduler, Submission, Ticket},
    },
    journal::{self, BlockDevice, Journal},
    policy::{ExecutionState, Prerequisite},
    storage::TOTAL_BLOCKS,
};
use dependencies::AdmissionView;
use std::collections::BTreeMap;

struct Disk {
    durable: BTreeMap<u32, Box<[u8; 4096]>>,
    pending: BTreeMap<u32, Box<[u8; 4096]>>,
    writes: u64,
    flushes: u64,
    io: Option<Scheduler>,
    completions: Vec<u64>,
}
impl Disk {
    fn new() -> Self {
        Self {
            durable: BTreeMap::new(),
            pending: BTreeMap::new(),
            writes: 0,
            flushes: 0,
            io: None,
            completions: Vec::new(),
        }
    }
    fn request(&mut self, bytes: u32) -> Result<(), Error> {
        let Some(io) = self.io.as_mut() else {
            return Ok(());
        };
        let request = recovery_request(bytes);
        let ticket = io.enqueue(request, 0)?;
        assert_eq!(
            io.dispatch(0, |_, _| true, |_, _| Submission::Accepted)?,
            Some(ticket)
        );
        io.complete(ticket, Ok(()), 0)?;
        self.completions
            .push(io.acknowledge(ticket)?.policy_version);
        Ok(())
    }
}
fn recovery_request(bytes: u32) -> Request {
    Request {
        object: ObjectKey {
            id: 1,
            generation: 1,
        },
        class: Class::Recovery,
        bytes,
        pages: u32::from(bytes != 0),
        descriptors: 1,
    }
}
impl BlockDevice for Disk {
    type Error = Error;
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, block: u32, output: &mut [u8; 4096]) -> Result<(), Error> {
        self.request(4096)?;
        if let Some(page) = self
            .pending
            .get(&block)
            .or_else(|| self.durable.get(&block))
        {
            output.copy_from_slice(page.as_ref());
        } else {
            output.fill(0);
        }
        Ok(())
    }
    fn write_block(&mut self, block: u32, bytes: &[u8; 4096]) -> Result<(), Error> {
        self.request(4096)?;
        self.writes += 1;
        self.pending.insert(block, Box::new(*bytes));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.request(0)?;
        self.flushes += 1;
        self.durable.append(&mut self.pending);
        Ok(())
    }
}
fn fixture() -> (Disk, Journal) {
    let mut disk = Disk::new();
    let mut scratch = [0; 8192];
    journal::format(&mut disk, [7; 16], &mut scratch).unwrap();
    let mut journal = Journal::new();
    journal.mount(&mut disk, &mut scratch).unwrap();
    BootSession::new()
        .allocate(&mut journal, &mut disk, &mut scratch, &mut [[0; 4096]; 4])
        .unwrap();
    (disk, journal)
}
fn failed_memory() -> (AdmissionView, Prerequisite) {
    let view = AdmissionView::new();
    let prerequisite = Prerequisite {
        domain: 3,
        target: ObjectKey {
            id: 5_064_013,
            generation: 1,
        },
    };
    // Actual C4 terminal D03 intent. Expiry does not forgive a failed intent.
    view.publish(
        0,
        prerequisite,
        1431,
        52_513_494_992,
        ExecutionState::Failed(Error::Stale),
    );
    assert_eq!(
        view.admit(prerequisite, 4, 313_412_788_992),
        Err(Error::Conflict)
    );
    (view, prerequisite)
}
fn full_dirty_continues(budget: usize) {
    let (mut disk, mut journal) = fixture();
    let mut scratch = [0; 8192];
    let mut fs = FileSystem::<512>::new();
    fs.mount(&mut journal, &mut disk, &mut scratch).unwrap();
    fs.set_cache_partition(budget, 16).unwrap();
    fs.create("/pressure", &mut journal, &mut disk, &mut scratch)
        .unwrap();
    let handle = fs
        .open(
            "/pressure",
            OpenMode::ReadWrite,
            &mut journal,
            &mut disk,
            &mut scratch,
        )
        .unwrap();
    for chunk in 0..budget / 16 {
        assert_eq!(
            fs.write(
                handle,
                (chunk * 65536) as u64,
                &[chunk as u8; 65536],
                &mut journal,
                &mut disk,
                &mut scratch
            ),
            Ok(65536)
        );
    }
    assert_eq!(fs.cache_usage(), [budget, budget, budget, 512]);
    let next = (budget * 4096) as u64;
    assert_eq!(
        fs.write(
            handle,
            next,
            &[0xab; 65536],
            &mut journal,
            &mut disk,
            &mut scratch
        ),
        Err(Error::Again)
    );
    let (view, memory) = failed_memory();
    let before = (journal.last_commit_lsn(), disk.writes, disk.flushes);
    disk.io = Some(Scheduler::new(64, 64));
    let receipt = fs
        .reclaim_flush_one(&mut journal, &mut disk, &mut scratch)
        .unwrap()
        .expect("already accepted all-dirty pages at the exact cache quota must drain");
    assert_eq!((receipt.pages, receipt.policy_version), (32, 0));
    assert_eq!(fs.cache_usage(), [budget, budget - 32, budget, 512]);
    assert!(
        journal.last_commit_lsn() > before.0 && disk.writes > before.1 && disk.flushes > before.2
    );
    assert!(disk.pending.is_empty());
    assert!(!disk.completions.is_empty() && disk.completions.iter().all(|&version| version == 0));
    assert_eq!(fs.metrics().last_flush_version, 0);
    assert_eq!(view.admit(memory, 4, u64::MAX), Err(Error::Conflict));
    // Recheck at the actual owner: the earlier full-dirty observation cannot
    // authorize another necessary flush after clean replacements now exist.
    let after_commit = (journal.last_commit_lsn(), disk.writes, disk.flushes);
    assert!(!cache_writeback_required(
        budget as u64,
        (budget - 32) as u64,
        budget as u64
    ));
    assert_eq!(
        fs.reclaim_flush_one(&mut journal, &mut disk, &mut scratch),
        Ok(None)
    );
    assert_eq!(
        (journal.last_commit_lsn(), disk.writes, disk.flushes),
        after_commit
    );
    assert_eq!(
        fs.write(
            handle,
            next,
            &[0xab; 65536],
            &mut journal,
            &mut disk,
            &mut scratch
        ),
        Ok(65536)
    );
    assert_eq!(fs.cache_usage()[2], budget);
    let mut actual = [0; 65536];
    assert_eq!(
        fs.read(
            handle,
            next,
            &mut actual,
            0,
            &mut journal,
            &mut disk,
            &mut scratch
        ),
        Ok(65536)
    );
    assert_eq!(actual, [0xab; 65536]);
}
fn large(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(body)
        .unwrap()
        .join()
        .unwrap();
}
#[test]
fn actual_192_page_baseline_drains_full_dirty_cache_despite_failed_optional_dependency() {
    large(|| full_dirty_continues(192));
}
#[test]
fn thirty_third_64k_write_continues_at_512_pages_without_renewing_any_policy() {
    large(|| full_dirty_continues(512));
}

#[test]
fn required_writeback_does_not_bypass_exhausted_real_completion_credits() {
    large(|| {
        let (mut disk, mut journal) = fixture();
        let mut scratch = [0; 8192];
        let mut fs = FileSystem::<512>::new();
        fs.mount(&mut journal, &mut disk, &mut scratch).unwrap();
        fs.set_cache_partition(16, 16).unwrap();
        fs.create("/credits", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        let handle = fs
            .open(
                "/credits",
                OpenMode::ReadWrite,
                &mut journal,
                &mut disk,
                &mut scratch,
            )
            .unwrap();
        fs.write(
            handle,
            0,
            &[0x6a; 65536],
            &mut journal,
            &mut disk,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(fs.cache_usage(), [16, 16, 16, 512]);
        let mut io = Scheduler::new(64, 64);
        let held: Vec<Ticket> = (0..COMPLETION_CREDITS)
            .map(|_| io.enqueue(recovery_request(0), 0).unwrap())
            .collect();
        assert_eq!(io.usage().recovery_credits, COMPLETION_CREDITS);
        assert_eq!(io.enqueue(recovery_request(4096), 0), Err(Error::Again));
        disk.io = Some(io);
        let before = (journal.last_commit_lsn(), disk.writes, disk.flushes);
        assert_eq!(
            fs.reclaim_flush_one(&mut journal, &mut disk, &mut scratch),
            Err(Error::Io)
        );
        assert_eq!(fs.cache_usage(), [16, 16, 16, 512]);
        assert_eq!(
            (journal.last_commit_lsn(), disk.writes, disk.flushes),
            before
        );
        assert_eq!(fs.metrics().last_flush_version, 0);
        assert!(disk.completions.is_empty());
        let io = disk.io.as_mut().unwrap();
        for ticket in held {
            io.cancel(ticket).unwrap();
        }
        let available = io.enqueue(recovery_request(4096), 0).unwrap();
        io.cancel(available).unwrap();
        // The adapter's definite refusal was surfaced as I/O error. Existing
        // journal poisoning remains authoritative even after credits reopen;
        // do not invent a retry success or erase the retained dirty pages.
        assert_eq!(
            fs.reclaim_flush_one(&mut journal, &mut disk, &mut scratch),
            Err(Error::Io)
        );
        assert_eq!(fs.cache_usage(), [16, 16, 16, 512]);
        assert_eq!(
            (journal.last_commit_lsn(), disk.writes, disk.flushes),
            before
        );
    });
}

#[test]
fn clean_replacements_and_unused_quota_keep_the_optional_gate() {
    assert!(!cache_writeback_required(0, 0, 0));
    assert!(!cache_writeback_required(192, 0, 192));
    assert!(!cache_writeback_required(192, 191, 192));
    assert!(!cache_writeback_required(191, 191, 192));
    assert!(cache_writeback_required(192, 192, 192));
    assert!(cache_writeback_required(513, 1, 512));
    assert!(!cache_writeback_required(513, 0, 512));
    let (view, memory) = failed_memory();
    assert_eq!(view.admit(memory, 4, u64::MAX), Err(Error::Conflict));
}

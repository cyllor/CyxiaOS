//! A01 component fault matrix. This is not native boot/SAFE_EXEC acceptance.
use cyxia_prototype::{
    boot::{BootSession, Error as BootError},
    journal::{self, BlockDevice, Journal},
    storage::{BLOCK_SIZE, TOTAL_BLOCKS},
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Write(u32),
    Flush,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Before,
    CompletionLost,
}
#[derive(Clone, Default)]
struct Disk {
    durable: BTreeMap<u32, Box<[u8; BLOCK_SIZE]>>,
    pending: BTreeMap<u32, Box<[u8; BLOCK_SIZE]>>,
    operations: Vec<Operation>,
    fault: Option<(usize, Failure)>,
    hits: usize,
}
impl Disk {
    fn record(&mut self, operation: Operation) -> Option<Failure> {
        self.operations.push(operation);
        let (at, failure) = self.fault?;
        if self.operations.len() == at {
            self.hits += 1;
            Some(failure)
        } else {
            None
        }
    }
    fn crash(&mut self) {
        self.pending.clear();
        self.fault = None;
        self.operations.clear();
    }
}
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, block: u32, bytes: &mut [u8; BLOCK_SIZE]) -> Result<(), ()> {
        if let Some(stored) = self
            .pending
            .get(&block)
            .or_else(|| self.durable.get(&block))
        {
            bytes.copy_from_slice(stored.as_ref());
        } else {
            bytes.fill(0);
        }
        Ok(())
    }
    fn write_block(&mut self, block: u32, bytes: &[u8; BLOCK_SIZE]) -> Result<(), ()> {
        let fault = self.record(Operation::Write(block));
        if fault == Some(Failure::Before) {
            return Err(());
        }
        self.pending.insert(block, Box::new(*bytes));
        if fault == Some(Failure::CompletionLost) {
            return Err(());
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        let fault = self.record(Operation::Flush);
        if fault == Some(Failure::Before) {
            return Err(());
        }
        self.durable.append(&mut self.pending);
        if fault == Some(Failure::CompletionLost) {
            return Err(());
        }
        Ok(())
    }
}
fn allocate(
    session: &mut BootSession,
    journal: &mut Journal,
    disk: &mut Disk,
) -> Result<u64, BootError<()>> {
    session
        .allocate(journal, disk, &mut [0; 8192], &mut [[0; BLOCK_SIZE]; 4])
        .map(|identity| identity.epoch)
}
fn prepared(previous_epoch: u64) -> Disk {
    let mut disk = Disk::default();
    journal::format(&mut disk, [9; 16], &mut [0; 8192]).unwrap();
    let mut journal = Journal::new();
    journal.mount(&mut disk, &mut [0; 8192]).unwrap();
    for epoch in 1..=previous_epoch {
        assert_eq!(
            allocate(&mut BootSession::new(), &mut journal, &mut disk),
            Ok(epoch)
        );
    }
    journal.checkpoint(&mut disk, &mut [0; 8192]).unwrap();
    disk.crash();
    disk
}
fn mounted(disk: &mut Disk) -> Journal {
    let mut journal = Journal::new();
    journal.mount(disk, &mut [0; 8192]).unwrap();
    // The injection index refers only to this boot allocation, not recovery.
    disk.operations.clear();
    journal
}
fn exercise(previous_epoch: u64) {
    let original = prepared(previous_epoch);
    let mut healthy = original.clone();
    let mut journal = mounted(&mut healthy);
    assert_eq!(
        allocate(&mut BootSession::new(), &mut journal, &mut healthy),
        Ok(previous_epoch + 1)
    );
    let operations = healthy.operations;
    assert!(
        operations
            .iter()
            .any(|op| matches!(op, Operation::Write(_)))
    );
    assert_eq!(operations.len(), if previous_epoch == 0 { 12 } else { 8 });
    assert_eq!(
        operations
            .iter()
            .filter(|op| **op == Operation::Flush)
            .count(),
        2
    );
    assert_eq!(operations.last(), Some(&Operation::Flush));
    for at in 1..=operations.len() {
        for failure in [Failure::Before, Failure::CompletionLost] {
            let mut disk = original.clone();
            let mut journal = mounted(&mut disk);
            disk.fault = Some((at, failure));
            let mut owner = BootSession::new();
            assert!(
                allocate(&mut owner, &mut journal, &mut disk).is_err(),
                "at={at} {failure:?}"
            );
            assert_eq!(disk.hits, 1, "fault point must actually execute");
            assert_eq!(&disk.operations, &operations[..at]);
            assert!(!journal.is_writable(), "uncertain I/O must close writes");
            let durable = disk.durable.clone();
            let pending = disk.pending.clone();
            let attempts = disk.operations.len();
            disk.fault = None;
            assert_eq!(
                allocate(&mut owner, &mut journal, &mut disk),
                Err(BootError::AlreadyAttempted)
            );
            assert_eq!(
                disk.operations.len(),
                attempts,
                "same-boot retry issued I/O"
            );
            assert_eq!(disk.durable, durable);
            assert_eq!(disk.pending, pending);
            // Lost final FLUSH completion means the epoch committed even though
            // no identity was returned. A real new boot must skip that epoch.
            let committed = at == operations.len() && failure == Failure::CompletionLost;
            disk.crash();
            let mut recovered = mounted(&mut disk);
            let expected = previous_epoch + 1 + u64::from(committed);
            assert_eq!(
                allocate(&mut BootSession::new(), &mut recovered, &mut disk),
                Ok(expected)
            );
        }
    }
}
#[test]
fn fresh_boot_every_write_and_flush_failure_retains_unique_epoch() {
    exercise(0);
}
#[test]
fn subsequent_boot_every_write_and_flush_failure_retains_unique_epoch() {
    exercise(3);
}

//! Replace only the sector device and clock. The service, grant ledger, RAMFS,
//! CRC, commit protocol, recovery, and public checkpoint calls are production.
#![allow(dead_code)]
extern crate self as cyxia_driver_virtio;
use core::cell::RefCell;
pub use driver::{Error, QueueMemory, snapshot};
use std::rc::Rc;

pub trait Platform {
    fn now_ms(&self) -> u64;
}
mod virtio_platform {
    pub struct Board;
    impl super::Platform for Board {
        fn now_ms(&self) -> u64 {
            static CLOCK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
            CLOCK.fetch_add(8, core::sync::atomic::Ordering::Relaxed)
        }
    }
}

type Sector = [u8; 512];
#[derive(Default)]
struct Disk {
    sectors: Vec<Sector>,
    writes: usize,
    flushes: usize,
    fail_flush: Option<usize>,
}
#[derive(Clone)]
pub struct Transport(Rc<RefCell<Disk>>);
impl Transport {
    fn device_id(&self) -> usize {
        2
    }
    unsafe fn attach(_: usize, _: usize) -> Result<Self, Error> {
        Err(Error::Device)
    }
}
mod block {
    use super::*;
    pub use driver::block::Operation;
    pub struct Block {
        disk: Rc<RefCell<Disk>>,
        pending: Option<(Operation, Sector)>,
    }
    impl Block {
        pub fn attach(
            transport: Transport,
            _: &mut QueueMemory,
            _: &impl Platform,
        ) -> Result<Self, Error> {
            Ok(Self {
                disk: transport.0,
                pending: None,
            })
        }
        pub fn sectors(&self) -> u64 {
            self.disk.borrow().sectors.len() as u64
        }
        pub fn read_only(&self) -> bool {
            false
        }
        pub fn begin(
            &mut self,
            op: Operation,
            data: &Sector,
            _: &impl Platform,
        ) -> Result<(), Error> {
            assert!(self.pending.replace((op, *data)).is_none());
            Ok(())
        }
        pub fn poll(
            &mut self,
            data: &mut Sector,
            _: &impl Platform,
        ) -> Result<Option<Operation>, Error> {
            let (op, sector) = self.pending.take().unwrap();
            let mut disk = self.disk.borrow_mut();
            match op {
                Operation::Read(s) => *data = disk.sectors[s as usize],
                Operation::Write(s) => {
                    disk.sectors[s as usize] = sector;
                    disk.writes += 1;
                }
                Operation::Flush => {
                    if disk.fail_flush == Some(disk.flushes + 1) {
                        return Err(Error::Device);
                    }
                    disk.flushes += 1;
                }
            }
            Ok(Some(op))
        }
    }
}
const HIGH: u64 = 0;
fn log(_: &[u8]) {}
mod storage;

use cyxia_ai_fs::{FileSystem, Path};
use cyxia_posix::Errno;
use cyxia_shell::Shell;

fn boot(disk: &Rc<RefCell<Disk>>) -> Shell {
    storage::reboot();
    storage::init_transports([Transport(Rc::clone(disk))]);
    let mut shell = Shell::new();
    for _ in 0..100 {
        if !storage::recovering() {
            return shell;
        }
        storage::poll(&mut shell, &mut String::new());
    }
    panic!("recovery did not finish");
}
fn finish(shell: &mut Shell, generation: u64) -> Result<u64, Errno> {
    for _ in 0..100 {
        match storage::checkpoint_complete(generation) {
            Err(Errno::Again) => storage::poll(shell, &mut String::new()),
            result => return result,
        }
    }
    panic!("checkpoint did not finish");
}
fn blank_disk() -> Rc<RefCell<Disk>> {
    Rc::new(RefCell::new(Disk {
        sectors: vec![[0; 512]; snapshot::REQUIRED_SECTORS as usize],
        ..Disk::default()
    }))
}
fn expect_reuse(shell: &mut Shell, disk: &RefCell<Disk>, expected: u64) {
    let before = (disk.borrow().writes, disk.borrow().flushes);
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Ok(expected));
    assert_eq!(storage::checkpoint_complete(expected), Ok(expected));
    storage::poll(shell, &mut String::new());
    let mut out = String::new();
    for &byte in b"storage checkpoint\r" {
        shell.input(byte, &mut out).unwrap();
    }
    storage::poll(shell, &mut out);
    assert!(out.contains(&format!(
        "STORAGE_CHECKPOINT_UNCHANGED generation={expected} flushes="
    )));
    assert_eq!((disk.borrow().writes, disk.borrow().flushes), before);
}

#[test]
fn only_an_unchanged_durable_image_satisfies_a_caller() {
    let disk = blank_disk();
    let mut shell = boot(&disk);
    let path = Path::resolve(Path::ROOT, "/data").unwrap();
    // Even a pristine filesystem must write a first image on a blank disk.
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Ok(1));
    assert_eq!(storage::checkpoint_complete(1), Err(Errno::Again));
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Err(Errno::Busy));
    assert_eq!(finish(&mut shell, 1), Ok(1));
    assert_eq!((disk.borrow().writes, disk.borrow().flushes), (2, 2));
    expect_reuse(&mut shell, &disk, 1);

    shell.fs_mut().write(path, b"old", false).unwrap();
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Ok(2));
    shell.fs_mut().write(path, b"new", false).unwrap();
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Err(Errno::Busy));
    assert_eq!(finish(&mut shell, 2), Ok(2));
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Ok(3));
    assert_eq!(finish(&mut shell, 3), Ok(3));

    let mut shell = boot(&disk);
    let mut data = [0; 3];
    assert_eq!(shell.fs_mut().read(path, &mut data), Ok(3));
    assert_eq!(data, *b"new");
    expect_reuse(&mut shell, &disk, 3);

    shell.fs_mut().set_mode(path, 0o400).unwrap();
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Ok(4));
    let inode = shell.fs_mut().pin(path).unwrap();
    shell.fs_mut().set_inode_mode(inode, 0o600).unwrap();
    assert_eq!(finish(&mut shell, 4), Ok(4));
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Ok(5));
    assert_eq!(finish(&mut shell, 5), Ok(5));
    let mut shell = boot(&disk);
    assert_eq!(shell.fs_mut().stat(path).unwrap().mode, 0o600);
    expect_reuse(&mut shell, &disk, 5);
    // Equal revisions across different objects do not guarantee equal bytes.
    let mut unrelated = FileSystem::new();
    unrelated.write(path, b"xyz", false).unwrap();
    unrelated.write(path, b"xyz", false).unwrap();
    assert_eq!(
        unrelated.status().revision,
        shell.fs_mut().status().revision
    );
    assert_eq!(storage::start_checkpoint(&mut unrelated), Ok(6));
}

#[test]
fn a_failed_final_flush_never_acknowledges_the_staged_generation() {
    let disk = blank_disk();
    let mut shell = boot(&disk);
    disk.borrow_mut().fail_flush = Some(2);
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Ok(1));
    assert_eq!(finish(&mut shell, 1), Err(Errno::Io));
    assert_eq!(storage::start_checkpoint(shell.fs_mut()), Err(Errno::Io));
    assert_eq!(disk.borrow().flushes, 1);
}

#[test]
fn recovery_reuses_only_the_payload_that_passed_validation() {
    let disk = blank_disk();
    let mut shell = boot(&disk);
    let path = Path::resolve(Path::ROOT, "/file").unwrap();
    for (generation, contents) in [(1, b'a'), (2, b'b')] {
        shell.fs_mut().write(path, &[contents], false).unwrap();
        assert_eq!(storage::start_checkpoint(shell.fs_mut()), Ok(generation));
        assert_eq!(finish(&mut shell, generation), Ok(generation));
    }
    // Damage generation two's payload without disturbing its valid header.
    disk.borrow_mut().sectors[snapshot::SLOT_SECTORS as usize + 1][0] ^= 0xff;
    let mut shell = boot(&disk);
    let mut data = [0];
    assert_eq!(shell.fs_mut().read(path, &mut data), Ok(1));
    assert_eq!(data, *b"a");
    assert_eq!(storage::checkpoint_complete(2), Err(Errno::Inval));
    expect_reuse(&mut shell, &disk, 1);
}

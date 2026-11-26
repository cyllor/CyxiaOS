extern crate std;
use self::std::{boxed::Box, collections::BTreeMap, vec::Vec};
use super::*;
use crate::{
    journal::{self, AfterImage, BlockDevice, Journal, Scratch},
    storage::{self, BLOCK_SIZE, INODE_START, TOTAL_BLOCKS},
};

type Block = [u8; BLOCK_SIZE];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Cut,
}
#[derive(Clone, Copy)]
enum Cut {
    Before(usize),
    After(usize),
}
#[derive(Clone, Default)]
struct Disk {
    stable: BTreeMap<u32, Box<Block>>,
    pending: BTreeMap<u32, Option<Box<Block>>>,
    reads: usize,
    cpu_progress_calls: usize,
    operations: usize,
    cut: Option<Cut>,
    recovery_depth: usize,
    reject_ordinary: bool,
    reject_recovery: bool,
}
impl Disk {
    fn before(&mut self) -> Result<(), Fault> {
        self.operations += 1;
        if matches!(self.cut,Some(Cut::Before(n)) if n==self.operations) {
            Err(Fault::Cut)
        } else {
            Ok(())
        }
    }
    fn after(&self) -> Result<(), Fault> {
        if matches!(self.cut,Some(Cut::After(n)) if n==self.operations) {
            Err(Fault::Cut)
        } else {
            Ok(())
        }
    }
    fn crash(&mut self) {
        self.pending.clear();
        self.cut = None;
        self.operations = 0;
    }
}
impl BlockDevice for Disk {
    type Error = Fault;
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, b: u32, out: &mut Block) -> Result<(), Fault> {
        self.reads += 1;
        match self.pending.get(&b) {
            Some(Some(v)) => out.copy_from_slice(&v[..]),
            Some(None) => out.fill(0),
            None => match self.stable.get(&b) {
                Some(v) => out.copy_from_slice(&v[..]),
                None => out.fill(0),
            },
        }
        Ok(())
    }
    fn write_block(&mut self, b: u32, bytes: &Block) -> Result<(), Fault> {
        self.before()?;
        self.pending.insert(
            b,
            if bytes.iter().all(|v| *v == 0) {
                None
            } else {
                Some(Box::new(*bytes))
            },
        );
        self.after()
    }
    fn flush(&mut self) -> Result<(), Fault> {
        self.before()?;
        for (b, v) in core::mem::take(&mut self.pending) {
            if let Some(v) = v {
                self.stable.insert(b, v);
            } else {
                self.stable.remove(&b);
            }
        }
        self.after()
    }
    fn cpu_progress(&mut self) {
        self.cpu_progress_calls += 1;
    }
    fn recovery_enter(&mut self) {
        self.recovery_depth += 1;
        assert_eq!(self.recovery_depth, 1, "recovery hooks must not nest");
    }
    fn recovery_exit(&mut self) {
        assert_eq!(self.recovery_depth, 1);
        self.recovery_depth = 0;
    }
    fn transaction_begin(&mut self, _bytes: u64) -> Result<(), Fault> {
        if (self.reject_ordinary && self.recovery_depth == 0)
            || (self.reject_recovery && self.recovery_depth != 0)
        {
            Err(Fault::Cut)
        } else {
            Ok(())
        }
    }
}
struct Harness {
    disk: Disk,
    journal: Journal,
    manager: Manager,
    scratch: Scratch,
    tx: Box<Workspace>,
}
impl Harness {
    fn new() -> Self {
        let mut disk = Disk::default();
        let mut scratch = [0; 2 * BLOCK_SIZE];
        journal::format(&mut disk, [0x57; 16], &mut scratch).unwrap();
        Self::mount(disk)
    }
    fn mount(mut disk: Disk) -> Self {
        let mut journal = Journal::new();
        let mut scratch = [0; 2 * BLOCK_SIZE];
        journal.mount(&mut disk, &mut scratch).unwrap();
        let mut manager = Manager::new();
        let mut tx = Box::new([[0; BLOCK_SIZE]; 40]);
        manager
            .mount(&mut journal, &mut disk, &mut scratch, &mut tx)
            .unwrap();
        disk.operations = 0;
        Self {
            disk,
            journal,
            manager,
            scratch,
            tx,
        }
    }
    fn request(&self, slot: u32, seq: u64, epoch: u64) -> Request {
        Request {
            key: FileReqKey {
                fs_uuid: [0x57; 16],
                client_slot: slot,
                client_generation: 1,
                request_seq: seq,
            },
            expected_live_view_epoch: epoch,
        }
    }
    fn create(&mut self, request: Request, seconds: u64) -> Result<RequestRecord, Error<Fault>> {
        self.manager.create(
            &mut self.journal,
            &mut self.disk,
            &mut self.scratch,
            &mut self.tx,
            request,
            seconds,
            SlotClass::OnDemand,
            None,
        )
    }
    fn advance(&mut self, now: u64) -> u64 {
        self.manager
            .advance_age(
                &mut self.journal,
                &mut self.disk,
                &mut self.scratch,
                &mut self.tx,
                now,
            )
            .unwrap()
    }
    fn query(&mut self, key: FileReqKey) -> Result<RequestRecord, Error<Fault>> {
        self.manager.query_request(
            &mut self.journal,
            &mut self.disk,
            &mut self.scratch,
            &mut self.tx,
            key,
        )
    }
    fn checkpoint(&mut self) {
        self.journal
            .checkpoint(&mut self.disk, &mut self.scratch)
            .unwrap();
    }
    fn bootstrap(&mut self) {
        for (seq, layer) in [(1, PeriodicLayer::Short), (2, PeriodicLayer::Long)] {
            let req = self.request(14, seq, 1);
            let r = self
                .manager
                .create(
                    &mut self.journal,
                    &mut self.disk,
                    &mut self.scratch,
                    &mut self.tx,
                    req,
                    layer.retention_seconds(),
                    SlotClass::Periodic,
                    Some(layer),
                )
                .unwrap();
            self.manager
                .ack(
                    &mut self.journal,
                    &mut self.disk,
                    &mut self.scratch,
                    &mut self.tx,
                    req.key,
                    r.result_digest,
                )
                .unwrap();
        }
    }
    fn periodic(&mut self, layer: PeriodicLayer) -> RequestRecord {
        let key = self
            .manager
            .next_request_key(
                &mut self.journal,
                &mut self.disk,
                &mut self.scratch,
                &mut self.tx,
                14,
            )
            .unwrap();
        let request = Request {
            key,
            expected_live_view_epoch: self.manager.control.live_view_epoch,
        };
        self.manager
            .create(
                &mut self.journal,
                &mut self.disk,
                &mut self.scratch,
                &mut self.tx,
                request,
                layer.retention_seconds(),
                SlotClass::Periodic,
                Some(layer),
            )
            .unwrap()
    }
    fn collect_allocated(&mut self) {
        self.manager
            .gc_begin(
                &mut self.journal,
                &mut self.disk,
                &mut self.scratch,
                &mut self.tx,
            )
            .unwrap();
        self.checkpoint();
        for page in 0..4 {
            self.journal
                .read_block(
                    &mut self.disk,
                    storage::BITMAP_START + page as u32,
                    &mut self.tx[24 + page],
                    &mut self.scratch,
                )
                .unwrap();
        }
        self.manager
            .gc_publish_pages(
                &mut self.journal,
                &mut self.disk,
                &mut self.scratch,
                &mut self.tx,
                24,
            )
            .unwrap();
        self.checkpoint();
        self.manager
            .gc_finish(
                &mut self.journal,
                &mut self.disk,
                &mut self.scratch,
                &mut self.tx,
            )
            .unwrap();
    }
    fn root_seq(&mut self, seq: u64) {
        self.journal
            .read_block(
                &mut self.disk,
                INODE_START,
                &mut self.tx[0],
                &mut self.scratch,
            )
            .unwrap();
        let mut root = storage::Inode::decode(0, &self.tx[0][..256]).unwrap();
        root.durable_write_seq = seq;
        root.encode(0, &mut self.tx[0][..256]).unwrap();
        self.journal
            .commit(
                &mut self.disk,
                &[AfterImage {
                    home_block: INODE_START,
                    bytes: &self.tx[0],
                }],
                &mut self.scratch,
            )
            .unwrap();
    }
}

#[test]
fn fixed_codecs_validate_widths_crc_reserved_and_budget() {
    let mut block = [0; BLOCK_SIZE];
    let control = Control::initial([1; 16]);
    control.encode(&mut block).unwrap();
    assert_eq!(Control::decode(&block), Ok(control));
    assert_eq!(u32::from_le_bytes(block[228..232].try_into().unwrap()), 1);
    let catalog = Catalog::initial([1; 16]);
    catalog.encode(&mut block).unwrap();
    assert_eq!(&block[8..16], &[0xc0, 1, 8, 0, 0, 0, 0, 0]);
    assert_eq!(Catalog::decode(&block), Ok(catalog));
    block[4095] = 1;
    assert_eq!(Catalog::decode(&block), Err(storage::Error::Checksum));
    catalog.encode(&mut block).unwrap();
    block[12] = 1;
    super::codec::seal(&mut block, 40);
    assert_eq!(Catalog::decode(&block), Err(storage::Error::Reserved));
    assert!(core::mem::size_of::<Manager>() <= 8192);
    for page in 0..16 {
        format_request_block(page, [1; 16], &mut block).unwrap();
        if page == 0 {
            super::requests::validate_header(&block, [1; 16]).unwrap();
        } else if page <= 8 {
            for i in 0..8 {
                assert_eq!(
                    RequestRecord::decode(&block[i * 512..(i + 1) * 512]),
                    Ok(RequestRecord::FREE)
                );
            }
        }
    }
    assert_eq!(storage::crc32c(b"123456789"), 0xe306_9283);
}

#[test]
fn create_copies_committed_log_view_and_retry_never_recaptures() {
    let mut h = Harness::new();
    h.root_seq(7);
    let request = h.request(0, 1, 1);
    let created = h.create(request, 3600).unwrap();
    let key = created.snapshot_key;
    assert_eq!(created.state, RequestState::Done);
    h.root_seq(9);
    let replay = h.create(request, 3600).unwrap();
    assert_eq!(replay, created);
    assert_eq!(
        h.create(request, 3601),
        Err(Error::Status(Status::Conflict))
    );
    h.journal
        .read_block(
            &mut h.disk,
            descriptor_block(key.slot as usize) + 1,
            &mut h.tx[0],
            &mut h.scratch,
        )
        .unwrap();
    assert_eq!(
        storage::Inode::decode(0, &h.tx[0][..256])
            .unwrap()
            .durable_write_seq,
        7
    );
    h.checkpoint();
    h.disk.crash();
    let mut h = Harness::mount(h.disk);
    assert_eq!(h.query(request.key).unwrap(), created);
    assert_eq!(h.manager.active(key).unwrap().captured_live_view_epoch, 1);
}

#[test]
fn pending_creation_reboot_is_incomplete_and_cannot_capture_later() {
    let mut h = Harness::new();
    let request = h.request(0, 1, 1);
    let pending = h
        .manager
        .begin_create(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request,
            3600,
            SlotClass::OnDemand,
            None,
        )
        .unwrap();
    assert_eq!(pending.state, RequestState::Pending);
    h.root_seq(13);
    h.disk.crash();
    let mut h = Harness::mount(h.disk);
    let original = h.create(request, 3600).unwrap();
    assert_eq!(original.state, RequestState::Incomplete);
    assert_eq!(h.manager.catalog.entries[6].state, State::Free);
    assert_eq!(
        h.manager
            .finish_create(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                request.key
            )
            .unwrap(),
        original
    );
}

#[test]
fn retention_refs_freeze_and_safe_slot_reuse() {
    let mut h = Harness::new();
    let create = h.request(0, 1, 1);
    let original = h.create(create, 3600).unwrap();
    let key = original.snapshot_key;
    let delete = h.request(0, 2, 0);
    assert_eq!(
        h.manager.delete(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            delete,
            key,
            false,
            false
        ),
        Err(Error::Status(Status::Retention))
    );
    assert_eq!(h.advance(100 * SECOND_NS), 0);
    assert_eq!(h.advance(3699 * SECOND_NS), 3599 * SECOND_NS);
    assert_eq!(
        h.manager.delete(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            delete,
            key,
            false,
            false
        ),
        Err(Error::Status(Status::Retention))
    );
    h.advance(3700 * SECOND_NS);
    h.advance(3760 * SECOND_NS);
    assert_eq!(
        h.manager.delete(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            delete,
            key,
            true,
            false
        ),
        Err(Error::Status(Status::Busy))
    );
    let freeze = h.request(15, 1, 0);
    h.manager
        .freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            freeze,
            1,
            7,
        )
        .unwrap();
    assert_eq!(
        h.manager.delete(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            delete,
            key,
            false,
            false
        ),
        Err(Error::Status(Status::Frozen))
    );
    let clear = h.request(15, 2, 0);
    h.manager
        .clear_freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            clear,
            2,
        )
        .unwrap();
    let deleted = h
        .manager
        .delete(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            delete,
            key,
            false,
            false,
        )
        .unwrap();
    assert_eq!(deleted.state, RequestState::Done);
    let mut bitmap = [0u8; 16384];
    for page in 0..4 {
        h.journal
            .read_block(
                &mut h.disk,
                storage::BITMAP_START + page as u32,
                &mut h.tx[0],
                &mut h.scratch,
            )
            .unwrap();
        bitmap[page * 4096..(page + 1) * 4096].copy_from_slice(&h.tx[0]);
    }
    h.manager
        .gc_begin(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx)
        .unwrap();
    h.checkpoint();
    for page in 0..4 {
        h.tx[24 + page].copy_from_slice(&bitmap[page * BLOCK_SIZE..(page + 1) * BLOCK_SIZE]);
    }
    h.manager
        .gc_publish_pages(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx, 24)
        .unwrap();
    assert_eq!(
        h.manager
            .gc_finish(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx),
        Err(Error::Status(Status::Busy))
    );
    h.checkpoint();
    h.manager
        .gc_finish(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx)
        .unwrap();
    for page in 0..4 {
        assert_eq!(
            &h.tx[24 + page],
            &bitmap[page * BLOCK_SIZE..(page + 1) * BLOCK_SIZE]
        );
    }
    assert_eq!(h.manager.query(key), Err(Status::Stale));
    let next = h.request(0, 3, 1);
    let recreated = h.create(next, 3600).unwrap();
    assert_eq!(recreated.snapshot_key.slot, key.slot);
    assert_eq!(
        recreated.snapshot_key.slot_generation,
        key.slot_generation + 1
    );
    assert_eq!(
        h.manager
            .delete(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                delete,
                key,
                false,
                false
            )
            .unwrap(),
        deleted
    );
    h.manager
        .ack(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            create.key,
            original.result_digest,
        )
        .unwrap();
    assert_eq!(h.create(create, 3600), Err(Error::Status(Status::Stale)));
}

#[test]
fn restore_epoch_result_atomic_and_ack_preserves_opening_proof() {
    let mut h = Harness::new();
    h.bootstrap();
    h.root_seq(4);
    let c = h.request(0, 1, 1);
    let snapshot = h.create(c, 3600).unwrap();
    h.root_seq(8);
    let request = h.request(15, 1, 1);
    let restored = h
        .manager
        .restore(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request,
            snapshot.snapshot_key,
            RestoreMode::PreserveDirty,
        )
        .unwrap();
    assert_eq!(restored.state, RequestState::Done);
    assert_eq!(h.manager.control.live_view_epoch, 2);
    assert_eq!(h.manager.control.business_write_gate, Gate::Frozen);
    assert_eq!(h.manager.control.protection_generation, 3);
    assert_eq!(
        h.manager
            .restore(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                request,
                snapshot.snapshot_key,
                RestoreMode::PreserveDirty
            )
            .unwrap(),
        restored
    );
    h.journal
        .read_block(&mut h.disk, INODE_START, &mut h.tx[0], &mut h.scratch)
        .unwrap();
    assert_eq!(
        storage::Inode::decode(0, &h.tx[0][..256])
            .unwrap()
            .durable_write_seq,
        4
    );
    h.manager
        .ack(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request.key,
            restored.result_digest,
        )
        .unwrap();
    assert_eq!(h.manager.control.restore_request, request.key);
    let freeze = h.request(15, 2, 0);
    h.manager
        .freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            freeze,
            3,
            1,
        )
        .unwrap();
    let opening = h.request(15, 3, 2);
    assert_eq!(
        h.manager.open_writes(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            opening,
            3,
            request.key
        ),
        Err(Error::Status(Status::Stale))
    );
    h.manager
        .open_writes(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            opening,
            4,
            request.key,
        )
        .unwrap();
    assert_eq!(h.manager.control.business_write_gate, Gate::Open);
    assert!(h.manager.control.cleanup_freeze);
    assert_eq!(h.manager.control.restore_phase, RestorePhase::Idle);
}

#[test]
fn request_partition_sequence_and_ack_checks() {
    let mut h = Harness::new();
    let gap = h.request(0, 2, 1);
    assert_eq!(h.create(gap, 3600), Err(Error::Status(Status::Sequence)));
    let request = h.request(0, 1, 1);
    let created = h.create(request, 3600).unwrap();
    assert_eq!(
        h.manager.ack(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request.key,
            [0; 32]
        ),
        Err(Error::Status(Status::Conflict))
    );
    // Ordinary records can fill all 48 slots without consuming the independent
    // recovery partition. Query and ACK keep operating at that boundary.
    for seq in 2..=48 {
        let request = h.request(0, seq, 0);
        h.manager
            .extend(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                request,
                created.snapshot_key,
                3600,
            )
            .unwrap();
    }
    let request49 = h.request(0, 49, 0);
    assert_eq!(
        h.manager.extend(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request49,
            created.snapshot_key,
            3600
        ),
        Err(Error::Status(Status::NoSpace))
    );
    assert_eq!(h.query(request.key).unwrap(), created);
    let recovery = h.request(15, 1, 0);
    assert_eq!(
        h.manager
            .freeze(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                recovery,
                1,
                99
            )
            .unwrap()
            .state,
        RequestState::Done
    );
    h.manager
        .ack(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request.key,
            created.result_digest,
        )
        .unwrap();
    h.manager
        .extend(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request49,
            created.snapshot_key,
            3600,
        )
        .unwrap();
    assert_eq!(h.query(request.key), Err(Error::Status(Status::Stale)));
}

#[test]
fn power_cuts_at_every_create_write_and_flush_publish_all_or_nothing() {
    let seed = Harness::new().disk;
    let mut success = Harness::mount(seed.clone());
    let request = success.request(0, 1, 1);
    success.create(request, 3600).unwrap();
    let count = success.disk.operations;
    assert!(count > 40);
    let mut outcomes = Vec::new();
    for point in 1..=count {
        for after in [false, true] {
            let mut h = Harness::mount(seed.clone());
            h.disk.cut = Some(if after {
                Cut::After(point)
            } else {
                Cut::Before(point)
            });
            let _ = h.create(request, 3600);
            h.disk.crash();
            let mut recovered = Harness::mount(h.disk);
            let record = recovered.query(request.key);
            match record {
                Ok(r) if r.state == RequestState::Done => {
                    assert_eq!(
                        recovered
                            .manager
                            .active(r.snapshot_key)
                            .unwrap()
                            .snapshot_id,
                        1
                    );
                    outcomes.push(2);
                }
                Ok(r) => {
                    assert_eq!(r.state, RequestState::Incomplete);
                    assert!(
                        recovered
                            .manager
                            .catalog
                            .entries
                            .iter()
                            .all(|e| e.state == State::Free)
                    );
                    outcomes.push(1);
                }
                Err(Error::Status(Status::Stale)) => {
                    assert!(
                        recovered
                            .manager
                            .catalog
                            .entries
                            .iter()
                            .all(|e| e.state == State::Free)
                    );
                    outcomes.push(0);
                }
                other => panic!("unexpected recovered state at {point}, after={after}: {other:?}"),
            }
        }
    }
    assert!(outcomes.contains(&0) && outcomes.contains(&1) && outcomes.contains(&2));
}

#[test]
fn power_cuts_at_every_restore_boundary_keep_root_epoch_and_result_together() {
    let mut base = Harness::new();
    base.root_seq(4);
    let c = base.request(0, 1, 1);
    let snapshot = base.create(c, 3600).unwrap();
    base.root_seq(9);
    base.checkpoint();
    let seed = base.disk;
    let mut success = Harness::mount(seed.clone());
    let request = success.request(15, 1, 1);
    success
        .manager
        .restore(
            &mut success.journal,
            &mut success.disk,
            &mut success.scratch,
            &mut success.tx,
            request,
            snapshot.snapshot_key,
            RestoreMode::DiscardVolatile,
        )
        .unwrap();
    let count = success.disk.operations;
    let mut outcomes = Vec::new();
    for point in 1..=count {
        for after in [false, true] {
            let mut h = Harness::mount(seed.clone());
            h.disk.cut = Some(if after {
                Cut::After(point)
            } else {
                Cut::Before(point)
            });
            let _ = h.manager.restore(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                request,
                snapshot.snapshot_key,
                RestoreMode::DiscardVolatile,
            );
            h.disk.crash();
            let mut recovered = Harness::mount(h.disk);
            recovered
                .journal
                .read_block(
                    &mut recovered.disk,
                    INODE_START,
                    &mut recovered.tx[0],
                    &mut recovered.scratch,
                )
                .unwrap();
            let root_seq = storage::Inode::decode(0, &recovered.tx[0][..256])
                .unwrap()
                .durable_write_seq;
            match recovered.query(request.key) {
                Ok(r) if r.state == RequestState::Done => {
                    assert_eq!(root_seq, 4);
                    assert_eq!(recovered.manager.control.live_view_epoch, 2);
                    assert_eq!(
                        recovered.manager.control.restore_phase,
                        RestorePhase::Published
                    );
                    outcomes.push(2);
                }
                Ok(r) => {
                    assert_eq!(r.state, RequestState::Incomplete);
                    assert_eq!(root_seq, 9);
                    assert_eq!(recovered.manager.control.live_view_epoch, 1);
                    assert_eq!(recovered.manager.control.restore_phase, RestorePhase::Idle);
                    outcomes.push(1);
                }
                Err(Error::Status(Status::Stale)) => {
                    assert_eq!(root_seq, 9);
                    assert_eq!(recovered.manager.control.live_view_epoch, 1);
                    outcomes.push(0);
                }
                other => panic!("unexpected restore outcome at {point}, after={after}: {other:?}"),
            }
            assert_eq!(recovered.manager.control.business_write_gate, Gate::Frozen);
        }
    }
    assert!(outcomes.contains(&0) && outcomes.contains(&1) && outcomes.contains(&2));
}

#[test]
fn protected_clock_discards_wait_fraction_downtime_and_pre_creation_time() {
    struct Clock {
        values: std::vec::IntoIter<u64>,
    }
    impl MonotonicClock for Clock {
        fn monotonic_ns(&mut self) -> Option<u64> {
            self.values.next()
        }
    }
    let mut h = Harness::new();
    h.advance(1_100_000_000);
    assert_eq!(h.advance(61_999_999_999), 60 * SECOND_NS);
    // The next sample arms a post-commit anchor; the wait was not credited.
    assert_eq!(h.advance(101 * SECOND_NS), 60 * SECOND_NS);
    let request = h.request(0, 1, 1);
    let r = h.create(request, 3600).unwrap();
    assert_eq!(
        h.manager
            .active(r.snapshot_key)
            .unwrap()
            .created_online_age_ns,
        60 * SECOND_NS
    );
    assert_eq!(h.advance(151 * SECOND_NS), 60 * SECOND_NS);
    let mut clock = Clock {
        values: std::vec![211 * SECOND_NS + 500_000_000, 219 * SECOND_NS].into_iter(),
    };
    assert_eq!(
        h.manager
            .advance_age_from_clock(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                &mut clock
            )
            .unwrap(),
        120 * SECOND_NS
    );
    assert_eq!(h.advance(278 * SECOND_NS + 999_999_999), 120 * SECOND_NS);
    assert_eq!(h.advance(279 * SECOND_NS), 180 * SECOND_NS);
    h.disk.crash();
    let mut h = Harness::mount(h.disk);
    assert_eq!(h.advance(1_000_000 * SECOND_NS), 180 * SECOND_NS);
    let mut backwards = Clock {
        values: std::vec![999_999 * SECOND_NS].into_iter(),
    };
    assert_eq!(
        h.manager.advance_age_from_clock(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            &mut backwards
        ),
        Err(Error::Status(Status::Invalid))
    );
    assert!(h.manager.control.cleanup_freeze);
    assert_eq!(h.manager.control.business_write_gate, Gate::Frozen);
}

#[test]
fn recovery_freeze_and_ack_have_independent_commit_reservation() {
    let mut h = Harness::new();
    let ordinary = h.request(0, 1, 1);
    let snapshot = h.create(ordinary, 3600).unwrap();
    h.disk.reject_ordinary = true;
    let extra = h.request(0, 2, 1);
    assert_eq!(
        h.create(extra, 3600),
        Err(Error::Journal(journal::Error::Io(Fault::Cut)))
    );
    assert!(h.journal.is_writable());
    let recovery = h.request(15, 1, 0);
    h.manager
        .freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            recovery,
            1,
            0,
        )
        .unwrap();
    h.manager
        .ack(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            ordinary.key,
            snapshot.result_digest,
        )
        .unwrap();
    assert_eq!(h.disk.recovery_depth, 0);
}

#[test]
fn corrupt_active_image_is_rejected_without_erasing_protected_root() {
    let mut h = Harness::new();
    let request = h.request(0, 1, 1);
    let snapshot = h.create(request, 3600).unwrap();
    h.checkpoint();
    let home = descriptor_block(snapshot.snapshot_key.slot as usize) + 1;
    h.disk.stable.get_mut(&home).unwrap()[17] ^= 1;
    h.disk.crash();
    let mut j = Journal::new();
    j.mount(&mut h.disk, &mut h.scratch).unwrap();
    let mut manager = Manager::new();
    assert_eq!(
        manager.mount(&mut j, &mut h.disk, &mut h.scratch, &mut h.tx),
        Err(Error::Status(Status::Corrupt))
    );
    assert!(!manager.is_mounted());
    assert!(!manager.writes_open());
    j.read_block(
        &mut h.disk,
        storage::CATALOG_START,
        &mut h.tx[0],
        &mut h.scratch,
    )
    .unwrap();
    assert_eq!(
        Catalog::decode(&h.tx[0]).unwrap().entries[snapshot.snapshot_key.slot as usize].state,
        State::Active
    );
}

#[test]
fn full_recovery_record_partition_still_allows_internal_safety_freeze() {
    let mut h = Harness::new();
    h.bootstrap();
    for seq in 1..=8 {
        let generation = h.manager.control.protection_generation;
        if seq % 2 == 1 {
            let request = h.request(15, seq, 0);
            h.manager
                .freeze(
                    &mut h.journal,
                    &mut h.disk,
                    &mut h.scratch,
                    &mut h.tx,
                    request,
                    generation,
                    1,
                )
                .unwrap();
        } else {
            let request = h.request(15, seq, 1);
            h.manager
                .open_writes(
                    &mut h.journal,
                    &mut h.disk,
                    &mut h.scratch,
                    &mut h.tx,
                    request,
                    generation,
                    FileReqKey::ZERO,
                )
                .unwrap();
        }
    }
    assert_eq!(h.manager.control.business_write_gate, Gate::Open);
    let request = h.request(15, 9, 0);
    let generation = h.manager.control.protection_generation;
    assert_eq!(
        h.manager.freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request,
            generation,
            1
        ),
        Err(Error::Status(Status::NoSpace))
    );
    assert_eq!(h.manager.control.business_write_gate, Gate::Frozen);
    assert_eq!(h.manager.control.protection_generation, generation + 1);
    assert_eq!(h.query(request.key), Err(Error::Status(Status::Stale)));
}

#[test]
fn periodic_layers_rotate_without_changing_other_tier_schedule() {
    let mut h = Harness::new();
    let first = h.periodic(PeriodicLayer::Short);
    let opening = h.request(15, 1, 1);
    assert_eq!(
        h.manager.open_writes(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            opening,
            1,
            FileReqKey::ZERO
        ),
        Err(Error::Status(Status::Retention))
    );
    let long = h.periodic(PeriodicLayer::Long);
    assert_eq!((first.snapshot_key.slot, long.snapshot_key.slot), (0, 3));
    h.manager
        .open_writes(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            opening,
            1,
            FileReqKey::ZERO,
        )
        .unwrap();
    assert!(h.manager.writes_open());
    assert!(!h.manager.periodic_due(PeriodicLayer::Short));
    assert!(!h.manager.periodic_due(PeriodicLayer::Long));
    h.advance(0);
    h.advance(SHORT_PERIOD_SECONDS * SECOND_NS);
    assert!(h.manager.periodic_due(PeriodicLayer::Short));
    assert!(!h.manager.periodic_due(PeriodicLayer::Long));
    let second = h.periodic(PeriodicLayer::Short);
    assert_eq!(second.snapshot_key.slot, 1);
    assert_eq!(
        h.manager.control.short_last_auto_age_ns,
        SHORT_PERIOD_SECONDS * SECOND_NS
    );
    assert_eq!(h.manager.control.long_last_auto_age_ns, 0);
    h.advance(SHORT_PERIOD_SECONDS * SECOND_NS);
    h.advance(2 * SHORT_PERIOD_SECONDS * SECOND_NS);
    assert_eq!(h.periodic(PeriodicLayer::Short).snapshot_key.slot, 2);
    h.advance(2 * SHORT_PERIOD_SECONDS * SECOND_NS);
    h.advance(3 * SHORT_PERIOD_SECONDS * SECOND_NS);
    let request = h.request(14, 5, 0);
    h.manager
        .delete(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            request,
            first.snapshot_key,
            false,
            true,
        )
        .unwrap();
    assert_eq!(h.manager.catalog.entries[0].state, State::Deleting);
    assert!(h.manager.active(second.snapshot_key).is_ok());
    assert!(h.manager.active(long.snapshot_key).is_ok());
    h.collect_allocated();
    let replaced = h.periodic(PeriodicLayer::Short);
    assert_eq!(replaced.snapshot_key.slot, 0);
    assert_eq!(
        replaced.snapshot_key.slot_generation,
        first.snapshot_key.slot_generation + 1
    );
    assert_eq!(
        h.manager.control.short_last_auto_age_ns,
        SHORT_RETENTION_SECONDS * SECOND_NS
    );
    assert_eq!(h.manager.control.long_last_auto_age_ns, 0);
    assert!(!h.manager.periodic_due(PeriodicLayer::Short));
    h.disk.crash();
    let h = Harness::mount(h.disk);
    assert_eq!(
        h.manager.control.short_last_auto_age_ns,
        SHORT_RETENTION_SECONDS * SECOND_NS
    );
    assert_eq!(h.manager.control.long_last_auto_age_ns, 0);
}

#[test]
fn neither_automatic_nor_manual_delete_can_remove_either_tiers_last_readable_root() {
    let mut h = Harness::new();
    let short = h.periodic(PeriodicLayer::Short);
    let long = h.periodic(PeriodicLayer::Long);
    h.advance(0);
    h.advance(LONG_RETENTION_SECONDS * SECOND_NS);
    let request = h.request(14, 3, 0);
    for key in [short.snapshot_key, long.snapshot_key] {
        assert_eq!(
            h.manager.delete(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                request,
                key,
                false,
                true
            ),
            Err(Error::Status(Status::Retention))
        );
        assert_eq!(h.manager.active(key).unwrap().state, State::Active);
    }
    // The candidate contract also guards explicitly authorized root drops.
    let manual = h.request(0, 1, 0);
    for key in [short.snapshot_key, long.snapshot_key] {
        assert_eq!(
            h.manager.delete(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                manual,
                key,
                false,
                false,
            ),
            Err(Error::Status(Status::Retention))
        );
        assert_eq!(h.manager.active(key).unwrap().state, State::Active);
    }
    let replacement = h.periodic(PeriodicLayer::Short);
    let deleted = h
        .manager
        .delete(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            manual,
            short.snapshot_key,
            false,
            false,
        )
        .unwrap();
    assert_eq!(deleted.state, RequestState::Done);
    assert_eq!(
        h.manager.catalog.entries[short.snapshot_key.slot as usize].state,
        State::Deleting
    );
    assert!(h.manager.active(replacement.snapshot_key).is_ok());
    assert!(h.manager.active(long.snapshot_key).is_ok());
    h.disk.crash();
    let h = Harness::mount(h.disk);
    assert!(h.manager.active(replacement.snapshot_key).is_ok());
    assert!(h.manager.active(long.snapshot_key).is_ok());
}

#[test]
fn fixed_slot_classes_and_periodic_layers_cannot_borrow_capacity() {
    let mut h = Harness::new();
    let first = h.request(0, 1, 1);
    let second = h.request(0, 2, 1);
    assert_eq!(h.create(first, 3600).unwrap().snapshot_key.slot, 6);
    assert_eq!(h.create(second, 3600).unwrap().snapshot_key.slot, 7);
    let next = h.request(0, 3, 1);
    assert_eq!(h.create(next, 3600), Err(Error::Status(Status::NoSpace)));
    assert_eq!(
        h.manager.create(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            next,
            SHORT_RETENTION_SECONDS,
            SlotClass::Periodic,
            Some(PeriodicLayer::Short)
        ),
        Err(Error::Status(Status::Permission))
    );
    for slot in 0..3 {
        assert_eq!(h.periodic(PeriodicLayer::Short).snapshot_key.slot, slot);
    }
    let maintenance = h.request(14, 4, 1);
    assert_eq!(
        h.manager.create(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            maintenance,
            SHORT_RETENTION_SECONDS,
            SlotClass::Periodic,
            Some(PeriodicLayer::Short)
        ),
        Err(Error::Status(Status::NoSpace))
    );
    let wire_long = h
        .manager
        .create(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            maintenance,
            LONG_RETENTION_SECONDS,
            SlotClass::Periodic,
            None,
        )
        .unwrap();
    assert_eq!(wire_long.snapshot_key.slot, 3);
    let maintenance = h.request(14, 5, 1);
    assert_eq!(
        h.manager.create(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            maintenance,
            3600,
            SlotClass::OnDemand,
            None
        ),
        Err(Error::Status(Status::Permission))
    );
    assert_eq!(
        h.manager.create(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            maintenance,
            3600,
            SlotClass::Periodic,
            Some(PeriodicLayer::Long)
        ),
        Err(Error::Status(Status::Retention))
    );
}

#[test]
fn maintenance_reaper_recovers_lost_ack_quota_without_touching_other_owners() {
    let mut h = Harness::new();
    let reads = h.disk.reads;
    let cpu_progress_calls = h.disk.cpu_progress_calls;
    let operations = h.disk.operations;
    assert_eq!(
        h.manager
            .reap_maintenance_requests(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx)
            .unwrap(),
        0
    );
    assert_eq!(h.disk.reads - reads, 1, "empty maintenance page read once");
    assert_eq!(h.disk.operations, operations, "empty scan has no writes");
    assert_eq!(
        h.disk.cpu_progress_calls - cpu_progress_calls,
        1 + 8,
        "one verified journal page and all eight decoded slots yield CPU"
    );
    let periodic = h.periodic(PeriodicLayer::Short);
    for seq in 2..=8 {
        let request = h.request(14, seq, 0);
        h.manager
            .extend(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                request,
                periodic.snapshot_key,
                SHORT_RETENTION_SECONDS,
            )
            .unwrap();
    }
    let ordinary = h.request(0, 1, 1);
    let ordinary_result = h.create(ordinary, 3600).unwrap();
    let recovery = h.request(15, 1, 0);
    let recovery_result = h
        .manager
        .freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            recovery,
            1,
            0,
        )
        .unwrap();
    h.disk.crash();
    let mut h = Harness::mount(h.disk);
    assert_eq!(
        h.manager
            .reap_maintenance_requests(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx)
            .unwrap(),
        8
    );
    assert_eq!(h.query(ordinary.key).unwrap(), ordinary_result);
    assert_eq!(h.query(recovery.key).unwrap(), recovery_result);
    assert_eq!(h.query(periodic.key), Err(Error::Status(Status::Stale)));
    let created = h.periodic(PeriodicLayer::Long);
    assert_eq!(created.key.request_seq, 9);
    assert_eq!(
        h.manager
            .reap_maintenance_requests(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx)
            .unwrap(),
        1
    );
    let pending = h.request(14, 10, 1);
    h.manager
        .begin_create(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            pending,
            SHORT_RETENTION_SECONDS,
            SlotClass::Periodic,
            Some(PeriodicLayer::Short),
        )
        .unwrap();
    assert_eq!(
        h.manager
            .reap_maintenance_requests(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx)
            .unwrap(),
        0
    );
    assert_eq!(h.query(pending.key).unwrap().state, RequestState::Pending);
    h.disk.crash();
    let mut h = Harness::mount(h.disk);
    assert_eq!(
        h.query(pending.key).unwrap().state,
        RequestState::Incomplete
    );
    assert_eq!(
        h.manager
            .reap_maintenance_requests(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx)
            .unwrap(),
        1
    );
}

#[test]
fn exhausted_management_counters_close_new_writes_but_preserve_history() {
    let mut h = Harness::new();
    h.bootstrap();
    let opening = h.request(15, 1, 1);
    let done = h
        .manager
        .open_writes(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            opening,
            1,
            FileReqKey::ZERO,
        )
        .unwrap();
    assert!(h.manager.writes_open());
    let saved_control = h.manager.control;
    let saved_catalog = h.manager.catalog;
    for field in 0..8 {
        h.manager.control = saved_control;
        h.manager.catalog = saved_catalog;
        match field {
            0 => h.manager.control.control_generation = u64::MAX,
            1 => h.manager.control.live_view_epoch = u64::MAX,
            2 => h.manager.control.next_snapshot_id = u64::MAX,
            3 => h.manager.control.protection_generation = u64::MAX,
            4 => h.manager.catalog.catalog_generation = u64::MAX,
            5 => h.manager.control.age_generation = u64::MAX,
            6 => h.manager.control.gc_generation = u64::MAX,
            _ => h.manager.control.online_age_ns = u64::MAX / SECOND_NS * SECOND_NS,
        }
        assert!(!h.manager.writes_open(), "counter field {field}");
        let before = h.disk.operations;
        assert_eq!(
            h.manager
                .open_writes(
                    &mut h.journal,
                    &mut h.disk,
                    &mut h.scratch,
                    &mut h.tx,
                    opening,
                    1,
                    FileReqKey::ZERO
                )
                .unwrap(),
            done
        );
        h.manager.control.business_write_gate = Gate::Frozen;
        let request = h.request(15, 2, h.manager.control.live_view_epoch);
        let generation = h.manager.control.protection_generation;
        assert_eq!(
            h.manager.open_writes(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                request,
                generation,
                FileReqKey::ZERO
            ),
            Err(Error::Status(Status::Counter))
        );
        assert_eq!(h.disk.operations, before);
        assert!(!h.manager.writes_open());
        assert_eq!(h.manager.control.business_write_gate, Gate::Frozen);
    }
    h.manager.control = saved_control;
    h.manager.catalog = saved_catalog;
    h.manager.control.next_snapshot_id = u64::MAX;
    let request = h.request(0, 1, 1);
    assert_eq!(h.create(request, 3600), Err(Error::Status(Status::Counter)));
    assert_eq!(h.manager.control.next_snapshot_id, u64::MAX);
    assert_eq!(h.query(request.key), Err(Error::Status(Status::Stale)));
}

#[test]
fn new_protection_relaxations_cannot_bypass_a_pending_capture_barrier() {
    let mut h = Harness::new();
    h.bootstrap();
    let freeze = h.request(15, 1, 0);
    h.manager
        .freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            freeze,
            1,
            0,
        )
        .unwrap();
    let creating = h.request(0, 1, 1);
    h.manager
        .begin_create(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            creating,
            3600,
            SlotClass::OnDemand,
            None,
        )
        .unwrap();
    let opening = h.request(15, 2, 1);
    assert_eq!(
        h.manager.open_writes(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            opening,
            2,
            FileReqKey::ZERO
        ),
        Err(Error::Status(Status::Busy))
    );
    let clearing = h.request(15, 2, 0);
    assert_eq!(
        h.manager.clear_freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            clearing,
            2
        ),
        Err(Error::Status(Status::Busy))
    );
    assert_eq!(h.manager.control.business_write_gate, Gate::Frozen);
    assert!(h.manager.control.cleanup_freeze);
    assert_eq!(h.query(creating.key).unwrap().state, RequestState::Pending);
}

#[test]
fn periodic_delete_refuses_corrupt_surviving_image_and_retains_valid_root() {
    for automatic in [false, true] {
        let mut h = Harness::new();
        let old = h.periodic(PeriodicLayer::Short);
        let survivor = h.periodic(PeriodicLayer::Short);
        h.advance(0);
        h.advance(SHORT_RETENTION_SECONDS * SECOND_NS);
        h.checkpoint();
        let home = descriptor_block(survivor.snapshot_key.slot as usize) + 1;
        h.disk.stable.get_mut(&home).unwrap()[17] ^= 1;
        let request = h.request(
            if automatic { 14 } else { 0 },
            if automatic { 3 } else { 1 },
            0,
        );
        assert_eq!(
            h.manager.delete(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                request,
                old.snapshot_key,
                false,
                automatic
            ),
            Err(Error::Status(Status::Corrupt))
        );
        assert!(h.manager.active(old.snapshot_key).is_ok());
        assert!(h.manager.control.cleanup_freeze);
        assert_eq!(h.manager.control.business_write_gate, Gate::Frozen);
        assert_eq!(h.query(request.key), Err(Error::Status(Status::Stale)));
    }
}

#[test]
fn retention_clock_regression_between_samples_and_after_anchor_reset_freezes_cleanup() {
    for reset in [false, true] {
        let mut h = Harness::new();
        assert_eq!(h.advance(100 * SECOND_NS), 0);
        assert_eq!(h.advance(140 * SECOND_NS), 0);
        if reset {
            let request = h.request(0, 1, 1);
            h.create(request, 3600).unwrap();
        }
        assert_eq!(
            h.manager.advance_age(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                130 * SECOND_NS
            ),
            Err(Error::Status(Status::Invalid))
        );
        assert_eq!(h.manager.control.online_age_ns, 0);
        assert!(h.manager.control.cleanup_freeze);
        assert_eq!(h.manager.control.business_write_gate, Gate::Frozen);
        // A second lower sample must not replace the high-water.
        assert_eq!(
            h.manager.advance_age(
                &mut h.journal,
                &mut h.disk,
                &mut h.scratch,
                &mut h.tx,
                139 * SECOND_NS
            ),
            Err(Error::Status(Status::Invalid))
        );
        h.disk.crash();
        let mut recovered = Harness::mount(h.disk);
        // A new boot legitimately starts a new clock origin, not a new
        // durable retention age or an automatically open write gate.
        assert_eq!(recovered.advance(0), 0);
        assert!(recovered.manager.control.cleanup_freeze);
    }
}

#[test]
fn internal_fault_freeze_retries_rejected_durability_before_any_relaxation() {
    let mut h = Harness::new();
    h.bootstrap();
    let opening = h.request(15, 1, 1);
    let generation = h.manager.control.protection_generation;
    h.manager
        .open_writes(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            opening,
            generation,
            FileReqKey::ZERO,
        )
        .unwrap();
    let generation = h.manager.control.protection_generation;
    assert!(h.manager.writes_open());
    h.disk.reject_recovery = true;
    for _ in 0..2 {
        assert_eq!(
            h.manager
                .fault_freeze(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx),
            Err(Error::Journal(journal::Error::Io(Fault::Cut)))
        );
        assert!(h.journal.is_writable());
        assert!(!h.manager.writes_open());
        assert!(h.manager.control.cleanup_freeze);
        assert_eq!(h.manager.control.protection_generation, generation);
        assert_eq!(h.disk.recovery_depth, 0);
    }
    let relaxation = h.request(15, 2, 0);
    assert_eq!(
        h.manager.clear_freeze(
            &mut h.journal,
            &mut h.disk,
            &mut h.scratch,
            &mut h.tx,
            relaxation,
            generation
        ),
        Err(Error::Status(Status::Busy))
    );
    assert_eq!(h.query(opening.key).unwrap().state, RequestState::Done);
    h.disk.reject_recovery = false;
    // Maintenance retries the original protection intent, not a new
    // relaxation or a fictitious age advance.
    assert_eq!(h.advance(0), 0);
    assert_eq!(h.manager.control.protection_generation, generation + 1);
    h.manager
        .fault_freeze(&mut h.journal, &mut h.disk, &mut h.scratch, &mut h.tx)
        .unwrap();
    assert_eq!(h.manager.control.protection_generation, generation + 1);
    h.disk.crash();
    let h = Harness::mount(h.disk);
    assert!(h.manager.control.cleanup_freeze);
    assert_eq!(h.manager.control.business_write_gate, Gate::Frozen);
    assert_eq!(h.manager.control.protection_generation, generation + 1);
}

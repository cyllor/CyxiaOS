use cyxia_contracts::{Generation, MemoryRegion, PageCount, PhysAddr, RegionKind, TaskId};
use cyxia_kernel_core::{frames::*, grants::*};
use cyxia_posix::{
    Errno,
    vm::{self, Page, PageBatch, Vm},
};

#[path = "../../../kernel/src/desktop/memory/user_heap/transaction.rs"]
mod transaction;
use transaction::Backing;

fn owner() -> Owner {
    Owner {
        task: TaskId::new(7).unwrap(),
        generation: Generation::new(1).unwrap(),
    }
}
fn request(pages: usize) -> AuthorizedGrantRequest {
    unsafe { AuthorizedGrantRequest::validated_ai(owner(), PageCount(pages as u32), 8199) }.unwrap()
}
struct Zero {
    bytes: [[u8; 4096]; 8],
    calls: usize,
    fail: usize,
}
impl PageZeroer for Zero {
    fn zero(&mut self, address: PhysAddr) -> Result<(), FrameError> {
        self.calls += 1;
        if self.calls == self.fail {
            return Err(FrameError::ZeroFailed);
        }
        self.bytes[(address.0 as usize - 4096) / 4096].fill(0);
        Ok(())
    }
}
struct Pages<'a> {
    pool: FramePool<'a>,
    zero: Zero,
    frames: Vec<Option<FrameHandle>>,
    ptes: Vec<Option<PhysAddr>>,
    stages: usize,
    fail_pte: usize,
    preserved_ptes: usize,
}
impl<'a> Pages<'a> {
    fn new(metadata: &'a mut [FrameMeta]) -> Self {
        let ram = MemoryRegion {
            start: PhysAddr(4096),
            len: metadata.len() as u64 * 4096,
            kind: RegionKind::Ram,
        };
        Self {
            pool: FramePool::from_memory(&[ram], &[], metadata).unwrap(),
            zero: Zero {
                bytes: [[0xa5; 4096]; 8],
                calls: 0,
                fail: usize::MAX,
            },
            frames: vec![None; vm::PAGE_COUNT],
            ptes: vec![None; vm::PAGE_COUNT],
            stages: 0,
            fail_pte: usize::MAX,
            preserved_ptes: 0,
        }
    }
}
impl Backing for Pages<'_> {
    fn stage(&mut self, page: Page) -> Result<(), Errno> {
        let frame = self
            .pool
            .alloc_zeroed(owner().task, &mut self.zero)
            .map_err(|e| {
                if e == FrameError::Exhausted {
                    Errno::Nomem
                } else {
                    Errno::Io
                }
            })?;
        self.frames[page.slot] = Some(frame);
        self.stages += 1;
        if self.stages == self.fail_pte {
            return Err(Errno::Io);
        }
        self.ptes[((page.address - vm::BASE) / 4096) as usize] = Some(frame.address());
        Ok(())
    }
    fn unstage(&mut self, page: Page) {
        self.ptes[((page.address - vm::BASE) / 4096) as usize] = None;
    }
    fn release(&mut self, page: Page) -> Result<(), Errno> {
        assert_eq!(
            self.ptes.iter().flatten().count(),
            self.preserved_ptes,
            "remove every new PTE before releasing any backing"
        );
        if let Some(frame) = self.frames[page.slot] {
            self.pool.begin_revoke(frame, owner().task).unwrap();
            self.zero.zero(frame.address()).unwrap();
            self.pool
                .finish_revoke(frame, unsafe { RevokeComplete::after_unmap(frame) })
                .unwrap();
            self.frames[page.slot] = None;
        }
        Ok(())
    }
}

#[test]
fn partial_staging_failures_restore_existing_mapping_capacity_and_allow_retry() {
    for (capacity, zero_failure, pte_failure, pages, expected) in [
        (8, 3, usize::MAX, 4, Errno::Io),
        (8, usize::MAX, 3, 4, Errno::Io),
        (3, usize::MAX, usize::MAX, 3, Errno::Nomem),
    ] {
        let mut metadata = vec![FrameMeta::EMPTY; capacity];
        let mut backing = Pages::new(&mut metadata);
        let (mut vm, mut batch) = (Vm::new(), PageBatch::new());
        let mut ledger = BoundedGrantLedger::<16>::new(PageCount(vm::PAGE_COUNT as u32));
        let mut events = Vec::new();
        transaction::allocate(
            &mut vm,
            &mut batch,
            &mut ledger,
            request(1),
            owner(),
            1,
            &mut backing,
            |grant, n| events.push((grant, n)),
        )
        .unwrap();
        let original = backing.frames[0].unwrap();
        backing.zero.bytes[original.index()][0] = 77;
        let (frames, ptes) = (backing.frames.clone(), backing.ptes.clone());
        let (pool_before, ledger_before) = (backing.pool.snapshot(), ledger.snapshot());
        events.clear();
        backing.stages = 0;
        backing.preserved_ptes = 1;
        backing.zero.calls = 0;
        backing.zero.fail = zero_failure;
        backing.fail_pte = pte_failure;
        assert_eq!(
            transaction::allocate(
                &mut vm,
                &mut batch,
                &mut ledger,
                request(pages),
                owner(),
                pages,
                &mut backing,
                |grant, n| events.push((grant, n))
            ),
            Err(expected)
        );
        assert!(
            backing.stages >= 2,
            "failure must follow actual partial staging"
        );
        assert_eq!(backing.frames, frames);
        assert_eq!(backing.ptes, ptes);
        assert_eq!(backing.pool.snapshot(), pool_before);
        assert_eq!(ledger.snapshot(), ledger_before);
        assert_eq!(vm.used(), 1);
        assert_eq!(vm.largest_free_run(), vm::PAGE_COUNT - 1);
        assert_eq!(vm.permissions(vm::BASE), Ok(3));
        assert_eq!(vm.validate(vm::BASE + 4096, 1), Err(Errno::Fault));
        assert_eq!(backing.zero.bytes[original.index()][0], 77);
        backing.pool.check_owned(original, owner().task).unwrap();
        assert_eq!(events, [(true, pages), (false, pages)]);
        backing.zero.fail = usize::MAX;
        backing.fail_pte = usize::MAX;
        transaction::allocate(
            &mut vm,
            &mut batch,
            &mut ledger,
            request(2),
            owner(),
            2,
            &mut backing,
            |grant, n| events.push((grant, n)),
        )
        .unwrap();
        assert_eq!((batch.start(), batch.page_count()), (vm::BASE + 4096, 2));
        assert_eq!(
            (
                vm.used(),
                ledger.snapshot().in_use,
                backing.pool.snapshot().used
            ),
            (3, 3, 3)
        );
        assert_eq!(events.last(), Some(&(true, 2)));
    }
}

#[test]
fn fragmented_vm_rolls_back_redeemed_grant_without_touching_backing() {
    let (mut vm, mut batch) = (Vm::new(), PageBatch::new());
    vm.allocate_into(vm::PAGE_COUNT, &mut batch).unwrap();
    for index in (0..vm::PAGE_COUNT).step_by(2) {
        vm.unmap_into(vm::BASE + index as u64 * 4096, 1, &mut batch)
            .unwrap();
    }
    let mut metadata = [FrameMeta::EMPTY; 8];
    let mut backing = Pages::new(&mut metadata);
    let mut ledger = BoundedGrantLedger::<16>::new(PageCount(vm::PAGE_COUNT as u32));
    let (pool_before, ledger_before) = (backing.pool.snapshot(), ledger.snapshot());
    let mut events = Vec::new();
    assert_eq!(
        transaction::allocate(
            &mut vm,
            &mut batch,
            &mut ledger,
            request(2),
            owner(),
            2,
            &mut backing,
            |grant, n| events.push((grant, n))
        ),
        Err(Errno::Nomem)
    );
    assert_eq!((vm.used(), vm.largest_free_run()), (vm::PAGE_COUNT / 2, 1));
    assert_eq!(vm.permissions(vm::BASE + 4096), Ok(3));
    assert_eq!(vm.validate(vm::BASE, 1), Err(Errno::Fault));
    assert_eq!(backing.stages, 0);
    assert_eq!(backing.zero.calls, 0);
    assert!(backing.frames.iter().all(Option::is_none));
    assert!(backing.ptes.iter().all(Option::is_none));
    assert_eq!(backing.pool.snapshot(), pool_before);
    assert_eq!(ledger.snapshot(), ledger_before);
    assert_eq!(events, [(true, 2), (false, 2)]);
}

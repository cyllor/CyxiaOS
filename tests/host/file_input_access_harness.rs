//! Production preflight/copy bodies, real Memory authorization, controlled task
//! gate contention and frame backing. PTE/TLB hardware is deliberately outside
//! this host regression's claim.
#![allow(dead_code)]
use cyxia_prototype::domains::{Error, ObjectKey, tasks::{Memory, MemoryBackend, CacheHandle}};
use std::sync::{Mutex, atomic::{AtomicBool, AtomicU64, Ordering}};
#[path = ABI_PATH]
mod abi;
use abi::*;
const OWNER: ObjectKey = ObjectKey { id: 4096, generation: 4 };
const REQUEST: u64 = 0x50000;
const DATA_ADDRESS: u64 = 0x60000;
const READONLY: u64 = 0x70000;

mod domain_tasks {
    use super::*;
    const TASKS: usize = 1;
    const PAGES: usize = 16;
    const USER_LIMIT: u64 = 0x200000;
    const CLIENT_PACKAGE: u64 = 2;
    const PACKAGE: u64 = 1;
    const CLIENT_CODE_FRAME: usize = 12;
    const CODE_FRAME: usize = 11;
    type Remote = ();
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Life { Waiting, Exiting }
    #[derive(Clone, Copy)]
    struct Task { key: ObjectKey, life: Life, package: u64 }
    struct State { memory: Memory<PAGES, 512>, tasks: [Task; TASKS], remote: Option<Remote> }
    static STATE: Mutex<State> = Mutex::new(State { memory: Memory::new(),
        tasks: [Task { key: OWNER, life: Life::Waiting, package: CLIENT_PACKAGE }], remote: None });
    struct Page([u8; 4096]);
    static mut POOL: [Page; PAGES] = [const { Page([0; 4096]) }; PAGES];
    pub static GATES: AtomicU64 = AtomicU64::new(0);
    pub static LIMIT: AtomicU64 = AtomicU64::new(u64::MAX);
    fn locked<R>(f: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
        if GATES.fetch_add(1, Ordering::AcqRel) >= LIMIT.load(Ordering::Acquire) {
            return Err(Error::Busy);
        }
        f(&mut STATE.lock().unwrap())
    }
    fn task_index(tasks: &[Task; TASKS], owner: ObjectKey) -> Result<usize, Error> {
        tasks.iter().position(|task| task.key == owner).ok_or(Error::Stale)
    }
    fn now_ns() -> u64 { 1000 }
    struct Pages<'a> { tasks: &'a [Task; TASKS], remote: Option<Remote>, load: Option<()> }
    impl MemoryBackend for Pages<'_> {
        fn zero(&mut self, frame: usize) -> Result<(), Error> {
            unsafe { core::ptr::write_bytes(frame_ptr(frame)?, 0, 4096); }
            Ok(())
        }
        fn map(&mut self, _: ObjectKey, _: u64, _: usize, _: bool) -> Result<(), Error> { Ok(()) }
        fn revoke(&mut self, _: ObjectKey, _: u64, _: usize) -> Result<(), Error> { Ok(()) }
        fn load_cache(&mut self, _: ObjectKey, _: u64, _: usize) -> Result<(), Error> { Err(Error::NotReady) }
        fn drop_cache(&mut self, _: CacheHandle) -> Result<(), Error> { Ok(()) }
    }
    // MEMORY_BODIES
    // Former public per-probe API, retained only as a negative control after
    // production callers moved into the single memory-only borrow.
    pub fn probe_user(owner: ObjectKey, address: u64, len: usize, write: bool) -> Result<(), Error> {
        with_user_memory(owner, |memory| memory.probe(address, len, write))
    }
    pub fn reset(frame: &Frame, address: u64) {
        let mut s = STATE.lock().unwrap();
        s.memory = Memory::new();
        s.tasks[0].life = Life::Waiting;
        s.memory.reserve_frames(CODE_FRAME, 5).unwrap();
        s.memory.register_owner(OWNER, 8).unwrap();
        s.memory.reserve(OWNER, REQUEST, 1, true).unwrap();
        s.memory.reserve(OWNER, DATA_ADDRESS, 2, true).unwrap();
        s.memory.reserve(OWNER, READONLY, 1, false).unwrap();
        let tasks = s.tasks;
        let mut backend = Pages { tasks: &tasks, remote: None, load: None };
        let at = if address == 0x10000 { CLIENT_CODE_FRAME } else {
            s.memory.fault(OWNER, address, false, &mut backend).unwrap()
        };
        unsafe { core::ptr::copy_nonoverlapping(frame.bytes.as_ptr(), frame_ptr(at).unwrap(), FRAME_BYTES); }
        let at = s.memory.fault(OWNER, DATA_ADDRESS, true, &mut backend).unwrap();
        unsafe { core::ptr::write_bytes(frame_ptr(at).unwrap(), 0xa5, 4096); }
        GATES.store(0, Ordering::Release);
        LIMIT.store(u64::MAX, Ordering::Release);
    }
    pub fn exiting() { STATE.lock().unwrap().tasks[0].life = Life::Exiting; }
}
struct Context { regs: [u64; 31] }
struct Pending {
    owner: ObjectKey, address: u64, data_address: u64, data_len: usize,
    frame: Frame, capture_io: Option<u64>, capture_len: usize, capture_misses: u64,
}
static mut PENDING: Option<Pending> = None;
static mut DATA: [u8; MAX_IO] = [0; MAX_IO];
static CLEARED: AtomicBool = AtomicBool::new(false);
fn clear_pending() {
    unsafe { *core::ptr::addr_of_mut!(PENDING) = None; }
    CLEARED.store(true, Ordering::Release);
}
mod storage_fault_capture {
    pub fn selected(_: super::ObjectKey) -> bool { false }
    pub fn delivered(_: super::ObjectKey, _: &[u8], _: &[u8], _: u64, _: u64) {}
    pub fn snapshot_failed() {}
}
// Independent-gate negative control. It deliberately reproduces the former
// access sequence with the actual public copy/probe wrappers.
struct SplitUserMemory(ObjectKey);
impl SplitUserMemory {
    fn probe(&mut self, address: u64, len: usize, write: bool) -> Result<(), Error> {
        domain_tasks::probe_user(self.0, address, len, write)
    }
    fn copyin(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
        domain_tasks::copyin(self.0, address, bytes)
    }
    fn copyout(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        domain_tasks::copyout(self.0, address, bytes)
    }
}
fn split_user_memory<R>(owner: ObjectKey, body: impl FnOnce(&mut SplitUserMemory) -> Result<R, Error>) -> Result<R, Error> {
    body(&mut SplitUserMemory(owner))
}
// FILE_BODIES
fn prepared(owner: ObjectKey, address: u64, data: &mut [u8; MAX_IO]) -> Result<Frame, Error> {
    let mut frame = Frame { bytes: [0; FRAME_BYTES] };
    let mut copied = false;
    prepare_input(owner, address, &mut frame, data, &mut copied)?;
    assert!(copied);
    Ok(frame)
}

fn write_frame() -> Frame {
    let mut f = Frame::new(WRITE, 1, Capability { id: 1, generation: 1 });
    f.set_u64(OFF_DATA, DATA_ADDRESS);
    f.set_u32(OFF_DATA_LENGTH, 64);
    f
}
#[test]
fn one_borrow_finishes_preflight_where_split_accesses_lose_the_owner_gate() {
    let frame = write_frame();
    domain_tasks::reset(&frame, REQUEST);
    domain_tasks::LIMIT.store(1, Ordering::Release);
    domain_tasks::probe_user(OWNER, REQUEST, FRAME_BYTES, true).unwrap();
    // The former separate data-range acquisition collides after the frame
    // probe, even though the same bounded owner borrow could finish.
    assert_eq!(domain_tasks::probe_user(OWNER, DATA_ADDRESS, 64, false), Err(Error::Busy));
    domain_tasks::reset(&frame, REQUEST);
    domain_tasks::LIMIT.store(1, Ordering::Release);
    let mut data = [0; MAX_IO];
    let result = prepared(OWNER, REQUEST, &mut data).expect("preflight reacquired the contended owner gate");
    assert_eq!(result.bytes, frame.bytes);
    assert_eq!(&data[..64], &[0xa5; 64]);
    assert_eq!(domain_tasks::GATES.load(Ordering::Acquire), 1);
}
#[test]
fn shape_and_overlap_errors_leave_data_untouched() {
    for overlap in [false, true] {
        let mut f = write_frame();
        if overlap { f.set_u64(OFF_DATA, REQUEST); }
        else { f.set_u32(OFF_DATA_LENGTH, MAX_IO as u32 + 1); }
        domain_tasks::reset(&f, REQUEST);
        let mut data = [0x77; MAX_IO];
        assert_eq!(prepared(OWNER, REQUEST, &mut data).err(), Some(if overlap { Error::Format } else { Error::Range }));
        assert!(data.iter().all(|byte| *byte == 0x77));
    }
}
#[test]
fn frame_output_must_be_writable_including_code_and_readonly_regions() {
    for address in [READONLY, 0x10000] {
        let f = write_frame();
        domain_tasks::reset(&f, address);
        assert_eq!(prepared(OWNER, address, &mut [0; MAX_IO]).err(), Some(Error::Auth));
    }
}
#[test]
fn read_output_cannot_target_readonly_memory() {
    let mut f = Frame::new(READ, 1, Capability { id: 1, generation: 1 });
    f.set_u64(OFF_DATA, READONLY);
    f.set_u32(OFF_DATA_LENGTH, 64);
    domain_tasks::reset(&f, REQUEST);
    assert_eq!(prepared(OWNER, REQUEST, &mut [0; MAX_IO]).err(), Some(Error::Auth));
}
#[test]
fn foreign_exiting_or_contended_owner_cannot_enter_the_memory_callback() {
    let f = write_frame();
    domain_tasks::reset(&f, REQUEST);
    let called = AtomicBool::new(false);
    let foreign = ObjectKey { id: OWNER.id, generation: OWNER.generation + 1 };
    assert_eq!(domain_tasks::with_user_memory(foreign, |_| { called.store(true, Ordering::Release); Ok(()) }), Err(Error::Stale));
    domain_tasks::exiting();
    assert_eq!(domain_tasks::with_user_memory(OWNER, |_| { called.store(true, Ordering::Release); Ok(()) }), Err(Error::Stale));
    domain_tasks::reset(&f, REQUEST);
    domain_tasks::LIMIT.store(0, Ordering::Release);
    assert_eq!(domain_tasks::with_user_memory(OWNER, |_| { called.store(true, Ordering::Release); Ok(()) }), Err(Error::Busy));
    assert!(!called.load(Ordering::Acquire));
}
fn pending_result() -> Frame {
    let mut frame = Frame::new(READ, 4, Capability { id: 1, generation: 1 });
    frame.set_u64(OFF_COUNT, 64);
    domain_tasks::reset(&frame, REQUEST);
    unsafe {
        (&mut *core::ptr::addr_of_mut!(DATA))[..64].fill(0x3c);
        *core::ptr::addr_of_mut!(PENDING) = Some(Pending {
            owner: OWNER, address: REQUEST, data_address: DATA_ADDRESS, data_len: 64,
            frame, capture_io: None, capture_len: 0, capture_misses: 0,
        });
    }
    CLEARED.store(false, Ordering::Release);
    frame
}
#[test]
fn retained_data_and_frame_are_delivered_under_one_owner_borrow() {
    let expected = pending_result();
    domain_tasks::LIMIT.store(1, Ordering::Release);
    let mut context = Context { regs: [99; 31] };
    context.regs[1] = REQUEST;
    deliver(OWNER, &mut context).expect("retained delivery reacquired the owner gate");
    assert_eq!(context.regs[0], 0);
    assert!(CLEARED.load(Ordering::Acquire));
    assert_eq!(domain_tasks::GATES.load(Ordering::Acquire), 1);
    domain_tasks::LIMIT.store(u64::MAX, Ordering::Release);
    let mut data = [0; 64];
    domain_tasks::copyin(OWNER, DATA_ADDRESS, &mut data).unwrap();
    assert_eq!(data, [0x3c; 64]);
    let mut frame = [0; FRAME_BYTES];
    domain_tasks::copyin(OWNER, REQUEST, &mut frame).unwrap();
    assert_eq!(frame, expected.bytes);
}
#[test]
fn failed_delivery_keeps_the_same_receipt_and_context_until_real_copyout() {
    pending_result();
    domain_tasks::LIMIT.store(0, Ordering::Release);
    let mut context = Context { regs: [99; 31] };
    context.regs[1] = REQUEST;
    assert_eq!(deliver(OWNER, &mut context), Err(Error::Busy));
    assert!(!CLEARED.load(Ordering::Acquire));
    assert_eq!(context.regs[0], 99);
    domain_tasks::GATES.store(0, Ordering::Release);
    domain_tasks::LIMIT.store(1, Ordering::Release);
    deliver(OWNER, &mut context).unwrap();
    assert!(CLEARED.load(Ordering::Acquire));
    assert_eq!(context.regs[0], 0);
}
#[test]
fn failed_header_copy_keeps_original_error_stage_and_staging_bytes() {
    domain_tasks::reset(&write_frame(), REQUEST);
    let mut input = Frame { bytes: [0x77; FRAME_BYTES] };
    let mut data = [0x77; MAX_IO];
    let mut copied = false;
    assert!(prepare_input(OWNER, 0x80000, &mut input, &mut data, &mut copied).is_err());
    assert!(!copied);
    assert_eq!(input.bytes, [0x77; FRAME_BYTES]);
    assert!(data.iter().all(|byte| *byte == 0x77));
}
#[test]
fn invalid_copied_frame_retains_its_distinct_error_delivery_stage() {
    let mut invalid = write_frame();
    invalid.bytes[0] ^= 1;
    domain_tasks::reset(&invalid, REQUEST);
    let mut input = Frame { bytes: [0; FRAME_BYTES] };
    let mut data = [0x77; MAX_IO];
    let mut copied = false;
    assert_eq!(prepare_input(OWNER, REQUEST, &mut input, &mut data, &mut copied), Err(Error::Format));
    assert!(copied, "copied frame lost its error-delivery stage");
    assert_eq!(input.bytes, invalid.bytes);
    assert!(data.iter().all(|byte| *byte == 0x77));
}

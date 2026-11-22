extern crate self as cyxia_arch_aarch64;
use cyxia_prototype::{
    domains::{Error, ObjectKey, filesystem::*},
    journal::{self, BlockDevice, Journal},
    snapshot::{FileReqKey, SnapshotKey},
    storage::{BLOCK_SIZE, TOTAL_BLOCKS},
};
use std::{cell::RefCell, collections::BTreeMap, sync::atomic::{AtomicBool, AtomicU64, Ordering}};
pub mod cpu { pub fn slot() -> usize { 0 } }
pub mod timer { pub fn ticks() -> u64 { super::NOW.fetch_add(1, super::Ordering::Relaxed) } }
pub mod user { #[derive(Default)] pub struct Context { pub regs: [u64; 31] } }
static NOW: AtomicU64 = AtomicU64::new(1);
static WRITES: AtomicU64 = AtomicU64::new(0);
static FAIL_COPYOUT: AtomicBool = AtomicBool::new(false);
static FAIL_COPYOUT_ADDRESS: AtomicU64 = AtomicU64::new(RESPONSE);
const REQUEST: u64 = 0x1000;
const RESPONSE: u64 = 0x3000;
const DATA: u64 = 0x6000;
const UUID: [u8; 16] = [7; 16];
const OWNER: ObjectKey = ObjectKey { id: 11, generation: 1 };
const AUDITOR: ObjectKey = ObjectKey { id: 12, generation: 1 };
const RECOVERY: ObjectKey = ObjectKey { id: 13, generation: 1 };
#[derive(Default)] struct Disk(BTreeMap<u32, [u8; 4096]>);
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 { TOTAL_BLOCKS }
    fn read_block(&mut self, block: u32, out: &mut [u8; BLOCK_SIZE]) -> Result<(), ()> {
        *out = self.0.get(&block).copied().unwrap_or([0; 4096]); Ok(())
    }
    fn write_block(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), ()> {
        WRITES.fetch_add(1, Ordering::Relaxed); self.0.insert(block, *data); Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> { Ok(()) }
}
struct State { fs: FileSystem<64>, journal: Journal, disk: Disk, scratch: [u8; 8192] }
thread_local! {
    static FS: RefCell<Option<State>> = const { RefCell::new(None) };
    static USER: RefCell<Vec<u8>> = RefCell::new(vec![0; 0x10000]);
}
fn with_fs<R>(f: impl FnOnce(&mut FileSystem<64>, &mut Journal, &mut Disk, &mut [u8; 8192]) -> R) -> R {
    FS.with(|state| {
        let mut state = state.borrow_mut();
        let State { fs, journal, disk, scratch } = state.as_mut().unwrap();
        f(fs, journal, disk, scratch)
    })
}
mod prototype_storage {
    pub struct Identity { pub epoch: u64 }
    pub fn identity() -> Option<Identity> { Some(Identity { epoch: 1 }) }
}
mod storage_fault_capture {
    use super::*;
    pub const PROFILE: bool = false;
    pub fn selected(_: ObjectKey) -> bool { false }
    pub fn entered(_: ObjectKey, _: &[u8]) -> Result<(), Error> { Ok(()) }
    pub fn snapshot() -> Option<[u64; 4]> { None }
    pub fn delivered(_: ObjectKey, _: &[u8], _: &[u8], _: u64, _: [u64; 4]) {}
    pub fn snapshot_failed() {}
}
mod domain_storage {
    use super::*;
    include!("__SNAPSHOT_ADAPTER__");
    pub fn read(h: Handle, o: u64, b: &mut [u8], _: &mut dyn FnMut()) -> Result<usize, Error> { with_fs(|f,j,d,s| f.read(h,o,b,0,j,d,s)) }
    pub fn write(h: Handle, o: u64, b: &[u8], _: &mut dyn FnMut()) -> Result<usize, Error> { with_fs(|f,j,d,s| f.write(h,o,b,j,d,s)) }
    pub fn create(p: &str, _: &mut dyn FnMut()) -> Result<ObjectKey, Error> { with_fs(|f,j,d,s| f.create(p,j,d,s)) }
    pub fn mkdir(p: &str, _: &mut dyn FnMut()) -> Result<ObjectKey, Error> { with_fs(|f,j,d,s| f.mkdir(p,j,d,s)) }
    pub fn open(p: &str, m: OpenMode, _: &mut dyn FnMut()) -> Result<Handle, Error> { with_fs(|f,j,d,s| f.open(p,m,j,d,s)) }
    pub fn close(h: Handle) -> Result<(), Error> { with_fs(|f,_,_,_| f.close(h)) }
    pub fn handle_object(h: Handle) -> Result<ObjectKey, Error> { with_fs(|f,_,_,_| f.handle_object(h)) }
    pub fn fsync(h: Handle, _: &mut dyn FnMut()) -> Result<SyncReceipt, Error> { with_fs(|f,j,d,s| f.fsync(h,j,d,s)) }
    pub fn readdir(h: Handle, c: u16, _: &mut dyn FnMut()) -> Result<Option<Entry>, Error> { with_fs(|f,j,d,s| f.readdir(h,c,j,d,s)) }
    pub fn stat(p: &str, _: &mut dyn FnMut()) -> Result<Stat, Error> { with_fs(|f,j,d,s| f.stat(p,j,d,s)) }
    pub fn unlink(p: &str, _: &mut dyn FnMut()) -> Result<(), Error> { with_fs(|f,j,d,s| f.unlink(p,j,d,s)) }
    pub fn metrics() -> Metrics { with_fs(|f,_,_,_| f.metrics()) }
    pub fn read_io_demand(h: Handle, o: u64, n: usize) -> Result<bool, Error> { with_fs(|f,_,_,_| f.read_io_demand(h,o,n,0,true)) }
    pub fn write_io_demand(h: Handle, o: u64, n: usize) -> Result<bool, Error> { with_fs(|f,_,_,_| f.write_io_demand(h,o,n)) }
    pub fn readdir_io_demand(h: Handle) -> Result<bool, Error> { with_fs(|f,_,_,_| f.readdir_io_demand(h)) }
}
mod domain_tasks {
    use super::*;
    pub struct Memory;
    impl Memory {
        pub fn copyin(&mut self, address: u64, out: &mut [u8]) -> Result<(), Error> {
            USER.with(|user| { out.copy_from_slice(user.borrow().get(address as usize..address as usize + out.len()).ok_or(Error::Range)?); Ok(()) })
        }
        pub fn copyout(&mut self, address: u64, bytes: &[u8]) -> Result<(), Error> {
            if address == FAIL_COPYOUT_ADDRESS.load(Ordering::Acquire) && FAIL_COPYOUT.swap(false, Ordering::AcqRel) { return Err(Error::Again); }
            USER.with(|user| { user.borrow_mut().get_mut(address as usize..address as usize + bytes.len()).ok_or(Error::Range)?.copy_from_slice(bytes); Ok(()) })
        }
        pub fn probe(&mut self, address: u64, length: usize, _: bool) -> Result<(), Error> {
            USER.with(|user| if (address as usize).checked_add(length).is_some_and(|end| end <= user.borrow().len()) { Ok(()) } else { Err(Error::Range) })
        }
    }
    pub fn with_user_memory<R>(_: ObjectKey, f: impl FnOnce(&mut Memory) -> Result<R, Error>) -> Result<R, Error> { f(&mut Memory) }
    pub fn copyin(_: ObjectKey, address: u64, out: &mut [u8]) -> Result<(), Error> { Memory.copyin(address,out) }
    pub fn copyout(_: ObjectKey, address: u64, data: &[u8]) -> Result<(), Error> { Memory.copyout(address,data) }
    pub fn pending_file_requests() -> Result<[Option<(ObjectKey,u64)>; 60],Error> { Ok([None;60]) }
    pub fn grant_file_cap(_: ObjectKey, _: ObjectKey) -> Result<u64, Error> { Ok(99) }
}
#[path = "__BROKER__"] mod broker;
use broker::abi::{self as file, snapshot as wire};
fn key(slot: u32, seq: u64) -> FileReqKey { FileReqKey { fs_uuid: UUID, client_slot: slot, client_generation: 1, request_seq: seq } }
fn request(operation: u16, cap: ObjectKey, key: FileReqKey, epoch: u64, payload: &[u8]) -> wire::RequestBuffer {
    let mut encoded = [0;36]; key.encode(&mut encoded).unwrap();
    let mut result = wire::RequestBuffer::new(operation, cap.id as u32, encoded, epoch);
    result.set_payload(payload).unwrap(); result
}
fn context(cap: ObjectKey) -> user::Context {
    let mut context = user::Context::default();
    context.regs[8] = wire::SERVICE_CALL;
    context.regs[0] = cap.id; context.regs[1] = REQUEST; context.regs[2] = cap.generation;
    context.regs[3] = RESPONSE; context.regs[4] = wire::MAX_RESPONSE as u64; context
}
fn submit(owner: ObjectKey, cap: ObjectKey, request: &wire::RequestBuffer) -> (i64, Vec<u8>) {
    USER.with(|user| {
        let mut user = user.borrow_mut();
        user[REQUEST as usize..REQUEST as usize + request.len].copy_from_slice(request.as_bytes());
        user[RESPONSE as usize..RESPONSE as usize + wire::MAX_RESPONSE].fill(0xa5);
    });
    let mut c = context(cap);
    assert_eq!(broker::dispatch(owner, &mut c, &mut || {}), broker::DispatchResult::Returned);
    assert!(!broker::pending_delivery(owner));
    let response = USER.with(|user| user.borrow()[RESPONSE as usize..RESPONSE as usize + wire::MAX_RESPONSE].to_vec());
    (c.regs[0] as i64, response)
}
fn old_call(owner: ObjectKey, frame: &mut file::Frame) -> i64 {
    domain_tasks::copyout(owner, REQUEST, &frame.bytes).unwrap();
    let mut c = user::Context::default(); c.regs[8] = file::DISPATCH; c.regs[1] = REQUEST;
    assert_eq!(broker::dispatch(owner, &mut c, &mut || {}), broker::DispatchResult::Returned);
    domain_tasks::copyin(owner, REQUEST, &mut frame.bytes).unwrap(); c.regs[0] as i64
}
fn authority(cap: ObjectKey) -> file::Capability { file::Capability { id: cap.id, generation: cap.generation } }
fn old_handle(frame: &mut file::Frame, token: u64, generation: u64) {
    frame.set_u64(file::OFF_HANDLE_ID, token); frame.set_u64(file::OFF_HANDLE_GENERATION, generation);
}
fn open_payload(key: SnapshotKey, path: &str) -> Vec<u8> {
    let mut result = vec![0;48 + path.len()]; key.encode(&mut result[..40]).unwrap();
    wire::put_u16(&mut result,40,path.len() as u16); result[48..].copy_from_slice(path.as_bytes()); result
}
fn run() {
    assert!(HANDLE_STORAGE_BYTES + broker::HANDLE_STORAGE_BYTES <= 128);
    println!("HANDLE_BUDGET PASS core={} broker={}", HANDLE_STORAGE_BYTES, broker::HANDLE_STORAGE_BYTES);
    assert!(broker::SNAPSHOT_COORDINATION_STORAGE_BYTES <= 4096);
    println!("SNAPSHOT_BUDGET PASS authorities={} completion={} total={}",
        broker::SNAPSHOT_AUTHORITY_STORAGE_BYTES,broker::SNAPSHOT_COMPLETION_STORAGE_BYTES,
        broker::SNAPSHOT_COORDINATION_STORAGE_BYTES);
    assert_eq!(cyxia_prototype::snapshot::history_prefix_digest(b"/team"),[
        0x72,0xe5,0xc4,0x58,0x76,0xa9,0x4f,0x87,0x8f,0xde,0x98,0x5b,0xb4,0x1e,0x06,0xd7,
        0x80,0xe8,0x44,0xad,0xa7,0x5b,0xcf,0x86,0x73,0xca,0x46,0xb0,0x33,0xe5,0x37,0x5a]);
    let mut disk = Disk::default(); let mut scratch = [0;8192];
    journal::format(&mut disk, UUID, &mut scratch).unwrap();
    let mut journal = Journal::new(); journal.mount(&mut disk,&mut scratch).unwrap();
    cyxia_prototype::boot::BootSession::new().allocate(&mut journal,&mut disk,&mut scratch,&mut [[0;4096];4]).unwrap();
    let mut fs = FileSystem::<64>::new(); fs.mount(&mut journal,&mut disk,&mut scratch).unwrap();
    fs.initialize_business(&mut journal,&mut disk,&mut scratch).unwrap();
    fs.mkdir("/team",&mut journal,&mut disk,&mut scratch).unwrap();
    fs.create("/team/value",&mut journal,&mut disk,&mut scratch).unwrap();
    let h = fs.open("/team/value",OpenMode::ReadWrite,&mut journal,&mut disk,&mut scratch).unwrap();
    fs.write(h,0,b"old bytes",&mut journal,&mut disk,&mut scratch).unwrap();
    fs.fsync(h,&mut journal,&mut disk,&mut scratch).unwrap(); fs.close(h).unwrap();
    fs.mkdir("/teal",&mut journal,&mut disk,&mut scratch).unwrap();
    fs.create("/teal/value",&mut journal,&mut disk,&mut scratch).unwrap();
    let mut long_prefix=String::new(); let component="p".repeat(63);
    for _ in 0..8 {
        long_prefix.push('/'); long_prefix.push_str(&component);
        fs.mkdir(&long_prefix,&mut journal,&mut disk,&mut scratch).unwrap();
    }
    assert_eq!(long_prefix.len(),512);
    FS.with(|state| *state.borrow_mut() = Some(State {fs,journal,disk,scratch}));
    let live = broker::grant(OWNER,file::ALL_RIGHTS).unwrap();
    let audit_files = broker::grant(AUDITOR,file::ALL_RIGHTS).unwrap();
    let rights = wire::RIGHT_CREATE | wire::RIGHT_LIST | wire::RIGHT_HISTORY_READ;
    let cap = broker::grant_snapshots(OWNER,UUID,1,1,rights,"/team").unwrap();
    let audit = broker::grant_snapshots(AUDITOR,UUID,2,1,wire::RIGHT_LIST,"").unwrap();
    assert_eq!(broker::grant_snapshots(AUDITOR,UUID,2,1,wire::RIGHT_RESTORE,""),Err(Error::Auth));
    assert_eq!(broker::grant_snapshots(AUDITOR,UUID,14,1,wire::RIGHT_CREATE,""),Err(Error::Auth));
    let q = request(wire::SNAP_LIST,live,FileReqKey::ZERO,0,&[]);
    assert_eq!(submit(OWNER,live,&q).0,-13,"ordinary ALL_RIGHTS minted snapshot authority");
    let q = request(wire::SNAP_LIST,cap,FileReqKey::ZERO,0,&[]);
    assert_eq!(submit(AUDITOR,cap,&q).0,-13,"capability crossed owner boundary");
    assert_eq!(submit(OWNER,ObjectKey {generation:cap.generation+1,..cap},&q).0,-13);
    let mut create = [0;16]; wire::put_u64(&mut create,0,3600); wire::put_u32(&mut create,8,2); wire::put_u32(&mut create,12,1);
    let before = WRITES.load(Ordering::Relaxed);
    let wrong_subject = request(wire::SNAP_CREATE,cap,key(2,1),1,&create);
    assert_eq!(submit(OWNER,cap,&wrong_subject).0,-13);
    assert_eq!(WRITES.load(Ordering::Relaxed),before);
    let unauthorized = request(wire::SNAP_CREATE,audit,key(2,1),1,&create);
    assert_eq!(submit(AUDITOR,audit,&unauthorized).0,-13);
    println!("AUTHORITY_BOUNDARIES PASS");

    let create_request = request(wire::SNAP_CREATE,cap,key(1,1),1,&create);
    domain_tasks::copyout(OWNER,REQUEST,create_request.as_bytes()).unwrap();
    let mut too_small = context(cap); too_small.regs[4] = 32;
    assert_eq!(broker::dispatch(OWNER,&mut too_small,&mut ||{}),broker::DispatchResult::Returned);
    assert_eq!(too_small.regs[0] as i64,-34);
    assert_eq!(WRITES.load(Ordering::Relaxed),before,"short result buffer permitted effect");
    let next_id = with_fs(|f,_,_,_|f.snapshot_control().unwrap().next_snapshot_id);
    let mut c = context(cap); FAIL_COPYOUT.store(true,Ordering::Release);
    assert_eq!(broker::dispatch(OWNER,&mut c,&mut ||{}),broker::DispatchResult::Returned);
    assert!(broker::pending_delivery(OWNER));
    let mut blocked = context(audit);
    let blocked_arguments = blocked.regs[..5].to_vec();
    assert_eq!(broker::dispatch(AUDITOR,&mut blocked,&mut||{}),broker::DispatchResult::RetryBeforeEffect);
    assert_eq!(&blocked.regs[..5],blocked_arguments.as_slice(),"pre-effect retry destroyed complete capability identity");
    // A competing v1 WRITE would copy its input over the shared DATA bank.
    // It must stay before preflight while the v2 reply retains that bank.
    let mut competing = file::Frame::new(file::WRITE,1,authority(audit_files));
    competing.set_u64(file::OFF_DATA,DATA); competing.set_u32(file::OFF_DATA_LENGTH,2048);
    domain_tasks::copyout(AUDITOR,DATA,&[0xcc;2048]).unwrap();
    domain_tasks::copyout(AUDITOR,REQUEST+0x800,&competing.bytes).unwrap();
    let mut blocked_v1 = user::Context::default();
    blocked_v1.regs[8]=file::DISPATCH; blocked_v1.regs[1]=REQUEST+0x800;
    assert_eq!(broker::dispatch(AUDITOR,&mut blocked_v1,&mut||{}),broker::DispatchResult::RetryBeforeEffect);
    assert!(broker::pending_delivery(OWNER));
    assert_eq!(with_fs(|f,_,_,_|f.snapshot_control().unwrap().next_snapshot_id),next_id+1);
    let durable_writes = WRITES.load(Ordering::Relaxed);
    let changed_input = request(wire::SNAP_CREATE,cap,key(1,2),1,&create);
    domain_tasks::copyout(OWNER,REQUEST,changed_input.as_bytes()).unwrap();
    assert_eq!(broker::dispatch(OWNER,&mut c,&mut ||{}),broker::DispatchResult::Returned);
    assert_eq!(c.regs[0],0); assert!(!broker::pending_delivery(OWNER));
    assert_eq!(WRITES.load(Ordering::Relaxed),durable_writes,"copyout retry replayed mutation");
    let mut key_bytes = [0;40]; domain_tasks::copyin(OWNER,RESPONSE+32,&mut key_bytes).unwrap();
    let snapshot = SnapshotKey::decode(&key_bytes).unwrap();
    assert_eq!(snapshot.snapshot_id,next_id);
    assert_eq!(submit(OWNER,cap,&create_request).0,0);
    assert_eq!(with_fs(|f,_,_,_|f.snapshot_control().unwrap().next_snapshot_id),next_id+1);
    let mut query_key = [0;36]; key(1,1).encode(&mut query_key).unwrap();
    let query = request(wire::QUERY_REQUEST,cap,FileReqKey::ZERO,0,&query_key);
    let (status,response) = submit(OWNER,cap,&query); assert_eq!(status,0);
    assert_eq!(wire::u32_at(&response,24),512);
    let query = request(wire::QUERY_REQUEST,audit,FileReqKey::ZERO,0,&query_key);
    assert_eq!(submit(AUDITOR,audit,&query).0,-13,"public request key exposed another principal's result");
    println!("RETAINED_COMPLETION PASS");

    let open = request(wire::SNAP_OPEN,cap,FileReqKey::ZERO,0,&open_payload(snapshot,"/team/value"));
    let (status,response) = submit(OWNER,cap,&open); assert_eq!(status,0);
    let token = wire::u64_at(&response,32);
    let out_of_scope = request(wire::SNAP_OPEN,cap,FileReqKey::ZERO,0,&open_payload(snapshot,"/teamish/value"));
    assert_eq!(submit(OWNER,cap,&out_of_scope).0,-13);
    let metadata_only = request(wire::SNAP_OPEN,audit,FileReqKey::ZERO,0,&open_payload(snapshot,"/team/value"));
    assert_eq!(submit(AUDITOR,audit,&metadata_only).0,-13);
    let same_length = request(wire::SNAP_OPEN,cap,FileReqKey::ZERO,0,&open_payload(snapshot,"/teal/value"));
    assert_eq!(submit(OWNER,cap,&same_length).0,-13,"prefix length substituted for exact digest identity");
    let other_prefix=broker::grant_snapshots(OWNER,UUID,1,1,rights,"/teal").unwrap();
    assert_ne!(other_prefix,cap,"same-length prefixes collapsed into one authority");
    let wrong_authority=request(wire::SNAP_OPEN,other_prefix,FileReqKey::ZERO,0,&open_payload(snapshot,"/team/value"));
    assert_eq!(submit(OWNER,other_prefix,&wrong_authority).0,-13);
    let long_cap=broker::grant_snapshots(OWNER,UUID,1,1,wire::RIGHT_HISTORY_READ,&long_prefix).unwrap();
    let long_open=request(wire::SNAP_OPEN,long_cap,FileReqKey::ZERO,0,&open_payload(snapshot,&long_prefix));
    let (long_status,long_reply)=submit(OWNER,long_cap,&long_open); assert_eq!(long_status,0,"512-byte prefix lost authority");
    let mut long_close=file::Frame::new(file::CLOSE,1,authority(long_cap));
    old_handle(&mut long_close,wire::u64_at(&long_reply,32),0); assert_eq!(old_call(OWNER,&mut long_close),0);
    with_fs(|f,j,d,s| { f.mkdir("/late",j,d,s).unwrap(); f.create("/late/value",j,d,s).unwrap(); });
    let late_cap=broker::grant_snapshots(OWNER,UUID,1,1,wire::RIGHT_HISTORY_READ,"/late").unwrap();
    let late=request(wire::SNAP_OPEN,late_cap,FileReqKey::ZERO,0,&open_payload(snapshot,"/late/value"));
    assert_eq!(submit(OWNER,late_cap,&late).0,-2,"missing historical prefix fell back to live namespace");
    println!("PREFIX_DIGEST_SCOPE PASS");
    let mut f = file::Frame::new(file::OPEN,1,authority(live)); f.set_path("/team/value"); f.set_u16(file::OFF_MODE,file::MODE_READ_WRITE);
    assert_eq!(old_call(OWNER,&mut f),0);
    let live_handle = (f.u64(file::OFF_HANDLE_ID),f.u64(file::OFF_HANDLE_GENERATION));
    domain_tasks::copyout(OWNER,DATA,b"new bytes").unwrap();
    f = file::Frame::new(file::WRITE,2,authority(live)); old_handle(&mut f,live_handle.0,live_handle.1);
    f.set_u64(file::OFF_DATA,DATA); f.set_u32(file::OFF_DATA_LENGTH,9); assert_eq!(old_call(OWNER,&mut f),0);
    f = file::Frame::new(file::FSYNC,3,authority(live)); old_handle(&mut f,live_handle.0,live_handle.1); assert_eq!(old_call(OWNER,&mut f),0);
    f = file::Frame::new(file::READ,1,authority(cap)); old_handle(&mut f,token,0);
    f.set_u64(file::OFF_DATA,DATA); f.set_u32(file::OFF_DATA_LENGTH,9); assert_eq!(old_call(OWNER,&mut f),0);
    let mut data = [0;9]; domain_tasks::copyin(OWNER,DATA,&mut data).unwrap(); assert_eq!(&data,b"old bytes");
    f = file::Frame::new(file::READ,4,authority(live)); old_handle(&mut f,token,0);
    f.set_u64(file::OFF_DATA,DATA); f.set_u32(file::OFF_DATA_LENGTH,9); assert_eq!(old_call(OWNER,&mut f),-13);
    for op in [file::WRITE,file::FSYNC,file::GET_STAT_CAP] {
        f = file::Frame::new(op,2,authority(cap)); old_handle(&mut f,token,0);
        assert_eq!(old_call(OWNER,&mut f),if op==file::GET_STAT_CAP{-13}else{-30});
    }
    println!("IMMUTABLE_HISTORY PASS");

    // Exercise the other direction: a retained v1 READ owns DATA while a V2
    // metadata request tries to produce a response in the same storage.
    let mut audit_frame = file::Frame::new(file::OPEN,1,authority(audit_files));
    audit_frame.set_path("/team/value"); audit_frame.set_u16(file::OFF_MODE,file::MODE_READ);
    assert_eq!(old_call(AUDITOR,&mut audit_frame),0);
    let audit_handle=(audit_frame.u64(file::OFF_HANDLE_ID),audit_frame.u64(file::OFF_HANDLE_GENERATION));
    audit_frame=file::Frame::new(file::READ,2,authority(audit_files));
    old_handle(&mut audit_frame,audit_handle.0,audit_handle.1);
    audit_frame.set_u64(file::OFF_DATA,DATA); audit_frame.set_u32(file::OFF_DATA_LENGTH,9);
    domain_tasks::copyout(AUDITOR,REQUEST,&audit_frame.bytes).unwrap();
    let mut retained_v1=user::Context::default(); retained_v1.regs[8]=file::DISPATCH; retained_v1.regs[1]=REQUEST;
    FAIL_COPYOUT_ADDRESS.store(DATA,Ordering::Release); FAIL_COPYOUT.store(true,Ordering::Release);
    assert_eq!(broker::dispatch(AUDITOR,&mut retained_v1,&mut||{}),broker::DispatchResult::Returned);
    assert!(broker::pending_delivery(AUDITOR));
    let list=request(wire::SNAP_LIST,cap,FileReqKey::ZERO,0,&[]);
    domain_tasks::copyout(OWNER,REQUEST+0x800,list.as_bytes()).unwrap();
    let mut blocked_v2=context(cap); blocked_v2.regs[1]=REQUEST+0x800;
    assert_eq!(broker::dispatch(OWNER,&mut blocked_v2,&mut||{}),broker::DispatchResult::RetryBeforeEffect);
    assert!(broker::pending_delivery(AUDITOR));
    assert_eq!(broker::dispatch(AUDITOR,&mut retained_v1,&mut||{}),broker::DispatchResult::Returned);
    assert_eq!(retained_v1.regs[0],0); assert!(!broker::pending_delivery(AUDITOR));
    domain_tasks::copyin(AUDITOR,DATA,&mut data).unwrap(); assert_eq!(&data,b"new bytes");
    FAIL_COPYOUT_ADDRESS.store(RESPONSE,Ordering::Release);
    audit_frame=file::Frame::new(file::CLOSE,3,authority(audit_files));
    old_handle(&mut audit_frame,audit_handle.0,audit_handle.1); assert_eq!(old_call(AUDITOR,&mut audit_frame),0);
    println!("SHARED_COMPLETION_CUSTODY PASS");

    let recovery = broker::grant_snapshot_recovery(RECOVERY,UUID,15,1,wire::RIGHT_RESTORE | wire::RIGHT_PROTECTION | wire::RIGHT_LIST,"").unwrap();
    let mut restore = [0;48]; snapshot.encode(&mut restore[..40]).unwrap(); wire::put_u32(&mut restore,40,2);
    let request = request(wire::SNAP_RESTORE,recovery,key(15,2),1,&restore);
    let restored = submit(RECOVERY,recovery,&request).0;
    assert_eq!(restored,0,"restore control {:?}",with_fs(|f,_,_,_|f.snapshot_control()));
    assert_eq!(domain_storage::snapshot_live_epoch().unwrap(),2);
    f = file::Frame::new(file::READ,5,authority(live)); old_handle(&mut f,live_handle.0,live_handle.1);
    f.set_u64(file::OFF_DATA,DATA); f.set_u32(file::OFF_DATA_LENGTH,9); assert_eq!(old_call(OWNER,&mut f),-116);
    f = file::Frame::new(file::GET_STAT_CAP,6,authority(live)); old_handle(&mut f,live_handle.0,live_handle.1); assert_eq!(old_call(OWNER,&mut f),-116);
    f = file::Frame::new(file::READ,3,authority(cap)); old_handle(&mut f,token,0);
    f.set_u64(file::OFF_DATA,DATA); f.set_u32(file::OFF_DATA_LENGTH,9); assert_eq!(old_call(OWNER,&mut f),0);
    domain_tasks::copyin(OWNER,DATA,&mut data).unwrap(); assert_eq!(&data,b"old bytes");
    assert_eq!(submit(RECOVERY,recovery,&request).0,0);
    assert_eq!(domain_storage::snapshot_live_epoch().unwrap(),2,"same durable request restored twice");
    println!("RESTORE_EPOCH PASS");
    broker::exit(OWNER).unwrap(); broker::exit(AUDITOR).unwrap(); broker::exit(RECOVERY).unwrap();
}
fn main() { std::thread::Builder::new().stack_size(32*1024*1024).spawn(run).unwrap().join().unwrap(); }

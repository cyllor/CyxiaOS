
extern crate self as cyxia_arch_aarch64;
use cyxia_prototype::{domains::{Error,ObjectKey,filesystem::*},journal::{self,Journal,BlockDevice},storage::{BLOCK_SIZE,TOTAL_BLOCKS}};
use std::{cell::RefCell,collections::BTreeMap,sync::{Mutex,atomic::{AtomicU64,AtomicBool,Ordering}}};
pub mod cpu{pub fn slot()->usize{0}}
pub mod timer{pub fn ticks()->u64{super::NOW.fetch_add(1,super::Ordering::Relaxed)}}
pub mod user{#[derive(Default)]pub struct Context{pub regs:[u64;31]}}
static NOW:AtomicU64=AtomicU64::new(0);
fn clock()->u64{NOW.load(Ordering::Relaxed)}
fn fail(code:u64)->!{panic!("actual client fail {code}")}
const BUFFER:u64=0x80000;
static YIELDS:AtomicU64=AtomicU64::new(0);
static CALLS:AtomicU64=AtomicU64::new(0);
fn yield_now(){YIELDS.fetch_add(1,Ordering::Relaxed);domain_storage::reclaim();}
fn progress(_:u64,_:u64){}
fn get(a:u64)->u64{USER.with(|u|u64::from_le_bytes(u.borrow()[a as usize..a as usize+8].try_into().unwrap()))}
const PROGRESS:u64=0x30000;
#[derive(Default)]struct Disk(BTreeMap<u32,[u8;4096]>);
impl BlockDevice for Disk{type Error=();fn block_count(&self)->u32{TOTAL_BLOCKS}
fn read_block(&mut self,b:u32,out:&mut[u8;BLOCK_SIZE])->Result<(),()>{DISK_READS.fetch_add(1,Ordering::Relaxed);*out=self.0.get(&b).copied().unwrap_or([0;4096]);Ok(())}
fn write_block(&mut self,b:u32,input:&[u8;BLOCK_SIZE])->Result<(),()>{DISK_WRITES.fetch_add(1,Ordering::Relaxed);self.0.insert(b,*input);Ok(())}fn flush(&mut self)->Result<(),()>{Ok(())}}
struct State{fs:FileSystem<4096>,journal:Journal,disk:Disk,scratch:[u8;8192]}
thread_local!{static FS:RefCell<Option<State>>=const{RefCell::new(None)};static USER:RefCell<Vec<u8>>=RefCell::new(vec![0;0xa0000]);}
fn with_fs<R>(f:impl FnOnce(&mut FileSystem<4096>,&mut Journal,&mut Disk,&mut[u8;8192])->R)->R{
FS.with(|s|{let mut s=s.borrow_mut();let State{fs,journal,disk,scratch}=s.as_mut().unwrap();f(fs,journal,disk,scratch)})}
mod prototype_storage{pub struct Identity{pub epoch:u64}pub fn identity()->Option<Identity>{Some(Identity{epoch:1})}}
mod storage_fault_capture{use super::*;pub const PROFILE:bool=false;pub fn selected(_:ObjectKey)->bool{false}
pub fn entered(_:ObjectKey,_:&[u8])->Result<(),Error>{Ok(())}pub fn snapshot()->Option<[u64;4]>{None}
pub fn delivered(_:ObjectKey,_:&[u8],_:&[u8],_:u64,_:[u64;4]){}pub fn snapshot_failed(){}}
mod domain_storage{use super::*;
 pub fn read(h:Handle,o:u64,b:&mut[u8],_:&mut dyn FnMut())->Result<usize,Error>{with_fs(|f,j,d,s|{let misses=f.metrics().cache_misses;let reads=DISK_READS.load(Ordering::Relaxed);let result=f.read(h,o,b,clock(),j,d,s);READS.lock().unwrap().push((f.metrics().cache_misses-misses,DISK_READS.load(Ordering::Relaxed)-reads));result})}
 pub fn write(h:Handle,o:u64,b:&[u8],_:&mut dyn FnMut())->Result<usize,Error>{with_fs(|f,j,d,s|{
 let key=f.handle_object(h).unwrap();let a=f.stat("/a10/pressure-a",j,d,s).unwrap();let path=if a.object==key{"/a10/pressure-a"}else{"/a10/pressure-b"};let before=f.stat(path,j,d,s).unwrap();let metric=f.metrics();let dw=DISK_WRITES.load(Ordering::Relaxed);let usage=f.cache_usage();let result=f.write(h,o,b,j,d,s);
 if result==Err(Error::Again){let after=f.stat(path,j,d,s).unwrap();assert_eq!((before.object,before.size,before.write_seq,before.durable_write_seq),(after.object,after.size,after.write_seq,after.durable_write_seq));assert_eq!(metric.write_bytes,f.metrics().write_bytes);assert_eq!(metric.dirty_pages,f.metrics().dirty_pages);assert_eq!(dw,DISK_WRITES.load(Ordering::Relaxed));AGAIN.fetch_add(1,Ordering::Relaxed);println!("REAL_FS_AGAIN offset={o} before_size={} before_seq={} cache={usage:?} zero_file_or_disk_effect=true",before.size,before.write_seq);}
 result})}
 pub fn create(p:&str,_:&mut dyn FnMut())->Result<ObjectKey,Error>{with_fs(|f,j,d,s|f.create(p,j,d,s))}
 pub fn mkdir(p:&str,_:&mut dyn FnMut())->Result<ObjectKey,Error>{with_fs(|f,j,d,s|f.mkdir(p,j,d,s))}
 pub fn open(p:&str,m:OpenMode,_:&mut dyn FnMut())->Result<Handle,Error>{with_fs(|f,j,d,s|f.open(p,m,j,d,s))}
 pub fn close(h:Handle)->Result<(),Error>{with_fs(|f,_,_,_|f.close(h))}
 pub fn handle_object(h:Handle)->Result<ObjectKey,Error>{with_fs(|f,_,_,_|f.handle_object(h))}
 pub fn fsync(h:Handle,_:&mut dyn FnMut())->Result<SyncReceipt,Error>{with_fs(|f,j,d,s|f.fsync(h,j,d,s))}
 pub fn readdir(h:Handle,c:u16,_:&mut dyn FnMut())->Result<Option<Entry>,Error>{with_fs(|f,j,d,s|f.readdir(h,c,j,d,s))}
 pub fn stat(p:&str,_:&mut dyn FnMut())->Result<Stat,Error>{with_fs(|f,j,d,s|f.stat(p,j,d,s))}
 pub fn unlink(p:&str,_:&mut dyn FnMut())->Result<(),Error>{with_fs(|f,j,d,s|f.unlink(p,j,d,s))}
 pub fn metrics()->Metrics{with_fs(|f,_,_,_|f.metrics())}
 pub fn read_io_demand(h:Handle,o:u64,n:usize)->Result<bool,Error>{with_fs(|f,_,_,_|f.read_io_demand(h,o,n,clock(),true))}
 pub fn write_io_demand(h:Handle,o:u64,n:usize)->Result<bool,Error>{with_fs(|f,_,_,_|f.write_io_demand(h,o,n))}
 pub fn readdir_io_demand(h:Handle)->Result<bool,Error>{with_fs(|f,_,_,_|f.readdir_io_demand(h))}
 pub fn shrink(){with_fs(|f,_,_,_|f.set_cache_partition(32,16).unwrap());}
 pub fn reclaim(){with_fs(|f,_,_,_|{while f.reclaim_cache()!=0{}});}
}
mod domain_tasks{use super::*;
 pub struct Memory;impl Memory{
 pub fn copyin(&mut self,a:u64,out:&mut[u8])->Result<(),Error>{USER.with(|u|{out.copy_from_slice(u.borrow().get(a as usize..a as usize+out.len()).ok_or(Error::Range)?);Ok(())})}
 pub fn copyout(&mut self,a:u64,b:&[u8])->Result<(),Error>{USER.with(|u|{u.borrow_mut().get_mut(a as usize..a as usize+b.len()).ok_or(Error::Range)?.copy_from_slice(b);Ok(())})}
 pub fn probe(&mut self,a:u64,n:usize,_:bool)->Result<(),Error>{USER.with(|u|if (a as usize).checked_add(n).is_some_and(|e|e<=u.borrow().len()){Ok(())}else{Err(Error::Range)})}}
 pub fn with_user_memory<R>(_:ObjectKey,f:impl FnOnce(&mut Memory)->Result<R,Error>)->Result<R,Error>{f(&mut Memory)}
 pub fn copyin(_:ObjectKey,a:u64,b:&mut[u8])->Result<(),Error>{Memory.copyin(a,b)}
 pub fn copyout(_:ObjectKey,a:u64,b:&[u8])->Result<(),Error>{Memory.copyout(a,b)}
 pub fn pending_file_requests()->Result<[Option<(ObjectKey,u64)>;60],Error>{Ok([None;60])}
 pub fn grant_file_cap(_:ObjectKey,_:ObjectKey)->Result<u64,Error>{Err(Error::Unsupported)}
}
#[path="__BROKER__"]mod broker;
use broker::abi as file;
fn owner()->ObjectKey{ObjectKey{id:11,generation:1}}

static DISK_WRITES:AtomicU64=AtomicU64::new(0);
static DISK_READS:AtomicU64=AtomicU64::new(0);
static STALLED:AtomicBool=AtomicBool::new(false);
static EXPIRE:AtomicBool=AtomicBool::new(false);
static DEADLINE:AtomicU64=AtomicU64::new(0);
static READS:Mutex<Vec<(u64,u64)>>=Mutex::new(Vec::new());
thread_local!{static LAST_AGAIN:RefCell<Option<file::Frame>>=const{RefCell::new(None)};}

static AGAIN:AtomicU64=AtomicU64::new(0);
fn put(a:u64,v:u64){USER.with(|u|u.borrow_mut()[a as usize..a as usize+8].copy_from_slice(&v.to_le_bytes()));}
fn handle(f:&mut file::Frame,id:u64,g:u64){f.set_u64(file::OFF_HANDLE_ID,id);f.set_u64(file::OFF_HANDLE_GENERATION,g);}
fn waiting(deadline:u64)->bool{let _=call(0,0,0,0,0,0);clock()<deadline}
fn call(op:u64,_a:u64,p:u64,_c:u64,_d:u64,_e:u64)->[u64;4]{
 if op==14 || op==15{return [0;4]}
 if op==0{
 if EXPIRE.load(Ordering::Relaxed)&&AGAIN.load(Ordering::Relaxed)>0{NOW.store(DEADLINE.load(Ordering::Relaxed),Ordering::Relaxed);}
 else{NOW.fetch_add(1_000_000_000,Ordering::Relaxed);}
 if !STALLED.load(Ordering::Relaxed){with_fs(|f,j,d,s|{f.background_flush(clock(),j,d,s).unwrap();});}
 return [0;4]}
 assert_eq!(op,file::DISPATCH);CALLS.fetch_add(1,Ordering::Relaxed);let frame=unsafe{&mut*(p as *mut file::Frame)};let submitted=*frame;domain_tasks::copyout(owner(),0x1000,&frame.bytes).unwrap();let mut c=user::Context::default();c.regs[8]=op;c.regs[1]=0x1000;let result=broker::dispatch(owner(),&mut c,&mut||{});assert_eq!(result,broker::DispatchResult::Returned);domain_tasks::copyin(owner(),0x1000,&mut frame.bytes).unwrap();if frame.result()==-11{LAST_AGAIN.with(|saved|*saved.borrow_mut()=Some(submitted));}if frame.result()<0{println!("REAL_BROKER result={} operation={} request={} offset={}",frame.result(),frame.u16(file::OFF_OPERATION),frame.u64(file::OFF_REQUEST),frame.u64(file::OFF_OFFSET));}[c.regs[0],c.regs[1],c.regs[2],0]
}
// ACTUAL_FILE_CALL

#[path="__CLIENT__"]mod storage_fault;
fn run(){
 let case=std::env::args().nth(1).unwrap_or_else(||"normal".into());
 STALLED.store(case=="stalled"||case=="identity",Ordering::Relaxed);EXPIRE.store(case=="deadline",Ordering::Relaxed);
 let mut disk=Disk::default();let mut scratch=[0;8192];journal::format(&mut disk,[1;16],&mut scratch).unwrap();let mut journal=Journal::new();journal.mount(&mut disk,&mut scratch).unwrap();cyxia_prototype::boot::BootSession::new().allocate(&mut journal,&mut disk,&mut scratch,&mut[[0;4096];4]).unwrap();
 let mut fs=FileSystem::<4096>::new();fs.mount(&mut journal,&mut disk,&mut scratch).unwrap();fs.set_cache_partition(if case=="partial"{191}else{192},16).unwrap();fs.set_writeback_baseline(32).unwrap();fs.mkdir("/a10",&mut journal,&mut disk,&mut scratch).unwrap();fs.create("/a10/value",&mut journal,&mut disk,&mut scratch).unwrap();let h=fs.open("/a10/value",OpenMode::ReadWrite,&mut journal,&mut disk,&mut scratch).unwrap();
 for version in 1..=3u64{let mut data=[0u8;4096];for(i,b)in data.chunks_exact_mut(8).enumerate(){b.copy_from_slice(&(0xa100_0000_0000_0000u64|(version<<32)|i as u64).to_le_bytes());}fs.write(h,0,&data,&mut journal,&mut disk,&mut scratch).unwrap();fs.fsync(h,&mut journal,&mut disk,&mut scratch).unwrap();}fs.close(h).unwrap();
 FS.with(|s|*s.borrow_mut()=Some(State{fs,journal,disk,scratch}));let a=broker::grant(owner(),if case=="auth"{file::ALL_RIGHTS&!file::RIGHT_WRITE}else{file::ALL_RIGHTS}).unwrap();put(0x20000,40);put(0x21000,1);put(0x21008,4);put(0x21010,2);put(0x21018,1);put(0x21020,21_600_000_000_000);
 DEADLINE.store(clock()+21_600_000_000_000,Ordering::Relaxed);
 let result=storage_fault::run(file::Capability{id:a.id,generation:a.generation});println!("ACTUAL_CLIENT_RESULT {result} progress_stage={} progress_error={} real_again={} requests={}",get(0x30030),get(0x30060),AGAIN.load(Ordering::Relaxed),CALLS.load(Ordering::Relaxed));
 if case=="normal"||case=="partial"{
  assert_eq!(result,0);assert_eq!(get(0x30030),8);assert_eq!(get(0x30058),8192);assert!(AGAIN.load(Ordering::Relaxed)>0&&AGAIN.load(Ordering::Relaxed)<=90);
  let reads=READS.lock().unwrap();assert_eq!(reads.len(),2);assert!(reads[1].0>0&&reads[1].1>0);println!("REAL_CACHE_EVICTION final_misses={} final_backing_reads={}",reads[1].0,reads[1].1);drop(reads);
  with_fs(|f,j,d,s|{for(index,path)in[(1u64,"/a10/pressure-a"),(2,"/a10/pressure-b")]{let st=f.stat(path,j,d,s).unwrap();assert_eq!((st.size,st.write_seq,st.durable_write_seq),(8*1024*1024,128,128));let h=f.open(path,OpenMode::Read,j,d,s).unwrap();let mut data=[0;65536];for chunk in 0..128u64{assert_eq!(f.read(h,chunk*65536,&mut data,clock(),j,d,s).unwrap(),65536);for(word,b)in data.chunks_exact(8).enumerate(){assert_eq!(u64::from_le_bytes(b.try_into().unwrap()),0xa400_0000_0000_0000|(index<<48)|(chunk*8192+word as u64));}}f.close(h).unwrap();}});
  println!("REAL_DURABLE_PRESSURE both_8MiB_exact seq128 original8192 PASS");
 }else if case=="stalled"||case=="identity"{
  assert_eq!(result,214);assert_eq!(AGAIN.load(Ordering::Relaxed),91);assert!(clock()<DEADLINE.load(Ordering::Relaxed));println!("GLOBAL_RETRY_LIMIT retries90 completed_EAGAIN91 exact_error214 original_deadline_not_extended PASS");
  if case=="identity"{let old=LAST_AGAIN.with(|saved|saved.borrow().unwrap());let mut stale=old;assert!(file_call(&mut stale,DEADLINE.load(Ordering::Relaxed)));assert_eq!(stale.result(),-116);with_fs(|f,j,d,s|{assert!(f.background_flush(clock(),j,d,s).unwrap().is_some());});let mut fresh=old;fresh.set_u64(file::OFF_REQUEST,old.u64(file::OFF_REQUEST)+1);assert!(file_call(&mut fresh,DEADLINE.load(Ordering::Relaxed)));assert_eq!(fresh.result(),0);assert_eq!(fresh.u64(file::OFF_COUNT),65536);println!("OLD_COMPLETED_ID_STALE new_request_same_offset_after_actual_flush_success PASS");}
 }else if case=="deadline"{assert_eq!(result,205);assert_eq!(AGAIN.load(Ordering::Relaxed),1);assert!(clock()>=DEADLINE.load(Ordering::Relaxed));println!("ORIGINAL_ABSOLUTE_DEADLINE error205 no_new_write PASS");}
 else if case=="auth"{assert_eq!(result,207);assert_eq!(AGAIN.load(Ordering::Relaxed),0);println!("REAL_AUTH_FAILURE fatal207 no_retry PASS");}
 else{panic!("unknown case {case}");}

}
fn main(){std::thread::Builder::new().stack_size(192*1024*1024).spawn(run).unwrap().join().unwrap();}

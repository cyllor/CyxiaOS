"""Real file broker + real Journal/FS + source-extracted ordinary client READ.

Only CPU clock/slot and bounded user-copy are host seams. No error result or
receipt state is injected: the real cache partition/reclaim path creates AGAIN.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest
from doctor import ROOT,RUST_BIN,env
from host_prototype_library import build_host_prototype_library
from test_a01_formal_recorder import function


class RealFileBackpressure(unittest.TestCase):
    def test_500_requests_then_completed_again_requires_fresh_read_identity(self):
        client=(ROOT/'user/prototype-memory-client/main.rs').read_text()
        program=r'''
extern crate self as cyxia_arch_aarch64;
use cyxia_prototype::{domains::{Error,ObjectKey,filesystem::*},journal::{self,Journal,BlockDevice},storage::{BLOCK_SIZE,TOTAL_BLOCKS}};
use std::{cell::RefCell,collections::BTreeMap,sync::atomic::{AtomicU64,Ordering}};
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
fn get(_:u64)->u64{0}
const PROGRESS:u64=0x30000;
#[derive(Default)]struct Disk(BTreeMap<u32,[u8;4096]>);
impl BlockDevice for Disk{type Error=();fn block_count(&self)->u32{TOTAL_BLOCKS}
fn read_block(&mut self,b:u32,out:&mut[u8;BLOCK_SIZE])->Result<(),()>{*out=self.0.get(&b).copied().unwrap_or([0;4096]);Ok(())}
fn write_block(&mut self,b:u32,input:&[u8;BLOCK_SIZE])->Result<(),()>{self.0.insert(b,*input);Ok(())}fn flush(&mut self)->Result<(),()>{Ok(())}}
struct State{fs:FileSystem<64>,journal:Journal,disk:Disk,scratch:[u8;8192]}
thread_local!{static FS:RefCell<Option<State>>=const{RefCell::new(None)};static USER:RefCell<Vec<u8>>=RefCell::new(vec![0;0xa0000]);}
fn with_fs<R>(f:impl FnOnce(&mut FileSystem<64>,&mut Journal,&mut Disk,&mut[u8;8192])->R)->R{
FS.with(|s|{let mut s=s.borrow_mut();let State{fs,journal,disk,scratch}=s.as_mut().unwrap();f(fs,journal,disk,scratch)})}
mod prototype_storage{pub struct Identity{pub epoch:u64}pub fn identity()->Option<Identity>{Some(Identity{epoch:1})}}
mod storage_fault_capture{use super::*;pub const PROFILE:bool=false;pub fn selected(_:ObjectKey)->bool{false}
pub fn entered(_:ObjectKey,_:&[u8])->Result<(),Error>{Ok(())}pub fn snapshot()->Option<[u64;4]>{None}
pub fn delivered(_:ObjectKey,_:&[u8],_:&[u8],_:u64,_:[u64;4]){}pub fn snapshot_failed(){}}
mod domain_storage{use super::*;
 pub fn read(h:Handle,o:u64,b:&mut[u8],_:&mut dyn FnMut())->Result<usize,Error>{with_fs(|f,j,d,s|f.read(h,o,b,clock(),j,d,s))}
 pub fn write(h:Handle,o:u64,b:&[u8],_:&mut dyn FnMut())->Result<usize,Error>{with_fs(|f,j,d,s|f.write(h,o,b,j,d,s))}
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
#[path="BROKER_PATH"]mod broker;
use broker::abi as file;
fn owner()->ObjectKey{ObjectKey{id:11,generation:1}}
fn call(op:u64,_:u64,p:u64,_:u64)->[u64;3]{
 assert_eq!(op,file::DISPATCH);CALLS.fetch_add(1,Ordering::Relaxed);
 let frame=unsafe{&mut*(p as *mut file::Frame)};domain_tasks::copyout(owner(),0x1000,&frame.bytes).unwrap();
 let mut c=user::Context::default();c.regs[8]=op;c.regs[1]=0x1000;
 assert_eq!(broker::dispatch(owner(),&mut c,&mut||{}),broker::DispatchResult::Returned);
 domain_tasks::copyin(owner(),0x1000,&mut frame.bytes).unwrap();[c.regs[0],c.regs[1],c.regs[2]]
}
struct Client{authority:file::Capability,next:u64,deadline:u64}
impl Client{
// ACTUAL_FRAME
// ACTUAL_RUN
// ACTUAL_READ
}
fn run(){
 let mut disk=Disk::default();let mut scratch=[0;8192];journal::format(&mut disk,[1;16],&mut scratch).unwrap();let mut journal=Journal::new();journal.mount(&mut disk,&mut scratch).unwrap();
 cyxia_prototype::boot::BootSession::new().allocate(&mut journal,&mut disk,&mut scratch,&mut[[0;4096];4]).unwrap();
 let mut fs=FileSystem::<64>::new();fs.mount(&mut journal,&mut disk,&mut scratch).unwrap();fs.create("/data",&mut journal,&mut disk,&mut scratch).unwrap();let h=fs.open("/data",OpenMode::ReadWrite,&mut journal,&mut disk,&mut scratch).unwrap();
 for page in 0..65u64{fs.write(h,page*4096,&[page as u8;4096],&mut journal,&mut disk,&mut scratch).unwrap();fs.fsync(h,&mut journal,&mut disk,&mut scratch).unwrap();}fs.close(h).unwrap();
 FS.with(|s|*s.borrow_mut()=Some(State{fs,journal,disk,scratch}));let a=broker::grant(owner(),file::ALL_RIGHTS).unwrap();let mut c=Client{authority:file::Capability{id:a.id,generation:a.generation},next:0,deadline:1_000_000};
 let mut f=c.frame(file::OPEN);f.set_path("/data");f.set_u16(file::OFF_MODE,file::MODE_READ);c.run(&mut f);assert_eq!(f.result(),0);let id=f.u64(file::OFF_HANDLE_ID);let generation=f.u64(file::OFF_HANDLE_GENERATION);
 for _ in 0..500{let r=c.read_batch(id,generation,0,4096);assert_eq!(r.result(),0);assert_eq!(r.u64(file::OFF_COUNT),4096);}
 println!("ACTUAL_FILE_BROKER 500 sequential delivered READs passed; no 256-receipt exhaustion");
 domain_storage::shrink();let before=CALLS.load(Ordering::Relaxed);let r=c.read_batch(id,generation,4096,4096);
 assert_eq!(r.result(),0,"actual ordinary client failed to handle a completed real FS AGAIN");assert_eq!(r.u64(file::OFF_COUNT),4096);assert_eq!(CALLS.load(Ordering::Relaxed)-before,2);assert_eq!(YIELDS.load(Ordering::Relaxed),1);
 USER.with(|u|assert_eq!(&u.borrow()[BUFFER as usize..BUFFER as usize+4096],&[1;4096]));
 // A consumed completion cannot be replayed with its old request key.
 let mut old=r;c.run(&mut old);assert_eq!(old.result(),-116,"same completed request unexpectedly re-executed");
 println!("HOST_ONLY actual completed READ AGAIN -> fresh identity -> real clean reclaim -> success PASS");
}
fn main(){std::thread::Builder::new().stack_size(32*1024*1024).spawn(run).unwrap().join().unwrap();}
'''
        program=program.replace('BROKER_PATH',str(ROOT/'kernel/src/domain_file_abi.rs'))
        for marker,name in [('ACTUAL_FRAME','fn frame('),('ACTUAL_RUN','fn run('),('ACTUAL_READ','fn read_batch(')]:
            program=program.replace('// '+marker,function(client,name))
        deps,library=build_host_prototype_library()
        with tempfile.TemporaryDirectory(prefix='cyx-a09-file-') as temp:
            source,binary=Path(temp)/'harness.rs',Path(temp)/'harness';source.write_text(program)
            result=subprocess.run([str(RUST_BIN/'rustc'),'--edition=2024','-C','panic=abort',str(source),'-L','dependency='+str(deps),'--extern','cyxia_prototype='+str(library),'-o',str(binary)],env=env(),capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__=='__main__':unittest.main()

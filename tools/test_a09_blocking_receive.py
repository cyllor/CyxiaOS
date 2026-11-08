"""Real receive arm, task return, grant, Mailbox, wake tail + real IPC/Scheduler.

Only hardware clock/CPU observations and virtual user-buffer copy are host
seams. The test never sets RunState::Blocked or manufactures a wake itself.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest
from doctor import ROOT,RUST_BIN,env
from host_prototype_library import build_host_prototype_library
from test_a01_formal_recorder import function


class ActualBlockingReceive(unittest.TestCase):
    def test_empty_receive_settles_credit_then_only_authorized_message_wakes(self):
        execution=(ROOT/'kernel/src/domain_tasks/execution.rs').read_text()
        abi=(ROOT/'kernel/src/domain_tasks/abi.rs').read_text()
        parent=(ROOT/'kernel/src/domain_tasks.rs').read_text()
        arm='7 | 22 => {' if '7 | 22 => {' in abi else '7 => {'
        receive=function(abi,arm)
        wake_tail=function(execution,'    if s.wake & (1u64 << i) != 0 {')
        mailbox=function(abi,"pub(super) struct Mailbox<'a> {")+'\n'+function(abi,"impl IpcBackend<IPC_BYTES> for Mailbox<'_> {")
        program=r'''
use cyxia_prototype::domains::{Error,ObjectKey,tasks::*};
use core::sync::atomic::{AtomicBool,AtomicU64,Ordering};
use std::cell::{RefCell,UnsafeCell};
const TASKS:usize=3;const IPC_BYTES:usize=256;const ZERO:ObjectKey=ObjectKey{id:0,generation:0};
const KERNEL_CALLER:ObjectKey=ObjectKey{id:u64::MAX,generation:1};
static NOW:AtomicU64=AtomicU64::new(0);
fn now_ns()->u64{NOW.load(Ordering::Relaxed)}
mod cpu{pub fn slot()->usize{0}}
mod user{#[derive(Default)]pub struct Context{pub regs:[u64;31],pub kind:u64,pub esr:u64,pub pc:u64,pub far:u64}}
#[derive(Clone,Copy,PartialEq)]enum Life{Free,Ready,Running,Waiting,Exiting}
#[derive(Clone,Copy)]struct Task{key:ObjectKey,group:ObjectKey,endpoint:ObjectKey,caps:[ObjectKey;8],closed:bool,life:Life,recipe:u16,deadline:u64,exit_code:u64,terminal_seen:bool,response:u64,completed_sequence:u64,pending_sequence:u64,pending:bool,heartbeat_ns:u64,blocked:bool,cpu:u16,optional:bool}
#[derive(Clone,Copy)]struct Active{dispatch:Dispatch,state:RunState}
#[derive(Clone,Copy,Default)]struct Rate;impl Rate{fn add(&mut self,_:u64,_:u64){}}
struct Facts{wakes:[Rate;16]}
struct UserMemory{bytes:UnsafeCell<[u8;8192]>}
struct State{tasks:[Task;3],ipc:Box<Ipc<IPC_BYTES>>,memory:UserMemory,remote:Option<()>,wake:u64,scheduler:Scheduler,active:[Option<Active>;4],throttled:[Option<(ObjectKey,u64)>;2],facts:Facts}
thread_local!{static STATE:RefCell<Option<State>>=const{RefCell::new(None)};}
fn locked<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{STATE.with(|cell|f(cell.borrow_mut().as_mut().unwrap()))}
fn task_index(tasks:&[Task],key:ObjectKey)->Result<usize,Error>{tasks.iter().position(|t|t.key==key&&t.life!=Life::Free).ok_or(Error::Stale)}
fn group_index(_: &State,_:ObjectKey)->Result<usize,Error>{Ok(0)}
fn prepare(_: &mut UserMemory,_:&[Task],_:Option<()>,_:ObjectKey,address:u64,len:usize,_:bool)->Result<(),Error>{if address!=0x71000||len>8192{Err(Error::Range)}else{Ok(())}}
fn copy_to(memory:&UserMemory,_:ObjectKey,address:u64,bytes:&[u8])->Result<(),Error>{
 assert_eq!(address,0x71000);
 // The actual kernel's physical user-copy seam is represented by an owned
 // bounded RAM buffer; no IPC/authentication/scheduling behavior is replaced.
 unsafe{core::ptr::copy_nonoverlapping(bytes.as_ptr(),memory.bytes.get().cast::<u8>(),bytes.len());}Ok(())
}
fn copy_from(_: &UserMemory,_:&[Task],_:ObjectKey,_:u64,_:&mut[u8])->Result<(),Error>{Err(Error::Unsupported)}
static RETURN_PENDING:[AtomicBool;3]=[const{AtomicBool::new(false)};3];
static FILE_PENDING:[AtomicBool;3]=[const{AtomicBool::new(false)};3];
// REAL_ERROR
// REAL_GRANT
// REAL_MAILBOX
mod abi{use super::*;
 pub fn syscall_locked(s:&mut State,i:usize,context:&mut user::Context)->Result<(),Error>{
  let task=s.tasks[i];let args=[context.regs[0],context.regs[1],context.regs[2],context.regs[3],context.regs[4]];
  match context.regs[8]{ // REAL_RECEIVE_ARM
   _=>return Err(Error::Unsupported),
  }
  context.regs[0]=0;Ok(())
 }
 pub fn fault_locked(_: &mut State,_:ObjectKey,_:&user::Context)->Result<(),Error>{Err(Error::Unsupported)}
}
// REAL_RETURN
// REAL_WAKE
fn service_actual_notification(s:&mut State){for i in 0..3{ // REAL_WAKE_TAIL
}}
fn k(id:u64)->ObjectKey{ObjectKey{id,generation:1}}
fn context(op:u64)->user::Context{let mut c=user::Context::default();c.kind=8;c.esr=(0x15<<26)|0x45;c.regs[8]=op;c.regs[0]=0x71000;c.regs[1]=128;c}
fn run(){
 let tasks=core::array::from_fn(|i|Task{key:k(10+i as u64),group:k(1),endpoint:ZERO,caps:[ZERO;8],closed:false,life:Life::Ready,recipe:0,deadline:1_000_000_000,exit_code:0,terminal_seen:false,response:0,completed_sequence:0,pending_sequence:0,pending:false,heartbeat_ns:0,blocked:false,cpu:3,optional:false});
 let mut s=State{tasks,ipc:Box::new(Ipc::new()),memory:UserMemory{bytes:UnsafeCell::new([0;8192])},remote:None,wake:0,scheduler:Scheduler::new(),active:[None;4],throttled:[None;2],facts:Facts{wakes:[Rate;16]}};
 let layout=CpuLayout{business_mask:8,healthy_mask:15,generation:1};
 s.scheduler.register_group(k(1)).unwrap();
 s.scheduler.admit(ThreadSpec{key:k(11),group:k(1),cpu:3,allowed_mask:8,minimum_ns:0,budget_ns:10_000_000},layout,0).unwrap();
 let ep=s.ipc.open(k(11),false).unwrap();s.tasks[1].endpoint=ep;
 STATE.with(|cell|*cell.borrow_mut()=Some(s));
 locked(|s|{
  let d=s.scheduler.dispatch(3,layout,0,1_000_000)?.unwrap();s.active[3]=Some(Active{dispatch:d,state:RunState::Runnable});
  let mut c=context(22);process_return_inner(s,1,&mut c);
  assert_eq!(c.regs[0] as i64,-11,"blocking variant did not preserve AGAIN return semantics");
  let a=s.active[3].take().unwrap();assert_eq!(a.state,RunState::Blocked,"real task-return callsite left empty receiver Runnable");
  s.scheduler.complete(a.dispatch,1000,a.state,1000)?;
  assert!(s.scheduler.active(3).is_none());assert!(s.scheduler.dispatch(3,layout,2000,1_000_000)?.is_none(),"blocked receiver retained or reacquired a CPU credit");
  let stats=s.ipc.stats(ep)?;
  for endpoint in [ep,ObjectKey{generation:ep.generation+1,..ep}]{
   let mut backend=Mailbox{tasks:&s.tasks,wake:&mut s.wake,received:&mut[],used:0};
   assert!(s.ipc.send(k(12),endpoint,1,b"payload",2000,&mut backend).is_err());
   assert_eq!(s.wake,0,"unauthorized/stale send manufactured a wake");assert_eq!(s.ipc.stats(ep)?,stats,"unauthorized send consumed queue custody");
  }Ok(())
 }).unwrap();
 // Actual native grant_endpoint validates the endpoint owner's generation and
 // appends the real sender cap; the test does not set the cap array itself.
 grant_endpoint(k(11),k(10),ep).unwrap();NOW.store(3000,Ordering::Relaxed);
 locked(|s|{
  let mut backend=Mailbox{tasks:&s.tasks,wake:&mut s.wake,received:&mut[],used:0};
  s.ipc.send(k(10),ep,7,b"payload",3000,&mut backend)?;assert_eq!(s.wake,2);
  service_actual_notification(s);assert_eq!(s.wake,0);assert!(!s.tasks[1].blocked);
  let d=s.scheduler.dispatch(3,layout,3000,1_000_000)?.unwrap();s.active[3]=Some(Active{dispatch:d,state:RunState::Runnable});
  let mut c=context(22);process_return_inner(s,1,&mut c);assert_eq!(c.regs[0],0);assert_eq!(c.regs[1],1);
  assert_eq!(unsafe{&(&*s.memory.bytes.get())[32..39]},b"payload");let a=s.active[3].take().unwrap();assert_eq!(a.state,RunState::Runnable);
  s.scheduler.complete(a.dispatch,1000,a.state,4000)?;Ok(())
 }).unwrap();
 NOW.store(5000,Ordering::Relaxed);
 locked(|s|{let d=s.scheduler.dispatch(3,layout,5000,1_000_000)?.unwrap();s.active[3]=Some(Active{dispatch:d,state:RunState::Runnable});let mut c=context(7);process_return_inner(s,1,&mut c);assert_eq!(c.regs[0]as i64,-11);assert_eq!(s.active[3].unwrap().state,RunState::Runnable,"existing nonblocking receive semantics changed");Ok(())}).unwrap();
 println!("HOST_ONLY actual receive-return-credit-send-grant-wake PASS native_acceptance_status=NOT_RUN");
}
fn main(){std::thread::Builder::new().stack_size(32*1024*1024).spawn(run).unwrap().join().unwrap();}
'''
        replacements={
            '// REAL_ERROR':function(parent,'fn error_word('),
            '// REAL_GRANT':function(abi,'pub fn grant_endpoint('),
            '// REAL_MAILBOX':mailbox,
            '// REAL_RECEIVE_ARM':receive,
            '// REAL_RETURN':function(execution,'fn process_return_inner('),
            '// REAL_WAKE':function(execution,'pub(super) fn wake_task('),
            '// REAL_WAKE_TAIL':wake_tail,
        }
        for marker in sorted(replacements,key=len,reverse=True):program=program.replace(marker,replacements[marker].replace('pub(super)','pub'))
        deps,library=build_host_prototype_library()
        with tempfile.TemporaryDirectory(prefix='cyxia-a09-receive-') as temp:
            source,binary=Path(temp)/'harness.rs',Path(temp)/'harness';source.write_text(program)
            result=subprocess.run([str(RUST_BIN/'rustc'),'--edition=2024','-C','panic=abort',str(source),'-L','dependency='+str(deps),
                '--extern','cyxia_prototype='+str(library),'-o',str(binary)],env=env(),capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__=='__main__':unittest.main()

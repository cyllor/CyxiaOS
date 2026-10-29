//! Real supervisor and kernel backend wiring. Hardware/task effects in this
//! group are controlled boundaries; paid TaskGuard predicates have another group.
#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use std::sync::Mutex;
use cyxia_prototype::{domains::{ApplyId,Error,ObjectKey,PolicyStamp,maintenance::*},policy::ExecutionState};
const KEY:ObjectKey=ObjectKey{id:4153,generation:14};
const ID:ApplyId=ApplyId{boot_epoch:1,controller_epoch:1,plan_seq:443,action_index:0,target:KEY};
const STAMP:PolicyStamp=PolicyStamp{version:406,snapshot_ns:100_000_000,installed_until_ns:0};
pub mod cpu{pub fn slot()->usize{0}}
mod domain_platform{pub fn now_ns()->u64{100_000_000}}
// EVIDENCE_MODULE
#[derive(Default)]struct Hardware{closed:bool,drained:bool,stopped:bool,running:bool,start_error:Option<Error>,close_calls:u64,stop_calls:u64,start_calls:u64,queries:u64}
static HARDWARE:Mutex<Hardware>=Mutex::new(Hardware{closed:false,drained:false,stopped:false,running:false,start_error:None,close_calls:0,stop_calls:0,start_calls:0,queries:0});
mod domain_tasks{
 use super::*;
 pub fn close_admission(k:ObjectKey,a:ApplyId)->Result<(),Error>{assert_eq!((k,a),(KEY,ID));let mut h=HARDWARE.lock().unwrap();h.closed=true;h.close_calls+=1;Ok(())}
 pub fn readonly_drained(k:ObjectKey)->Result<bool,Error>{assert_eq!(k,KEY);let mut h=HARDWARE.lock().unwrap();h.queries+=1;Ok(h.drained)}
 pub fn request_stop(k:ObjectKey,a:ApplyId)->Result<(),Error>{assert_eq!((k,a),(KEY,ID));HARDWARE.lock().unwrap().stop_calls+=1;Ok(())}
 pub fn stopped(k:ObjectKey)->Result<bool,Error>{assert_eq!(k,KEY);let mut h=HARDWARE.lock().unwrap();h.queries+=1;Ok(h.stopped)}
 pub fn start_generation(k:ObjectKey,n:u64,a:ApplyId)->Result<(),Error>{assert_eq!((k,n,a),(KEY,15,ID));let mut h=HARDWARE.lock().unwrap();h.start_calls+=1;h.start_error.map_or(Ok(()),Err)}
 pub fn running(k:ObjectKey)->Result<bool,Error>{assert_eq!(k,ObjectKey{id:4153,generation:15});let mut h=HARDWARE.lock().unwrap();h.queries+=1;Ok(h.running)}
}
// KERNEL_RECOVERY_BACKEND
fn poll(r:&mut RecoverySupervisor,at:u64)->RecoveryReceipt{r.poll(ID,at,&mut Recovery{apply:ID}).unwrap()}
fn reset()->RecoverySupervisor{
 *HARDWARE.lock().unwrap()=Hardware::default();domain_evidence::clear_recovery();
 let mut r=RecoverySupervisor::new();r.register(KEY,2).unwrap();r.begin_policy(ID,2,STAMP,100_000_000).unwrap();r
}
fn latest()->[u64;26]{let h=domain_evidence::header();h[328..354].try_into().unwrap()}
fn advance_to_start(r:&mut RecoverySupervisor){
 poll(r,100_000_001);HARDWARE.lock().unwrap().drained=true;poll(r,100_000_002);
 poll(r,100_000_003);HARDWARE.lock().unwrap().stopped=true;poll(r,100_000_004);
}
#[test]fn recovery_observation_distinguishes_real_poll_from_receipt_query_and_preserves_original_time(){
 let mut r=reset();poll(&mut r,100_000_001);let h=domain_evidence::header();
 assert_eq!(h[320],0x4359_5253_5643_0001,"actual supervisor poll lost phase/backend evidence");
 assert_eq!(&h[328..334],&[1,1,443,0,4153,14]);let a=latest();
 assert_eq!((a[6],a[7],a[8],a[9],a[10],a[11],a[12],a[13],a[14],a[15],a[16]),(2,406,15,100_000_000,100_000_001,0,0,1,0,1,1));
 let before=h;for _ in 0..100{assert_eq!(r.query(ID).unwrap().state,ExecutionState::Pending);}
 assert_eq!(domain_evidence::header(),before,"receipt queries fabricated supervisor progress");
 poll(&mut r,1_100_000_000);let a=latest();assert_eq!((a[11],a[13],a[15],a[16],a[20]),(1,1,2,2,4));
 poll(&mut r,1_200_000_000);assert_eq!(latest()[10],1_200_000_000);assert_eq!(latest()[9],100_000_000);
 let h=domain_evidence::header();assert_eq!(h[325],1);assert_eq!(h[356+10],1_100_000_000,"later Unknown overwrote first Unknown for this apply");
}
#[test]fn recovery_observation_retains_ambiguous_start_without_reissuing_it(){
 for error in [Error::Io,Error::NotReady]{
 let mut r=reset();advance_to_start(&mut r);HARDWARE.lock().unwrap().start_error=Some(error);
 assert_eq!(poll(&mut r,100_000_005).state,ExecutionState::Unknown);let a=latest();
 assert_eq!((a[11],a[12],a[13],a[14],a[15],a[16],a[17]),(3,0,3,1,5,3,error as u64+1));
 for n in 0..3{poll(&mut r,1_100_000_000+n);}
 assert_eq!(HARDWARE.lock().unwrap().start_calls,1,"ambiguous start was issued twice");
 assert_eq!((latest()[15],latest()[16],latest()[20]),(6,2,4));
 HARDWARE.lock().unwrap().running=true;assert_eq!(poll(&mut r,1_200_000_000).state,ExecutionState::Applied);
 assert_eq!((latest()[13],latest()[14],latest()[20],latest()[22]),(4,0,2,1_200_000_000));
 }}
#[test]fn recovery_observation_preserves_retryable_start_and_recipe_separation(){
 for error in [Error::Busy,Error::Again]{
 let mut r=reset();advance_to_start(&mut r);HARDWARE.lock().unwrap().start_error=Some(error);
 poll(&mut r,100_000_005);assert_eq!((latest()[13],latest()[14],latest()[16]),(3,0,3));
 HARDWARE.lock().unwrap().start_error=None;poll(&mut r,100_000_006);
 assert_eq!(HARDWARE.lock().unwrap().start_calls,2);
 assert_eq!(domain_evidence::header()[256],0,"recipe2 wrote recipe1's lane");
 assert_eq!(domain_evidence::header()[383]%2,0);
 }}

//! Actual post-submit accounting boundary. Registry transition is an explicit
//! facade; the real Registry's retained-stop contract has its own Rust tests.
#![allow(dead_code)]
use core::sync::atomic::{AtomicU64,Ordering};
use cyxia_prototype::{domains::{Error,ObjectKey},policy::{self,CpuTime,PublicationTime,ModelBinding}};
static PUB:AtomicU64=AtomicU64::new(408_583);
mod timer{pub fn cpu_elapsed_ns(_:u64)->u64{super::PUB.load(super::Ordering::Acquire)}}
mod domain_platform{pub fn now_ns()->u64{4_462_500_992}}
// EVIDENCE_MODULE
struct Registry{stopped:bool}
impl Registry{fn optimization_stopped(&self)->bool{self.stopped}fn stop_optimization(&mut self){self.stopped=true}}
struct State{registry:Registry,boot:u64,sequence:u64}
struct Set{target:ObjectKey,model:ModelBinding}
struct Job{read_only:bool,controller:u64,sequence:u64,set:Set,cpu:usize}
fn post(s:&mut State,job:&Job,transition:bool,result:Result<u64,Error>,decoded_ns:Option<u64>){
    let publication_started=PublicationTime{wall_ns:4_457_264_000,cpu:CpuTime{cpu:2,ns:3_690_000_000}};
    let wall_begin=publication_started.wall_ns;
    let publication_cpu_started=Some(0);
    let decode_cpu_started=0;
    // ACTUAL_STOP_ORIGIN
    // This boundary models the actual Registry callback's return. It cannot
    // clear an already retained stop or alter a published receipt.
    if transition{s.registry.stopped=true;}
    // ACTUAL_POST_SUBMISSION
}
fn main(){
    let job=Job{read_only:false,controller:1,sequence:144,set:Set{target:ObjectKey{id:11,generation:1},
        model:ModelBinding{generation:1,model_hash:[1;32],schema_hash:[2;32]}},cpu:2};
    let mut s=State{registry:Registry{stopped:false},boot:1,sequence:144};
    post(&mut s,&job,true,Ok(135),Some(107_832));
    let w=domain_evidence::header();
    assert_eq!(w[160],0x4359_4f50_5354_0001,"Registry stopped without original publication provenance");
    assert_eq!(&w[164..177],&[1,4_457_264_000,1,1,144,11,1,135,0,0,107_832,408_583,516_415]);
    assert!(s.registry.stopped);assert_eq!(w[191]%2,0);
    PUB.store(500_001,Ordering::Release);post(&mut s,&job,false,Err(Error::Budget),Some(0));
    let w2=domain_evidence::header();assert_eq!(&w2[164..184],&w[164..184],"later stop replaced first original publication");
    assert_eq!(w2[162],1,"already stopped registry invented another transition");
    // Separate new boot fixture exercises the native post-decode meter's stop.
    s.registry.stopped=false;post(&mut s,&job,false,Err(Error::Budget),Some(0));
    assert!(s.registry.stopped,"diagnostic removed the original native budget stop");
    assert_eq!(domain_evidence::header()[162],2);
    println!("actual publication stop provenance passed");
}

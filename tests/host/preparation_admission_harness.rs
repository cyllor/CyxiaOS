//! Actual early preparation gate and Root projection; Registry/owners and
//! clocks are controlled boundaries, never native WCET or authority proofs.
#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicU64,AtomicUsize,Ordering};
use cyxia_prototype::{domains::{Error,ObjectKey,ApplyId},learning::Family,policy::Snapshot};
static CPU:AtomicUsize=AtomicUsize::new(1);
static NOW:AtomicU64=AtomicU64::new(100_000_000);
static CLOCKS:AtomicU64=AtomicU64::new(0);
static NORMAL:AtomicU64=AtomicU64::new(0);
pub mod cpu{pub fn slot()->usize{super::CPU.load(super::Ordering::Acquire)}}
mod domain_platform{pub fn now_ns()->u64{super::now()}}
fn now()->u64{CLOCKS.fetch_add(1,Ordering::Relaxed);NOW.load(Ordering::Acquire)}
const fn key(id:u64)->ObjectKey{ObjectKey{id,generation:1}}
// EVIDENCE_MODULE
mod control {
    use super::*;
    struct Owner{prepared_count:usize}
    struct Registry{stopped:bool}
    impl Registry{fn optimization_stopped(&self)->bool{self.stopped}fn publisher(&self)->u64{7}
        fn change_publisher(&mut self,_:u64,_:u64)->Result<(),Error>{Ok(())}}
    struct Jobs{reserved:bool,calls:u64}
    impl Jobs{fn reserves_publication(&mut self,_:u64)->bool{self.calls+=1;self.reserved}}
    #[derive(Clone,Copy)]struct Job{sequence:u64}
    #[derive(Clone,Copy)]struct Identity{sequence:u64,work:Option<u64>}
    #[derive(Clone,Copy)]struct Pending{identity:Identity}
    struct State{boot:u64,job:Option<Job>,registry:Registry,governance_jobs:Jobs,
        preparation:Option<Pending>,sequence:u64,owner:Owner}
    fn require_control(_: &Owner)->Result<(),Error>{if cpu::slot()>2{Err(Error::Auth)}else{Ok(())}}
    fn publisher(_:u64)->u64{7}
    fn preparation_phase(_:usize){}fn preparation_detail(_:usize){}
    fn clear_preparation_context(){}fn preparation_entry_detail(_:usize){}
    mod core_replay{use super::*;pub struct PaidWorkWitness;
        pub(super)fn next(_: &mut State,_:u64,_:&PaidWorkWitness,_:u64,_:u64,_:&mut[u64;512])->Result<bool,Error>{panic!("read-only work outside gate fixture")}}
    fn next_normal(_: &mut State,_:u64,_:Option<&core_replay::PaidWorkWitness>,_:u64,_:u64,_:&mut[u64;512])->Result<bool,Error>{NORMAL.fetch_add(1,Ordering::Relaxed);Ok(true)}
    // ACTUAL_NEXT_LOCKED
    mod replay {
        use super::*;
        #[derive(Clone,Copy,PartialEq,Eq)]enum TrialKind{Baseline,Candidate}
        #[derive(Clone,Copy,PartialEq,Eq)]enum Phase{Frozen,Running,Complete}
        #[derive(Clone,Copy)]struct Token{id:u64,boot_epoch:u64,owner:ObjectKey}
        #[derive(Clone,Copy)]struct Request{trial_id:u64,kind:TrialKind,family:Family,target:ObjectKey}
        struct Root{token:Option<Token>,request:Option<Request>,phase:Phase,first:Option<Snapshot>,first_ready:bool,initial:Option<ApplyId>}
        static mut ROOT:Root=Root{token:None,request:None,phase:Phase::Complete,first:None,first_ready:false,initial:None};
        fn root()->&'static Root{unsafe{&*core::ptr::addr_of!(ROOT)}}
        // ACTUAL_ROOT_PROJECTION
        pub fn reset(){unsafe{ROOT=Root{token:Some(Token{id:9,boot_epoch:1,owner:key(7)}),
            request:Some(Request{trial_id:2,kind:TrialKind::Candidate,family:Family{domain:1,kind:1},target:key(12)}),
            phase:Phase::Running,first:None,first_ready:false,initial:None}}}
    }
    pub fn scenario(){
        replay::reset();let mut s=State{boot:1,job:None,registry:Registry{stopped:false},governance_jobs:Jobs{reserved:false,calls:0},
            preparation:None,sequence:144,owner:Owner{prepared_count:0}};
        let mut input=[0;512];assert_eq!(next_locked_inner(&mut s,1,None,100_000_000,0,&mut input),Ok(true));
        let w=domain_evidence::header();assert_eq!(w[128],0x4359_4144_4d49_0001,"actual preparation gate has no admission evidence");
        assert_eq!(w[138],0);assert_eq!(NORMAL.load(Ordering::Acquire),1);
        for reason in 1..=4 {
            s.boot=if reason==1{0}else{1};s.job=(reason==2).then_some(Job{sequence:144});s.registry.stopped=reason==3;s.governance_jobs.reserved=reason==4;
            let calls=s.governance_jobs.calls;let clocks=CLOCKS.load(Ordering::Acquire);
            assert_eq!(next_locked_inner(&mut s,1,None,100_000_000+reason,0,&mut input),Ok(false));
            let w=domain_evidence::header();assert_eq!(w[138],reason,"actual early return lost its exact reason");
            assert_eq!(w[137],100_000_000+reason);assert_eq!((w[143],w[144],w[146],w[148],w[149],w[152],w[153]),(9,2,1,12,1,0,0));
            assert_eq!(NORMAL.load(Ordering::Acquire),1,"closed gate entered preparation work");
            assert_eq!(s.governance_jobs.calls-calls,u64::from(reason==4));
            assert_eq!(CLOCKS.load(Ordering::Acquire)-clocks,u64::from(reason==4),"diagnostics added an owner/clock query");
        }
        let w=domain_evidence::header();assert_eq!((w[130],w[131]),(5,4));assert_eq!(&w[132..136],&[1,1,1,1]);
        assert_eq!(w[194],1,"first candidate denial was replaced by later causes");assert_eq!(w[159]%2,0);
        CPU.store(3,Ordering::Release);let old=w;assert_eq!(next_locked_inner(&mut s,1,None,100_000_010,0,&mut input),Err(Error::Auth));
        assert_eq!(domain_evidence::header(),old,"unauthorized entry wrote diagnostic gate state");
        println!("actual preparation admission gate passed");
    }
}
fn main(){control::scenario();}

#![allow(dead_code)]
use cyxia_prototype::{domains::{Action,Error,ObjectKey,ApplyId},
    policy::{ExecutionState,Candidate,CandidateSet,Snapshot,ModelBinding,BoundDependency},features::RawFeatures,
    learning::Family as LearningFamily};
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};
fn key(id:u64)->ObjectKey{ObjectKey{id,generation:1}}
const SNAP:Snapshot=Snapshot{sequence:409,taken_ns:188_721_780_000,ledger_generation:7,core_generation:4};
fn now()->u64{210_128_534_000}
mod preparation { // ACTUAL_IDENTITY
}
mod core_replay {
    #[derive(Clone,Copy)] pub struct WorkId;
    pub fn evaluated(_:WorkId,_:u64,_:Result<u64,super::Error>,_:[u8;32])->Result<(),super::Error>{
        if super::DELIVERY_BUSY.load(super::Ordering::Acquire){Err(super::Error::Busy)}else{Ok(())}}
}
mod domain_evidence {
    pub fn finish(_:usize,_:u64,_:u64,_:u64,_:u64,_:u64,_:u64,_:super::ExecutionState,_:u64,_:Option<&[u64;512]>){super::EVIDENCE.fetch_add(1,super::Ordering::Relaxed);}
    pub fn aborted(){super::ABORTS.fetch_add(1,super::Ordering::Relaxed);}
}
static DELIVERY_BUSY:AtomicBool=AtomicBool::new(false);
static EVIDENCE:AtomicUsize=AtomicUsize::new(0);
static ABORTS:AtomicUsize=AtomicUsize::new(0);
// ACTUAL_JOB
// ACTUAL_COMPLETION
struct State{job:Option<Job>,boot:u64}
extern crate self as cyxia_arch_aarch64;
pub mod cpu{pub fn slot()->usize{1}}
static CONTROL:std::sync::Mutex<State>=std::sync::Mutex::new(State{job:None,boot:1});
fn with<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{f(&mut CONTROL.lock().unwrap())}
// ACTUAL_ABORT
// ACTUAL_FINISH_JOB
mod replay {
    use super::*;
    #[derive(Clone,Copy,PartialEq,Eq,Debug)] enum TrialKind{Baseline,Candidate}
    #[derive(Clone,Copy,PartialEq,Eq,Debug)] enum Phase{Running,Faulted,Complete}
    // ACTUAL_TOKEN
    #[derive(Clone,Copy)] struct Request{family:LearningFamily,target:ObjectKey,kind:TrialKind,baseline:Action,not_before_ns:u64}
    #[derive(Clone,Copy)] struct Preparing{gate:bool,bound:Option<()>,failure:Option<Error>}
    struct Lifecycle{closed:bool}
    impl Lifecycle{fn closing(&self)->Option<()>{self.closed.then_some(())}}
    struct Root {first:Option<Snapshot>,initial:Option<ApplyId>,request:Option<Request>,phase:Phase,fault:Option<Error>,
        first_ready:bool,token:Option<Token>,preparing:Option<Preparing>,spectator:Option<()>,lifecycle:Lifecycle,renew_after:u64}
    static mut ROOT:Root=Root{first:None,initial:None,request:None,phase:Phase::Complete,fault:None,first_ready:false,
        token:None,preparing:None,spectator:None,lifecycle:Lifecycle{closed:false},renew_after:0};
    fn root()->&'static Root{unsafe{&*core::ptr::addr_of!(ROOT)}}
    fn root_mut()->&'static mut Root{unsafe{&mut *core::ptr::addr_of_mut!(ROOT)}}
    pub struct Prefix;
    fn activate(_:Token,_:Request,_:Snapshot)->Result<Prefix,Error>{panic!("capture activation is outside this already-open scope fixture")}
    // ACTUAL_ROOT_FUNCTIONS
    pub fn reset(){let r=root_mut();r.first=Some(SNAP);r.initial=None;r.phase=Phase::Running;r.fault=None;r.first_ready=true;
        r.request=Some(Request{family:LearningFamily{domain:1,kind:1},target:key(12),kind:TrialKind::Candidate,baseline:Action::CpuWeight(1),not_before_ns:0});
        r.token=Some(Token{id:12,boot_epoch:1,owner:key(7)});r.lifecycle.closed=false;}
    pub fn fault()->Option<Error>{root().fault}
    pub fn current_token()->Token{root().token.unwrap()}
    pub fn retained(token:Token)->Result<Option<Error>,Error>{if root().token==Some(token){Ok(root().fault)}else{Err(Error::Stale)}}
    pub fn original()->Option<Snapshot>{root().first}
    pub fn fresh()->Result<Snapshot,Error>{first(Snapshot{sequence:410,taken_ns:now(),..SNAP},1,1,key(12)).map(|x|x.0)}
    pub fn scenario(change:u8){let r=root_mut();match change{
        1=>r.request.as_mut().unwrap().kind=TrialKind::Baseline,
        2=>r.initial=Some(ApplyId{boot_epoch:1,controller_epoch:1,plan_seq:409,action_index:0,target:key(12)}),
        3=>r.phase=Phase::Complete,4=>r.token.as_mut().unwrap().boot_epoch=2,_=>()}}
    pub fn phase_faulted()->bool{root().phase==Phase::Faulted}
}
fn fixture()->(State,Job){
    replay::reset();DELIVERY_BUSY.store(false,Ordering::Release);EVIDENCE.store(0,Ordering::Release);ABORTS.store(0,Ordering::Release);
    let choices=[Candidate{action:Action::CpuWeight(1),features:RawFeatures::default()}];
    let set=CandidateSet::new(SNAP,key(12),ModelBinding{generation:1,..ModelBinding::default()},&choices,Some(Action::CpuWeight(1))).unwrap();
    let job=Job{cpu:1,set,sequence:409,controller:1,base_version:0,started:SNAP.taken_ns,encode_ns:598915,evidence:Some(24),
        dependencies:[None;2],work:None,read_only:false,completion:Some(JobCompletion{result:Err(Error::Busy),selected:0,decoded_ns:57706,
        elapsed_ns:204331,cpu_ns:225128,output_hash:[9;32],aborted:false})};
    (State{job:None,boot:1},job)
}
#[test]fn first_candidate_actual_completed_rejection_closes_original_scope(){
    for error in [Error::Busy,Error::Again,Error::NotReady,Error::Expired,Error::Budget,Error::Auth]{
        let(mut s,mut job)=fixture();job.completion.as_mut().unwrap().result=Err(error);
        assert_eq!(finish_job(&mut s,job,Some(&[1;512])),Err(error));
        assert_eq!(EVIDENCE.load(Ordering::Acquire),1);assert!(s.job.is_none());
        assert_eq!(replay::fault(),Some(error),"retired first candidate left its captured scope open");
        assert!(replay::phase_faulted());assert_eq!(replay::original(),Some(SNAP));
        assert_eq!(replay::fresh(),Err(Error::Busy),"new first snapshot refreshed a failed captured trial");
        assert_eq!(finish_job(&mut s,job,None),Err(error));assert_eq!(replay::fault(),Some(error));
    }
    let(mut s,mut job)=fixture();job.completion.as_mut().unwrap().aborted=true;
    job.completion.as_mut().unwrap().result=Err(Error::Expired);
    assert_eq!(finish_job(&mut s,job,None),Err(Error::Expired));
    assert_eq!(replay::fault(),Some(Error::Expired));assert_eq!(ABORTS.load(Ordering::Acquire),1);
}
#[test]fn first_candidate_success_publication_and_foreign_jobs_are_not_rejected(){
    for change in 0..12 {
        let(mut s,mut job)=fixture();
        match change{
            0=>job.completion.as_mut().unwrap().result=Ok(384),
            1=>replay::scenario(1),2=>replay::scenario(2),3=>replay::scenario(3),4=>replay::scenario(4),
            5=>job.set.snapshot.sequence+=1,6=>job.set.snapshot.taken_ns+=1,7=>job.set.target.generation+=1,
            8=>job.read_only=true,9=>job.work=Some(core_replay::WorkId),10=>job.sequence+=1,
            11=>{let choices=[Candidate{action:Action::SpawnTokens(1),features:RawFeatures::default()}];
                job.set=CandidateSet::new(SNAP,key(12),job.set.model,&choices,Some(Action::SpawnTokens(1))).unwrap();},_=>unreachable!()}
        let expected=job.completion.unwrap().result;
        assert_eq!(finish_job(&mut s,job,None),expected);
        assert_eq!(replay::fault(),None,"unrelated or published obligation was failed: {change}");
        assert_eq!(replay::original(),Some(SNAP));
    }
}
#[test]fn first_candidate_retained_delivery_busy_is_not_actual_job_rejection(){
    let(mut s,mut job)=fixture();job.work=Some(core_replay::WorkId);
    DELIVERY_BUSY.store(true,Ordering::Release);
    assert_eq!(finish_job(&mut s,job,None),Err(Error::Busy));assert!(s.job.is_some());
    assert_eq!(EVIDENCE.load(Ordering::Acquire),0);assert_eq!(replay::fault(),None);
    DELIVERY_BUSY.store(false,Ordering::Release);let retained=s.job.take().unwrap();
    assert_eq!(retained.sequence,job.sequence);assert_eq!(retained.completion.unwrap().result,Err(Error::Busy));
    assert_eq!(finish_job(&mut s,retained,None),Err(Error::Busy));
    assert!(s.job.is_none());assert_eq!(EVIDENCE.load(Ordering::Acquire),1);assert_eq!(replay::fault(),None);
}

mod candidate_owner {
    use super::Error as DomainError;
    use super::*;
    #[derive(Clone,Copy,PartialEq,Eq,Debug)]enum Phase{Start,Activate,Run,Drain,PreparationArchive,PreparationReleaseWork,
        PreparationReleaseRoot,PreparationReleasePermit,PreparationAbort,Failed}
    struct OwnerState{token:Option<replay::Token>,scope:Option<()>,phase:Phase,last_error:Option<Error>,preparation:Option<()>,prepare_error:Option<(DomainError,u64)>}
    static mut OWNER:OwnerState=OwnerState{token:None,scope:None,phase:Phase::Failed,last_error:None,preparation:None,prepare_error:None};
    fn with<T>(f:impl FnOnce(&mut OwnerState)->Result<T,DomainError>)->Result<T,DomainError>{f(unsafe{&mut *core::ptr::addr_of_mut!(OWNER)})}
    fn native_error(e:DomainError)->Error{e}
    mod diagnostic {pub struct Attempt;impl Attempt{pub fn retain(&mut self,_:super::Error,_:Option<super::Error>,_:u64){panic!("no diagnostic attempt in fixture")}}}
    mod root {
        pub fn retained_fault(t:super::replay::Token)->Result<Option<super::Error>,super::Error>{super::replay::retained(t)}
        pub fn abort_preparation(_:(),_:super::Error,_:u64)->Result<(),super::Error>{panic!("preparation custody is outside already-captured owner fixture")}
    }
    // ACTUAL_OWNER_RETAIN_ERROR
    pub fn reset(){with(|s|{s.token=Some(replay::current_token());s.scope=Some(());s.phase=Phase::Activate;s.last_error=None;Ok(())}).unwrap();}
    pub fn observe(e:DomainError){retain_error(e,None)}
    pub fn drained()->bool{with(|s|Ok(s.phase==Phase::Drain)).unwrap()}
    pub fn error()->Option<Error>{with(|s|Ok(s.last_error)).unwrap()}
}
mod domain_platform{pub fn now_ns()->u64{super::now()}}
#[test]fn first_candidate_owner_preserves_terminal_busy_and_drains_original_scope(){
    let(mut s,job)=fixture();candidate_owner::reset();
    candidate_owner::observe(Error::Busy);assert!(!candidate_owner::drained());assert_eq!(candidate_owner::error(),None);
    assert_eq!(finish_job(&mut s,job,None),Err(Error::Busy));
    candidate_owner::observe(Error::Busy);
    assert!(candidate_owner::drained(),"retained Root Busy was mistaken for transient owner contention");
    assert_eq!(candidate_owner::error(),Some(Error::Busy));assert_eq!(replay::original(),Some(SNAP));
    let(mut s,mut job)=fixture();candidate_owner::reset();job.completion.as_mut().unwrap().result=Err(Error::Auth);
    assert_eq!(finish_job(&mut s,job,None),Err(Error::Auth));candidate_owner::observe(Error::Busy);
    assert!(candidate_owner::drained());assert_eq!(candidate_owner::error(),Some(Error::Auth));
}
// ACTUAL_LIFECYCLE_MODULE
#[test]fn first_candidate_unactivated_gate_cannot_close_published_or_entered_custody(){
    use cyxia_prototype::learning::capture::RunKey;
    let run=RunKey{boot_epoch:1,trial_id:3,generation:1};
    let(mut s,job)=fixture();assert_eq!(finish_job(&mut s,job,None),Err(Error::Busy));
    let mut gate=close_lifecycle::CloseGate::new();
    assert_eq!(gate.begin(run,false,true),Err(Error::Busy));assert_eq!(gate.closing(),None);
    assert_eq!(gate.begin(run,true,false),Ok(false));assert_eq!(gate.closing(),None);
    assert_eq!(gate.begin(run,false,false),Ok(true));assert_eq!(gate.closing(),Some(run));
    assert_eq!(gate.finish_activation(run),Err(Error::Auth));
    let mut entered=close_lifecycle::CloseGate::new();entered.finish_activation(run).unwrap();
    assert_eq!(entered.begin(run,false,false),Err(Error::Conflict));
    // Actual CloseGate only: protected no-publication/owner/Memory/capture proof
    // and abort/export/release are separate boundaries, never synthesized here.
}

#[test]fn first_candidate_abort_keeps_existing_completion_and_publication_custody(){
    for mode in 0..4 {
        let(_,mut job)=fixture();
        if mode==0{job.completion=None;}
        if mode==1{job.completion.as_mut().unwrap().result=Ok(384);replay::scenario(2);}
        if mode==3{job.completion=None;job.cpu=2;}
        with(|s|{s.job=Some(job);Ok(())}).unwrap();
        assert_eq!(abort(100),if mode==3{Err(Error::Auth)}else{Ok(())});
        assert_eq!(replay::fault(),match mode{0=>Some(Error::Expired),2=>Some(Error::Busy),_=>None});
        assert_eq!(ABORTS.load(Ordering::Acquire),usize::from(mode==0));
        assert_eq!(with(|s|Ok(s.job.is_some())).unwrap(),mode==3);
    }
}

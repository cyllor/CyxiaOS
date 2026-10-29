// Real Root publication/hint, helper/CAS/service pieces, warm, submission,
// admission and Scheduler. Owner Run/capture and hardware are explicit facades.
static CANDIDATE_MODE:AtomicBool=AtomicBool::new(false);
mod candidate {
    use super::*;
    use cyxia_prototype::{domains::{Action,ApplyId,PolicyStamp},learning::Family,policy::ExecutionState};
    const STAMP:PolicyStamp=PolicyStamp{version:41,snapshot_ns:100_000_000,installed_until_ns:10_100_000_000};
    const ID:ApplyId=ApplyId{boot_epoch:7,controller_epoch:2,plan_seq:51,action_index:0,target:group(12)};
    const fn key(id:u64)->ObjectKey{ObjectKey{id,generation:1}}
    struct State;
    static mut STATE:State=State;
    // PAID_CONTROL_WITH
    // PAID_ROOT_SUPPORT
    pub fn prepare(){replay::reset();CANDIDATE_MODE.store(true,Ordering::Release);}
    pub fn commit(){with(|_|replay::commit(Some(STAMP),ID)).unwrap();}
    pub fn pending()->bool{replay::baseline_activation_pending()}
    pub fn settle(){let version=locked(|s|s.scheduler.policy_receipt(group(12))).unwrap();assert_eq!(version,41);
        with(|_|{replay::state(ID,STAMP,cyxia_prototype::policy::ExecutionState::Applied);Ok(())}).unwrap();}
    pub fn install(){locked(|s|s.scheduler.install_weight(group(12),2,STAMP,now_ns())).unwrap();}
}
mod candidate_warm {
    use super::*;
    use cyxia_prototype::learning::Family;
    mod evidence{pub(crate) use crate::candidate_trace as execution_trace;}
    fn now()->u64{now_ns()}
    const REQUEST_DEADLINE_NS:u64=1_000_000_000;
    #[derive(Clone,Copy)]struct Warm{id:u64,deadline:u64,active:bool}
    #[derive(Clone,Copy)]struct Scope{key:cyxia_prototype::learning::capture::RunKey}
    struct State{warm:Option<Warm>,seed:u64,warm_at:u64,next_warm:u64,scope:Option<Scope>}
    static mut WARM:State=State{warm:None,seed:1,warm_at:0,next_warm:101,scope:None};
    fn transient(e:Error)->bool{matches!(e,Error::Busy|Error::Again|Error::NotReady)}
    fn submit(_:Family,_:u64,id:u64,_:u64,deadline:u64)->Result<(),Error>{
        locked(|s|{service_witness_locked(s)?;
            submit_package(s,PACKAGE,request().caller,id,group(12),&1u64.to_le_bytes(),3,deadline,false,0)?;Ok(())})
    }
    fn outcome(_:Family,_:u64)->Result<Option<Result<u64,Error>>,Error>{Ok(None)}
    // PAID_REAL_WARM
    pub fn advance()->Result<(),Error>{let s=unsafe{&mut *core::ptr::addr_of_mut!(WARM)};
        warm(s,Family{domain:1,kind:1},2_000_000_000,now_ns())}
    pub fn reset(){unsafe{WARM=State{warm:None,seed:1,warm_at:0,next_warm:101,scope:None}}}
}
fn candidate_setup(){reset();candidate::prepare();candidate_warm::reset();HINT.store(false,Ordering::Release);}
#[test]
fn actual_candidate_initial_flows_through_fresh_helper_warm_admission_and_policy_receipt(){
    candidate_setup();let mut c=smp::prototype_runtime::Coordinator;
    mechanism_progress(&mut c);assert_eq!(STEP_CALLS.load(Ordering::Acquire),0,"unsubmitted initial ran helper");
    candidate::commit();assert!(candidate::pending(),"submitted candidate initial lost its progress opportunity");
    candidate::install();mechanism_progress(&mut c); // Original warm ID and deadline created.
    mechanism_progress(&mut c); // Original warm submitted; one independently paid construction.
    assert_eq!(CONSTRUCTIONS.load(Ordering::Acquire),1,"candidate warm never reached real admission");
    let submitted=locked(|s|s.admission.request(request().caller,101)).unwrap();
    assert_eq!((submitted.caller,submitted.request_id,submitted.package,submitted.group,submitted.recovery),
        (request().caller,101,PACKAGE,group(12),false));
    let deadline=locked(|s|Ok(s.launches.iter().find(|l|l.request==Some(submitted)).unwrap().deadline)).unwrap();
    assert_eq!(deadline,1_100_160_000,"candidate warm refreshed its original request deadline");
    let b=bills();assert!(b.len()>=4);assert_eq!(b.iter().map(|b|b.1).sum::<u64>(),280_000);
    assert!(b.windows(2).all(|p|p[0].0!=p[1].0),"candidate admission reused replay credit");
    let d=locked(|s|s.scheduler.dispatch_with_window_headroom(3,s.layout,now_ns(),1_000_000,20_000_000)).unwrap().unwrap();
    assert_eq!(d.policy_version,41);assert_eq!(d.thread,group(4096));
    locked(|s|s.scheduler.complete(d,33_000,RunState::Runnable,now_ns()+33_000)).unwrap();
    candidate::settle();assert!(!candidate::pending(),"actual candidate completion retained initial priority");
    let before=STEP_CALLS.load(Ordering::Acquire);mechanism_progress(&mut c);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire),before,"terminal initial got another helper body");
    CANDIDATE_MODE.store(false,Ordering::Release);
}
#[test]
fn candidate_old_bill_credit_denial_and_recursive_entry_preserve_original_custody(){
    candidate_setup();candidate::commit();REENTER.store(true,Ordering::Release);
    let old=begin_service_segment().unwrap();work(60_000);DENY_SETTLE.store(true,Ordering::Release);
    complete_service(60_000,now_ns()).unwrap();mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire),0);assert_eq!(COMPLETE_ACTUAL[0].load(Ordering::Acquire),60_000);
    assert_eq!(unsafe{(&*core::ptr::addr_of!(STATE)).active[0].unwrap().dispatch.sequence},old.sequence);
    assert!(candidate::pending());DENY_SETTLE.store(false,Ordering::Release);
    READY.store(false,Ordering::Release);mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire),0);READY.store(true,Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);assert_eq!(STEP_CALLS.load(Ordering::Acquire),1);
    assert!(RECURSED.load(Ordering::Acquire));assert_eq!(CONSTRUCTIONS.load(Ordering::Acquire),0);
    assert_eq!(bills().iter().map(|b|b.1).collect::<Vec<_>>(),[60_000,130_000,0]);
    assert!(candidate::pending());CANDIDATE_MODE.store(false,Ordering::Release);
}

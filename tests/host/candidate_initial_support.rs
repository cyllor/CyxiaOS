// Root's bounded projection is real; Registry commit, resource authorization,
// capture/history binding and hardware remain explicit host boundaries.
static CLAIMED: AtomicBool = AtomicBool::new(false);
// CANDIDATE_GUARD
pub mod replay {
    use super::*;
    use cyxia_prototype::{policy::Snapshot, policy_wire::{self, Plan, PlanHeader, Envelope, Decision}};
    type LearningFamily = Family;
    #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum TrialKind {Baseline,Candidate}
    #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum Phase {Frozen,Running,Restoring,Faulted,Complete}
    // CANDIDATE_TOKEN
    #[derive(Clone,Copy)] struct Request {trial_id:u64,owner:ObjectKey,target:ObjectKey,family:Family,kind:TrialKind}
    #[derive(Clone,Copy)] struct Receipt {stamp:PolicyStamp,state:ExecutionState}
    struct Lifecycle {closed:bool}
    impl Lifecycle {fn closing(&self)->Option<()>{self.closed.then_some(())}}
    // CANDIDATE_INITIAL_TYPE
    struct Root {token:Option<Token>,request:Option<Request>,first:Option<Snapshot>,first_ready:bool,
        phase:Phase,initial:Option<ApplyId>,candidate_publication:Option<CandidatePublication>,selected:Option<Action>,
        renew_after:u64,baseline:[Option<Receipt>;32],baseline_count:usize,closing:Option<Receipt>,
        unpublished:Option<()>,fault:Option<Error>,lifecycle:Lifecycle}
    static mut ROOT:Root=Root{token:None,request:None,first:None,first_ready:false,phase:Phase::Complete,
        initial:None,candidate_publication:None,selected:None,renew_after:0,baseline:[None;32],baseline_count:0,
        closing:None,unpublished:None,fault:None,lifecycle:Lifecycle{closed:false}};
    fn root()->&'static Root{unsafe{&*core::ptr::addr_of!(ROOT)}}
    fn root_mut()->&'static mut Root{unsafe{&mut *core::ptr::addr_of_mut!(ROOT)}}
    // CANDIDATE_ROOT_BODIES
    // CANDIDATE_STALE_HOOK
    // CANDIDATE_STALE_CASE
    pub const TOKEN:Token=Token{id:9,boot_epoch:7,owner:key(7)};
    pub fn reset(){let r=root_mut();r.token=Some(TOKEN);r.request=Some(Request{trial_id:3,owner:key(7),target:key(12),
        family:Family{domain:Action::CpuWeight(2).domain(),kind:Action::CpuWeight(2).kind()},kind:TrialKind::Candidate});
        r.first=Some(Snapshot{sequence:ID.plan_seq,taken_ns:STAMP.snapshot_ns,ledger_generation:1,core_generation:1});
        r.first_ready=true;r.phase=Phase::Running;r.initial=None;r.candidate_publication=None;r.selected=None;
        r.unpublished=None;r.fault=None;r.lifecycle.closed=false;r.closing=None;r.baseline_count=0;
        BASELINE_ACTIVATION_PENDING.store(false,Ordering::Release);}
    pub fn commit(stamp:Option<PolicyStamp>,id:ApplyId)->Result<(),Error>{
        let mut bytes=[0u8;1024];let n=policy_wire::encode_plan(PlanHeader{plan_seq:id.plan_seq,
            controller_epoch:id.controller_epoch,snapshot_seq:ID.plan_seq,active_model_generation:1,active_until_local_ns:STAMP.installed_until_ns,
            ..PlanHeader::default()},&[Decision{envelope:Envelope{target:id.target,controller_epoch:id.controller_epoch,
                snapshot_seq:ID.plan_seq,decision_seq:1,ledger_generation:1,core_generation:1,..Envelope::default()},
                action:Action::CpuWeight(2),candidate_index:0}],&mut bytes)?;
        let plan=policy_wire::decode_plan(&bytes[..n])?;
        // CANDIDATE_PUBLISHED_CALL
        Ok(())
    }
    pub fn state(id:ApplyId,stamp:PolicyStamp,state:ExecutionState){candidate_execution(id,stamp,state);}
    pub fn commit_at(stamp:PolicyStamp,id:ApplyId,action:Action)->Result<(),Error>{
        let mut bytes=[0u8;1024];let n=policy_wire::encode_plan(PlanHeader{plan_seq:id.plan_seq,
            controller_epoch:id.controller_epoch,snapshot_seq:id.plan_seq,active_model_generation:1,active_until_local_ns:if action.one_shot(){0}else{stamp.installed_until_ns},
            ..PlanHeader::default()},&[Decision{envelope:Envelope{target:id.target,controller_epoch:id.controller_epoch,
                snapshot_seq:id.plan_seq,decision_seq:id.plan_seq,ledger_generation:1,core_generation:1,..Envelope::default()},
                action,candidate_index:0}],&mut bytes)?;
        let plan=policy_wire::decode_plan(&bytes[..n])?;
        let stamp=Some(stamp);
        // CANDIDATE_PUBLISHED_CALL
        Ok(())
    }
    pub fn first_identity()->(Snapshot,ApplyId){(root().first.unwrap(),root().initial.unwrap())}
    pub fn renewal_scenario(){
        const NEXT:ApplyId=ApplyId{plan_seq:52,..ID};
        const RENEW:PolicyStamp=PolicyStamp{version:42,snapshot_ns:120_000_000,installed_until_ns:10_120_000_000};
        reset();with(|_|commit(Some(STAMP),ID)).unwrap();
        with(|_|{state(ID,STAMP,ExecutionState::Applied);Ok(())}).unwrap();let original=first_identity();
        with(|_|commit_at(RENEW,NEXT,Action::CpuWeight(2))).unwrap();
        assert_eq!(first_identity(),original,"renewal replaced the original captured first identity");
        assert!(baseline_activation_pending(),"actual candidate renewal lost its paid progress opportunity");
        with(|_|{state(ID,STAMP,ExecutionState::Unknown);Ok(())}).unwrap();
        assert!(baseline_activation_pending(),"old terminal receipt retired the actual renewal");
        with(|_|{state(NEXT,PolicyStamp{version:43,..RENEW},ExecutionState::Applied);Ok(())}).unwrap();
        assert!(baseline_activation_pending(),"wrong stamp retired the renewal");
        with(|_|{state(NEXT,RENEW,ExecutionState::Unknown);Ok(())}).unwrap();
        let later=ApplyId{plan_seq:53,..ID};let late=PolicyStamp{version:43,snapshot_ns:140_000_000,installed_until_ns:10_140_000_000};
        with(|_|commit_at(late,later,Action::CpuWeight(2))).unwrap();
        with(|_|{state(later,late,ExecutionState::Applied);Ok(())}).unwrap();
        assert!(baseline_activation_pending(),"new publication replaced an unresolved renewal");
        with(|_|{state(NEXT,RENEW,ExecutionState::Applied);Ok(())}).unwrap();
        assert!(!baseline_activation_pending(),"terminal actual renewal retained priority");
        with(|_|{state(NEXT,RENEW,ExecutionState::Unknown);Ok(())}).unwrap();assert!(!baseline_activation_pending());
        with(|_|commit_at(late,later,Action::CpuWeight(2))).unwrap();assert!(baseline_activation_pending());
        with(|_|{root_mut().token.as_mut().unwrap().id+=1;state(later,late,ExecutionState::Applied);Ok(())}).unwrap();
        assert!(!baseline_activation_pending(),"new token inherited old renewal custody");
        // An actual one-shot cannot acquire a second execution hint, even if a
        // direct fixture call bypasses the separately tested publication gate.
        reset();root_mut().request.as_mut().unwrap().family=Family{domain:14,kind:1};
        with(|_|commit_at(STAMP,ID,Action::RecoveryRecipe(1))).unwrap();
        with(|_|{state(ID,STAMP,ExecutionState::Applied);Ok(())}).unwrap();
        with(|_|commit_at(RENEW,NEXT,Action::RecoveryRecipe(1))).unwrap();
        assert!(!baseline_activation_pending(),"one-shot candidate acquired renewal progress");
        println!("candidate renewal custody passed");
    }

    pub fn publication_started(_:Token)->Result<bool,Error>{
        if root().fault==Some(Error::Busy){return Err(Error::Busy)}
        Ok(root().initial.is_some())
    }
    pub fn baseline_apply(_:Token)->Result<(),Error>{panic!("candidate took baseline publication")}
    pub fn scenario(){
        reset();with(|_|Ok(())).unwrap();assert!(!baseline_activation_pending());
        with(|_|commit(Some(STAMP),ID)).unwrap();
        assert!(baseline_activation_pending(),"submitted candidate initial lost its progress opportunity");
        for state in [ExecutionState::Pending,ExecutionState::Unknown] {
            with(|_|{candidate_execution(ID,STAMP,state);Ok(())}).unwrap();assert!(baseline_activation_pending());
        }
        for id in [ApplyId{plan_seq:52,..ID},ApplyId{boot_epoch:8,..ID},ApplyId{target:key(13),..ID},ApplyId{action_index:1,..ID}] {
            with(|_|{candidate_execution(id,STAMP,ExecutionState::Applied);Ok(())}).unwrap();
            assert!(baseline_activation_pending(),"foreign execution consumed the initial obligation");
        }
        with(|_|{candidate_execution(ID,PolicyStamp{version:42,..STAMP},ExecutionState::Applied);Ok(())}).unwrap();
        assert!(baseline_activation_pending());
        for state in [ExecutionState::Applied,ExecutionState::Failed(Error::Stale)]{
            reset();with(|_|commit(Some(STAMP),ID)).unwrap();
            with(|_|{candidate_execution(ID,STAMP,state);Err::<(),_>(Error::Busy)}).unwrap_err();
            assert!(!baseline_activation_pending(),"terminal initial retained priority after a fallible caller");
            with(|_|{candidate_execution(ID,STAMP,ExecutionState::Unknown);Ok(())}).unwrap();
            assert!(!baseline_activation_pending(),"terminal initial was resurrected by a delayed update");
            with(|_|commit(Some(PolicyStamp{version:42,..STAMP}),ApplyId{plan_seq:52,..ID})).unwrap();
            assert!(!baseline_activation_pending(),"later publication stole initial priority");
        }
        for wrong in 0..12 {
            reset();with(|_|commit(if wrong==0{None}else{Some(if wrong==1{PolicyStamp{version:0,..STAMP}}else{STAMP})},ID)).unwrap();
            with(|_|{let r=root_mut();match wrong {
                2=>r.first.as_mut().unwrap().sequence+=1,3=>r.first.as_mut().unwrap().taken_ns+=1,
                4=>r.token.as_mut().unwrap().id+=1,5=>r.token.as_mut().unwrap().owner=key(8),
                6=>r.token.as_mut().unwrap().boot_epoch+=1,7=>r.first_ready=false,8=>r.phase=Phase::Complete,
                9=>r.fault=Some(Error::Stale),10=>r.lifecycle.closed=true,11=>r.unpublished=Some(()),_=>()};Ok(())}).unwrap();
            assert!(!baseline_activation_pending(),"unbound candidate identity requested service: {wrong}");
        }
        reset();with(|_|commit(Some(STAMP),ID)).unwrap();
        // A real new trial reset cannot accept the old initial's delayed state.
        reset();root_mut().token.as_mut().unwrap().id+=1;
        with(|_|{candidate_execution(ID,STAMP,ExecutionState::Unknown);Ok(())}).unwrap();assert!(!baseline_activation_pending());
        println!("candidate initial custody passed");
    }
}
pub fn candidate_poll_scenario(){
    replay::reset();with(|_|replay::commit(Some(STAMP),ID)).unwrap();
    assert!(replay::baseline_activation_pending(),"submitted candidate initial lost its progress opportunity");
    let mode=std::env::args().nth(1).unwrap_or_default();
    if mode=="renewal_stale" {
        let id=ApplyId{plan_seq:52,..ID};let stamp=PolicyStamp{version:42,snapshot_ns:120_000_000,installed_until_ns:10_120_000_000};
        with(|s|{replay::state(ID,STAMP,ExecutionState::Applied);replay::commit_at(stamp,id,Action::CpuWeight(2))?;
            let d=s.owner.desired[0].as_mut().unwrap();d.apply=id;d.stamp=stamp;d.job=52;d.published=120_000_000;
            s.owner.context.ledger_generation+=1;Ok(())}).unwrap();WALL.store(120_000_000,Ordering::Release);
        assert!(replay::baseline_activation_pending(),"actual candidate renewal lost its paid progress opportunity");
    }

    if mode=="stale"{with(|s|{s.owner.context.ledger_generation+=1;Ok(())}).unwrap();}
    if mode=="denial_ledger"{with(|s|{s.owner.context.ledger_generation+=1;Ok(())}).unwrap();}
    if mode=="denial_core"{with(|s|{s.owner.context.core_generation+=1;Ok(())}).unwrap();}
    if mode=="denial_binder"{BIND_MODE.store(2,Ordering::Release);}
    if mode=="denial_binding"{BIND_MODE.store(4,Ordering::Release);}
    if mode=="denial_executor"{with(|s|{s.owner.families[0].as_mut().unwrap().apply=|_,_,_,_|Err(Error::Stale);Ok(())}).unwrap();}

    if mode=="deadline"{WALL.store(200_000_000,Ordering::Release);}
    if mode=="failed"||mode=="registry"{with(|s|{s.owner.families[0].as_mut().unwrap().apply=|_,_,_,_|Err(Error::Conflict);Ok(())}).unwrap();}
    if mode=="registry"{REGISTRY_FAIL.store(true,Ordering::Release);}
    if mode=="busy"||mode=="deadline"{with(|s|{s.owner.families[0].as_mut().unwrap().apply=|_,_,_,_|Err(Error::Busy);Ok(())}).unwrap();}
    if mode=="unknown"{with(|s|{s.owner.families[0].as_mut().unwrap().apply=|_,_,_,_|Err(Error::NotReady);Ok(())}).unwrap();}
    let _=poll(now());
    let terminal=matches!(mode.as_str(),"stale"|"failed"|"deadline"|"registry"|"renewal_stale"|"denial_core"|"denial_ledger"|"denial_binder"|"denial_binding"|"denial_executor");
    assert_eq!(replay::baseline_activation_pending(),!terminal,"real final Control state did not update the initial hint");
    if mode.starts_with("denial_") {
        let h=crate::domain_evidence::candidate_stale_header();
        if mode=="denial_executor" {assert_eq!(h[2],0,"actual executor error was falsely recorded as pre-executor denial");}
        else {
            assert_eq!(h[3],1,"actual candidate pre-executor Stale lost its original denial facts");
            assert_eq!(h[2],1);assert_eq!(&h[4..9],&[9,7,7,1,3]);
            assert_eq!(&h[9..13],&[51,100_000_000,1,1]);
            assert_eq!(&h[13..19],&[7,2,51,0,12,1]);
            assert_eq!(&h[19..22],&[41,100_000_000,10_100_000_000]);
            assert_eq!(&h[23..27],match mode.as_str(){"denial_core"=>&[1,2,1,1],"denial_ledger"=>&[1,1,1,2],_=>&[1,1,1,1]});
            assert_eq!(h[27],match mode.as_str(){"denial_binder"=>2,"denial_binding"=>4,_=>1});assert_eq!(h[28],Error::Stale as u64+1);
            assert_eq!(&h[29..31],&[1,1]);assert_eq!(h[35]%2,0);
        }
    }
    if mode=="applied" {
        task::execute_and_settle();WALL.store(100_040_000,Ordering::Release);poll(now()).unwrap();
        assert!(!replay::baseline_activation_pending(),"real Scheduler receipt did not retire initial priority");
    }
    println!("candidate actual poll passed");
}

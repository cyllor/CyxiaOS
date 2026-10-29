// Actual Active scope composition, ordinary selection and dependency binder.
// Root allowance is controlled; the model CommitGate and ADMISSION are real.
mod active_scope_fixture {
 use super::*;
 use policy::{BoundDependency,Prerequisite,ModelBinding,RegisteredSet};
 use cyxia_prototype::domains::{PolicyStamp,POLICY_NS};
 use cyxia_prototype::policy_wire::{Envelope,encode_plan,decode_plan,MAX_PLAN_BYTES};
 use cyxia_prototype::{policy_wire::{Plan,Decision,PlanHeader},learning::governance::CommitGate};
 #[derive(Clone,Copy)]struct Family{domain:u16,kind:u16,current:fn(u16,u16,ObjectKey)->Result<Action,Error>,legal:fn(Action,ObjectKey,u64)->Result<(),Error>,legal_options:fn(&[Option<Action>],ObjectKey,u64,&mut[Option<Action>])->Result<usize,Error>}
 struct Context{control_mask:u64,healthy_mask:u64,draining_mask:u64}
 type Resolver=fn(ObjectKey)->Result<[Option<Prerequisite>;2],Error>;
 type Binder=fn(ObjectKey,u64)->Result<[Option<BoundDependency>;2],Error>;
 struct Owner{context:Context,stability:[Option<StabilityGuard>;1],stability_high:usize,families:[Option<Family>;18],dependencies:[Option<Resolver>;16],dependency_binders:[Option<Binder>;16]}
 fn family(domain:u16)->Family{Family{domain,kind:1,current:|domain,_,target|locked(|s|current_locked(s,domain,target,now_ns())),legal:|action,target,_|locked(|s|validate_locked(s,action,target,now_ns())),legal_options:|options,target,_,out|locked(|s|policy::collect_legal_actions(options,out,|action|validate_locked(s,action,target,now_ns())))}}
 fn owner(target:ObjectKey)->Owner{let mut families=[None;18];families[0]=Some(family(1));families[13]=Some(family(13));let mut dependencies:[Option<Resolver>;16]=[None;16];dependencies[0]=Some(|target|locked(|s|scheduling_dependencies_locked(s,target)));Owner{context:Context{control_mask:6,healthy_mask:15,draining_mask:0},stability:[Some(StabilityGuard::new(target,Action::CpuWeight(1),now_ns()-WINDOW_NS).unwrap())],stability_high:1,families,dependencies,dependency_binders:[None;16]}}
 // ACTUAL_ADMISSION_MODULE
 static ADMISSION:admission_view::AdmissionView=admission_view::AdmissionView::new();
 static ALLOW_ROOT:AtomicBool=AtomicBool::new(true);
 mod replay{pub fn allows_action(_:super::Action,_:super::ObjectKey)->bool{super::ALLOW_ROOT.load(super::Ordering::Acquire)}}
 // ACTUAL_SCOPE_SUPPORT
 // ACTUAL_ACTIVE_SCOPE
 // ACTUAL_ACTIVE_PUBLICATION
 fn binding()->ModelBinding{ModelBinding{generation:1,model_hash:[1;32],schema_hash:[2;32]}}
 fn gate()->CommitGate{CommitGate::new(1,binding()).unwrap()}
 fn plan(target:ObjectKey)->Plan{let set=policy::CandidateSet::new(policy::Snapshot{sequence:1,taken_ns:now_ns(),core_generation:4,ledger_generation:3},target,binding(),&[policy::Candidate{action:Action::CpuWeight(1),features:cyxia_prototype::features::RawFeatures::default()},policy::Candidate{action:Action::CpuWeight(2),features:cyxia_prototype::features::RawFeatures::default()}],Some(Action::CpuWeight(1))).unwrap();let header=PlanHeader{plan_seq:1,base_plan_version:0,active_model_generation:1,controller_epoch:1,snapshot_seq:1,active_until_local_ns:now_ns()+POLICY_NS};let decision=Decision{action:Action::CpuWeight(2),candidate_index:1,envelope:Envelope{controller_epoch:1,decision_seq:1,snapshot_seq:1,target,ledger_generation:3,core_generation:4,expires_local_ns:now_ns()+WINDOW_NS,model_hash:binding().model_hash,candidate_set_hash:set.hash()}};let mut wire=[0;MAX_PLAN_BYTES];let n=encode_plan(header,&[decision],&mut wire).unwrap();decode_plan(&wire[..n]).unwrap()}
 #[test]fn active_scope_commit_keeps_original_root_and_model_gates(){
  fixture();ALLOW_ROOT.store(true,Ordering::Release);let owner=owner(key(15));let gate=gate();let view=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().unwrap();let mut scope=// ACTIVE_PUBLICATION_CONSTRUCTOR
  ;let plan=plan(key(15));assert_eq!(scope.commit(&owner,binding(),&plan,&[],1,now_ns()),Ok(()));let wrong=ModelBinding{generation:2,..binding()};assert_eq!(scope.commit(&owner,wrong,&plan,&[],1,now_ns()),Err(Error::Busy),"Active borrow bypassed actual model gate");ALLOW_ROOT.store(false,Ordering::Release);assert_eq!(scope.commit(&owner,binding(),&plan,&[],1,now_ns()),Err(Error::Busy),"Active borrow bypassed original Root allowance");ALLOW_ROOT.store(true,Ordering::Release);assert_eq!(scope.authorize_recovery(binding(),&plan,now_ns()),Err(Error::Budget));drop(scope);
 }

 #[test]fn active_scope_borrow_retains_legality_selection_and_real_dependency_version(){
  fixture();ALLOW_ROOT.store(true,Ordering::Release);let owner=owner(key(15));let gate=gate();let view=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().unwrap();let scope=// ACTIVE_PUBLICATION_CONSTRUCTOR
  ;
  assert_eq!(scope.legal(family(1),Action::CpuWeight(2),key(15),now_ns()),Ok(()),"Active scope legal did not use its one task borrow");
  assert_eq!(scope.selection(&owner,family(1),Action::CpuWeight(2),key(15),now_ns()),Ok(()),"Active scope selection reentered the task gate");assert_eq!(scope.selection(&owner,family(1),Action::CpuWeight(4),key(15),now_ns()),Err(Error::Conflict));
  let prerequisite=Prerequisite{domain:13,target:key(15)};ADMISSION.publish(0,prerequisite,7,now_ns()+10_000_000_000,ExecutionState::Applied);
  assert_eq!(scope.dependencies(&owner,Action::CpuWeight(2),key(15),now_ns()),Ok([Some(BoundDependency{prerequisite,version:7}),None]),"Active scope dropped or reacquired registered dependency");
  ADMISSION.publish(0,prerequisite,8,now_ns()+10_000_000_000,ExecutionState::Applied);assert_eq!(scope.dependencies(&owner,Action::CpuWeight(2),key(15),now_ns()).unwrap()[0].unwrap().version,8);
  ADMISSION.publish(0,prerequisite,8,now_ns()+10_000_000_000,ExecutionState::Unknown);assert_eq!(scope.dependencies(&owner,Action::CpuWeight(2),key(15),now_ns()),Err(Error::NotReady),"Active scope bypassed an Unknown dependency");ADMISSION.retire(0);
  drop(scope);assert_eq!(locked(|_|Ok(())),Ok(()),"Active scope retained task guard after exit");
 }
 #[test]fn active_scope_owner_dependency_refusal_is_not_a_new_acquisition_busy(){
  fixture();unsafe{(&mut *core::ptr::addr_of_mut!(STATE)).background.reserve(key(15),1000,now_ns()).unwrap();}NOW.fetch_add(WINDOW_NS,Ordering::AcqRel);let owner=owner(key(15));let gate=gate();let view=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().unwrap();let scope=// ACTIVE_PUBLICATION_CONSTRUCTOR
  ;assert_eq!(scope.dependencies(&owner,Action::CpuWeight(2),key(15),now_ns()),Err(Error::Busy),"unsettled owner debit was treated as a healthy baseline");drop(scope);
 }
 #[test]fn active_scope_requires_registered_dependency_contract_and_control_role(){
  fixture();let mut owner=owner(key(15));let gate=gate();let view=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().unwrap();let scope=// ACTIVE_PUBLICATION_CONSTRUCTOR
  ;owner.dependencies[0]=None;assert_eq!(scope.dependencies(&owner,Action::CpuWeight(2),key(15),now_ns()),Err(Error::NotReady),"Active scope silently replaced missing registered dependency");owner.dependencies[0]=Some(|target|locked(|s|scheduling_dependencies_locked(s,target)));owner.dependency_binders[0]=Some(|_,_|Ok([None;2]));assert_eq!(scope.dependencies(&owner,Action::CpuWeight(2),key(15),now_ns()),Err(Error::Unsupported),"borrow silently bypassed a custom binder");owner.context.control_mask=0;assert_eq!(scope.authorize_executor(&owner),Err(Error::Auth));drop(scope);let unborrowed=// ACTIVE_PUBLICATION_NONE_CONSTRUCTOR
 ;assert_eq!(unborrowed.dependencies(&owner,Action::CpuWeight(2),key(15),now_ns()),Ok([None;2]));
 }
}

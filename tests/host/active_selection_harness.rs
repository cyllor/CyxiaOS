// Actual ordinary selection with real stability and the task publication view.
use cyxia_prototype::domains::stability::Guard as StabilityGuard;
use cyxia_prototype::policy::ExecutionState;
const WINDOW_NS:u64=100_000_000;
static CURRENT_CALLS:AtomicUsize=AtomicUsize::new(0);
#[derive(Clone,Copy)]struct Family{domain:u16,kind:u16,current:fn(u16,u16,ObjectKey)->Result<Action,Error>,legal_options:fn(&[Option<Action>],ObjectKey,u64,&mut[Option<Action>])->Result<usize,Error>}
struct Owner{stability:[Option<StabilityGuard>;1],stability_high:usize}
fn owner(at:u64)->Owner{Owner{stability:[Some(StabilityGuard::new(key(12),Action::CpuWeight(1),at).unwrap())],stability_high:1}}
fn family()->Family{Family{domain:1,kind:1,current:|domain,_,target|{CURRENT_CALLS.fetch_add(1,Ordering::AcqRel);locked(|s|current_locked(s,domain,target,now_ns()))},legal_options:|options,target,_,out|locked(|s|{let at=now_ns();policy::collect_legal_actions(options,out,|action|validate_locked(s,action,target,at))})}}
// ACTUAL_SELECTION_BODIES
fn selected(view:&SchedulerPublication,owner:&Owner,action:Action,target:ObjectKey,at:u64)->Result<(),Error>{
 // BORROWED_SELECTION
}
#[test]fn active_selection_same_current_and_adjacent_change_use_the_held_owner_view(){
 fixture();let owner=owner(now_ns()-WINDOW_NS);let view=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().unwrap();
 assert_eq!(selected(&view,&owner,Action::CpuWeight(1),key(12),now_ns()),Ok(()),"borrowed selection reentered Task gate");assert_eq!(selected(&view,&owner,Action::CpuWeight(2),key(12),now_ns()),Ok(()),"adjacent ordinary selection was bypassed or reacquired");assert_eq!(selected(&view,&owner,Action::CpuWeight(4),key(12),now_ns()),Err(Error::Conflict),"publication bypassed ordinary adjacency");drop(view);
}
#[test]fn active_selection_original_hold_and_sticky_freeze_are_preserved(){
 fixture();let mut owner=owner(now_ns());let view=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().unwrap();assert_eq!(selected(&view,&owner,Action::CpuWeight(2),key(12),now_ns()+WINDOW_NS-1),Err(Error::Busy),"publication bypassed minhold");assert_eq!(selected(&view,&owner,Action::CpuWeight(2),key(12),now_ns()+WINDOW_NS),Ok(()),"hold boundary lost the borrowed owner view");
 let origin=now_ns();for (index,value) in [2,1,2,1,2,1].into_iter().enumerate(){owner.stability[0].as_mut().unwrap().observe_execution(index as u64+1,Action::CpuWeight(value),ExecutionState::Applied,origin+(700+index as u64*100)*1_000_000).unwrap();}
 assert!(owner.stability[0].as_ref().unwrap().frozen());assert_eq!(selected(&view,&owner,Action::CpuWeight(2),key(12),origin+2_000_000_000),Err(Error::Busy),"publication bypassed sticky freeze");assert_eq!(selected(&view,&owner,Action::CpuWeight(1),key(12),origin+2_000_000_000),Ok(()));drop(view);
}
#[test]fn active_selection_missing_exact_stability_never_queries_the_owner(){
 fixture();let owner=owner(now_ns()-WINDOW_NS);let view=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().unwrap();CURRENT_CALLS.store(0,Ordering::Release);assert_eq!(selected(&view,&owner,Action::CpuWeight(2),ObjectKey{id:12,generation:2},now_ns()),Err(Error::Stale));assert_eq!(CURRENT_CALLS.load(Ordering::Acquire),0);let foreign=ObjectKey{id:12,generation:2};let foreign_owner=Owner{stability:[Some(StabilityGuard::new(foreign,Action::CpuWeight(1),now_ns()-WINDOW_NS).unwrap())],stability_high:1};assert_eq!(selected(&view,&foreign_owner,Action::CpuWeight(1),foreign,now_ns()),Err(Error::Stale),"selection trusted a cached action over the real current owner");drop(view);
}
#[test]fn active_selection_legacy_callbacks_still_observe_the_same_normal_rules(){
 fixture();let owner=owner(now_ns()-WINDOW_NS);assert_eq!(validate_selection(&owner,family(),Action::CpuWeight(2),key(12),now_ns()),Ok(()));assert_eq!(validate_selection(&owner,family(),Action::CpuWeight(4),key(12),now_ns()),Err(Error::Conflict));
}

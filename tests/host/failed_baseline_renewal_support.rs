static APPLY_CALLS:AtomicU64=AtomicU64::new(0);
static RECONCILE_CALLS:AtomicU64=AtomicU64::new(0);
static APPLY_MODE:AtomicU64=AtomicU64::new(0);
static RECEIPT_CPU:AtomicU64=AtomicU64::new(0);
pub(crate) static PAID_PREFIX_CPU:AtomicU64=AtomicU64::new(0);
static PUBLICATION_CPU:AtomicU64=AtomicU64::new(0);
fn locate(owner:&Owner,action:Action,target:ObjectKey)->Option<usize>{
 WORK.fetch_add(RECEIPT_CPU.load(Ordering::Relaxed),Ordering::Relaxed);
 owner.desired.iter().position(|d|d.is_some_and(|d|d.action==action&&d.apply.target==target))
}
fn locate_family(owner:&Owner,domain:u16,kind:u16,target:ObjectKey)->Option<usize>{owner.desired.iter().position(|d|d.is_some_and(|d|d.action.domain()==domain&&d.action.kind()==kind&&d.apply.target==target))}
pub mod renewal {
 use super::*;
 use cyxia_prototype::policy;
 use cyxia_prototype::policy::Snapshot;
 use cyxia_prototype::learning::reward::BaselineAdoption;
 #[derive(Clone,Copy,Debug,PartialEq,Eq)] enum TrialKind{Baseline,Candidate}
 #[derive(Clone,Copy,Debug,PartialEq,Eq)] enum Phase{Quiescing,Frozen,Running,Restoring,Complete}
 #[derive(Clone,Copy,Debug,PartialEq,Eq)] struct Token{ id:u64 }
 #[derive(Clone,Copy)] struct Request{kind:TrialKind,baseline:Action,target:ObjectKey,owner:ObjectKey,family:Family,not_before_ns:u64}
 #[derive(Clone,Copy,Debug,PartialEq,Eq)] struct Receipt{
  action:Action,apply:ApplyId,stamp:PolicyStamp,snapshot:Snapshot,state:ExecutionState,
  executor_generation:u64,issued_ns:u64,accepted_ns:u64,started_ns:Option<u64>,observed_ns:u64,approved_deadline_ns:u64,
 }
 struct Lifecycle;impl Lifecycle{fn closing(&self)->Option<()>{None}}
 #[derive(Clone,Copy)]struct Checks{owner:ObjectKey,settled:fn(Token)->Result<(),Error>}
 struct UnpublishedClose{token:Token,family:Family,target:ObjectKey,first:Snapshot,closed_ns:u64,capture:Option<RunKey>}
 struct Root{token:Option<Token>,request:Option<Request>,phase:Phase,baseline:[Option<Receipt>;32],baseline_count:usize,closing:Option<Receipt>,fault:Option<Error>,lifecycle:Lifecycle,registered:[Option<Checks>;1],initial:Option<()>,first:Option<Snapshot>,unpublished:Option<UnpublishedClose>,first_ready:bool}
 static mut ROOT:Root=Root{token:None,request:None,phase:Phase::Complete,baseline:[None;32],baseline_count:0,closing:None,fault:None,lifecycle:Lifecycle,registered:[None],initial:None,first:None,unpublished:None,first_ready:true};
 fn root()->&'static Root{unsafe{&*core::ptr::addr_of!(ROOT)}}
 fn root_mut()->&'static mut Root{unsafe{&mut *core::ptr::addr_of_mut!(ROOT)}}
 fn exact(r:&Root,t:Token)->Result<Request,Error>{if r.token!=Some(t){return Err(Error::Stale)}r.request.ok_or(Error::NotReady)}
 static AUTHORIZED:AtomicBool=AtomicBool::new(true);
 static PUBLICATIONS:AtomicU64=AtomicU64::new(0);
 static CONFIG_CHECKS:AtomicU64=AtomicU64::new(0);
 static NEXT:AtomicU64=AtomicU64::new(51);
 static RESOURCE_LEDGER:AtomicU64=AtomicU64::new(1);
 static EVENTS:Mutex<Vec<&'static str>>=Mutex::new(Vec::new());
 fn resource_change()->u64{EVENTS.lock().unwrap().push("resource");RESOURCE_LEDGER.fetch_add(1,Ordering::Relaxed)+1}
 const TOKEN:Token=Token{id:9};
 fn authorized(_: &State)->Result<(),Error>{if AUTHORIZED.load(Ordering::Relaxed){Ok(())}else{Err(Error::Auth)}}
 fn check_configs(_: &State,_:&mut Root)->Result<(),Error>{CONFIG_CHECKS.fetch_add(1,Ordering::Relaxed);Ok(())}
 struct PublicationTrace{stage:u64}
 // PUBLICATION_PREFIX
 fn publish_baseline(s:&mut State,t:Token,closing:bool)->Result<Receipt,Error>{
  publish_baseline_traced(s,t,closing,&mut PublicationTrace{stage:1})
 }
 // Registry/Plan publication is a counted storage boundary after the actual
 // guard and paid prefix, never a substitute for replacement authorization.
 fn publication_boundary(s:&mut State,t:Token,closing:bool,started:policy::PublicationTime)->Result<Receipt,Error>{
  PUBLICATION_CPU.store(policy::Clock::read(&mut NativeClock).cpu.ns-started.cpu.ns,Ordering::Relaxed);
  // Registry is controlled here; use its real budget contract at this boundary.
  policy::publication_budget(started,policy::Clock::read(&mut NativeClock))?;
  assert!(closing||root().baseline_count<32,"full receipt cache reached publication");EVENTS.lock().unwrap().push("publication");
  let q=exact(root(),t)?;let at=now();let seq=NEXT.fetch_add(1,Ordering::Relaxed);
  let snapshot=Snapshot{sequence:seq,taken_ns:at,core_generation:s.owner.context.core_generation,ledger_generation:s.owner.context.ledger_generation};
  let apply=ApplyId{plan_seq:seq,..ID};let stamp=PolicyStamp::for_action(q.baseline,seq,at,at)?;
  s.owner.desired[0]=Some(Desired{action:q.baseline,apply,stamp,state:ExecutionState::Pending,
   started:false,first_entry_ns:None,observed_ns:at,published:at,evidence:None,job:seq,
   dependencies:[None;2],core_generation:snapshot.core_generation,ledger_generation:snapshot.ledger_generation,execution_observed:false});
  PUBLICATIONS.fetch_add(1,Ordering::Relaxed);let mut value=receipt(s,apply,stamp,snapshot,q.baseline)?;
  // Actual OfferCpu(0) publication uses its synchronous stop-owner receipt;
  // that owner is a boundary here, not the asynchronous Desired cache path.
  if q.baseline==Action::OfferCpu(0){value.state=ExecutionState::Applied;value.started_ns=Some(at);}
  if closing{root_mut().closing=Some(value);root_mut().phase=Phase::Restoring;}
  Ok(value)
 }
 // ROOT_BODIES
 fn poll(t:Token)->Result<(),Error>{with(|s|{authorized(s)?;exact(root(),t)?;let r=root_mut();match r.phase{
  // ROOT_RUNNING_ARM
  _=>(),
 }Ok(())})}
 fn context(ledger:u64){publish_context(Context{core_generation:1,ledger_generation:ledger,control_mask:6,business_mask:9}).unwrap();}
 fn setup(){
  AUTHORIZED.store(true,Ordering::Relaxed);PUBLICATIONS.store(0,Ordering::Relaxed);NEXT.store(51,Ordering::Relaxed);RESOURCE_LEDGER.store(1,Ordering::Relaxed);EVENTS.lock().unwrap().clear();
  APPLY_CALLS.store(0,Ordering::Relaxed);APPLY_MODE.store(0,Ordering::Relaxed);RECONCILE_CALLS.store(0,Ordering::Relaxed);WALL.store(100_000_000,Ordering::Release);
  RECEIPT_CPU.store(0,Ordering::Relaxed);PAID_PREFIX_CPU.store(0,Ordering::Relaxed);PUBLICATION_CPU.store(0,Ordering::Relaxed);WORK.store(0,Ordering::Relaxed);
  with(|s|{s.owner.context=Context{core_generation:1,ledger_generation:1,control_mask:6,business_mask:9};s.owner.desired=[None];s.owner.family_epochs=[1];
   *root_mut()=Root{token:Some(TOKEN),request:Some(Request{kind:TrialKind::Baseline,baseline:Action::CpuWeight(2),target:key(12),owner:key(88),family:Family{domain:1,kind:1},not_before_ns:0}),phase:Phase::Frozen,baseline:[None;32],baseline_count:0,closing:None,fault:None,lifecycle:Lifecycle,registered:[Some(Checks{owner:key(88),settled:|_|Ok(())})],initial:None,first:None,unpublished:None,first_ready:true};Ok(())}).unwrap();
 }
 fn execute()->Receipt{super::poll(now()).unwrap();poll(TOKEN).unwrap();*root().baseline[root().baseline_count-1].as_ref().unwrap()}
 fn applied_initial()->Receipt{let p=baseline_apply(TOKEN).unwrap();root_mut().first=Some(p.snapshot);assert_eq!(p.state,if p.action==Action::OfferCpu(0){ExecutionState::Applied}else{ExecutionState::Pending});WALL.fetch_add(1_000_000,Ordering::Release);let a=execute();assert_eq!(a.state,ExecutionState::Applied);assert!(a.started_ns.is_some());a}
 fn failed_renewal(before:bool)->(Receipt,Receipt){
  setup();let a=applied_initial();WALL.store(a.stamp.installed_until_ns-750_000_000,Ordering::Release);
  if before{
   // Real resource change precedes publication, but the coordinator has not
   // yet published that new context. It must still be rejected at fresh poll.
   let actual_resource_ledger=resource_change();let b=baseline_apply(TOKEN).unwrap();context(actual_resource_ledger);
   assert!(EVENTS.lock().unwrap().ends_with(&["resource","publication"]));
   reject_and_sync(a,b)
  }else{
   let b=baseline_apply(TOKEN).unwrap();context(resource_change());assert!(EVENTS.lock().unwrap().ends_with(&["publication","resource"]));reject_and_sync(a,b)
  }
 }
 fn reject_and_sync(a:Receipt,b:Receipt)->(Receipt,Receipt){
  let calls=APPLY_CALLS.load(Ordering::Relaxed);super::poll(now()).unwrap();
  assert_eq!(APPLY_CALLS.load(Ordering::Relaxed),calls,"stale renewal invoked executor");
  assert_eq!(root().baseline[1].unwrap(),b,"fixture bypassed actual Root synchronization");
  assert_eq!(baseline_apply(TOKEN).unwrap(),b,"unsynchronized Pending produced a replacement");
  assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),2);
  poll(TOKEN).unwrap();let failed=root().baseline[1].unwrap();
  assert_eq!(failed.state,ExecutionState::Failed(Error::Stale),"Root poll did not synchronize the real denial");assert_eq!(failed.started_ns,None);
  assert_eq!(failed.apply,b.apply);assert_eq!(failed.snapshot,b.snapshot);assert_eq!(failed.stamp,b.stamp);
  assert_eq!(failed.approved_deadline_ns,b.approved_deadline_ns);
  (a,failed)
 }
 fn renewal_scenarios(){
  for before in [false,true]{
   let(a,b)=failed_renewal(before);WALL.fetch_add(1_000_000,Ordering::Release);let c=baseline_apply(TOKEN).unwrap();
   assert_ne!(c.apply,b.apply,"failed renewal future stamp blocked an independent successor");
   assert_ne!(c.stamp.version,b.stamp.version);assert_eq!(c.snapshot.ledger_generation,2);
   assert!(c.snapshot.taken_ns>b.snapshot.taken_ns);assert_eq!(c.stamp.installed_until_ns-c.snapshot.taken_ns,10_000_000_000);
   assert_eq!(c.snapshot.taken_ns,now());assert_eq!(c.state,ExecutionState::Pending);
   assert_eq!(root().baseline_count,3);assert_eq!(root().baseline[1],Some(b),"successor overwrote retained failed receipt");
   assert_eq!(baseline_apply(TOKEN).unwrap(),c,"Pending successor duplicated publication");
   let c=execute();assert_eq!(c.state,ExecutionState::Applied);assert!(c.observed_ns<a.stamp.installed_until_ns,"test failed to restore continuous coverage");
   assert_eq!(root().baseline[1],Some(b),"old failed attempt was revived");assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),3);
   assert!(a.baseline(None).is_ok());assert!(matches!(b.baseline(None),Err(Error::NotReady)));assert!(c.baseline(None).is_ok());
  }
 }
 fn guard_scenarios(){
  for mode in [1,2,3]{
   setup();let a=applied_initial();WALL.store(a.stamp.installed_until_ns-750_000_000,Ordering::Release);
   let p=baseline_apply(TOKEN).unwrap();APPLY_MODE.store(mode,Ordering::Relaxed);let b=execute();
   assert_eq!(b.state,match mode{1=>ExecutionState::Pending,2=>ExecutionState::Unknown,_=>ExecutionState::Failed(Error::Stale)});
   assert!(b.started_ns.is_some());let old_count=PUBLICATIONS.load(Ordering::Relaxed);
   assert_eq!(baseline_apply(TOKEN).unwrap(),b,"pending, unknown or started failure lost custody");assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),old_count);assert_eq!(b.apply,p.apply);
  }
  setup();let b=baseline_apply(TOKEN).unwrap();context(2);super::poll(now()).unwrap();poll(TOKEN).unwrap();let b=root().baseline[0].unwrap();assert_eq!(b.state,ExecutionState::Failed(Error::Stale));assert_eq!(baseline_apply(TOKEN).unwrap(),b,"first failed baseline became a renewal");
  for offset in [0,1]{let(a,b)=failed_renewal(false);WALL.store(a.stamp.installed_until_ns+offset,Ordering::Release);assert_eq!(baseline_apply(TOKEN).unwrap(),b,"expired earlier installation authorized recovery of a coverage gap");}
  for wrong in [0,1,2,3]{let(_,b)=failed_renewal(false);let a=root_mut().baseline[0].as_mut().unwrap();match wrong{0=>a.apply.target=key(13),1=>a.action=Action::CpuWeight(3),2=>a.apply.boot_epoch+=1,_=>a.started_ns=None};assert_eq!(baseline_apply(TOKEN).unwrap(),b,"unrelated installation authorized renewal");}
  for action in [Action::ControlSet(6),Action::OfferCpu(0)]{setup();root_mut().request.as_mut().unwrap().baseline=action;let a=applied_initial();assert_eq!(baseline_apply(TOKEN).unwrap(),a,"one-shot or stop acquired another renewal");assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),1);}
  let(_,b)=failed_renewal(false);root_mut().request.as_mut().unwrap().kind=TrialKind::Candidate;assert_eq!(baseline_apply(TOKEN),Err(Error::Conflict));root_mut().request.as_mut().unwrap().kind=TrialKind::Baseline;
  AUTHORIZED.store(false,Ordering::Relaxed);let count=PUBLICATIONS.load(Ordering::Relaxed);assert_eq!(baseline_apply(TOKEN),Err(Error::Auth));assert_eq!(root().baseline[1],Some(b));assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),count);
 }
 fn capacity_scenarios(){
  let(_,first_failure)=failed_renewal(false);let mut failed=vec![first_failure];let initial=root().baseline[0];
  while root().baseline_count<32{
   let before=root().baseline_count;let next=baseline_apply(TOKEN).unwrap();assert_eq!(root().baseline_count,before+1,"failed renewal did not append within fixed capacity");
   context(resource_change());let calls=APPLY_CALLS.load(Ordering::Relaxed);super::poll(now()).unwrap();poll(TOKEN).unwrap();let b=root().baseline[before].unwrap();
   assert_eq!(b.apply,next.apply);assert_eq!(b.state,ExecutionState::Failed(Error::Stale));assert_eq!(b.started_ns,None);assert_eq!(APPLY_CALLS.load(Ordering::Relaxed),calls);failed.push(b);
  }
  let snapshot=root().baseline;let count=PUBLICATIONS.load(Ordering::Relaxed);
  assert_eq!(baseline_apply(TOKEN),Err(Error::Capacity));assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),count,"full receipt cache published another decision");assert_eq!(root().baseline,snapshot);assert_eq!(root().baseline[0],initial);
  for(i,b)in failed.iter().enumerate(){assert_eq!(root().baseline[i+1],Some(*b));}
  restore(TOKEN).unwrap();assert_eq!(root().phase,Phase::Restoring);assert_eq!(root().baseline_count,32);
  super::poll(now()).unwrap();poll(TOKEN).unwrap();assert_eq!(root().phase,Phase::Complete,"full baseline cache blocked independent closing receipt");assert_eq!(root().closing.unwrap().state,ExecutionState::Applied);assert_eq!(root().baseline,snapshot);
 }
 fn missed_sync_scenario(){
  setup();let a=applied_initial();WALL.store(a.stamp.installed_until_ns-750_000_000,Ordering::Release);
  let b=baseline_apply(TOKEN).unwrap();super::poll(now()).unwrap();
  let terminal=with(|s|receipt(s,b.apply,b.stamp,b.snapshot,b.action)).unwrap();
  assert_eq!(terminal.state,ExecutionState::Applied);assert_eq!(root().baseline[1],Some(b));
  RECEIPT_CPU.store(17,Ordering::Relaxed);
  restore(TOKEN).unwrap();let c=root().closing.unwrap();assert_ne!(c.apply,b.apply);
  let publication_cpu=PUBLICATION_CPU.load(Ordering::Relaxed);let prefix_cpu=PAID_PREFIX_CPU.load(Ordering::Relaxed);
  super::poll(now()).unwrap();
  assert_eq!(poll(TOKEN),Ok(()),"missed Root sync stranded the old receipt after replacement");
  assert_eq!(publication_cpu,17,"receipt refresh escaped original publication CPU sample");
  assert_eq!(prefix_cpu,34,"receipt refresh escaped original physical prefix sample");
  assert_eq!(root().baseline[0],Some(a));assert_eq!(root().baseline[1],Some(terminal),"replacement lost exact terminal receipt");
  assert_eq!(root().phase,Phase::Complete);assert_eq!(root().closing.unwrap().state,ExecutionState::Applied);
  assert_eq!(root().closing.unwrap().apply,c.apply);assert_eq!(root().closing.unwrap().approved_deadline_ns,c.approved_deadline_ns);
  assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),3);
 }
 fn closing_reuse(){
  setup();let a=applied_initial();WALL.store(a.stamp.installed_until_ns-750_000_000,Ordering::Relaxed);
  baseline_apply(TOKEN).unwrap();super::poll(now()).unwrap();root_mut().fault=Some(Error::Conflict);
  restore(TOKEN).unwrap();let closing=root().closing.unwrap();APPLY_MODE.store(2,Ordering::Relaxed);
  super::poll(now()).unwrap();poll(TOKEN).unwrap();let unknown=root().closing.unwrap();
  assert_eq!(unknown.state,ExecutionState::Unknown);assert_eq!(root().phase,Phase::Restoring);
  restore(TOKEN).unwrap();assert_eq!(root().closing,Some(unknown));assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),3);
  super::poll(now()).unwrap();poll(TOKEN).unwrap();assert_eq!(root().phase,Phase::Complete);
  assert_eq!(root().fault,Some(Error::Conflict));assert_eq!(root().closing.unwrap().apply,closing.apply);
  assert_eq!(root().closing.unwrap().approved_deadline_ns,closing.approved_deadline_ns);
  restore(TOKEN).unwrap();assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),3);
  for action in [Action::RecoveryRecipe(1),Action::Placement(1)]{
   setup();root_mut().request.as_mut().unwrap().baseline=action;let original=applied_initial();
   restore(TOKEN).unwrap();assert_eq!(root().closing,Some(original));assert_eq!(root().phase,Phase::Complete);
   assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),1,"one-shot restore published a second decision");
  }
 }
 fn paid_refresh_limit(){
  for cost in [500_000,500_001]{
   setup();let a=applied_initial();WALL.store(a.stamp.installed_until_ns-750_000_000,Ordering::Relaxed);
   let b=baseline_apply(TOKEN).unwrap();super::poll(now()).unwrap();
   let terminal=with(|s|receipt(s,b.apply,b.stamp,b.snapshot,b.action)).unwrap();
   RECEIPT_CPU.store(cost,Ordering::Relaxed);let result=restore(TOKEN);
   assert_eq!(result,if cost==500_000{Ok(())}else{Err(Error::Budget)},"refresh CPU escaped unchanged 500us publication cap");
   assert_eq!(root().baseline[1],Some(terminal));assert_eq!(terminal.approved_deadline_ns,b.approved_deadline_ns);
   assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),if cost==500_000{3}else{2});
   if cost>500_000{assert_eq!(root().closing,None);assert_eq!(PAID_PREFIX_CPU.load(Ordering::Relaxed),500_001);}
  }
 }
 fn replacement_guards(){
  for mode in [1,2]{
   setup();let a=applied_initial();WALL.store(a.stamp.installed_until_ns-750_000_000,Ordering::Release);
   let b=baseline_apply(TOKEN).unwrap();APPLY_MODE.store(mode,Ordering::Relaxed);super::poll(now()).unwrap();
   let current=with(|s|receipt(s,b.apply,b.stamp,b.snapshot,b.action)).unwrap();
   assert_eq!(current.state,if mode==1{ExecutionState::Pending}else{ExecutionState::Unknown});
   assert_eq!(restore(TOKEN),Err(Error::Busy),"unresolved Desired was replaced");
   assert_eq!(root().baseline[1],Some(b));assert_eq!(root().closing,None);assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),2);
   poll(TOKEN).unwrap();assert_eq!(root().baseline[1],Some(current));
  }
  for wrong in 0..7{
   setup();let a=applied_initial();WALL.store(a.stamp.installed_until_ns-750_000_000,Ordering::Release);
   let b=baseline_apply(TOKEN).unwrap();super::poll(now()).unwrap();
   with(|s|{let d=s.owner.desired[0].as_mut().unwrap();match wrong{
    0=>d.apply.plan_seq+=1,1=>d.stamp.version+=1,2=>d.action=Action::CpuWeight(3),
    3=>d.apply.target.generation+=1,4=>d.apply.boot_epoch+=1,_=>(),
   }if wrong==6{s.owner.family_epochs[0]=0;}Ok(())}).unwrap();
   let result=restore(if wrong==5{Token{id:TOKEN.id+1}}else{TOKEN});
   assert_eq!(result,Err(if matches!(wrong,2|3){Error::NotFound}else if wrong==6{Error::NotReady}else{Error::Stale}),"identity mismatch replaced retained custody");
   assert_eq!(root().baseline[1],Some(b));assert_eq!(root().closing,None);assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),2);
  }
  // Cached Pending must retain a real failed terminal result too. Existing
  // failed-started/expired coverage renewal denial is covered above; restore
  // may issue its independently checked closing command after terminal failure.
  for started in [false,true]{
   setup();let a=applied_initial();WALL.store(a.stamp.installed_until_ns-750_000_000,Ordering::Release);
   let b=baseline_apply(TOKEN).unwrap();
   if started{APPLY_MODE.store(3,Ordering::Relaxed);}else{context(2);}
   super::poll(now()).unwrap();let terminal=with(|s|receipt(s,b.apply,b.stamp,b.snapshot,b.action)).unwrap();
   assert_eq!(terminal.state,ExecutionState::Failed(Error::Stale));
   assert_eq!(terminal.started_ns.is_some(),started);
   restore(TOKEN).unwrap();assert_eq!(root().baseline[1],Some(terminal),"replacement fabricated or discarded failed receipt");
   assert_eq!(terminal.stamp,b.stamp);assert_eq!(terminal.snapshot,b.snapshot);assert_eq!(terminal.approved_deadline_ns,b.approved_deadline_ns);
  }
  setup();let b=baseline_apply(TOKEN).unwrap();APPLY_MODE.store(1,Ordering::Relaxed);
  WALL.store(b.approved_deadline_ns+1,Ordering::Relaxed);super::poll(now()).unwrap();
  assert_eq!(restore(TOKEN),Err(Error::Busy),"expired started operation lost unknown custody");
  poll(TOKEN).unwrap();let unknown=root().baseline[0].unwrap();assert_eq!(unknown.state,ExecutionState::Unknown);
  assert_eq!(unknown.approved_deadline_ns,b.approved_deadline_ns);assert_eq!(unknown.snapshot,b.snapshot);
  assert_eq!(root().closing,None);assert_eq!(PUBLICATIONS.load(Ordering::Relaxed),1);
 }
 pub fn scenarios(){
  match std::env::args().nth(1).as_deref(){Some("renewal")=>renewal_scenarios(),Some("guards")=>guard_scenarios(),Some("capacity")=>capacity_scenarios(),Some("missed-sync")=>missed_sync_scenario(),Some("replacement-guards")=>replacement_guards(),Some("closing-reuse")=>closing_reuse(),Some("paid-limit")=>paid_refresh_limit(),_=>panic!("unknown scenario")}
  println!("failed renewal custody scenarios passed");
 }
}

//! Serialized EL1 desired-plan owner for the V0.19.9 fixed CPU0 topology.
//! The registered decision gate must precede publication; this is its native
//! atomic metadata adapter, NOT an alternate SVC, permission or model gate.
//! The real resource owners must preflight all constraints and reserve all
//! obligations under the same serializer. No device/redo work occurs here.
//! No optimization can overwrite an unresolved desired action.
use super::{Error,Identity,action_schema_v2::ActionV2,
    apply_report_v1::{ActionStatus,ApplyReportV1,ExecutorBindingV1,PlanKey,ReportOrigin,MAX_BINDINGS},
    apply_work_v1::ApplyWorkV1,plan_wire_v2::{PlanV2,MAX_ACTIONS},
    registered_gate_v3::TrustedRegistrationScope};
use sha2::{Digest,Sha256};
fn report_digest(r:&ApplyReportV1<'_>)->Result<[u8;32],Error>{
    let mut wire=[0;super::apply_report_v1::MAX_APPLY_REPORT_BYTES];
    let n=r.encode(&mut wire)?;
    Ok(Sha256::digest(&wire[..n]).into())
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct PublishedAction{
    pub key:PlanKey,pub index:u16,pub binding:ExecutorBindingV1,
    pub plan_digest:[u8;32],
    pub version:u64,pub prior_target_version:u64,pub until_ns:u64,
    pub value:ActionV2,pub published_ns:u64,pub accepted_ns:Option<u64>,
}
#[derive(Clone,Copy)]
struct TargetSlot{
    binding:ExecutorBindingV1,
    // Version accepted by the executor, not proof of actual APPLIED effect.
    accepted_version:u64,pending:Option<PublishedAction>,
    no_effect:Option<[u8;32]>,
}
pub struct DesiredBank{
    boot:u64,controller:u64,publisher:Identity,version:u64,plan_hi:u64,last_ns:u64,
    fenced:bool,slots:[Option<TargetSlot>;MAX_BINDINGS],
}
fn origin(b:ExecutorBindingV1)->ReportOrigin{
    if b.domain==4{ReportOrigin::User{holder:b.holder,cap_id:b.endpoint_cap_id}}
    else{ReportOrigin::Kernel}
}
fn target(a:&PublishedAction)->Identity{a.binding.target}
impl DesiredBank{
    pub const fn empty()->Self{Self{boot:0,controller:0,publisher:Identity{id:0,generation:0},
        version:0,plan_hi:0,last_ns:0,fenced:false,slots:[None;MAX_BINDINGS]}}
    pub fn bind_boot(&mut self,boot:u64,controller:u64,publisher:Identity,
        verify_registry:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if self.boot!=0{return Err(Error::Busy);}
        if boot==0||controller==0||!publisher.valid(){return Err(Error::Invalid);}
        verify_registry()?;self.boot=boot;self.controller=controller;self.publisher=publisher;Ok(())
    }
    pub fn version(&self)->u64{self.version}
    pub fn fence_publications(&mut self){self.fenced=true;}
    /// Controller-epoch replacement is deliberately narrower than an
    /// arbitrary registry reset. The native owner must prove the old
    /// controller/publisher are stopped or fenced, all retained plans
    /// have settled, and every target policy has safely returned to its
    /// deterministic fallback. No active work or global version is erased.
    pub fn replace_controller(&mut self,old_epoch:u64,next_epoch:u64,next_publisher:Identity,now:u64,
        verify_handoff:impl FnOnce(u64,u64,Identity,Identity,u64)->Result<(),Error>)->Result<(),Error>{
        self.clock(now)?;
        if self.boot==0||!self.fenced{return Err(Error::NotReady);}
        if old_epoch!=self.controller||old_epoch.checked_add(1)!=Some(next_epoch)
            ||!next_publisher.valid()||next_publisher.id!=self.publisher.id
            ||next_publisher.generation<self.publisher.generation{return Err(Error::Stale);}
        if self.slots.iter().flatten().any(|r|r.pending.is_some()||r.no_effect.is_some()){
            return Err(Error::Busy);
        }
        verify_handoff(old_epoch,next_epoch,self.publisher,next_publisher,self.version)?;
        self.controller=next_epoch;self.publisher=next_publisher;self.plan_hi=0;
        self.last_ns=now;self.fenced=false;Ok(())
    }
    fn ready(&self,now:u64)->Result<(),Error>{
        if self.boot==0||self.fenced{return Err(Error::NotReady);}
        self.clock(now)
    }
    fn clock(&self,now:u64)->Result<(),Error>{
        if now==0||now<self.last_ns{return Err(Error::Clock);}Ok(())
    }
    fn index(&self,domain:u16,target:Identity)->Result<usize,Error>{
        self.slots.iter().position(|s|s.is_some_and(|s|
            s.binding.domain==domain&&s.binding.target==target)).ok_or(Error::Stale)
    }
    pub fn register_target(&mut self,binding:ExecutorBindingV1,
        verify_live:impl FnOnce(ExecutorBindingV1)->Result<(),Error>)->Result<(),Error>{
        if self.boot==0||self.fenced{return Err(Error::NotReady);}
        if !binding.permits(origin(binding)){return Err(Error::Denied);}
        let previous=self.slots.iter().position(|s|s.is_some_and(|s|
            s.binding.domain==binding.domain&&s.binding.target.id==binding.target.id));
        let i=if let Some(i)=previous{
            let old=self.slots[i].unwrap();
            if old.binding.active||old.pending.is_some(){return Err(Error::Busy);}
            if binding.target.generation<=old.binding.target.generation{return Err(Error::Stale);}
            i
        }else{self.slots.iter().position(Option::is_none).ok_or(Error::Exhausted)?};
        verify_live(binding)?;
        self.slots[i]=Some(TargetSlot{binding,accepted_version:0,pending:None,no_effect:None});Ok(())
    }
    pub fn retire_target(&mut self,domain:u16,id:Identity,
        verify_stopped:impl FnOnce(ExecutorBindingV1)->Result<(),Error>)->Result<(),Error>{
        let i=self.index(domain,id)?;let row=self.slots[i].as_mut().unwrap();
        if !row.binding.active{return Err(Error::Stale);}
        if row.pending.is_some(){return Err(Error::Busy);}
        verify_stopped(row.binding)?;row.binding.active=false;Ok(())
    }
    /// Publish exact desired metadata atomically, with one globally increasing
    /// version for all actions. Must be invoked inside RegisteredDecisionGate's
    /// publish callback, with the actual authenticated publisher/CPU and scope.
    /// The all-target callback is observational (or an atomic reservation that
    /// leaves no effects on error); no I/O or asynchronous dispatch inside it.
    pub fn publish_registered(&mut self,actor:Identity,cpu:usize,wire:&[u8],
        scope:TrustedRegistrationScope,
        verify_all:impl FnOnce(&[Option<PublishedAction>])->Result<(),Error>)->Result<u64,Error>{
        self.ready(scope.now_ns)?;
        if actor!=self.publisher||cpu!=0||scope.boot_epoch!=self.boot
            ||scope.controller_epoch!=self.controller{return Err(Error::Denied);}
        let plan=PlanV2::decode(wire)?;
        if plan.header.controller_epoch!=self.controller||plan.header.plan_seq<=self.plan_hi
            ||scope.base_plan_version!=self.version||plan.header.base_plan_version!=self.version
            ||plan.header.snapshot_seq!=scope.snapshot_seq||plan.ledger_generation!=scope.ledger_generation
            ||plan.core_generation!=scope.core_generation{return Err(Error::Stale);}
        if scope.sampled_ns>scope.now_ns||scope.now_ns-scope.sampled_ns>=100_000_000{return Err(Error::Expired);}
        let next=self.version.checked_add(1).ok_or(Error::Exhausted)?;
        let count=usize::from(plan.header.action_count);
        let plan_digest=Sha256::digest(wire).into();
        let mut slots=[0usize;MAX_ACTIONS];let mut stage=[None;MAX_ACTIONS];
        for i in 0..count{
            let a=plan.action(i)?;
            if a.expires_local_ns<=scope.now_ns||a.expires_local_ns>
                scope.sampled_ns.checked_add(100_000_000).ok_or(Error::Clock)?{return Err(Error::Expired);}
            let until=if a.domain_id==14{0}else{scope.sampled_ns.checked_add(10_000_000_000).ok_or(Error::Clock)?};
            if plan.header.active_until_local_ns!=until{return Err(Error::Denied);}
            let slot=self.index(a.domain_id,Identity{id:a.target_id,generation:a.target_generation})?;
            let row=self.slots[slot].unwrap();
            if !row.binding.active{return Err(Error::Stale);}
            if row.pending.is_some()||row.no_effect.is_some(){return Err(Error::Busy);}
            if slots[..i].contains(&slot){return Err(Error::Denied);}
            slots[i]=slot;
            stage[i]=Some(PublishedAction{key:PlanKey{boot_epoch:self.boot,controller_epoch:self.controller,
                plan_seq:plan.header.plan_seq},index:i as u16,binding:row.binding,plan_digest,version:next,
                prior_target_version:row.accepted_version,until_ns:until,
                value:ActionV2::decode(a.domain_id,a.action_kind,a.action_payload)?,
                published_ns:scope.now_ns,accepted_ns:None});
        }
        verify_all(&stage[..count])?;
        // Commit all entries only after every target and the independent
        // reservation preflight passed. No fallible work after this point.
        for i in 0..count{self.slots[slots[i]].as_mut().unwrap().pending=stage[i];}
        self.version=next;self.plan_hi=plan.header.plan_seq;self.last_ns=scope.now_ns;Ok(next)
    }
    /// Read-only reconciliation of a committed plan whose publisher reply
    /// was lost. All originally published target slots must still exist,
    /// carry the exact complete plan digest, and have no accepted work.
    /// No reconstructed reservation or new publication is performed.
    pub fn verify_committed_publication(&self,plan:&PlanV2<'_>,digest:[u8;32],version:u64,
        verify_reservations:impl FnOnce(&[Option<PublishedAction>])->Result<(),Error>,
    )->Result<(),Error>{
        if self.boot==0||self.fenced||plan.header.controller_epoch!=self.controller
            ||version<=plan.header.base_plan_version||version>self.version
            ||plan.header.plan_seq>self.plan_hi||digest==[0;32]{return Err(Error::Stale);}
        let count=usize::from(plan.header.action_count);
        let key=PlanKey{boot_epoch:self.boot,controller_epoch:self.controller,plan_seq:plan.header.plan_seq};
        let mut stage=[None;MAX_ACTIONS];
        for i in 0..count{
            let a=plan.action(i)?;
            let row=self.slots[self.index(a.domain_id,Identity{id:a.target_id,generation:a.target_generation})?].unwrap();
            let p=row.pending.ok_or(Error::NotReady)?;
            if p.key!=key||p.index!=i as u16||p.version!=version||p.plan_digest!=digest
                ||p.binding!=row.binding||!row.binding.active||p.accepted_ns.is_some()||row.no_effect.is_some()
                ||p.until_ns!=plan.header.active_until_local_ns
                ||p.value!=ActionV2::decode(a.domain_id,a.action_kind,a.action_payload)?{return Err(Error::Denied);}
            stage[i]=Some(p);
        }
        verify_reservations(&stage[..count])
    }

    /// Invoke only inside the registered gate's exact ApplyWork acceptance
    /// callback. No version/lease supplied by the executor can replace the
    /// metadata frozen at publication. Owner must accept atomically or have
    /// no effect on error; actual asynchronous work comes after acceptance.
    pub fn accept(&mut self,w:&ApplyWorkV1<'_>,actual_origin:ReportOrigin,now:u64,
        accept_native:impl FnOnce(PublishedAction)->Result<(),Error>)->Result<(),Error>{
        self.ready(now)?;
        let i=self.index(w.domain,w.target)?;
        let row=self.slots[i].as_mut().unwrap();
        let mut a=row.pending.ok_or(Error::NotReady)?;
        if !row.binding.permits(actual_origin)||a.binding!=row.binding||a.key!=w.key
            ||a.index!=w.action_index||a.version!=w.plan_version
            ||w.executor_generation!=a.binding.executor_generation
            ||a.value!=ActionV2::decode(w.domain,1,w.payload)?{return Err(Error::Denied);}
        if a.accepted_ns.is_some()||row.no_effect.is_some(){return Err(Error::Busy);}
        if now<a.published_ns{return Err(Error::Clock);}
        if a.until_ns!=0&&now>=a.until_ns{return Err(Error::Expired);}
        accept_native(a)?;
        a.accepted_ns=Some(now);row.accepted_version=a.version;row.pending=Some(a);
        self.last_ns=now;Ok(())
    }
    /// Seal an unaccepted action against later admission, keeping its
    /// reservation and exact terminal digest until registered-plan feedback
    /// custody is independently verified. Call from the terminal owner's
    /// seal_unaccepted_terminal callback under the same serializer.
    /// verify_no_effect is a read-only proof of no accepted native obligation,
    /// or an atomic fence with no state change on error.
    pub fn seal_unaccepted(&mut self,r:&ApplyReportV1<'_>,actual_origin:ReportOrigin,now:u64,
        verify_no_effect:impl FnOnce(PublishedAction)->Result<(),Error>)->Result<(),Error>{
        self.clock(now)?;
        let i=self.index(r.domain_id,r.target)?;let row=self.slots[i].as_mut().unwrap();
        let a=row.pending.ok_or(Error::Stale)?;
        if a.accepted_ns.is_some(){return Err(Error::Busy);}
        if !a.binding.permits(actual_origin)||a.key!=r.key||a.index!=r.action_index
            ||a.version!=r.plan_version||a.binding.executor_generation!=r.executor_generation
            ||a.value!=ActionV2::decode(r.domain_id,1,r.action)?
            ||!matches!(r.state,ActionStatus::Rejected|ActionStatus::Cancelled)
            ||r.result>=0||r.completed_ns<a.published_ns||r.completed_ns>now{return Err(Error::Denied);}
        let digest=report_digest(r)?;
        if let Some(old)=row.no_effect{
            return if old==digest{Ok(())}else{Err(Error::Denied)};
        }
        verify_no_effect(a)?;
        row.no_effect=Some(digest);self.last_ns=now;Ok(())
    }
    /// Close only an exact independently verified terminal. Accepted and
    /// unaccepted obligations survive expiry and fencing; neither releases
    /// on timeout. For an unaccepted action only no-effect terminals qualify.
    /// Does not invalidate a live executor's already installed policy.
    pub fn finish(&mut self,r:&ApplyReportV1<'_>,actual_origin:ReportOrigin,now:u64,
        verify_custody:impl FnOnce(PublishedAction)->Result<(),Error>)->Result<(),Error>{
        self.clock(now)?;
        let i=self.index(r.domain_id,r.target)?;let row=self.slots[i].as_mut().unwrap();
        let a=row.pending.ok_or(Error::Stale)?;
        if !a.binding.permits(actual_origin)||a.key!=r.key||a.index!=r.action_index
            ||a.version!=r.plan_version||target(&a)!=r.target
            ||a.binding.executor_generation!=r.executor_generation
            ||a.value!=ActionV2::decode(r.domain_id,1,r.action)?{return Err(Error::Denied);}
        if r.state==ActionStatus::Unknown{return Err(Error::NotReady);}
        if r.completed_ns<a.accepted_ns.unwrap_or(a.published_ns)||r.completed_ns>now
            ||a.accepted_ns.is_none()&&r.state==ActionStatus::Applied
            ||r.state==ActionStatus::Applied&&r.result!=0{return Err(Error::Denied);}
        if a.accepted_ns.is_none(){
            if row.no_effect!=Some(report_digest(r)?){return Err(Error::NotReady);}
        }
        verify_custody(a)?;
        row.pending=None;row.no_effect=None;self.last_ns=now;Ok(())
    }
    pub fn pending(&self,domain:u16,id:Identity)->Result<Option<PublishedAction>,Error>{
        Ok(self.slots[self.index(domain,id)?].unwrap().pending)
    }
}
const _:()=assert!(core::mem::size_of::<DesiredBank>()<=64*1024);
#[cfg(test)]
mod tests{
    use super::*;
    const PUB:Identity=Identity{id:8,generation:1};
    fn binding(id:u64)->ExecutorBindingV1{
        ExecutorBindingV1{domain:15,role:1,active:true,target:Identity{id,generation:1},
            executor_generation:1,holder:Identity{id:0,generation:0},endpoint_cap_id:0}
    }
    fn scope(base:u64)->TrustedRegistrationScope{
        TrustedRegistrationScope{boot_epoch:1,controller_epoch:1,rules_generation:1,rules_hash:[1;32],
            base_plan_version:base,ledger_generation:1,core_generation:1,snapshot_seq:1,sampled_ns:100,now_ns:120}
    }
    fn plan(seq:u64,base:u64,second:bool)->([u8;360],usize){
        let mut b=[0u8;360];let n=if second{360}else{212};
        b[..4].copy_from_slice(&0x43594c31u32.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());b[6..8].copy_from_slice(&64u16.to_le_bytes());
        b[8..12].copy_from_slice(&(n as u32).to_le_bytes());
        b[12..14].copy_from_slice(&(if second{2u16}else{1u16}).to_le_bytes());
        for(at,v)in [(16,seq),(24,base),(40,1),(48,1),(56,10_000_000_100)]{
            b[at..at+8].copy_from_slice(&v.to_le_bytes());
        }
        for i in 0..if second{2}else{1}{
            let h=64+i*148;b[h..h+4].copy_from_slice(&0x43595031u32.to_le_bytes());
            b[h+4..h+6].copy_from_slice(&2u16.to_le_bytes());
            b[h+6..h+8].copy_from_slice(&144u16.to_le_bytes());
            b[h+8..h+10].copy_from_slice(&15u16.to_le_bytes());
            b[h+10..h+12].copy_from_slice(&1u16.to_le_bytes());
            b[h+12..h+16].copy_from_slice(&4u32.to_le_bytes());
            for(at,v)in [(16,1),(24,seq*2+i as u64),(32,1),(40,15+i as u64),
                (48,1),(56,1),(64,1),(72,100_000_100u64)]{b[h+at..h+at+8].copy_from_slice(&v.to_le_bytes());}
            b[h+112..h+144].fill(2);b[h+144..h+146].copy_from_slice(&2u16.to_le_bytes());
            b[h+146..h+148].copy_from_slice(&[32,0]);
        }
        (b,n)
    }
    fn work(id:u64,index:u16)->ApplyWorkV1<'static>{
        ApplyWorkV1{key:PlanKey{boot_epoch:1,controller_epoch:1,plan_seq:1},action_index:index,domain:15,
            target:binding(id).target,executor_generation:1,plan_version:1,payload:&[32,0]}
    }
    fn report(w:ApplyWorkV1<'static>,state:ActionStatus)->ApplyReportV1<'static>{
        ApplyReportV1{key:w.key,action_index:w.action_index,domain_id:w.domain,target:w.target,
            executor_generation:w.executor_generation,plan_version:w.plan_version,state,
            result:if state==ActionStatus::Applied{0}else{-7},completed_ns:140,action:w.payload}
    }
    #[test]
    fn epoch_replacement_cannot_discard_pending_or_reset_global_version(){
        let mut b=DesiredBank::empty();b.bind_boot(1,1,PUB,||Ok(())).unwrap();
        let t=binding(15);b.register_target(t,|_|Ok(())).unwrap();
        let (p,n)=plan(1,0,false);
        b.publish_registered(PUB,0,&p[..n],scope(0),|_|Ok(())).unwrap();
        assert_eq!(b.replace_controller(1,2,PUB,130,|_,_,_,_,_|panic!()),Err(Error::NotReady));
        b.fence_publications();
        assert_eq!(b.replace_controller(1,2,PUB,130,|_,_,_,_,_|panic!()),Err(Error::Busy));
        let terminal=report(work(15,0),ActionStatus::Cancelled);
        b.seal_unaccepted(&terminal,ReportOrigin::Kernel,140,|_|Ok(())).unwrap();
        b.finish(&terminal,ReportOrigin::Kernel,141,|_|Ok(())).unwrap();
        let next=Identity{generation:2,..PUB};
        assert_eq!(b.replace_controller(1,2,next,142,|_,_,_,_,_|Err(Error::NotReady)),Err(Error::NotReady));
        assert_eq!(b.version(),1);
        b.replace_controller(1,2,next,143,|a,z,old,new,v|{
            assert_eq!((a,z,old,new,v),(1,2,PUB,next,1));Ok(())
        }).unwrap();
        let (mut p,n)=plan(1,1,false);
        let sc=TrustedRegistrationScope{controller_epoch:2,now_ns:150,..scope(1)};
        assert_eq!(b.publish_registered(next,0,&p[..n],sc,|_|panic!()),Err(Error::Stale));
        p[40..48].copy_from_slice(&2u64.to_le_bytes());
        p[80..88].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(b.publish_registered(PUB,0,&p[..n],sc,|_|panic!()),Err(Error::Denied));
        assert_eq!(b.publish_registered(next,0,&p[..n],sc,|_|Ok(())),Ok(2));
        assert_eq!(b.version(),2);
    }
    #[test]
    fn publication_atomic_global_version_and_exact_per_target_custody(){
        let mut b=DesiredBank::empty();b.bind_boot(1,1,PUB,||Ok(())).unwrap();
        let t0=binding(15);let t1=binding(16);
        b.register_target(t0,|_|Ok(())).unwrap();
        let (p,n)=plan(1,0,true);
        assert_eq!(b.publish_registered(PUB,0,&p[..n],scope(0),|_|panic!()),Err(Error::Stale));
        assert_eq!(b.version(),0);assert_eq!(b.pending(15,t0.target),Ok(None));
        b.register_target(t1,|_|Ok(())).unwrap();
        assert_eq!(b.publish_registered(PUB,1,&p[..n],scope(0),|_|panic!()),Err(Error::Denied));
        assert_eq!(b.publish_registered(PUB,0,&p[..n],scope(0),|_|Err(Error::Busy)),Err(Error::Busy));
        assert_eq!(b.version(),0);assert_eq!(b.pending(15,t1.target),Ok(None));
        assert_eq!(b.publish_registered(PUB,0,&p[..n],scope(0),|a|{
            assert_eq!(a.len(),2);assert!(a.iter().flatten().all(|a|a.version==1&&a.prior_target_version==0));
            Ok(())
        }),Ok(1));
        let decoded=PlanV2::decode(&p[..n]).unwrap();let digest=Sha256::digest(&p[..n]).into();
        assert_eq!(b.verify_committed_publication(&decoded,[3;32],1,|_|panic!()),Err(Error::Denied));
        assert_eq!(b.verify_committed_publication(&decoded,digest,1,|a|{assert_eq!(a.len(),2);Ok(())}),Ok(()));
        let w=work(15,0);let other=work(16,1);let origin=ReportOrigin::Kernel;
        assert_eq!(b.accept(&ApplyWorkV1{plan_version:2,..w},origin,130,|_|panic!()),Err(Error::Denied));
        assert_eq!(b.accept(&w,origin,130,|_|Err(Error::Busy)),Err(Error::Busy));
        assert_eq!(b.pending(15,t0.target).unwrap().unwrap().accepted_ns,None);
        b.accept(&w,origin,130,|a|{assert_eq!(a.until_ns,10_000_000_100);Ok(())}).unwrap();
        assert_eq!(b.accept(&w,origin,131,|_|panic!()),Err(Error::Busy));
        assert_eq!(b.verify_committed_publication(&decoded,digest,1,|_|panic!()),Err(Error::Denied));
        assert_eq!(b.finish(&report(other,ActionStatus::Applied),origin,140,|_|panic!()),Err(Error::Denied));
        let (p2,n2)=plan(2,1,false);
        assert_eq!(b.publish_registered(PUB,0,&p2[..n2],TrustedRegistrationScope{now_ns:140,..scope(1)},|_|panic!()),Err(Error::Busy));
        assert_eq!(b.finish(&report(w,ActionStatus::Unknown),origin,140,|_|panic!()),Err(Error::NotReady));
        assert_eq!(b.finish(&report(w,ActionStatus::Applied),origin,140,|_|Err(Error::NotReady)),Err(Error::NotReady));
        b.finish(&report(w,ActionStatus::Applied),origin,140,|_|Ok(())).unwrap();
        assert_eq!(b.publish_registered(PUB,0,&p2[..n2],TrustedRegistrationScope{now_ns:141,..scope(1)},|a|{
            assert_eq!(a[0].unwrap().prior_target_version,1);Ok(())
        }),Ok(2));
        assert_eq!(b.pending(15,t1.target).unwrap().unwrap().version,1);
        let cancelled=report(other,ActionStatus::Cancelled);
        assert_eq!(b.finish(&cancelled,origin,142,|_|panic!()),Err(Error::NotReady));
        assert_eq!(b.seal_unaccepted(&cancelled,origin,142,|_|Err(Error::NotReady)),Err(Error::NotReady));
        b.seal_unaccepted(&cancelled,origin,142,|a|{assert_eq!(a.accepted_ns,None);Ok(())}).unwrap();
        assert_eq!(b.accept(&other,origin,142,|_|panic!("sealed action cannot execute")),Err(Error::Busy));
        b.fence_publications();
        assert_eq!(b.accept(&other,origin,142,|_|panic!()),Err(Error::NotReady));
        let altered=ApplyReportV1{result:-8,..cancelled};
        assert_eq!(b.finish(&altered,origin,142,|_|panic!()),Err(Error::NotReady));
        assert_eq!(b.finish(&cancelled,origin,142,|_|Err(Error::NotReady)),Err(Error::NotReady));
        b.finish(&cancelled,origin,142,|_|Ok(())).unwrap();
        b.retire_target(15,t1.target,|_|Ok(())).unwrap();
        assert_eq!(b.register_target(t1,|_|panic!()),Err(Error::NotReady));
    }
}

//! Current D02 task-group creation admission and exact native effect custody.
//! Serialized protected task owner. No model or wire request confers a
//! package, task, resource or recovery capability. The native loader must
//! authenticate and reserve actual task/VM/scheduler resources before create.
//! Not a replacement for the independent recovery creation pool.
use super::{Error,Identity,action_schema_v2::ActionV2,
    apply_work_v1::ApplyWorkV1,
    apply_report_v1::{ApplyReportV1,ActionStatus,PlanKey,MAX_APPLY_REPORT_BYTES}};
pub const MAX_THREADS:usize=64;
pub const MAX_PENDING:usize=64;
const WINDOW:u64=100_000_000;
const GROUPS:usize=64;
const RECEIPTS:usize=128; // bounded boot-local custody; no silent eviction
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Request{
    pub caller:Identity,pub request_id:u64,pub package:Identity,pub group:Identity,
    pub digest:[u8;32],
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum State{Queued,Unknown,Created(Identity),Rejected}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Outcome{Created(Identity),NoEffect,Unknown}
/// Actual constructor completion, independently sampled by the native
/// owner after its effect; the service invocation time is not completion.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Completion{pub outcome:Outcome,pub completed_ns:u64}
#[derive(Clone,Copy)]
struct Row{req:Request,state:State,sequence:u64,occupied:bool}
#[derive(Clone,Copy)]
struct Group{id:Identity,version:u64,limit:u16,until:u64,window:u64,used:u16,
    last_change:u64,changes:[u64;4],change_count:usize,work:Option<Work>}
#[derive(Clone,Copy)]
struct Work{key:PlanKey,index:u16,version:u64,limit:u16,accepted:u64,until:u64,
    effect:Option<(ActionStatus,u64)>}
pub struct Owner{boot:u64,executor:u64,last:u64,seq:u64,
    groups:[Option<Group>;GROUPS],rows:[Option<Row>;RECEIPTS]}
impl Owner{
    pub const fn empty()->Self{Self{boot:0,executor:0,last:0,seq:0,groups:[None;GROUPS],rows:[None;RECEIPTS]}}
    pub fn bind(&mut self,boot:u64,executor:u64,verify:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if self.boot!=0{return Err(Error::Busy);}
        if boot==0||executor==0{return Err(Error::Invalid);}
        verify()?;self.boot=boot;self.executor=executor;Ok(())
    }
    fn ready(&self,now:u64)->Result<(),Error>{
        if self.boot==0{return Err(Error::NotReady);}
        if now==0||now<self.last{return Err(Error::Clock);}Ok(())
    }
    fn group(&self,id:Identity)->Result<usize,Error>{
        self.groups.iter().position(|g|g.is_some_and(|g|g.id==id)).ok_or(Error::Stale)
    }
    fn row(&self,caller:Identity,id:u64)->Result<usize,Error>{
        self.rows.iter().position(|r|r.is_some_and(|r|r.req.caller==caller&&r.req.request_id==id)).ok_or(Error::Stale)
    }
    pub fn register_group(&mut self,id:Identity,verify:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if self.boot==0||!id.valid(){return Err(Error::Denied);}
        if self.groups.iter().flatten().any(|g|g.id.id==id.id){return Err(Error::Busy);}
        let slot=self.groups.iter_mut().find(|g|g.is_none()).ok_or(Error::Exhausted)?;
        verify()?;*slot=Some(Group{id,version:0,limit:2,until:0,window:u64::MAX,used:0,
            last_change:0,changes:[0;4],change_count:0,work:None});Ok(())
    }
    pub fn submit(&mut self,req:Request,now:u64,authorize:impl FnOnce(&Request)->Result<(),Error>)->Result<State,Error>{
        self.ready(now)?;
        if !req.caller.valid()||!req.package.valid()||req.request_id==0||req.digest==[0;32]{return Err(Error::Invalid);}
        authorize(&req)?;
        if let Ok(i)=self.row(req.caller,req.request_id){
            let r=self.rows[i].unwrap();return if r.req==req{Ok(r.state)}else{Err(Error::Denied)};
        }
        self.group(req.group)?;
        if self.rows.iter().flatten().filter(|r|r.state==State::Queued).count()>=MAX_PENDING{return Err(Error::Busy);}
        let i=self.rows.iter().position(Option::is_none).ok_or(Error::Exhausted)?;
        let seq=self.seq.checked_add(1).ok_or(Error::Exhausted)?;
        self.rows[i]=Some(Row{req,state:State::Queued,sequence:seq,occupied:false});
        self.seq=seq;self.last=now;Ok(State::Queued)
    }
    /// Independent native observation: known created and UNKNOWN occupied
    /// slots are distinct. No guessed request-rate or blocked ratio.
    pub fn counts(&self)->(usize,usize,usize){
        (self.rows.iter().flatten().filter(|r|r.state==State::Queued).count(),
         self.rows.iter().flatten().filter(|r|r.occupied&&matches!(r.state,State::Created(_))).count(),
         self.rows.iter().flatten().filter(|r|r.state==State::Unknown).count())
    }
    pub fn query(&self,caller:Identity,id:u64)->Result<State,Error>{
        Ok(self.rows[self.row(caller,id)?].unwrap().state)
    }
    fn limit(g:Group,now:u64)->u16{if now<g.until{g.limit}else{2}}
    pub fn accept(&mut self,w:&ApplyWorkV1<'_>,base:u64,until:u64,now:u64,
        verify_live:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        self.ready(now)?;
        if w.domain!=2||!w.key.valid()||w.key.boot_epoch!=self.boot||w.executor_generation!=self.executor
            ||w.action_index>=16{return Err(Error::Denied);}
        let i=self.group(w.target)?;let g=self.groups[i].as_mut().unwrap();
        if g.version!=base||w.plan_version<=base{return Err(Error::Stale);}
        if g.work.is_some(){return Err(Error::Busy);}
        if until<=now||until-now>10_000_000_000{return Err(Error::Expired);}
        let ActionV2::SpawnTokens(limit)=ActionV2::decode(2,1,w.payload)? else{return Err(Error::Invalid);};
        let changed=Self::limit(*g,now)!=limit;
        if changed&&(g.last_change!=0&&now-g.last_change<WINDOW
            ||g.changes[..g.change_count].iter().filter(|&&t|now-t<1_000_000_000).count()>=4){return Err(Error::Busy);}
        verify_live()?;
        if changed{
            if g.change_count<4{g.changes[g.change_count]=now;g.change_count+=1;}
            else{g.changes.rotate_left(1);g.changes[3]=now;}
            g.last_change=now;
        }
        g.version=w.plan_version;g.limit=limit;g.until=until;
        g.work=Some(Work{key:w.key,index:w.action_index,version:w.plan_version,limit,accepted:now,until,effect:None});
        self.last=now;Ok(())
    }
    /// The loader must reauthorize the exact request and reserve every
    /// required physical resource under its own ledger. A real constructor
    /// returns Created only after authoritative admission; Unknown owns a
    /// thread credit until independent reconciliation. The caller separately
    /// proves the global live inventory (including tasks created elsewhere).
    pub fn service_one(&mut self,now:u64,other_live:usize,
        authorize:impl FnOnce(&Request)->Result<(),Error>,
        create:impl FnOnce(&Request)->Completion)->Result<Option<State>,Error>{
        self.ready(now)?;
        let occupied=self.rows.iter().flatten().filter(|r|r.occupied).count();
        if other_live.checked_add(occupied).ok_or(Error::Exhausted)?>=MAX_THREADS{return Ok(None);}
        let mut best=None;
        for (i,r) in self.rows.iter().enumerate().filter_map(|(i,r)|r.as_ref().map(|r|(i,r))){
            if r.state!=State::Queued{continue;}
            let g=self.groups[self.group(r.req.group)?].unwrap();
            let used=if g.window==now/WINDOW{g.used}else{0};
            if used>=Self::limit(g,now){continue;}
            if best.is_none_or(|old:usize|self.rows[old].unwrap().sequence>r.sequence){best=Some(i);}
        }
        let Some(i)=best else{return Ok(None);};
        let req=self.rows[i].unwrap().req;let gi=self.group(req.group)?;
        self.last=now;
        if authorize(&req).is_err(){self.rows[i].as_mut().unwrap().state=State::Rejected;return Ok(Some(State::Rejected));}
        let g=self.groups[gi].as_mut().unwrap();
        if g.window!=now/WINDOW{g.window=now/WINDOW;g.used=0;}
        g.used+=1; // a real construction attempt, never refund on uncertainty
        let r=self.rows[i].as_mut().unwrap();r.state=State::Unknown;r.occupied=true;
        let completion=create(&req);
        if completion.completed_ns<now{return Err(Error::Clock);}
        self.last=completion.completed_ns;
        let result=self.finish(i,completion.outcome)?;
        if matches!(result,State::Created(_)){
            let g=self.groups[gi].as_mut().unwrap();
            if let Some(w)=g.work.as_mut(){
                if w.effect.is_none()&&now>=w.accepted&&now<w.until{
                    w.effect=Some((ActionStatus::Applied,completion.completed_ns));
                }
            }
        }
        Ok(Some(result))
    }
    fn finish(&mut self,i:usize,outcome:Outcome)->Result<State,Error>{
        let state=match outcome{
            Outcome::Created(task) if task.valid()&&!self.rows.iter().enumerate().any(|(j,r)|j!=i&&r.is_some_and(|r|
                matches!(r.state,State::Created(old) if old.id==task.id&&(r.occupied||old.generation>=task.generation))))=>State::Created(task),
            Outcome::NoEffect=>State::Rejected,
            _=>State::Unknown,
        };
        let r=self.rows[i].as_mut().unwrap();r.state=state;
        if state==State::Rejected{r.occupied=false;}
        Ok(state)
    }
    pub fn reconcile(&mut self,caller:Identity,id:u64,outcome:Outcome,now:u64,
        verify:impl FnOnce(Request,Outcome)->Result<(),Error>)->Result<State,Error>{
        self.ready(now)?;let i=self.row(caller,id)?;let r=self.rows[i].unwrap();
        if r.state!=State::Unknown{return Err(Error::Stale);}
        if outcome==Outcome::Unknown{return Err(Error::NotReady);}
        verify(r.req,outcome)?;self.last=now;self.finish(i,outcome)
        // A later reconciled creation does not by itself prove the policy's
        // effective timestamp. Its original execution evidence is separate.
    }
    pub fn exited(&mut self,task:Identity,now:u64,verify_stopped:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        self.ready(now)?;
        let r=self.rows.iter_mut().flatten().find(|r|r.occupied&&r.state==State::Created(task)).ok_or(Error::Stale)?;
        verify_stopped()?;r.occupied=false;self.last=now;Ok(())
    }
    /// Expiry cannot cancel a task or an uncertain create. The owner may
    /// attest a policy no-effect terminal only after checking that no
    /// unresolved create could have consumed that version.
    pub fn expire(&mut self,group:Identity,now:u64,verify_no_effect:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        self.ready(now)?;let i=self.group(group)?;
        if self.rows.iter().flatten().any(|r|r.req.group==group&&r.state==State::Unknown){return Err(Error::NotReady);}
        let w=self.groups[i].as_mut().unwrap().work.as_mut().ok_or(Error::Stale)?;
        if now<w.until||w.effect.is_some(){return Err(Error::Busy);}
        verify_no_effect()?;w.effect=Some((ActionStatus::Cancelled,now));self.last=now;Ok(())
    }
    pub fn report(&self,group:Identity,out:&mut[u8;MAX_APPLY_REPORT_BYTES])->Result<usize,Error>{
        let w=self.groups[self.group(group)?].unwrap().work.ok_or(Error::Stale)?;
        let (state,completed_ns)=w.effect.ok_or(Error::NotReady)?;
        ApplyReportV1{key:w.key,action_index:w.index,domain_id:2,state,target:group,executor_generation:self.executor,
            plan_version:w.version,result:if state==ActionStatus::Applied{0}else{-7},completed_ns,
            action:&w.limit.to_le_bytes()}.encode(out)
    }
    pub fn retire(&mut self,group:Identity,wire:&[u8],verify_custody:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        let mut out=[0;MAX_APPLY_REPORT_BYTES];let n=self.report(group,&mut out)?;
        if wire!=&out[..n]{return Err(Error::Denied);}
        verify_custody()?;let i=self.group(group)?;self.groups[i].as_mut().unwrap().work=None;Ok(())
    }
}
const _:()=assert!(core::mem::size_of::<Owner>()<=64*1024);
#[cfg(test)]
mod tests{
    use super::*;
    const GROUP:Identity=Identity{id:20,generation:1};
    const CALLER:Identity=Identity{id:21,generation:1};
    fn req(id:u64)->Request{Request{caller:CALLER,request_id:id,package:Identity{id:1,generation:1},group:GROUP,digest:[1;32]}}
    #[test]
    fn creation_tokens_no_refill_on_policy_change_and_unknown_retains_credit(){
        let mut o=Owner::empty();o.bind(1,1,||Ok(())).unwrap();o.register_group(GROUP,||Ok(())).unwrap();
        for id in 1..=4{o.submit(req(id),100,|_|Ok(())).unwrap();}
        let task=Identity{id:100,generation:1};
        assert_eq!(o.service_one(101,62,|_|Ok(()),|_|Completion{outcome:Outcome::Created(task),completed_ns:101}),Ok(Some(State::Created(task))));
        assert_eq!(o.service_one(102,62,|_|Ok(()),|_|Completion{outcome:Outcome::Unknown,completed_ns:102}),Ok(Some(State::Unknown)));
        assert_eq!(o.service_one(103,62,|_|panic!(),|_|panic!()),Ok(None));
        assert_eq!(o.submit(req(2),104,|_|Ok(())),Ok(State::Unknown));
        assert_eq!(o.submit(Request{digest:[2;32],..req(2)},104,|_|Ok(())),Err(Error::Denied));
        let w=ApplyWorkV1{key:PlanKey{boot_epoch:1,controller_epoch:1,plan_seq:1},action_index:0,domain:2,
            target:GROUP,executor_generation:1,plan_version:1,payload:&[4,0]};
        o.accept(&w,0,1_000_000_000,105,||Ok(())).unwrap();
        let mut out=[0;MAX_APPLY_REPORT_BYTES];assert_eq!(o.report(GROUP,&mut out),Err(Error::NotReady));
        assert_eq!(o.service_one(106,62,|_|panic!(),|_|panic!()),Ok(None));
        o.reconcile(CALLER,2,Outcome::NoEffect,107,|_,_|Ok(())).unwrap();
        let other=Identity{id:101,generation:1};
        assert_eq!(o.service_one(108,62,|_|Ok(()),|_|Completion{outcome:Outcome::Created(other),completed_ns:108}),Ok(Some(State::Created(other))));
        let n=o.report(GROUP,&mut out).unwrap();let r=ApplyReportV1::decode(&out[..n]).unwrap();
        assert_eq!(r.state,ActionStatus::Applied);assert_eq!(r.plan_version,1);
        o.retire(GROUP,&out[..n],||Ok(())).unwrap();
        o.exited(task,109,||Ok(())).unwrap();
        assert_eq!(o.service_one(110,62,|_|Ok(()),|_|Completion{outcome:Outcome::NoEffect,completed_ns:110}),Ok(Some(State::Rejected)));
        assert_eq!(o.query(CALLER,1),Ok(State::Created(task)));
    }
}

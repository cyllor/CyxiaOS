//! CPU0-only shared control accounting for the V0.19.9 reference machine.
//! Every dispatch is prepaid in one category, under a serialized EL1 owner.
//! No model-supplied time/role or scheduler migration is trusted. Actual timer
//! programming, CPU counter observation and task stop proof remain native
//! adapter duties; this ledger is not that adapter.
use super::{Error,Identity,role_manifest_v0199::{NativeRoleManifest,Role,CONTROL_CPU}};
pub const WINDOW_NS:u64=100_000_000;
pub const LIMIT_NS:u64=70_000_000;
pub const CLASS_LIMITS:[u64;6]=[30_000_000,8_000_000,7_500_000,8_000_000,8_000_000,8_500_000];
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Class { Operations, Security, Decision, Coordination, Recovery, Optional }
impl Class { fn index(self)->usize{self as usize} }
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Turn {
    serial:u64,
    window:u64,
    class:Class,
    actor:Option<Identity>,
    domain:u16,
    deadline_ns:u64,
    reserved_ns:u64,
}
impl Turn {
    pub fn deadline_ns(self)->u64{self.deadline_ns}
    pub fn reserved_ns(self)->u64{self.reserved_ns}
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Settlement {
    pub actual_ns:u64,
    pub overrun:bool,
    pub crossed_window:bool,
}
pub struct Cpu0BudgetLedger {
    window:Option<u64>,
    last_ns:u64,
    serial:u64,
    active:Option<Turn>,
    spent:[u64;6],
    operations_seen:u16,
    security_count:u8,
    decision_spent:[u64;15],
    ordinary_closed:bool,
}
impl Default for Cpu0BudgetLedger {fn default()->Self{Self::new()}}
impl Cpu0BudgetLedger {
    pub const fn new()->Self{Self{
        window:None,last_ns:0,serial:0,active:None,spent:[0;6],
        operations_seen:0,security_count:0,decision_spent:[0;15],
        ordinary_closed:false,
    }}
    pub fn spent(&self,class:Class)->u64{self.spent[class.index()]}
    pub fn ordinary_closed(&self)->bool{self.ordinary_closed}
    fn time(&mut self,now:u64)->Result<(),Error>{
        if now<self.last_ns{return Err(Error::Clock);}
        self.last_ns=now;Ok(())
    }
    fn enter_window(&mut self,now:u64)->Result<u64,Error>{
        let w=now/WINDOW_NS;
        let end=w.checked_add(1).and_then(|x|x.checked_mul(WINDOW_NS)).ok_or(Error::Clock)?;
        if self.window!=Some(w){
            if self.active.is_some(){return Err(Error::Busy);}
            self.window=Some(w);self.spent=[0;6];self.operations_seen=0;
            self.security_count=0;self.decision_spent=[0;15];
            // A new time window does not clear an observed execution fault.
        }
        Ok(end)
    }
    /// Authenticated live actor and actual CPU come from EL1 task metadata.
    /// The same ledger survives a role/model restart; changing identity
    /// cannot refill a category or a per-domain evaluation slot.
    pub fn reserve_role(&mut self,manifest:&NativeRoleManifest,actor:Identity,
        cpu:usize,class:Class,domain:u16,requested:u64,now:u64)->Result<Turn,Error>
    {
        manifest.validate()?;
        if cpu!=CONTROL_CPU{return Err(Error::Denied);}
        let member=manifest.members.iter().find(|m|m.actor==actor).ok_or(Error::Denied)?;
        let allowed=matches!((member.role,class),
            (Role::Operations,Class::Operations|Class::Optional)
            |(Role::Security,Class::Security)
            |(Role::DeterministicController|Role::Publisher,Class::Decision)
            |(Role::Supervisor|Role::ModelManager,Class::Coordination)
            |(Role::Validator|Role::Learner,Class::Optional));
        if !allowed{return Err(Error::Denied);}
        self.reserve(Some(actor),class,domain,requested,now)
    }
    /// Separate trusted EL1 recovery/coordination entry. There is no user
    /// request field that can select this authority.
    pub fn reserve_kernel(&mut self,cpu:usize,class:Class,requested:u64,now:u64)->Result<Turn,Error>{
        if cpu!=CONTROL_CPU || !matches!(class,Class::Coordination|Class::Recovery){
            return Err(Error::Denied);
        }
        self.reserve(None,class,0,requested,now)
    }
    fn reserve(&mut self,actor:Option<Identity>,class:Class,domain:u16,
        requested:u64,now:u64)->Result<Turn,Error>{
        self.time(now)?;
        if self.active.is_some(){return Err(Error::Busy);}
        if self.ordinary_closed && class!=Class::Recovery{return Err(Error::Denied);}
        let end=self.enter_window(now)?;
        let total=self.spent.iter().try_fold(0u64,|sum,&v|sum.checked_add(v)).ok_or(Error::Exhausted)?;
        if requested==0 || requested>end-now
            || requested>LIMIT_NS.saturating_sub(total)
            || requested>CLASS_LIMITS[class.index()].saturating_sub(self.spent[class.index()]){
            return Err(Error::Exhausted);
        }
        let mut bit=0u16;
        match class {
            Class::Operations=>{
                if !(1..=15).contains(&domain){return Err(Error::Invalid);}
                bit=1u16<<(domain-1);
                if requested>2_000_000 || self.operations_seen&bit!=0{return Err(Error::Exhausted);}
            }
            Class::Security=>{
                if !(1..=15).contains(&domain){return Err(Error::Invalid);}
                if requested>2_000_000 || self.security_count>=4{return Err(Error::Exhausted);}
            }
            Class::Decision=>{
                if !(1..=15).contains(&domain){return Err(Error::Invalid);}
                if requested>500_000u64.saturating_sub(self.decision_spent[usize::from(domain-1)]){
                    return Err(Error::Exhausted);
                }
            }
            _=>if domain!=0{return Err(Error::Invalid);},
        }
        let serial=self.serial.checked_add(1).ok_or(Error::Exhausted)?;
        let turn=Turn{serial,window:now/WINDOW_NS,class,actor,domain,deadline_ns:end.min(now+requested),reserved_ns:requested};
        self.serial=serial;
        self.active=Some(turn);
        self.operations_seen|=bit;
        if class==Class::Security{self.security_count+=1;}
        Ok(turn)
    }
    /// Only after the exact native context has returned/stopped and its
    /// actual CPU counter interval is known. A bad clock retains ownership.
    /// Actual overrun is charged, never clamped to the prepaid reservation.
    /// Cross-window completion conservatively carries the entire observed
    /// charge into the new window and closes ordinary admission.
    pub fn settle(&mut self,cpu:usize,turn:Turn,actual:u64,now:u64)->Result<Settlement,Error>{
        if cpu!=CONTROL_CPU{return Err(Error::Denied);}
        if self.active!=Some(turn){return Err(Error::Stale);}
        self.time(now)?;
        let crossed=now/WINDOW_NS!=turn.window;
        let overrun=actual>turn.reserved_ns || now>turn.deadline_ns;
        let idx=turn.class.index();
        let total=self.spent[idx].checked_add(actual).ok_or(Error::Exhausted)?;
        let decision=if turn.class==Class::Decision{
            Some(self.decision_spent[usize::from(turn.domain-1)].checked_add(actual).ok_or(Error::Exhausted)?)
        }else{None};
        if crossed{
            self.window=Some(now/WINDOW_NS);self.spent=[0;6];
            self.operations_seen=0;self.security_count=0;self.decision_spent=[0;15];
            self.spent[idx]=actual;
            if turn.class==Class::Decision{self.decision_spent[usize::from(turn.domain-1)]=actual;}
        }else{
            self.spent[idx]=total;
            if let Some(v)=decision{self.decision_spent[usize::from(turn.domain-1)]=v;}
        }
        self.active=None;
        if crossed||overrun{self.ordinary_closed=true;}
        Ok(Settlement{actual_ns:actual,overrun,crossed_window:crossed})
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::control_plane::role_manifest_v0199::{NativeRole,PrivateRegion,ROLES,REQUIRED_ONLINE_MASK,PAGE_SIZE};
    fn manifest()->NativeRoleManifest{
        NativeRoleManifest{online_mask:REQUIRED_ONLINE_MASK,
            members:core::array::from_fn(|i|NativeRole{
                role:ROLES[i],actor:Identity{id:i as u64+1,generation:1},
                ttbr0_root:0x100000+i as u64*PAGE_SIZE,
                private_rw:PrivateRegion{base:0x200000+i as u64*0x10000,bytes:PAGE_SIZE},
                caps:ROLES[i].allowed_caps(),control_ns_per_100ms:2_000_000,
                cpu_mask:1,thread_count:1,endpoint_id:i as u64+1}),
            other_protected_pool_bytes:5*1024*1024,other_control_ns_per_100ms:45_000_000}
    }
    #[test]
    fn fixed_categories_share_single_cpu_and_recovery_cannot_be_borrowed(){
        let m=manifest();let mut q=Cpu0BudgetLedger::new();
        let ops=m.members[0].actor;let sec=m.members[1].actor;
        let ctl=m.members[2].actor;let pubr=m.members[3].actor;
        let learner=m.members[6].actor;
        assert_eq!(CLASS_LIMITS.iter().sum::<u64>(),LIMIT_NS);
        assert_eq!(q.reserve_role(&m,ops,1,Class::Operations,1,1,0),Err(Error::Denied));
        assert_eq!(q.reserve_role(&m,ops,0,Class::Recovery,0,1,0),Err(Error::Denied));
        assert_eq!(q.reserve_role(&m,learner,0,Class::Optional,0,8_500_001,0),Err(Error::Exhausted));
        let a=q.reserve_role(&m,learner,0,Class::Optional,0,8_500_000,0).unwrap();
        assert_eq!(q.reserve_kernel(0,Class::Recovery,1,0),Err(Error::Busy));
        q.settle(0,a,8_500_000,8_500_000).unwrap();
        let r=q.reserve_kernel(0,Class::Recovery,8_000_000,8_500_000).unwrap();
        q.settle(0,r,8_000_000,16_500_000).unwrap();
        let a=q.reserve_role(&m,ctl,0,Class::Decision,1,300_000,17_000_000).unwrap();
        q.settle(0,a,300_000,17_300_000).unwrap();
        assert_eq!(q.reserve_role(&m,pubr,0,Class::Decision,1,200_001,17_300_000),Err(Error::Exhausted));
        let a=q.reserve_role(&m,pubr,0,Class::Decision,1,200_000,17_300_000).unwrap();
        q.settle(0,a,200_000,17_500_000).unwrap();
        let a=q.reserve_role(&m,ops,0,Class::Operations,1,2_000_000,18_000_000).unwrap();
        q.settle(0,a,1_000_000,19_000_000).unwrap();
        assert_eq!(q.reserve_role(&m,ops,0,Class::Operations,1,1,19_000_000),Err(Error::Exhausted));
        let mut restarted=m;restarted.members[0].actor.generation+=1;
        assert_eq!(q.reserve_role(&restarted,restarted.members[0].actor,0,Class::Operations,1,1,19_000_000),Err(Error::Exhausted));
        for i in 0..4{
            let t=q.reserve_role(&m,sec,0,Class::Security,12,2_000_000,20_000_000+i*2_000_000).unwrap();
            q.settle(0,t,2_000_000,22_000_000+i*2_000_000).unwrap();
        }
        assert_eq!(q.reserve_role(&m,sec,0,Class::Security,12,1,28_000_000),Err(Error::Exhausted));
    }
    #[test]
    fn actual_overrun_and_late_copy_never_refill_ordinary_budget(){
        let m=manifest();let mut q=Cpu0BudgetLedger::new();
        let ops=m.members[0].actor;
        let a=q.reserve_role(&m,ops,0,Class::Operations,1,100,WINDOW_NS-100).unwrap();
        assert_eq!(q.settle(0,a,100,WINDOW_NS-101),Err(Error::Clock));
        assert_eq!(q.reserve_kernel(0,Class::Recovery,1,WINDOW_NS),Err(Error::Busy));
        let r=q.settle(0,a,120,WINDOW_NS+20).unwrap();
        assert!(r.overrun&&r.crossed_window);
        assert_eq!(q.spent(Class::Operations),120);
        assert_eq!(q.settle(0,a,120,WINDOW_NS+20),Err(Error::Stale));
        assert!(q.ordinary_closed());
        assert_eq!(q.reserve_role(&m,ops,0,Class::Operations,2,1,2*WINDOW_NS),Err(Error::Denied));
        let recovery=q.reserve_kernel(0,Class::Recovery,100,2*WINDOW_NS).unwrap();
        q.settle(0,recovery,100,2*WINDOW_NS+100).unwrap();
    }
}

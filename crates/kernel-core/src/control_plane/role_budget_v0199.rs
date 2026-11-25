//! CPU0-only shared control accounting for the V0.19.9 reference machine.
//! Every dispatch is prepaid in one category, under a serialized EL1 owner.
//! No model-supplied time/role or scheduler migration is trusted. Actual timer
//! programming, CPU counter observation and task stop proof remain native
//! adapter duties; this ledger is not that adapter.
use super::{Error,Identity,role_manifest_v0199::{NativeRoleManifest,ValidatedRoleManifest,Role,ROLE_COUNT,CONTROL_CPU}};
pub const WINDOW_NS:u64=100_000_000;
pub const LIMIT_NS:u64=70_000_000;
// 6ms of the 8ms coordination class belongs to model manager/supervisor.
// EL1 coordination and dispatch overhead must not borrow those role slots.
pub const KERNEL_COORDINATION_LIMIT_NS:u64=2_000_000;
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
    role_index:Option<usize>,
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
/// Half-open CPU interval with a separately observed native counter debit.
/// Exact mode requires a real counter observation at EVERY aligned boundary.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct MeasuredSegment{pub start_ns:u64,pub end_ns:u64,pub cpu_ns:u64}
#[derive(Clone)]
pub struct Cpu0BudgetLedger {
    window:Option<u64>,
    last_ns:u64,
    serial:u64,
    active:Option<Turn>,
    active_start_ns:u64,
    spent:[u64;6],
    role_spent:[u64;ROLE_COUNT],
    kernel_coordination_spent:u64,
    lifetime_spent:[u64;6],
    max_window_upper_ns:u64,
    operations_seen:u16,
    security_count:u8,
    decision_spent:[u64;15],
    ordinary_closed:bool,
}
impl Default for Cpu0BudgetLedger {fn default()->Self{Self::new()}}
impl Cpu0BudgetLedger {
    pub const fn new()->Self{Self{
        window:None,last_ns:0,serial:0,active:None,active_start_ns:0,spent:[0;6],role_spent:[0;ROLE_COUNT],kernel_coordination_spent:0,lifetime_spent:[0;6],max_window_upper_ns:0,
        operations_seen:0,security_count:0,decision_spent:[0;15],
        ordinary_closed:false,
    }}
    pub fn spent(&self,class:Class)->u64{self.spent[class.index()]}
    pub fn ordinary_closed(&self)->bool{self.ordinary_closed}
    pub fn kernel_coordination_spent(&self)->u64{self.kernel_coordination_spent}
    pub fn total_spent(&self)->Result<u64,Error>{
        self.spent.iter().try_fold(0u64,|sum,&v|sum.checked_add(v)).ok_or(Error::Exhausted)
    }
    /// Cumulative actual CPU time; never reset by a window or role reload.
    pub fn lifetime_spent(&self,class:Class)->u64{self.lifetime_spent[class.index()]}
    pub fn lifetime_total(&self)->Result<u64,Error>{
        self.lifetime_spent.iter().try_fold(0u64,|sum,&v|sum.checked_add(v)).ok_or(Error::Exhausted)
    }
    pub fn max_window_upper_ns(&self)->u64{self.max_window_upper_ns}

    /// Account a trusted continuous CPU0 interval outside all active turns.
    /// These intervals use the preallocated 2ms EL1 coordination envelope.
    /// They include scheduler bookkeeping and idle entry/return, not an
    /// invented elapsed-wall-time cost. Call at each dispatch boundary.
    ///
    /// When the interval straddles aligned windows, its actual CPU debit
    /// is made exactly once, to the later window. Check the conservative
    /// upper bound in BOTH endpoint windows (and implicitly all empty
    /// intervening windows). This can deny otherwise legal work, never
    /// manufacture unused credit. It is not a measured per-window split.
    pub fn account_coordination_gap(&mut self,cpu:usize,start_ns:u64,now_ns:u64,
        actual:u64)->Result<Settlement,Error>{
        if cpu!=CONTROL_CPU{return Err(Error::Denied);}
        if self.active.is_some(){return Err(Error::Busy);}
        if start_ns<self.last_ns||now_ns<start_ns{return Err(Error::Clock);}
        self.time(start_ns)?;
        self.enter_window(start_ns)?;
        let idx=Class::Coordination.index();
        let checked_upper=|q:&Self|->Result<(u64,bool),Error>{
            let total=q.total_spent()?.checked_add(actual).ok_or(Error::Exhausted)?;
            let class=q.spent[idx].checked_add(actual).ok_or(Error::Exhausted)?;
            let kernel=q.kernel_coordination_spent.checked_add(actual).ok_or(Error::Exhausted)?;
            Ok((total,total>LIMIT_NS||class>CLASS_LIMITS[idx]||kernel>KERNEL_COORDINATION_LIMIT_NS))
        };
        let (before,early_overrun)=checked_upper(self)?;
        let crossed=start_ns/WINDOW_NS!=now_ns/WINDOW_NS;
        self.time(now_ns)?;
        self.enter_window(now_ns)?;
        let (after,late_overrun)=checked_upper(self)?;
        self.max_window_upper_ns=self.max_window_upper_ns.max(before).max(after);
        self.spent[idx]=self.spent[idx].checked_add(actual).ok_or(Error::Exhausted)?;
        self.kernel_coordination_spent=self.kernel_coordination_spent.checked_add(actual).ok_or(Error::Exhausted)?;
        self.lifetime_spent[idx]=self.lifetime_spent[idx].checked_add(actual).ok_or(Error::Exhausted)?;
        let overrun=early_overrun||late_overrun;
        if overrun{self.ordinary_closed=true;}
        Ok(Settlement{actual_ns:actual,overrun,crossed_window:crossed})
    }
    /// Exact coordination split when the trusted platform supplies actual
    /// aligned boundary samples. Unlike account_coordination_gap, this
    /// charges a segment ending at a boundary to its OLD window.
    /// Missing/late boundary evidence must use the conservative path;
    /// never interpolate PMU counts from wall time. The native verifier
    /// authenticates the whole trace and its independent endpoint delta.
    pub fn account_exact_coordination(&mut self,cpu:usize,segments:&[MeasuredSegment],
        observed_total:u64,verify_native:impl FnOnce(&[MeasuredSegment],u64)->Result<(),Error>,
    )->Result<Settlement,Error>{
        if cpu!=CONTROL_CPU{return Err(Error::Denied);}
        if self.active.is_some(){return Err(Error::Busy);}
        if segments.is_empty()||segments.len()>64{return Err(Error::Invalid);}
        let start=segments[0].start_ns;
        if start<self.last_ns||self.window.is_some()&&start!=self.last_ns{return Err(Error::Clock);}
        let mut cursor=start;let mut total=0u64;
        for segment in segments{
            if segment.start_ns!=cursor||segment.end_ns<=segment.start_ns
                ||segment.start_ns/WINDOW_NS!=(segment.end_ns-1)/WINDOW_NS{
                return Err(Error::Clock);
            }
            total=total.checked_add(segment.cpu_ns).ok_or(Error::Exhausted)?;
            cursor=segment.end_ns;
        }
        if total!=observed_total{return Err(Error::Denied);}
        verify_native(segments,total)?;
        // Stage accounting to prevent invalid later rows from consuming
        // a partial trace. The ledger is small and lives in protected EL1.
        let mut next=self.clone();let idx=Class::Coordination.index();let mut overrun=false;
        for segment in segments{
            next.time(segment.start_ns)?;next.enter_window(segment.start_ns)?;
            next.spent[idx]=next.spent[idx].checked_add(segment.cpu_ns).ok_or(Error::Exhausted)?;
            next.kernel_coordination_spent=next.kernel_coordination_spent.checked_add(segment.cpu_ns).ok_or(Error::Exhausted)?;
            next.lifetime_spent[idx]=next.lifetime_spent[idx].checked_add(segment.cpu_ns).ok_or(Error::Exhausted)?;
            let sum=next.total_spent()?;
            next.max_window_upper_ns=next.max_window_upper_ns.max(sum);
            overrun|=sum>LIMIT_NS||next.spent[idx]>CLASS_LIMITS[idx]
                ||next.kernel_coordination_spent>KERNEL_COORDINATION_LIMIT_NS;
            next.time(segment.end_ns)?;
        }
        if overrun{next.ordinary_closed=true;}
        *self=next;
        Ok(Settlement{actual_ns:total,overrun,crossed_window:start/WINDOW_NS!=(cursor-1)/WINDOW_NS})
    }
    fn time(&mut self,now:u64)->Result<(),Error>{
        if now<self.last_ns{return Err(Error::Clock);}
        self.last_ns=now;Ok(())
    }
    fn enter_window(&mut self,now:u64)->Result<u64,Error>{
        let w=now/WINDOW_NS;
        let end=w.checked_add(1).and_then(|x|x.checked_mul(WINDOW_NS)).ok_or(Error::Clock)?;
        if self.window!=Some(w){
            if self.active.is_some(){return Err(Error::Busy);}
            self.window=Some(w);self.spent=[0;6];self.role_spent=[0;ROLE_COUNT];self.kernel_coordination_spent=0;self.operations_seen=0;
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
        self.reserve_role_with_wall(manifest,actor,cpu,class,domain,requested,requested,now)
    }
    /// CPU execution quota and wall-clock deadline are separate clocks.
    /// The native adapter must arm a conservative preemption timer and
    /// debit actual per-CPU execution time before closing this turn.
    pub fn reserve_role_with_wall(&mut self,manifest:&NativeRoleManifest,actor:Identity,
        cpu:usize,class:Class,domain:u16,requested:u64,wall_ns:u64,now:u64)->Result<Turn,Error>
    {
        if wall_ns==0 || wall_ns>50_000_000{return Err(Error::Invalid);}
        self.reserve_validated_role_with_wall(&manifest.validated()?,actor,cpu,class,domain,requested,wall_ns,now)
    }
    /// Same admission rules with an immutable inventory validated before
    /// the turn. The caller must account for validation in coordination or
    /// recovery; the full-inventory check is not removed from CPU accounting.
    pub fn reserve_validated_role_with_wall(&mut self,manifest:&ValidatedRoleManifest<'_>,actor:Identity,
        cpu:usize,class:Class,domain:u16,requested:u64,wall_ns:u64,now:u64)->Result<Turn,Error>
    {
        if wall_ns==0 || wall_ns>50_000_000{return Err(Error::Invalid);}
        if cpu!=CONTROL_CPU{return Err(Error::Denied);}
        let index=manifest.manifest().members.iter().position(|m|m.actor==actor).ok_or(Error::Denied)?;
        self.reserve_indexed_role_with_wall(manifest,index,actor,cpu,class,domain,requested,wall_ns,now)
    }
    /// A trusted scheduler already has the selected live manifest index.
    /// Recheck the exact actor (including generation) and CPU at that index,
    /// then use the identical admission/settlement ledger. No second
    /// eight-entry scan and no authority derived from the index alone.
    #[inline]
    pub fn reserve_indexed_role_with_wall(&mut self,manifest:&ValidatedRoleManifest<'_>,index:usize,
        actor:Identity,cpu:usize,class:Class,domain:u16,requested:u64,wall_ns:u64,now:u64)->Result<Turn,Error>{
        if wall_ns==0||wall_ns>50_000_000{return Err(Error::Invalid);}
        if cpu!=CONTROL_CPU{return Err(Error::Denied);}
        let member=manifest.manifest().members.get(index).ok_or(Error::Denied)?;
        if member.actor!=actor{return Err(Error::Denied);}
        let allowed=matches!((member.role,class),
            (Role::Operations,Class::Operations|Class::Optional)
            |(Role::Security,Class::Security)
            |(Role::DeterministicController|Role::Publisher,Class::Decision)
            |(Role::Supervisor|Role::ModelManager,Class::Coordination)
            |(Role::Validator|Role::Learner,Class::Optional));
        if !allowed{return Err(Error::Denied);}
        self.reserve(Some(actor),Some((index,member.control_ns_per_100ms)),class,domain,requested,wall_ns,now)
    }
    /// Separate trusted EL1 recovery/coordination entry. There is no user
    /// request field that can select this authority.
    pub fn reserve_kernel(&mut self,cpu:usize,class:Class,requested:u64,now:u64)->Result<Turn,Error>{
        self.reserve_kernel_with_wall(cpu,class,requested,requested,now)
    }
    pub fn reserve_kernel_with_wall(&mut self,cpu:usize,class:Class,requested:u64,wall_ns:u64,now:u64)->Result<Turn,Error>{
        if cpu!=CONTROL_CPU || !matches!(class,Class::Coordination|Class::Recovery){
            return Err(Error::Denied);
        }
        if wall_ns==0||wall_ns>50_000_000{return Err(Error::Invalid);}
        self.reserve(None,None,class,0,requested,wall_ns,now)
    }
    #[inline]
    fn reserve(&mut self,actor:Option<Identity>,role:Option<(usize,u64)>,class:Class,domain:u16,
        requested:u64,wall_ns:u64,now:u64)->Result<Turn,Error>{
        if self.active.is_some(){return Err(Error::Busy);}
        self.time(now)?;
        if self.ordinary_closed && class!=Class::Recovery{return Err(Error::Denied);}
        let end=self.enter_window(now)?;
        let total=self.spent.iter().try_fold(0u64,|sum,&v|sum.checked_add(v)).ok_or(Error::Exhausted)?;
        if requested==0 || requested>end-now
            || requested>LIMIT_NS.saturating_sub(total)
            || requested>CLASS_LIMITS[class.index()].saturating_sub(self.spent[class.index()]){
            return Err(Error::Exhausted);
        }
        if let Some((index,quota))=role{
            if requested>quota.saturating_sub(self.role_spent[index]){return Err(Error::Exhausted);}
        }
        if actor.is_none() && class==Class::Coordination
            && requested>KERNEL_COORDINATION_LIMIT_NS.saturating_sub(self.kernel_coordination_spent){
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
        let turn=Turn{serial,window:now/WINDOW_NS,class,actor,role_index:role.map(|(index,_)|index),domain,deadline_ns:end.min(now.checked_add(wall_ns).ok_or(Error::Clock)?),reserved_ns:requested};
        self.serial=serial;
        self.active=Some(turn);self.active_start_ns=now;
        self.operations_seen|=bit;
        if class==Class::Security{self.security_count+=1;}
        Ok(turn)
    }
    /// Settle a stopped role or kernel turn using independently measured
    /// CPU-counter intervals at every aligned boundary. Unlike the
    /// conservative scalar settlement, an interval ending exactly at a
    /// boundary belongs to the old window. Crossing beyond the prepaid
    /// wall deadline still closes ordinary admission; exact measurement
    /// cannot excuse an overrun or create more reservation credit.
    /// All segment metadata is staged before committing the ledger.
    pub fn settle_measured(&mut self,cpu:usize,turn:Turn,segments:&[MeasuredSegment],
        observed_total:u64,verify_native:impl FnOnce(&[MeasuredSegment],u64)->Result<(),Error>,
    )->Result<Settlement,Error>{
        if cpu!=CONTROL_CPU{return Err(Error::Denied);}
        if self.active!=Some(turn){return Err(Error::Stale);}
        if segments.is_empty()||segments.len()>64{return Err(Error::Invalid);}
        let start=self.active_start_ns;
        if start/WINDOW_NS!=turn.window||segments[0].start_ns!=start{return Err(Error::Clock);}
        let mut cursor=start;let mut total=0u64;
        for s in segments{
            if s.start_ns!=cursor||s.end_ns<=s.start_ns
                ||s.start_ns/WINDOW_NS!=(s.end_ns-1)/WINDOW_NS{return Err(Error::Clock);}
            total=total.checked_add(s.cpu_ns).ok_or(Error::Exhausted)?;
            cursor=s.end_ns;
        }
        if cursor<self.last_ns{return Err(Error::Clock);}
        if total!=observed_total{return Err(Error::Denied);}
        verify_native(segments,total)?;
        let mut next=self.clone();next.active=None;next.active_start_ns=0;
        let idx=turn.class.index();
        let kernel_coord=turn.actor.is_none()&&turn.class==Class::Coordination;
        let crossed=(cursor-1)/WINDOW_NS!=turn.window;
        let mut overrun=total>turn.reserved_ns||cursor>turn.deadline_ns;
        for s in segments{
            let old=next.window;
            next.time(s.start_ns)?;next.enter_window(s.start_ns)?;
            if old!=next.window{
                // An overrun tail is real activity in the subsequent
                // window, not a fresh discretionary evaluation.
                if turn.class==Class::Operations{next.operations_seen|=1u16<<(turn.domain-1);}
                if turn.class==Class::Security{next.security_count=1;}
            }
            next.spent[idx]=next.spent[idx].checked_add(s.cpu_ns).ok_or(Error::Exhausted)?;
            next.lifetime_spent[idx]=next.lifetime_spent[idx].checked_add(s.cpu_ns).ok_or(Error::Exhausted)?;
            if let Some(i)=turn.role_index{
                next.role_spent[i]=next.role_spent[i].checked_add(s.cpu_ns).ok_or(Error::Exhausted)?;
            }
            if turn.class==Class::Decision{
                let d=&mut next.decision_spent[usize::from(turn.domain-1)];
                *d=d.checked_add(s.cpu_ns).ok_or(Error::Exhausted)?;
                overrun|=*d>500_000;
            }
            if kernel_coord{
                next.kernel_coordination_spent=next.kernel_coordination_spent.checked_add(s.cpu_ns).ok_or(Error::Exhausted)?;
                overrun|=next.kernel_coordination_spent>KERNEL_COORDINATION_LIMIT_NS;
            }
            let sum=next.total_spent()?;
            next.max_window_upper_ns=next.max_window_upper_ns.max(sum);
            overrun|=sum>LIMIT_NS||next.spent[idx]>CLASS_LIMITS[idx];
            next.time(s.end_ns)?;
        }
        if overrun||crossed{next.ordinary_closed=true;}
        *self=next;
        Ok(Settlement{actual_ns:total,overrun,crossed_window:crossed})
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
        let lifetime=self.lifetime_spent[idx].checked_add(actual).ok_or(Error::Exhausted)?;
        let upper=self.total_spent()?.checked_add(actual).ok_or(Error::Exhausted)?;
        let decision=if turn.class==Class::Decision{
            Some(self.decision_spent[usize::from(turn.domain-1)].checked_add(actual).ok_or(Error::Exhausted)?)
        }else{None};
        let role_total=match turn.role_index{
            Some(index)=>Some((index,self.role_spent[index].checked_add(actual).ok_or(Error::Exhausted)?)),
            None=>None,
        };
        let kernel_coordination=turn.class==Class::Coordination&&turn.role_index.is_none();
        let kernel_total=if kernel_coordination{
            self.kernel_coordination_spent.checked_add(actual).ok_or(Error::Exhausted)?
        }else{self.kernel_coordination_spent};
        if crossed{
            self.window=Some(now/WINDOW_NS);self.spent=[0;6];self.role_spent=[0;ROLE_COUNT];
            self.kernel_coordination_spent=if kernel_coordination{actual}else{0};
            self.operations_seen=0;self.security_count=0;self.decision_spent=[0;15];
            self.spent[idx]=actual;
            if let Some((index,_))=role_total{self.role_spent[index]=actual;}
            if turn.class==Class::Decision{self.decision_spent[usize::from(turn.domain-1)]=actual;}
        }else{
            self.kernel_coordination_spent=kernel_total;
            self.spent[idx]=total;
            if let Some((index,v))=role_total{self.role_spent[index]=v;}
            if let Some(v)=decision{self.decision_spent[usize::from(turn.domain-1)]=v;}
        }
        self.lifetime_spent[idx]=lifetime;
        self.max_window_upper_ns=self.max_window_upper_ns.max(upper).max(self.total_spent()?);
        self.active=None;self.active_start_ns=0;
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
                caps:ROLES[i].allowed_caps(),control_ns_per_100ms:[30_000_000,8_000_000,4_000_000,3_500_000,4_000_000,3_000_000,4_500_000,3_000_000][i],
                cpu_mask:1,thread_count:1,endpoint_id:i as u64+1}),
            other_protected_pool_bytes:5*1024*1024,other_control_ns_per_100ms:10_000_000}
    }
    #[test]
    fn measured_role_turn_retains_exact_boundary_charge_and_closes_real_overrun(){
        let m=manifest();let mut q=Cpu0BudgetLedger::new();
        let start=WINDOW_NS-250_000;
        let t=q.reserve_role_with_wall(&m,m.members[2].actor,0,Class::Decision,1,250_000,250_000,start).unwrap();
        let a=[MeasuredSegment{start_ns:start,end_ns:WINDOW_NS,cpu_ns:250_000}];
        assert_eq!(q.reserve_kernel(0,Class::Recovery,1,WINDOW_NS),Err(Error::Busy));
        assert_eq!(q.settle_measured(0,t,&a,249_999,|_,_|panic!()),Err(Error::Denied));
        assert_eq!(q.settle_measured(0,t,&a,250_000,|_,_|Err(Error::NotReady)),Err(Error::NotReady));
        assert_eq!(q.lifetime_total(),Ok(0));
        let r=q.settle_measured(0,t,&a,250_000,|_,_|Ok(())).unwrap();
        assert!(!r.crossed_window&&!r.overrun&&!q.ordinary_closed());
        assert_eq!(q.spent(Class::Decision),250_000);
        assert_eq!(q.lifetime_total(),Ok(250_000));
        let next=q.reserve_role_with_wall(&m,m.members[3].actor,0,Class::Decision,1,250_000,50_000_000,WINDOW_NS).unwrap();
        q.settle(0,next,100_000,WINDOW_NS+100_000).unwrap();
        let start=2*WINDOW_NS-250_000;
        let t=q.reserve_role_with_wall(&m,m.members[2].actor,0,Class::Decision,1,250_000,250_000,start).unwrap();
        let b=[MeasuredSegment{start_ns:start,end_ns:2*WINDOW_NS,cpu_ns:240_000},
            MeasuredSegment{start_ns:2*WINDOW_NS,end_ns:2*WINDOW_NS+20_000,cpu_ns:20_000}];
        let r=q.settle_measured(0,t,&b,260_000,|_,_|Ok(())).unwrap();
        assert!(r.overrun&&r.crossed_window&&q.ordinary_closed());
        assert_eq!(q.spent(Class::Decision),20_000);
        assert_eq!(q.lifetime_total(),Ok(610_000));
        assert_eq!(q.max_window_upper_ns(),340_000);
        assert_eq!(q.reserve_role(&m,m.members[2].actor,0,Class::Decision,1,1,3*WINDOW_NS),Err(Error::Denied));
    }
    #[test]
    fn measured_boundary_split_conserves_debit_and_never_invents_credit(){
        let mut q=Cpu0BudgetLedger::new();
        let start=WINDOW_NS-2_000_000;
        let segments=[MeasuredSegment{start_ns:start,end_ns:WINDOW_NS,cpu_ns:1_500_000},
            MeasuredSegment{start_ns:WINDOW_NS,end_ns:WINDOW_NS+2_000_000,cpu_ns:1_500_000}];
        assert_eq!(q.account_exact_coordination(0,&segments,2_999_999,|_,_|panic!()),Err(Error::Denied));
        assert_eq!(q.account_exact_coordination(0,&segments,3_000_000,|_,_|Err(Error::NotReady)),Err(Error::NotReady));
        assert_eq!(q.lifetime_total(),Ok(0));
        let receipt=q.account_exact_coordination(0,&segments,3_000_000,|_,_|Ok(())).unwrap();
        assert!(receipt.crossed_window&&!receipt.overrun);
        assert_eq!(q.lifetime_total(),Ok(3_000_000));assert_eq!(q.kernel_coordination_spent(),1_500_000);
        assert_eq!(q.max_window_upper_ns(),1_500_000);
        let extra=[MeasuredSegment{start_ns:WINDOW_NS+2_000_000,end_ns:WINDOW_NS+3_000_000,cpu_ns:500_001}];
        assert!(q.account_exact_coordination(0,&extra,500_001,|_,_|Ok(())).unwrap().overrun);
        assert!(q.ordinary_closed());assert_eq!(q.lifetime_total(),Ok(3_500_001));
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
        let a=q.reserve_role(&m,learner,0,Class::Optional,0,4_500_000,0).unwrap();
        assert_eq!(q.reserve_kernel(0,Class::Recovery,1,0),Err(Error::Busy));
        q.settle(0,a,4_500_000,4_500_000).unwrap();
        assert_eq!(q.reserve_role(&m,learner,0,Class::Optional,0,1,4_500_000),Err(Error::Exhausted));
        let a=q.reserve_role(&m,m.members[4].actor,0,Class::Optional,0,4_000_000,4_500_000).unwrap();
        q.settle(0,a,4_000_000,8_500_000).unwrap();
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
    fn kernel_coordination_is_prepaid_and_cannot_borrow_role_or_recovery_credit(){
        let m=manifest();let mut q=Cpu0BudgetLedger::new();
        assert_eq!(q.reserve_kernel(0,Class::Coordination,2_000_001,0),Err(Error::Exhausted));
        let a=q.reserve_kernel(0,Class::Coordination,2_000_000,0).unwrap();
        q.settle(0,a,2_000_000,2_000_000).unwrap();
        assert_eq!(q.kernel_coordination_spent(),2_000_000);
        assert_eq!(q.reserve_kernel(0,Class::Coordination,1,2_000_000),Err(Error::Exhausted));
        for i in [5,7]{
            let t=q.reserve_role(&m,m.members[i].actor,0,Class::Coordination,0,3_000_000,3_000_000*i as u64).unwrap();
            q.settle(0,t,3_000_000,3_000_000*(i as u64+1)).unwrap();
        }
        assert_eq!(q.spent(Class::Coordination),8_000_000);
        let r=q.reserve_kernel(0,Class::Recovery,8_000_000,30_000_000).unwrap();
        q.settle(0,r,8_000_000,38_000_000).unwrap();
        assert_eq!(q.total_spent(),Ok(16_000_000));
        let a=q.reserve_kernel(0,Class::Coordination,2_000_000,WINDOW_NS).unwrap();
        q.settle(0,a,1_000_000,WINDOW_NS+1_000_000).unwrap();
        assert_eq!(q.kernel_coordination_spent(),1_000_000);
    }
    #[test]
    fn continuous_gap_accounting_charges_once_and_bounds_both_windows(){
        let mut q=Cpu0BudgetLedger::new();
        let a=q.account_coordination_gap(0,0,10,1_000_000).unwrap();
        assert!(!a.overrun&&!a.crossed_window);
        let b=q.account_coordination_gap(0,10,WINDOW_NS+10,900_000).unwrap();
        assert!(!b.overrun&&b.crossed_window);
        assert_eq!(q.lifetime_total(),Ok(1_900_000));
        assert_eq!(q.kernel_coordination_spent(),900_000);
        assert_eq!(q.max_window_upper_ns(),1_900_000);
        let t=q.reserve_kernel(0,Class::Recovery,1000,WINDOW_NS+10).unwrap();
        assert_eq!(q.account_coordination_gap(0,WINDOW_NS+10,WINDOW_NS+11,1),Err(Error::Busy));
        q.settle(0,t,1000,WINDOW_NS+20).unwrap();
        let c=q.account_coordination_gap(0,WINDOW_NS+20,2*WINDOW_NS+10,1_100_001).unwrap();
        assert!(c.overrun&&c.crossed_window);
        assert_eq!(q.lifetime_total(),Ok(3_001_001));
        assert!(q.ordinary_closed());
        assert_eq!(q.reserve_kernel(0,Class::Coordination,1,2*WINDOW_NS+10),Err(Error::Denied));
    }
    #[test]
    fn indexed_dispatch_preserves_identity_generation_and_all_shared_limits(){
        let m=manifest();let checked=m.validated().unwrap();let actor=m.members[2].actor;
        let mut indexed=Cpu0BudgetLedger::new();let mut generic=Cpu0BudgetLedger::new();
        for (i,a,cpu,class) in [(3,actor,0,Class::Decision),(8,actor,0,Class::Decision),
            (2,Identity{generation:2,..actor},0,Class::Decision),(2,actor,1,Class::Decision),
            (2,actor,0,Class::Recovery)]{
            assert_eq!(indexed.reserve_indexed_role_with_wall(&checked,i,a,cpu,class,1,250_000,50_000_000,0),Err(Error::Denied));
        }
        assert_eq!(indexed.lifetime_total(),Ok(0));
        let a=indexed.reserve_indexed_role_with_wall(&checked,2,actor,0,Class::Decision,1,250_000,50_000_000,0).unwrap();
        let b=generic.reserve_validated_role_with_wall(&checked,actor,0,Class::Decision,1,250_000,50_000_000,0).unwrap();
        assert_eq!(a,b);
        assert_eq!(indexed.settle(0,a,240_000,300_000),generic.settle(0,b,240_000,300_000));
        assert_eq!(indexed.reserve_indexed_role_with_wall(&checked,3,m.members[3].actor,0,Class::Decision,1,260_001,50_000_000,300_000),Err(Error::Exhausted));
        assert_eq!(indexed.lifetime_total(),Ok(240_000));
    }
    #[test]
    fn cpu_quota_and_wall_deadline_are_independently_enforced(){
        let m=manifest();let mut q=Cpu0BudgetLedger::new();
        let a=q.reserve_role_with_wall(&m,m.members[2].actor,0,Class::Decision,1,
            250_000,50_000_000,0).unwrap();
        assert_eq!(a.deadline_ns(),50_000_000);
        assert!(!q.settle(0,a,200_000,10_000_000).unwrap().overrun);
        assert_eq!(q.reserve_role_with_wall(&m,m.members[3].actor,0,Class::Decision,1,
            300_001,50_000_000,10_000_000),Err(Error::Exhausted));
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

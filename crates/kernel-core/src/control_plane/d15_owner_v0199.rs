//! Current D15 ordinary UART owner, independent from emergency output.
//! One serialized native owner accepts only a registered ApplyWork at an
//! actual safe point. Business pumping never waits for a model. Native
//! platform supplies real MMIO and same-core PMU/wall clocks.
use super::{Error,Identity,action_schema_v2::ActionV2,
    apply_work_v1::ApplyWorkV1,apply_report_v1::{ApplyReportV1,ActionStatus,PlanKey}};
use cyxia_contracts::{ConsoleOps,PlatformError};

pub const DOMAIN:u16=15;
pub const QUEUE:usize=4096;
pub const BASELINE:u16=8;
pub const WINDOW:u64=100_000_000;
const RETRY:u64=100_000;
const HOLD:u64=100_000_000;
pub trait Clock{
    fn wall_ns(&mut self)->u64;
    fn cpu_ns(&mut self)->u64;
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct PumpEvidence{
    pub call:u64,pub start_ns:u64,pub end_ns:u64,pub cpu_ns:u64,
    pub before:u16,pub after:u16,pub chars:u16,pub limit:u16,pub tx_full:bool,
    pub version:u64,pub written_before:u64,pub written_after:u64,pub wait_ns:u64,
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
enum Effect{Pending,Applied(PumpEvidence),Cancelled(u64),Unknown(u64)}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
struct Work{
    key:PlanKey,index:u16,target:Identity,executor_generation:u64,version:u64,
    chars:u16,until:u64,accepted_ns:u64,effect:Effect,
}
#[derive(Clone,Copy)]
struct Installed{version:u64,chars:u16,until:u64}
pub struct Owner{
    boot:u64,target:Identity,executor_generation:u64,
    bytes:[u8;QUEUE],ages:[u64;QUEUE],head:usize,len:usize,
    installed:Installed,work:Option<Work>,retry_ns:u64,poisoned:bool,
    written:u64,calls:u64,last_change:u64,last_clock:u64,
    // Restrict all parameter changes to <=4 in each rolling second
    // (stronger than the reversal cap). Expired lease fallback is a
    // safety action and cannot be delayed by this optimization limit.
    changes:[u64;4],change_count:usize,
    window:u64,window_calls:u32,window_full:u32,window_cpu:u64,
    window_wait:Option<u64>,window_valid:bool,
}
impl Owner{
    pub const fn empty()->Self{Self{
        boot:0,target:Identity{id:0,generation:0},executor_generation:0,
        bytes:[0;QUEUE],ages:[0;QUEUE],head:0,len:0,
        installed:Installed{version:0,chars:BASELINE,until:0},work:None,retry_ns:0,
        poisoned:false,written:0,calls:0,last_change:0,last_clock:0,
        changes:[0;4],change_count:0,window:0,window_calls:0,window_full:0,
        window_cpu:0,window_wait:None,window_valid:true,
    }}
    /// The true HAL registry owner supplies exact current object identity
    /// and independently authenticates the actual device. No new device
    /// access is conferred by the plan or an AI score.
    pub fn bind(&mut self,boot:u64,target:Identity,generation:u64,
        verify_device:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if self.boot!=0{return Err(Error::Busy);}
        if boot==0||!target.valid()||generation==0{return Err(Error::Invalid);}
        verify_device()?;self.boot=boot;self.target=target;self.executor_generation=generation;Ok(())
    }
    pub fn target(&self)->Identity{self.target}
    pub fn installed_version(&self)->u64{self.installed.version}
    pub fn pending(&self)->usize{self.len}
    pub fn written(&self)->u64{self.written}
    pub fn current(&self,now:u64)->u16{
        if now<self.installed.until{self.installed.chars}else{BASELINE}
    }
    pub fn legal(&self,chars:u16,now:u64)->bool{
        if self.boot==0||self.poisoned||self.work.is_some()||now<self.last_clock
            ||!ActionV2::ConsolePump(chars).valid(){return false;}
        if chars==self.current(now){return true;}
        if self.last_change!=0&&now.saturating_sub(self.last_change)<HOLD{return false;}
        self.changes[..self.change_count].iter().filter(|&&t|now.saturating_sub(t)<1_000_000_000).count()<4
    }
    /// Must be called in the protected claim_apply_work admission callback.
    /// All fallible preflight precedes changes. Installing a desired value
    /// is not APPLIED; only actual successful HAL output establishes it.
    pub fn accept(&mut self,w:&ApplyWorkV1<'_>,base_version:u64,until:u64,now:u64,
        verify_live:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if w.domain!=DOMAIN||w.key.boot_epoch!=self.boot||w.target!=self.target
            ||w.executor_generation!=self.executor_generation||!w.key.valid()
            ||base_version!=self.installed.version||w.plan_version<=base_version{return Err(Error::Stale);}
        if until<=now||until-now>10_000_000_000{return Err(Error::Expired);}
        let ActionV2::ConsolePump(chars)=ActionV2::decode(DOMAIN,1,w.payload)?else{return Err(Error::Invalid);};
        if !self.legal(chars,now){return Err(Error::Busy);}
        verify_live()?;
        if chars!=self.current(now){
            if self.change_count<4{self.changes[self.change_count]=now;self.change_count+=1;}
            else{self.changes.rotate_left(1);self.changes[3]=now;}
            self.last_change=now;
        }
        self.installed=Installed{version:w.plan_version,chars,until};
        self.work=Some(Work{key:w.key,index:w.action_index,target:w.target,
            executor_generation:w.executor_generation,version:w.plan_version,chars,until,
            accepted_ns:now,effect:Effect::Pending});
        self.last_clock=now;Ok(())
    }
    /// Whole frame admission, never a partial enqueue. Caller keeps its
    /// sequence on backpressure. Emergency output is not routed here.
    pub fn enqueue(&mut self,bytes:&[u8],now:u64)->Result<(),Error>{
        if self.boot==0||self.poisoned{return Err(Error::NotReady);}
        if now<self.last_clock{return Err(Error::Clock);}
        if bytes.len()>QUEUE-self.len{return Err(Error::Busy);}
        for (i,&b) in bytes.iter().enumerate(){
            let p=(self.head+self.len+i)%QUEUE;self.bytes[p]=b;self.ages[p]=now;
        }
        self.len+=bytes.len();self.last_clock=now;Ok(())
    }
    fn expire(&mut self,now:u64){
        if let Some(w)=self.work.as_mut(){
            if w.effect==Effect::Pending&&now>=w.until{w.effect=Effect::Cancelled(now);}
        }
    }
    fn poison(&mut self,now:u64){
        self.poisoned=true;
        if let Some(w)=self.work.as_mut(){
            if w.effect==Effect::Pending{w.effect=Effect::Unknown(now.max(1));}
        }
    }
    /// One bounded ordinary pump. A full TX FIFO returns immediately and
    /// sets a 100us retry deadline. All accepted bytes advance the actual
    /// watermark even on a subsequent failure. No blocking IRQ loop.
    pub fn pump(&mut self,console:&mut impl ConsoleOps,clock:&mut impl Clock)->Result<Option<PumpEvidence>,Error>{
        if self.boot==0||self.poisoned{return Err(Error::NotReady);}
        let start=clock.wall_ns();
        if start<self.last_clock||start==0{self.poison(start);return Err(Error::Clock);}
        self.last_clock=start;self.expire(start);
        if start<self.retry_ns||self.len==0{return Ok(None);}
        let cpu_start=clock.cpu_ns();
        let before=self.len as u16;let limit=self.current(start);
        let version=if start<self.installed.until{self.installed.version}else{0};
        let wait=start.checked_sub(self.ages[self.head]).ok_or(Error::Clock)?;
        let written_before=self.written;
        if self.written.checked_add(u64::from(limit)).is_none()||self.calls==u64::MAX{return Err(Error::Exhausted);}
        let call=self.calls+1;self.calls=call;
        let mut chars=0u16;let mut full=false;let mut fault=false;
        for _ in 0..limit{
            if self.len==0{break;}
            match console.try_write(&self.bytes[self.head..self.head+1]){
                Ok(1)=>{
                    self.bytes[self.head]=0;self.ages[self.head]=0;
                    self.head=(self.head+1)%QUEUE;self.len-=1;
                    chars+=1;self.written+=1;
                }
                Ok(0)|Err(PlatformError::Again)=>{full=true;break;}
                _=>{fault=true;break;}
            }
        }
        let cpu_end=clock.cpu_ns();let end=clock.wall_ns();
        if end<start||cpu_end<cpu_start{self.poison(start);return Err(Error::Clock);}
        self.last_clock=end;
        if full{
            self.retry_ns=end.checked_add(RETRY).ok_or_else(||{self.poison(end);Error::Clock})?;
        }
        if self.window!=start/WINDOW{
            self.window=start/WINDOW;self.window_calls=0;self.window_full=0;
            self.window_cpu=0;self.window_wait=None;self.window_valid=true;
        }
        let cpu_ns=cpu_end-cpu_start;
        let add=||->Option<(u32,u32,u64)>{
            Some((self.window_calls.checked_add(1)?,self.window_full.checked_add(u32::from(full))?,
                self.window_cpu.checked_add(cpu_ns)?))
        };
        if let Some((calls,full,ns))=add(){self.window_calls=calls;self.window_full=full;self.window_cpu=ns;}
        else{self.window_valid=false;}
        if chars>0{self.window_wait=Some(wait);}
        // Without exact aligned PMU split do not present a cross-window
        // measurement as a valid current-window value.
        if end/WINDOW!=start/WINDOW||fault{self.window_valid=false;}
        let e=PumpEvidence{call,start_ns:start,end_ns:end,cpu_ns,before,after:self.len as u16,
            chars,limit,tx_full:full,version,written_before,written_after:self.written,wait_ns:wait};
        if fault{self.poison(end);return Err(Error::NotReady);}
        if let Some(w)=self.work.as_mut(){
            if w.effect==Effect::Pending&&version==w.version&&chars>0{
                w.effect=Effect::Applied(e);
            }
        }
        Ok(Some(e))
    }
    /// Actual raw D15 fields (24..27). Missing observation stays absent,
    /// never silently zeroed. Common ledger fields are supplied separately.
    pub fn observe(&self,now:u64)->Result<[Option<u64>;4],Error>{
        if self.boot==0||self.poisoned||now<self.last_clock{return Err(Error::NotReady);}
        let valid=self.window_valid&&self.window==now/WINDOW&&self.window_calls!=0;
        let ratio=valid.then(||u64::from(self.window_full)*1000/u64::from(self.window_calls));
        let cost=if valid{u32::try_from(self.window_cpu/1000).ok().map(u64::from)}else{None};
        let wait=if valid{self.window_wait.and_then(|v|u32::try_from(v/1000).ok()).map(u64::from)}else{None};
        Ok([Some(self.len as u64),ratio,cost,wait])
    }
    pub fn applied_evidence(&self)->Option<PumpEvidence>{
        match self.work?.effect{Effect::Applied(e)=>Some(e),_=>None}
    }
    pub fn report(&mut self,now:u64,out:&mut[u8;super::apply_report_v1::MAX_APPLY_REPORT_BYTES])->Result<usize,Error>{
        if now<self.last_clock{return Err(Error::Clock);}
        self.expire(now);
        let w=self.work.ok_or(Error::Stale)?;
        let (state,result,completed_ns)=match w.effect{
            Effect::Pending=>return Err(Error::NotReady),
            Effect::Applied(e)=>(ActionStatus::Applied,0,e.end_ns),
            Effect::Cancelled(t)=>(ActionStatus::Cancelled,-7,t),
            Effect::Unknown(t)=>(ActionStatus::Unknown,-16,t),
        };
        ApplyReportV1{key:w.key,action_index:w.index,domain_id:DOMAIN,state,target:w.target,
            executor_generation:w.executor_generation,plan_version:w.version,result,completed_ns,
            action:&w.chars.to_le_bytes()}.encode(out)
    }
    /// Independent terminal verifier reads retained HAL counters and exact
    /// applied key, not an EL0-supplied Boolean. UNKNOWN cannot settle.
    pub fn verify_report(&self,r:&ApplyReportV1<'_>)->Result<(),Error>{
        let w=self.work.ok_or(Error::Stale)?;
        if r.key!=w.key||r.action_index!=w.index||r.domain_id!=DOMAIN||r.target!=w.target
            ||r.executor_generation!=w.executor_generation||r.plan_version!=w.version
            ||r.action!=w.chars.to_le_bytes(){return Err(Error::Denied);}
        match w.effect{
            Effect::Applied(e) if r.state==ActionStatus::Applied&&r.result==0&&r.completed_ns==e.end_ns
                &&e.version==w.version&&e.limit==w.chars&&e.chars>0&&e.chars<=e.limit
                &&e.before-e.after==e.chars&&e.written_after-e.written_before==u64::from(e.chars)
                &&e.start_ns>=w.accepted_ns&&e.start_ns<w.until&&self.written>=e.written_after=>Ok(()),
            Effect::Cancelled(t) if r.state==ActionStatus::Cancelled&&r.result==-7&&r.completed_ns==t=>Ok(()),
            _=>Err(Error::NotReady),
        }
    }
    pub fn retire(&mut self,r:&ApplyReportV1<'_>,verify_custody:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        self.verify_report(r)?;verify_custody()?;self.work=None;Ok(())
    }
}
const _:()=assert!(core::mem::size_of::<Owner>()<64*1024);
#[cfg(test)]
mod tests{
    extern crate std;
    use super::*;
    struct C{wall:u64,cpu:u64}
    impl Clock for C{
        fn wall_ns(&mut self)->u64{self.wall+=10;self.wall}
        fn cpu_ns(&mut self)->u64{self.cpu+=1234;self.cpu}
    }
    struct U{full:bool,fail:bool,bytes:std::vec::Vec<u8>}
    impl ConsoleOps for U{
        fn try_write(&mut self,b:&[u8])->Result<usize,PlatformError>{
            if self.fail{return Err(PlatformError::Invalid);}
            if self.full{return Err(PlatformError::Again);}
            self.bytes.extend_from_slice(b);Ok(b.len())
        }
    }
    fn owner()->Owner{
        let mut o=Owner::empty();o.bind(1,Identity{id:15,generation:1},1,||Ok(())).unwrap();o
    }
    fn work(payload:&[u8])->ApplyWorkV1<'_>{ApplyWorkV1{
        key:PlanKey{boot_epoch:1,controller_epoch:1,plan_seq:1},action_index:0,domain:15,
        target:Identity{id:15,generation:1},executor_generation:1,plan_version:1,payload,
    }}
    #[test]
    fn actual_successful_pump_required_and_full_retains_queue(){
        let mut o=owner();let mut c=C{wall:100,cpu:0};let mut u=U{full:true,fail:false,bytes:std::vec::Vec::new()};
        let w=work(&[32,0]);o.accept(&w,0,1_000_000_000,100,||Ok(())).unwrap();
        o.enqueue(b"abcdefghijklmnopqrstuvwxyz0123456789",100).unwrap();
        let mut r=[0;super::super::apply_report_v1::MAX_APPLY_REPORT_BYTES];
        assert_eq!(o.report(100,&mut r),Err(Error::NotReady));
        let e=o.pump(&mut u,&mut c).unwrap().unwrap();assert_eq!((e.chars,e.limit),(0,32));assert!(e.tx_full);
        assert_eq!(o.pending(),36);assert!(o.pump(&mut u,&mut c).unwrap().is_none());
        c.wall+=100_000;u.full=false;
        let e=o.pump(&mut u,&mut c).unwrap().unwrap();assert_eq!((e.chars,e.before,e.after),(32,36,4));
        let n=o.report(c.wall,&mut r).unwrap();let report=ApplyReportV1::decode(&r[..n]).unwrap();
        o.verify_report(&report).unwrap();
        assert_eq!(o.verify_report(&ApplyReportV1{plan_version:2,..report}),Err(Error::Denied));
        assert_eq!(o.retire(&report,||Err(Error::NotReady)),Err(Error::NotReady));
        o.retire(&report,||Ok(())).unwrap();
        o.pump(&mut u,&mut c).unwrap();assert_eq!(u.bytes,b"abcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(o.observe(c.wall).unwrap()[0],Some(0));
    }
    #[test]
    fn uncertain_hardware_error_never_reports_applied(){
        let mut o=owner();let mut c=C{wall:100,cpu:0};let mut u=U{full:false,fail:true,bytes:std::vec::Vec::new()};
        o.accept(&work(&[8,0]),0,1_000_000_000,100,||Ok(())).unwrap();
        o.enqueue(b"abc",100).unwrap();
        assert_eq!(o.pump(&mut u,&mut c),Err(Error::NotReady));
        let mut b=[0;super::super::apply_report_v1::MAX_APPLY_REPORT_BYTES];
        let n=o.report(c.wall,&mut b).unwrap();let r=ApplyReportV1::decode(&b[..n]).unwrap();
        assert_eq!(r.state,ActionStatus::Unknown);assert_eq!(o.verify_report(&r),Err(Error::NotReady));
        assert_eq!(o.retire(&r,||panic!()),Err(Error::NotReady));
    }
}

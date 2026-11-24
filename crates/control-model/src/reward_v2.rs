//! Current single-device RewardSchema v2 arithmetic (V0.19.9 §6.3).
//! These results are measurements, not labels or authority. A protected
//! replay owner must authenticate actual requests, full CPU coverage,
//! initial APPLIED/renewals/restoration and same frozen experiment group.
//! No historical cluster nodes, model score or fabricated missing cost.
#[path="../../prototype/src/learning/softfloat.rs"]
pub mod softfloat;
use softfloat::F64;
pub const WINDOW_NS:u64=10_000_000_000;
pub const MAX_REQUESTS:usize=4096;
pub const MAX_INTERVALS:usize=8192;
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Error{Capacity,Invalid,Incomplete,Numeric}
impl From<softfloat::FloatError> for Error{fn from(_:softfloat::FloatError)->Self{Self::Numeric}}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum RequestResult{Completed{finished_ns:u64},Rejected,TimedOut,Pending}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Request{pub id:u64,pub arrived_ns:u64,pub result:RequestResult}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
#[repr(u8)]
pub enum CpuClass{Policy=0,Action=1,Work=2,Optional=3}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Interval{pub core:u8,pub start_ns:u64,pub end_ns:u64,pub class:CpuClass}
#[derive(Clone,Copy)]
pub struct Trace<'a>{
    pub domain:u16,pub first_ns:u64,pub start_ns:u64,pub closing_ns:u64,
    pub requests:&'a[Request],pub cpu:&'a[Interval],
    /// Actual coverage proof, separately authenticated by replay owner.
    /// P/E/O bits; E covers both actions and observed work. Empty but
    /// verified classes may have zero cost, absent evidence may not.
    pub required:u8,pub reported:u8,
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Performance{
    pub emitted:u64,pub completed:u64,pub rejected:u64,pub timed_out:u64,pub pending:u64,
    pub penalty_p99_ns:u64,pub actual_p99_ns:Option<u64>,
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Cost{pub union_ns:u64,pub by_class:[u64;3],pub raw_tagged:[u64;3]}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Metrics{pub performance:Performance,pub cost:Cost}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Reward{pub candidate:Metrics,pub baseline:Metrics,pub delta_x:F64,pub delta_l:F64,
    pub raw_cost:F64,pub clipped_cost:F64,pub value:F64}
#[derive(Clone,Copy)]
struct Event{at:u64,core:u8,class:u8,start:bool}
const EMPTY:Event=Event{at:0,core:0,class:0,start:false};
pub struct Workspace{events:[Event;2*MAX_INTERVALS],latencies:[u64;MAX_REQUESTS]}
impl Workspace{pub const fn new()->Self{Self{events:[EMPTY;2*MAX_INTERVALS],latencies:[0;MAX_REQUESTS]}}}
const _:()=assert!(core::mem::size_of::<Workspace>()<=1024*1024);
fn add(a:&mut u64,b:u64)->Result<(),Error>{*a=a.checked_add(b).ok_or(Error::Numeric)?;Ok(())}
fn observe(t:Trace<'_>,w:&mut Workspace)->Result<Metrics,Error>{
    let end=t.start_ns.checked_add(WINDOW_NS).ok_or(Error::Numeric)?;
    if !(1..=15).contains(&t.domain)||t.first_ns>t.start_ns||t.closing_ns<end
        ||t.closing_ns-end>5_000_000_000||t.start_ns-t.first_ns>6_000_000_000{
        return Err(Error::Invalid);
    }
    let mask=if t.domain==13{7}else{3};
    if t.required!=mask||t.reported!=mask{return Err(Error::Incomplete);}
    if t.requests.len()<100{return Err(Error::Incomplete);}
    if t.requests.len()>MAX_REQUESTS||t.cpu.len()>MAX_INTERVALS{return Err(Error::Capacity);}
    let mut counts=[0u64;4];let mut n=0;
    for (i,r) in t.requests.iter().enumerate(){
        if r.id==0||r.arrived_ns<t.start_ns||r.arrived_ns>=end
            ||t.requests[..i].iter().any(|p|p.id==r.id){return Err(Error::Invalid);}
        match r.result{
            RequestResult::Completed{finished_ns}=>{
                if finished_ns<r.arrived_ns||finished_ns>end{return Err(Error::Invalid);}
                w.latencies[n]=finished_ns-r.arrived_ns;n+=1;counts[0]+=1;
            }
            RequestResult::Rejected=>counts[1]+=1,
            RequestResult::TimedOut=>counts[2]+=1,
            RequestResult::Pending=>counts[3]+=1,
        }
    }
    w.latencies[..n].sort_unstable();
    let actual=if n==0{None}else{Some(w.latencies[(99*n).div_ceil(100)-1])};
    w.latencies[n..t.requests.len()].fill(WINDOW_NS);
    w.latencies[..t.requests.len()].sort_unstable();
    let performance=Performance{emitted:t.requests.len() as u64,completed:counts[0],rejected:counts[1],
        timed_out:counts[2],pending:counts[3],penalty_p99_ns:w.latencies[(99*t.requests.len()).div_ceil(100)-1],
        actual_p99_ns:actual};
    let mut cost=Cost{union_ns:0,by_class:[0;3],raw_tagged:[0;3]};
    for (i,a) in t.cpu.iter().enumerate(){
        if a.core>=4||a.start_ns>=a.end_ns||a.start_ns<t.first_ns||a.end_ns>t.closing_ns
            ||matches!(a.class,CpuClass::Work|CpuClass::Optional)&&(a.start_ns<t.start_ns||a.end_ns>end)
            ||a.class==CpuClass::Optional&&t.domain!=13{return Err(Error::Invalid);}
        let class=match a.class{CpuClass::Policy=>0,CpuClass::Action|CpuClass::Work=>1,CpuClass::Optional=>2};
        add(&mut cost.raw_tagged[class as usize],a.end_ns-a.start_ns)?;
        w.events[2*i]=Event{at:a.start_ns,core:a.core,class,start:true};
        w.events[2*i+1]=Event{at:a.end_ns,core:a.core,class,start:false};
    }
    let events=&mut w.events[..2*t.cpu.len()];
    // Half-open intervals. For each core, count active P/E/O and assign
    // each elementary interval to the first present class. Overlap is
    // charged once, never by summing raw tagged lengths.
    events.sort_unstable_by_key(|e|(e.core,e.at,e.start));
    let mut active=[0u32;3];let mut last=0;let mut core=None;
    for e in events{
        if core!=Some(e.core){
            if active!=[0;3]{return Err(Error::Invalid);}
            core=Some(e.core);last=e.at;
        }
        if let Some(i)=active.iter().position(|&n|n!=0){
            let elapsed=e.at.checked_sub(last).ok_or(Error::Invalid)?;
            add(&mut cost.union_ns,elapsed)?;add(&mut cost.by_class[i],elapsed)?;
        }
        let slot=&mut active[e.class as usize];
        *slot=if e.start{slot.checked_add(1)}else{slot.checked_sub(1)}.ok_or(Error::Invalid)?;
        last=e.at;
    }
    if active!=[0;3]||cost.by_class.iter().sum::<u64>()!=cost.union_ns{return Err(Error::Invalid);}
    Ok(Metrics{performance,cost})
}
/// Joint policy common interval: exact ordered, remainder-first partition.
pub fn split_policy(a:Interval,count:u16,index:u16)->Result<Interval,Error>{
    if a.class!=CpuClass::Policy||a.core>=4||a.end_ns<=a.start_ns||count==0||count>16||index>=count{
        return Err(Error::Invalid);
    }
    let len=a.end_ns-a.start_ns;let n=u64::from(count);let i=u64::from(index);
    let q=len/n;let rem=len%n;
    let start=a.start_ns.checked_add(i*q+i.min(rem)).ok_or(Error::Numeric)?;
    let end=start.checked_add(q+u64::from(i<rem)).ok_or(Error::Numeric)?;
    // Zero-length portions are legitimate when a source interval is
    // shorter than action_count; caller omits those from interval traces.
    Ok(Interval{start_ns:start,end_ns:end,..a})
}
/// Exact operation order, software binary64 RNE, no FMA. Request schedule
/// must be identical relative to the two independent observation windows.
pub fn compute(candidate:Trace<'_>,baseline:Trace<'_>,w:&mut Workspace)->Result<Reward,Error>{
    if candidate.domain!=baseline.domain||candidate.requests.len()!=baseline.requests.len(){return Err(Error::Invalid);}
    for (a,b) in candidate.requests.iter().zip(baseline.requests){
        if a.id!=b.id||a.arrived_ns.checked_sub(candidate.start_ns)!=b.arrived_ns.checked_sub(baseline.start_ns){
            return Err(Error::Invalid);
        }
    }
    let c=observe(candidate,w)?;let b=observe(baseline,w)?;
    let ten=F64::from_u64(10);
    let x=F64::from_u64(c.performance.completed).div(ten)?;
    let x0=F64::from_u64(b.performance.completed).div(ten)?;
    let floor=F64::ONE.div(ten)?;
    let dx=x.sub(x0)?.div(if x0.compare(floor).is_lt(){floor}else{x0})?;
    let unit=F64::from_u64(1_000_000_000);
    let l=F64::from_u64(c.performance.penalty_p99_ns).div(unit)?;
    let l0=F64::from_u64(b.performance.penalty_p99_ns).div(unit)?;
    let latency_floor=F64::ONE.div(F64::from_u64(1_000_000))?;
    let dl=l.sub(l0)?.div(if l0.compare(latency_floor).is_lt(){latency_floor}else{l0})?;
    let raw=F64::from_u64(c.cost.union_ns).div(F64::from_u64(WINDOW_NS))?;
    let cost=raw.clamp(F64::ZERO,F64::ONE)?;
    let four=F64::from_bits_checked(0x3fd999999999999a)?;
    let two=F64::from_bits_checked(0x3fc999999999999a)?;
    let value=four.mul(dx.clamp(F64::ONE.neg(),F64::ONE)?)?
        .sub(four.mul(dl.clamp(F64::ONE.neg(),F64::ONE)?)?)?.sub(two.mul(cost)?)?;
    Ok(Reward{candidate:c,baseline:b,delta_x:dx,delta_l:dl,raw_cost:raw,clipped_cost:cost,value})
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn penalties_union_cost_and_no_missing_coverage(){
        let start=1_000_000_000;
        let good:[Request;100]=core::array::from_fn(|i|Request{id:i as u64+1,arrived_ns:start+i as u64,
            result:RequestResult::Completed{finished_ns:start+i as u64+1_000_000}});
        let mut bad=good;bad[0].result=RequestResult::Rejected;bad[1].result=RequestResult::Pending;
        let cpu=[Interval{core:0,start_ns:start,end_ns:start+100,class:CpuClass::Policy},
            Interval{core:0,start_ns:start+50,end_ns:start+150,class:CpuClass::Action},
            Interval{core:1,start_ns:start,end_ns:start+100,class:CpuClass::Work}];
        let base=Trace{domain:1,first_ns:start,start_ns:start,closing_ns:start+WINDOW_NS,
            requests:&good,cpu:&cpu,required:3,reported:3};
        let mut work=Workspace::new();
        let r=compute(Trace{requests:&bad,..base},base,&mut work).unwrap();
        assert_eq!(r.candidate.cost.union_ns,250);
        assert_eq!(r.candidate.cost.by_class,[100,150,0]);
        assert_eq!(r.candidate.performance.penalty_p99_ns,WINDOW_NS);
        assert_eq!(r.candidate.performance.actual_p99_ns,Some(1_000_000));
        assert!(r.value.negative());
        assert_eq!(compute(Trace{reported:1,..base},base,&mut work),Err(Error::Incomplete));
        assert_eq!(compute(Trace{requests:&good[..99],..base},Trace{requests:&good[..99],..base},&mut work),Err(Error::Incomplete));
        assert_eq!(split_policy(cpu[0],3,0).unwrap().end_ns,start+34);
        assert_eq!(split_policy(cpu[0],3,2).unwrap().end_ns,start+100);
    }
}

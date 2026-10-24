//! Full-cost paired replay measurements. The protected producer must attest
//! the complete canonical record; hashes alone are never execution evidence.
use super::{Error, Family, ReplayGroup, SchemaBinding, softfloat::F64};
use crate::{domains::{Action, ApplyId}, features, model::{Model, MODEL_BYTES}, policy::{CandidateSet, ExecutionState}};
use sha2::{Digest, Sha256};

pub const OBSERVATION_NS: u64 = 10_000_000_000;
pub const MAX_REQUESTS: usize = 4096;
pub const MAX_CPU_INTERVALS: usize = 8192;
pub const MAX_RENEWALS: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuClass { Policy, ExecutorAction, ExecutorWork, Optional }
impl CpuClass { fn union_class(self)->usize { match self { Self::Policy=>0,Self::ExecutorAction|Self::ExecutorWork=>1,Self::Optional=>2 } } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuInterval {
    pub node: [u8;32], pub core: u16, pub start_ns: u64, pub end_ns: u64, pub class: CpuClass,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuCoverage {
    pub node: [u8;32], pub first_ns: u64, pub observation_ns: u64,
    pub observation_end_ns: u64, pub closing_ns: u64,
    /// P/E/O bits required by the frozen replay contract, including partners.
    pub required: u8, pub reported: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestResult { Completed { finished_ns:u64 }, Rejected, TimedOut, Pending }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkRequest { pub id:u64, pub arrived_ns:u64, pub result:RequestResult }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CostTotals { pub union_ns:u64, pub policy_ns:u64, pub executor_ns:u64, pub optional_ns:u64, pub raw_tagged_ns:[u64;3] }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Performance {
    pub emitted:u64, pub completed:u64, pub rejected:u64, pub timed_out:u64, pub pending:u64,
    pub penalty_p99_ns:u64, pub actual_completed_p99_ns:Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reward {
    pub candidate:Performance, pub baseline:Performance, pub candidate_cpu:CostTotals, pub baseline_cpu:CostTotals,
    pub raw_cost:F64, pub clipped_cost:F64, pub delta_throughput:F64, pub delta_latency:F64, pub value:F64,
}
#[derive(Clone, Copy)]
struct Event { at:u64, interval:u16, start:bool }
const EVENT:Event=Event{at:0,interval:0,start:false};
pub struct RewardWorkspace { events:[Event;MAX_CPU_INTERVALS*2], latencies:[u64;MAX_REQUESTS] }
impl Default for RewardWorkspace { fn default()->Self {Self::new()} }
impl RewardWorkspace { pub const fn new()->Self { Self{events:[EVENT;MAX_CPU_INTERVALS*2],latencies:[0;MAX_REQUESTS]} } }
const _:()=assert!(core::mem::size_of::<RewardWorkspace>()<=1024*1024);

pub fn split_joint_policy(interval:CpuInterval,count:u16,index:u16)->Result<CpuInterval,Error>{
    if interval.class!=CpuClass::Policy || count==0 || count>16 || index>=count || interval.end_ns<interval.start_ns {return Err(Error::Evidence)}
    let length=interval.end_ns-interval.start_ns;
    let (q,r)=(length/u64::from(count),length%u64::from(count));
    let offset=q.checked_mul(u64::from(index)).and_then(|n|n.checked_add(u64::from(index).min(r))).ok_or(Error::Numeric)?;
    let start=interval.start_ns.checked_add(offset).ok_or(Error::Numeric)?;
    let end=start.checked_add(q+u64::from(u64::from(index)<r)).ok_or(Error::Numeric)?;
    Ok(CpuInterval{start_ns:start,end_ns:end,..interval})
}

pub fn union_cpu(family:Family, intervals:&[CpuInterval],coverage:&[CpuCoverage],work:&mut RewardWorkspace)->Result<CostTotals,Error>{
    family.index()?;
    if intervals.len()>MAX_CPU_INTERVALS || coverage.is_empty() || coverage.len()>16 {return Err(Error::Capacity)}
    for (i,c) in coverage.iter().enumerate(){
        if c.node==[0;32] || c.required&!7!=0 || c.required&3!=3 || c.reported&!7!=0 || c.reported&c.required!=c.required
            || (family.domain!=13 && c.required&4!=0)
            || c.observation_end_ns.checked_sub(c.observation_ns)!=Some(OBSERVATION_NS)
            || c.first_ns>c.observation_ns || c.closing_ns<c.observation_end_ns
            || c.closing_ns-c.observation_end_ns>5_000_000_000
            || coverage[..i].iter().any(|p|p.node==c.node) {return Err(Error::Evidence)}
    }
    let mut raw=[0u64;3];
    for (i,c) in intervals.iter().enumerate(){
        let owner=coverage.iter().find(|v|v.node==c.node).ok_or(Error::Evidence)?;
        let class=c.class.union_class();
        let (begin,end)=match c.class {CpuClass::Policy|CpuClass::ExecutorAction=>(owner.first_ns,owner.closing_ns),
            CpuClass::ExecutorWork|CpuClass::Optional=>(owner.observation_ns,owner.observation_end_ns)};
        if c.end_ns<c.start_ns || c.start_ns<begin || c.end_ns>end || c.core>=64
            || owner.reported&(1<<class)==0 || (c.class==CpuClass::Optional && family.domain!=13) {return Err(Error::Evidence)}
        raw[class]=raw[class].checked_add(c.end_ns-c.start_ns).ok_or(Error::Numeric)?;
        work.events[2*i]=Event{at:c.start_ns,interval:i as u16,start:true};
        work.events[2*i+1]=Event{at:c.end_ns,interval:i as u16,start:false};
    }
    let events=&mut work.events[..intervals.len()*2];
    events.sort_unstable_by(|a,b|{
        let x=intervals[usize::from(a.interval)];let y=intervals[usize::from(b.interval)];
        (x.node,x.core,a.at,!a.start).cmp(&(y.node,y.core,b.at,!b.start))
    });
    let mut active=[0usize;3];let mut classified=[0u64;3];let mut last=None;
    for e in events.iter(){
        let c=intervals[usize::from(e.interval)];
        if let Some((node,core,at))=last {
            if (node,core)==(c.node,c.core){
                if let Some(class)=active.iter().position(|n|*n!=0){classified[class]=classified[class].checked_add(e.at-at).ok_or(Error::Numeric)?;}
            }else if active!=[0;3]{return Err(Error::Evidence)}
        }
        let count=&mut active[c.class.union_class()];
        if e.start {*count=count.checked_add(1).ok_or(Error::Numeric)?;}else{*count=count.checked_sub(1).ok_or(Error::Evidence)?;}
        last=Some((c.node,c.core,e.at));
    }
    if active!=[0;3]{return Err(Error::Evidence)}
    let total=classified.iter().try_fold(0u64,|a,b|a.checked_add(*b).ok_or(Error::Numeric))?;
    Ok(CostTotals{union_ns:total,policy_ns:classified[0],executor_ns:classified[1],optional_ns:classified[2],raw_tagged_ns:raw})
}

pub fn performance(requests:&[WorkRequest],start:u64,work:&mut RewardWorkspace)->Result<Performance,Error>{
    if !(100..=MAX_REQUESTS).contains(&requests.len()){return Err(Error::DataIncomplete)}
    let end=start.checked_add(OBSERVATION_NS).ok_or(Error::Numeric)?;
    let mut counts=[0u64;4];let mut completed=0usize;
    for (i,r) in requests.iter().enumerate(){
        if r.id==0 || r.arrived_ns<start || r.arrived_ns>=end || requests[..i].iter().any(|v|v.id==r.id){return Err(Error::Evidence)}
        if let RequestResult::Completed{finished_ns}=r.result{
            if finished_ns<r.arrived_ns || finished_ns>end {return Err(Error::Evidence)}
            work.latencies[completed]=finished_ns-r.arrived_ns;completed+=1;counts[0]+=1;
        }else{counts[match r.result{RequestResult::Rejected=>1,RequestResult::TimedOut=>2,_=>3}]+=1;}
    }
    work.latencies[..completed].sort_unstable();
    let actual=(completed!=0).then(||work.latencies[(99*completed).div_ceil(100)-1]);
    work.latencies[completed..requests.len()].fill(OBSERVATION_NS);
    work.latencies[..requests.len()].sort_unstable();
    Ok(Performance{emitted:requests.len() as u64,completed:counts[0],rejected:counts[1],timed_out:counts[2],pending:counts[3],
        penalty_p99_ns:work.latencies[(99*requests.len()).div_ceil(100)-1],actual_completed_p99_ns:actual})
}

pub struct Adoption<'a>{
    pub decision_seq:u64,pub apply:ApplyId,pub plan_version:u64,pub executor_generation:u64,
    pub candidates:&'a CandidateSet,pub model:&'a [u8;MODEL_BYTES],pub scores:&'a [i16],pub selected:u16,
    pub actual:Action,pub executed:ExecutionState,pub started_ns:u64,pub finished_ns:u64,pub installed_until_ns:u64,
}
pub struct Trial<'a>{
    pub id:u64,pub family:Family,pub group:ReplayGroup,pub frozen_other_domains:[u8;32],
    pub reward_schema:SchemaBinding,pub learning_config:SchemaBinding,
    pub observation_ns:u64,pub observation_end_ns:u64,pub warmed_from_ns:u64,pub closing_ns:u64,
    pub requests:&'a[WorkRequest],pub adoptions:&'a[Adoption<'a>],pub coverage:&'a[CpuCoverage],pub cpu:&'a[CpuInterval],
    pub correct:bool,pub frozen:bool,pub closing:ExecutionState,
    pub ordinary_warmup_cpu_ns:u64,pub later_workload_cpu_ns:u64,pub peak_workspace_bytes:u64,
}
/// Implemented by the protected replay/receipt owner. Native integration must
/// authenticate every participating node and bind its collected CPU trace;
/// a caller-supplied digest without that authority cannot produce a label.
pub trait EvidenceAuthority { fn attest(&self,trial:&Trial<'_>,canonical_digest:[u8;32])->Result<(),Error>; }
#[derive(Clone,Debug)]
pub struct AcceptedSample {
    pub(super) family:Family,pub(super) group:ReplayGroup,pub(super) input:[i16;64],
    pub(super) reward:Reward,pub(super) evidence:[u8;32],
    pub(super) reward_schema:SchemaBinding,pub(super) learning_config:SchemaBinding,
}
impl AcceptedSample {
    pub fn family(&self)->Family{self.family} pub fn group(&self)->ReplayGroup{self.group}
    pub fn input(&self)->&[i16;64]{&self.input} pub fn reward(&self)->Reward{self.reward}
    pub fn evidence_hash(&self)->[u8;32]{self.evidence}
}
fn number(hash:&mut Sha256,value:u64){hash.update(value.to_le_bytes());}
fn action(hash:&mut Sha256,value:Action)->Result<(),Error>{let mut b=[0;16];let n=crate::policy_wire::encode_payload(value,0,&mut b).map_err(|_|Error::Evidence)?;hash.update(value.domain().to_le_bytes());hash.update(value.kind().to_le_bytes());hash.update(&b[..n]);Ok(())}
fn terminal(s:ExecutionState)->Result<(),Error>{match s{ExecutionState::Applied=>Ok(()),ExecutionState::Unknown|ExecutionState::Pending=>Err(Error::Unknown),_=>Err(Error::Evidence)}}

fn verify_trial(t:&Trial<'_>,authority:&impl EvidenceAuthority)->Result<([u8;32],[i16;64]),Error>{
    t.family.index()?;t.reward_schema.validate()?;t.learning_config.validate()?;
    terminal(t.closing)?;
    if !t.correct || !t.frozen || t.id==0 || t.adoptions.is_empty() || t.adoptions.len()>MAX_RENEWALS
        || t.group.workload==[0;32] || t.group.initial_image==[0;32] || t.frozen_other_domains==[0;32]
        || t.observation_end_ns.checked_sub(t.observation_ns)!=Some(OBSERVATION_NS)
        || t.observation_ns.checked_sub(t.warmed_from_ns)!=Some(1_000_000_000)
        || t.closing_ns<t.observation_end_ns || t.closing_ns-t.observation_end_ns>5_000_000_000
        || t.peak_workspace_bytes>1024*1024 {return Err(Error::Evidence)}
    let first=&t.adoptions[0];let mut hash=Sha256::new();hash.update(b"CYXIA_FULL_CPU_TRIAL_1.3\0");
    for v in [t.id,t.family.domain as u64,t.family.kind as u64,t.group.seed,t.observation_ns,t.observation_end_ns,t.warmed_from_ns,t.closing_ns,t.ordinary_warmup_cpu_ns,t.later_workload_cpu_ns,t.peak_workspace_bytes]{number(&mut hash,v);}
    hash.update(t.group.workload);hash.update(t.group.initial_image);hash.update(t.frozen_other_domains);
    for s in [t.reward_schema,t.learning_config]{number(&mut hash,u64::from(s.version));hash.update(s.hash);}
    let mut input=[0i16;64];let mut covered_until=0;let mut previous_snapshot=0;
    for (i,a) in t.adoptions.iter().enumerate(){
        terminal(a.executed)?;
        if a.apply.boot_epoch==0 || a.apply.controller_epoch==0 || a.apply.plan_seq==0 || a.decision_seq==0
            || a.plan_version==0 || a.executor_generation==0 || a.apply.target!=a.candidates.target
            || a.scores.len()!=a.candidates.len() || a.selected as usize>=a.scores.len()
            || a.actual.domain()!=t.family.domain || a.actual.kind()!=t.family.kind
            || a.actual!=first.actual || a.candidates.model!=first.candidates.model
            || a.apply.target!=first.apply.target || a.apply.boot_epoch!=first.apply.boot_epoch
            || a.finished_ns<a.started_ns || a.finished_ns>t.closing_ns
            || Sha256::digest(a.model).as_slice()!=a.candidates.model.model_hash {return Err(Error::Evidence)}
        if i>0 && (a.candidates.snapshot.taken_ns<=previous_snapshot
            || t.adoptions[..i].iter().any(|old|old.apply==a.apply || (old.apply.controller_epoch==a.apply.controller_epoch && old.decision_seq==a.decision_seq))) {return Err(Error::Evidence)}
        previous_snapshot=a.candidates.snapshot.taken_ns;
        let model=Model::parse(a.model).map_err(|_|Error::Model)?;let mut best=0;let mut best_score=i16::MIN;
        for (index,c) in a.candidates.iter().enumerate(){
            let encoded=features::encode(c.action,c.features).map_err(|_|Error::Evidence)?.values;
            let score=model.score(&encoded);
            if a.scores[index]!=score{return Err(Error::Evidence)}
            if index==0 || score>best_score{best=index;best_score=score;}
            for x in encoded{hash.update(x.to_le_bytes());}hash.update(score.to_le_bytes());
            if i==0 && index==a.selected as usize{input=encoded;}
        }
        if best!=a.selected as usize || a.candidates.get(best).ok_or(Error::Evidence)?.action!=a.actual{return Err(Error::Evidence)}
        if a.actual.one_shot(){
            if t.adoptions.len()!=1 || a.started_ns!=t.observation_ns {return Err(Error::Evidence)}
            let bound=match a.actual{Action::ControlSet(_)=>200_000_000,Action::RecoveryRecipe(_)=>1_000_000_000,_=>5_000_000_000};
            if a.finished_ns-a.started_ns>bound{return Err(Error::Deadline)}
        }else{
            if a.installed_until_ns!=a.candidates.snapshot.taken_ns.checked_add(10_000_000_000).ok_or(Error::Numeric)?
                || a.finished_ns>a.installed_until_ns || (i==0 && (a.finished_ns>t.warmed_from_ns || a.finished_ns.saturating_sub(a.candidates.snapshot.taken_ns)>5_000_000_000))
                || (i>0 && a.finished_ns>covered_until){return Err(Error::Evidence)}
            covered_until=covered_until.max(a.installed_until_ns);
        }
        for v in [a.decision_seq,a.apply.boot_epoch,a.apply.controller_epoch,a.apply.plan_seq,u64::from(a.apply.action_index),a.apply.target.id,a.apply.target.generation,a.plan_version,a.executor_generation,a.started_ns,a.finished_ns,a.installed_until_ns,a.selected as u64]{number(&mut hash,v);}
        hash.update(a.candidates.hash());hash.update(a.candidates.model.model_hash);hash.update(a.candidates.model.schema_hash);number(&mut hash,a.candidates.model.generation);action(&mut hash,a.actual)?;
    }
    if !first.actual.one_shot() && covered_until<t.observation_end_ns{return Err(Error::Evidence)}
    for r in t.requests{number(&mut hash,r.id);number(&mut hash,r.arrived_ns);let(code,at)=match r.result{RequestResult::Completed{finished_ns}=>(0,finished_ns),RequestResult::Rejected=>(1,0),RequestResult::TimedOut=>(2,0),RequestResult::Pending=>(3,0)};number(&mut hash,code);number(&mut hash,at);}
    for c in t.coverage{hash.update(c.node);for v in [c.first_ns,c.observation_ns,c.observation_end_ns,c.closing_ns,c.required as u64,c.reported as u64]{number(&mut hash,v);}}
    for c in t.cpu{hash.update(c.node);for v in [u64::from(c.core),c.start_ns,c.end_ns,c.class as u64]{number(&mut hash,v);}}
    let digest=hash.finalize().into();authority.attest(t,digest)?;Ok((digest,input))
}

pub fn pair(candidate:&Trial<'_>,baseline:&Trial<'_>,authority:&impl EvidenceAuthority,work:&mut RewardWorkspace)->Result<AcceptedSample,Error>{
    if candidate.group!=baseline.group || candidate.family!=baseline.family || candidate.frozen_other_domains!=baseline.frozen_other_domains
        || candidate.reward_schema!=baseline.reward_schema || candidate.learning_config!=baseline.learning_config
        || candidate.requests.len()!=baseline.requests.len(){return Err(Error::Evidence)}
    let(c_hash,input)=verify_trial(candidate,authority)?;let(b_hash,_)=verify_trial(baseline,authority)?;
    for(c,b)in candidate.requests.iter().zip(baseline.requests){if c.id!=b.id || c.arrived_ns.checked_sub(candidate.observation_ns)!=b.arrived_ns.checked_sub(baseline.observation_ns){return Err(Error::Evidence)}}
    let cp=performance(candidate.requests,candidate.observation_ns,work)?;let bp=performance(baseline.requests,baseline.observation_ns,work)?;
    let cc=union_cpu(candidate.family,candidate.cpu,candidate.coverage,work)?;let bc=union_cpu(baseline.family,baseline.cpu,baseline.coverage,work)?;
    let ten=F64::from_u64(10);let x=F64::from_u64(cp.completed).div(ten)?;let x0=F64::from_u64(bp.completed).div(ten)?;
    let floor=F64::ONE.div(ten)?;let denom=if x0.compare(floor).is_lt(){floor}else{x0};
    let dx=x.sub(x0)?.div(denom)?;
    let l=F64::from_u64(cp.penalty_p99_ns).div(F64::from_u64(1_000_000_000))?;
    let l0=F64::from_u64(bp.penalty_p99_ns).div(F64::from_u64(1_000_000_000))?;
    let latency_floor=F64::ONE.div(F64::from_u64(1_000_000))?;
    let dl=l.sub(l0)?.div(if l0.compare(latency_floor).is_lt(){latency_floor}else{l0})?;
    let raw=F64::from_u64(cc.union_ns).div(F64::from_u64(OBSERVATION_NS))?;let cost=raw.clamp(F64::ZERO,F64::ONE)?;
    let four_tenths=F64::from_bits_checked(0x3fd9_9999_9999_999a)?;let fifth=F64::from_bits_checked(0x3fc9_9999_9999_999a)?;
    let reward=four_tenths.mul(dx.clamp(F64::ONE.neg(),F64::ONE)?)?.sub(four_tenths.mul(dl.clamp(F64::ONE.neg(),F64::ONE)?)?)?.sub(fifth.mul(cost)?)?;
    let mut digest=Sha256::new();digest.update(b"CYXIA_PAIRED_LABEL_1.3\0");digest.update(c_hash);digest.update(b_hash);digest.update(reward.to_bits().to_le_bytes());
    Ok(AcceptedSample{family:candidate.family,group:candidate.group,input,reward:Reward{candidate:cp,baseline:bp,candidate_cpu:cc,baseline_cpu:bc,raw_cost:raw,clipped_cost:cost,delta_throughput:dx,delta_latency:dl,value:reward},evidence:digest.finalize().into(),reward_schema:candidate.reward_schema,learning_config:candidate.learning_config})
}

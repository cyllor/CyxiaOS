//! Evidence-bound local learning data. Internal EL1 custody only.
//! A trace verifier must authenticate both replay branches, all executed work,
//! renewals/restoration and the complete CPU intervals. Neither an APPLIED
//! wire field nor a model's estimate is evidence by itself.
use super::{Error,Identity,action_schema_v2::ActionV2,
    apply_report_v1::{ActionStatus,ApplyReportV1},
    candidate_registry_v0199::FrozenCandidates,decision_record_v3::DecisionRecordV3,
    feedback_v0199::FeedbackRecord};
use cyxia_control_model::{native_v0199::{Candidate,operations_features,integer_model::{Model,MODEL_BYTES}},
    reward_v2::{self,Trace,Reward,Workspace,softfloat::F64},sgd_v2::{self,LastLayer}};
use sha2::{Digest,Sha256};

pub const MAX_SAMPLES:usize=1024;
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct ReplayGroup{pub seed:u64,pub workload:[u8;32],pub initial_image:[u8;32]}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct SchemaBinding{pub feature:[u8;32],pub action:[u8;32],pub reward:[u8;32],pub learning:[u8;32]}
impl SchemaBinding{
    fn valid(self)->bool{[self.feature,self.action,self.reward,self.learning].iter().all(|h|*h!=[0;32])}
}
#[derive(Clone,Copy)]
pub struct Sample{
    group:ReplayGroup,schemas:SchemaBinding,domain:u16,input:[i16;64],
    reward:Reward,candidate_receipt:[u8;32],baseline_receipt:[u8;32],pair:[u8;32],
}
impl Sample{
    pub fn capture(group:ReplayGroup,schemas:SchemaBinding,candidates:&FrozenCandidates,
        feedback:&FeedbackRecord,baseline:&FeedbackRecord,actual:Trace<'_>,reference:Trace<'_>,
        cpu:[Option<u64>;4],workspace:&mut Workspace,
        verify_archived_pair:impl FnOnce(&ReplayGroup,&SchemaBinding,&FrozenCandidates,
            &FeedbackRecord,&FeedbackRecord,&Trace<'_>,&Trace<'_>,[Option<u64>;4])->Result<[u8;32],Error>)
        ->Result<Self,Error>{
        if !schemas.valid()||group.workload==[0;32]||group.initial_image==[0;32]{return Err(Error::Invalid);}
        let (decision,report)=checked_feedback(feedback)?;
        let (base,base_report)=checked_feedback(baseline)?;
        let snap=candidates.snapshot();
        if decision.boot_epoch!=snap.boot_epoch||decision.snapshot_seq!=snap.snapshot_seq
            ||decision.target_id!=snap.target_id||decision.target_generation!=snap.target_generation
            ||decision.ledger_generation!=snap.ledger_generation||decision.core_generation!=snap.core_generation
            ||decision.domain_id!=snap.domain||decision.candidate_set_hash!=candidates.digest()
            ||base.domain_id!=decision.domain_id||base.rules_hash!=decision.rules_hash
            ||actual.domain!=snap.domain||reference.domain!=snap.domain
            ||report.completed_ns<actual.first_ns||report.completed_ns>actual.closing_ns
            ||base_report.completed_ns<reference.first_ns||base_report.completed_ns>reference.closing_ns{
            return Err(Error::Denied);
        }
        let view=candidates.view();
        let selected=view.selected(decision.selected_index)?;
        if selected.action_payload!=report.action{return Err(Error::Denied);}
        let action=ActionV2::decode(snap.domain,1,report.action)?;
        ActionV2::decode(snap.domain,1,base_report.action)?;
        let mut bytes=[0;6];let n=action.encode(snap.domain,&mut bytes)?;
        // Current ActionSchema v2 canonical payload lengths, not historical features.
        let (a1,a2)=match snap.domain{
            3=>(u32::from_le_bytes(bytes[..4].try_into().map_err(|_|Error::Invalid)?) as u64,
                Some(u16::from_le_bytes([bytes[4],bytes[5]]) as u64)),
            4=>(u16::from_le_bytes([bytes[0],bytes[1]]) as u64,
                Some(u16::from_le_bytes([bytes[2],bytes[3]]) as u64)),
            5=>(u16::from_le_bytes([bytes[0],bytes[1]]) as u64,Some(bytes[2] as u64)),
            _ if n==1=>(bytes[0] as u64,None),
            _ if n==2=>(u16::from_le_bytes([bytes[0],bytes[1]]) as u64,None),
            _=>return Err(Error::Invalid),
        };
        let input=operations_features(&snap,Candidate{a1,a2,cpu}).map_err(|_|Error::Invalid)?.values;
        let candidate_receipt=feedback.evidence_digest();let baseline_receipt=baseline.evidence_digest();
        if candidate_receipt==baseline_receipt{return Err(Error::Denied);}
        let pair=verify_archived_pair(&group,&schemas,candidates,feedback,baseline,&actual,&reference,cpu)?;
        if pair==[0;32]{return Err(Error::Denied);}
        let reward=reward_v2::compute(actual,reference,workspace).map_err(|_|Error::Denied)?;
        Ok(Self{group,schemas,domain:snap.domain,input,reward,candidate_receipt,baseline_receipt,pair})
    }
    pub fn reward(&self)->Reward{self.reward}
}
fn checked_feedback(f:&FeedbackRecord)->Result<(DecisionRecordV3,ApplyReportV1<'_>),Error>{
    if usize::from(f.report_len)>super::apply_report_v1::MAX_APPLY_REPORT_BYTES{return Err(Error::Invalid);}
    let d=DecisionRecordV3::decode(&f.decision)?;
    let r=ApplyReportV1::decode(f.report_bytes())?;
    if r.state!=ActionStatus::Applied||r.key.boot_epoch!=d.boot_epoch||r.key.controller_epoch!=d.controller_epoch
        ||r.key.plan_seq!=d.plan_seq||r.action_index!=d.action_index||r.domain_id!=d.domain_id
        ||r.target!=(Identity{id:d.target_id,generation:d.target_generation}){return Err(Error::Denied);}
    Ok((d,r))
}
fn split_ok(samples:&[Sample],schemas:SchemaBinding,minimum:usize)->Result<(),Error>{
    if !schemas.valid()||samples.len()>MAX_SAMPLES{return Err(Error::Invalid);}
    let mut count=[0usize;15];
    for (i,s) in samples.iter().enumerate(){
        if s.schemas!=schemas||!(1..=15).contains(&s.domain)||s.pair==[0;32]
            ||samples[..i].iter().any(|p|duplicates(p,s)){return Err(Error::Denied);}
        count[usize::from(s.domain-1)]+=1;
    }
    if count.iter().any(|n|*n<minimum){return Err(Error::NotReady);}
    Ok(())
}
fn duplicates(a:&Sample,b:&Sample)->bool{
    a.pair==b.pair||[a.candidate_receipt,a.baseline_receipt].iter()
        .any(|h|*h==b.candidate_receipt||*h==b.baseline_receipt)
}
fn digest(samples:&[Sample],schemas:SchemaBinding)->[u8;32]{
    let mut h=Sha256::new();h.update(b"CYX/LEARNING-DATA/v0199");
    for v in [schemas.feature,schemas.action,schemas.reward,schemas.learning]{h.update(v);}
    h.update((samples.len() as u32).to_le_bytes());
    for s in samples{
        h.update(s.group.seed.to_le_bytes());h.update(s.group.workload);h.update(s.group.initial_image);
        h.update(s.domain.to_le_bytes());for x in s.input{h.update(x.to_le_bytes());}
        h.update(s.reward.value.to_bits().to_le_bytes());h.update(s.pair);
        h.update(s.candidate_receipt);h.update(s.baseline_receipt);
    }
    h.finalize().into()
}
pub struct TrainingData<'a>{rows:&'a[Sample],schemas:SchemaBinding,hash:[u8;32]}
impl<'a> TrainingData<'a>{
    pub fn freeze(rows:&'a[Sample],schemas:SchemaBinding)->Result<Self,Error>{
        split_ok(rows,schemas,8)?;Ok(Self{rows,schemas,hash:digest(rows,schemas)})
    }
}
pub struct Trainer<'a>{data:TrainingData<'a>,layer:LastLayer<'a>,parent:[u8;32],learner:Identity}
pub struct CandidateModel{bytes:[u8;MODEL_BYTES],parent:[u8;32],data:[u8;32],schemas:SchemaBinding}
impl CandidateModel{pub fn bytes(&self)->&[u8;MODEL_BYTES]{&self.bytes}}
impl<'a> Trainer<'a>{
    pub fn start(data:TrainingData<'a>,active:&'a[u8;MODEL_BYTES],learner:Identity,
        verify_active:impl FnOnce(Identity,&[u8;MODEL_BYTES],SchemaBinding)->Result<(),Error>)->Result<Self,Error>{
        if !learner.valid(){return Err(Error::Denied);}
        verify_active(learner,active,data.schemas)?;
        let layer=LastLayer::start(active,data.rows.len()).map_err(|_|Error::Invalid)?;
        Ok(Self{data,layer,parent:Sha256::digest(active).into(),learner})
    }
    /// Exactly one ordered arithmetic step. The native owner must charge
    /// actual elapsed CPU including the invocation, never just the grant.
    pub fn step(&mut self,actor:Identity,verify_credit:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if actor!=self.learner{return Err(Error::Denied);}
        let s=self.data.rows.get(self.layer.completed()).ok_or(Error::Stale)?;
        verify_credit()?;
        self.layer.step(&s.input,s.reward.value).map_err(|_|Error::Invalid)
    }
    pub fn finish(self)->Result<CandidateModel,Error>{
        Ok(CandidateModel{bytes:self.layer.finish().map_err(|_|Error::NotReady)?,
            parent:self.parent,data:self.data.hash,schemas:self.data.schemas})
    }
}
/// Bounded consumed experiment groups. A failed validation consumes its
/// holdout as well, so repeating until a model happens to pass is rejected.
/// This volatile ledger must be restored by a trusted durable owner before
/// production use across restart.
pub struct Holdouts{used:[Option<ReplayGroup>;MAX_SAMPLES],len:usize}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct ValidationEvidence{pub candidate:[u8;32],pub parent:[u8;32],pub training:[u8;32],pub holdout:[u8;32]}
impl Holdouts{
    pub const fn new()->Self{Self{used:[None;MAX_SAMPLES],len:0}}
    pub fn validate(&mut self,validator:Identity,active:&[u8;MODEL_BYTES],model:&CandidateModel,
        training:&TrainingData<'_>,holdout:&[Sample],
        verify_native:impl FnOnce(Identity,&[u8;MODEL_BYTES],&CandidateModel,&[Sample])->Result<(),Error>)
        ->Result<ValidationEvidence,Error>{
        if !validator.valid()||model.schemas!=training.schemas||model.data!=training.hash
            ||model.parent!=<[u8;32]>::from(Sha256::digest(active))
            ||!sgd_v2::frozen_equal(active,&model.bytes){return Err(Error::Denied);}
        split_ok(holdout,training.schemas,4)?;
        let mut n=0;
        for (i,s) in holdout.iter().enumerate(){
            if training.rows.iter().any(|t|t.group==s.group||duplicates(t,s))
                ||self.used[..self.len].contains(&Some(s.group)){return Err(Error::Denied);}
            if !holdout[..i].iter().any(|t|t.group==s.group){n+=1;}
        }
        if n>MAX_SAMPLES-self.len{return Err(Error::Exhausted);}
        for (i,s) in holdout.iter().enumerate(){
            if !holdout[..i].iter().any(|t|t.group==s.group){
                self.used[self.len]=Some(s.group);self.len+=1;
            }
        }
        verify_native(validator,active,model,holdout)?;
        sgd_v2::operator_selftest().map_err(|_|Error::Denied)?;
        let old=Model::parse(active).map_err(|_|Error::Invalid)?;
        let new=Model::parse(&model.bytes).map_err(|_|Error::Invalid)?;
        let mut totals=[[F64::ZERO;16];2];let mut counts=[0u64;16];
        for s in holdout{
            let i=usize::from(s.domain-1);counts[i]+=1;counts[15]+=1;
            for (k,score) in [old.score(&s.input),new.score(&s.input)].into_iter().enumerate(){
                let prediction=F64::from_i64(i64::from(score)).div(F64::from_u64(256)).map_err(|_|Error::Invalid)?;
                let e=prediction.sub(s.reward.value).map_err(|_|Error::Invalid)?;
                let square=e.mul(e).map_err(|_|Error::Invalid)?;
                totals[k][i]=totals[k][i].add(square).map_err(|_|Error::Invalid)?;
                totals[k][15]=totals[k][15].add(square).map_err(|_|Error::Invalid)?;
            }
        }
        let tolerance=F64::ONE.div(F64::from_u64(65536)).map_err(|_|Error::Invalid)?;
        for i in 0..16{
            let divisor=F64::from_u64(counts[i]);
            let a=totals[0][i].div(divisor).map_err(|_|Error::Invalid)?;
            let b=totals[1][i].div(divisor).map_err(|_|Error::Invalid)?;
            let bound=if i==15{a}else{a.add(tolerance).map_err(|_|Error::Invalid)?};
            if b.compare(bound).is_gt(){return Err(Error::Denied);}
        }
        Ok(ValidationEvidence{candidate:Sha256::digest(model.bytes).into(),parent:model.parent,
            training:model.data,holdout:digest(holdout,training.schemas)})
    }
}
impl Default for Holdouts{fn default()->Self{Self::new()}}

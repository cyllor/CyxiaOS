//! Protected post-execution feedback custody, V0.19.9 §6.2.
//! This is an internal EL1 interface, not an invented syscall or wire ABI.
//! Only the registered gate may create a VerifiedFeedbackBatch, AFTER
//! all native effect proofs succeed. Reward/trial verification is separate.
use super::{Error,Identity,advice_envelope_v1::ADVICE_BYTES,
    advice_disposition_v1::{AdviceDispositionV1,DISPOSITION_BYTES},
    decision_record_v3::{DecisionRecordV3,DecisionSource,DECISION_BYTES},
    apply_report_v1::{ActionStatus,ApplyReportV1,BoundReport,MAX_APPLY_REPORT_BYTES},
    plan_wire_v2::{PlanV2,MAX_ACTIONS}};
use sha2::{Digest,Sha256};
pub const FEEDBACK_SLOTS:usize=64;
fn digest(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum CausalLabel{NoAdoption,AdoptedSameFallback,AdoptedDifferentFallback}
#[derive(Clone,Copy)]
pub struct CausalPair<'a>{
    pub advice:&'a[u8;ADVICE_BYTES],pub disposition:&'a[u8;DISPOSITION_BYTES],
}
/// Exact data retained for subsequent independent replay/reward verification.
/// No scalar reward or training eligibility can be derived from this alone.
#[derive(Clone,Copy)]
pub struct FeedbackRecord{
    pub decision:[u8;DECISION_BYTES],
    pub report:[u8;MAX_APPLY_REPORT_BYTES],
    pub report_len:u16,
    pub causal_label:CausalLabel,
    pub advice:Option<([u8;ADVICE_BYTES],[u8;DISPOSITION_BYTES])>,
}
impl FeedbackRecord{
    pub fn report_bytes(&self)->&[u8]{&self.report[..usize::from(self.report_len)]}
    pub fn evidence_digest(&self)->[u8;32]{
        let mut h=Sha256::new();h.update(b"CYX/EXECUTION-FEEDBACK/v0199");
        h.update(self.decision);h.update(self.report_len.to_le_bytes());h.update(self.report_bytes());
        h.update([match self.causal_label{CausalLabel::NoAdoption=>0,CausalLabel::AdoptedSameFallback=>1,CausalLabel::AdoptedDifferentFallback=>2}]);
        if let Some((a,d))=&self.advice{h.update([1]);h.update(a);h.update(d);}else{h.update([0]);}
        h.finalize().into()
    }
}
/// Borrowed protected native evidence. A caller cannot construct this with
/// arbitrary EL0 bytes; construction is restricted to the control-plane
/// implementation and must follow the registered gate's native proof checks.
pub struct VerifiedFeedbackBatch<'a>{
    pub(super) plan_wire:&'a[u8],
    pub(super) decisions:&'a[[u8;DECISION_BYTES]],
    pub(super) reports:&'a[BoundReport<'a>],
    pub(super) causal:Option<CausalPair<'a>>,
}
impl VerifiedFeedbackBatch<'_>{
    pub fn plan_wire(&self)->&[u8]{self.plan_wire}
    pub fn count(&self)->usize{self.decisions.len()}
    fn record(&self,index:usize)->Result<FeedbackRecord,Error>{
        let p=PlanV2::decode(self.plan_wire)?;
        p.matches_untrusted_sidecars(self.decisions)?;
        let raw=*self.decisions.get(index).ok_or(Error::Invalid)?;
        let decision=DecisionRecordV3::decode(&raw)?;
        if decision.plan_digest!=digest(self.plan_wire){return Err(Error::Denied);}
        let report_wire=self.reports.iter().find_map(|r|{
            let parsed=ApplyReportV1::decode(r.bytes).ok()?;
            (usize::from(parsed.action_index)==index).then_some(r.bytes)
        }).ok_or(Error::Denied)?;
        let report=ApplyReportV1::decode(report_wire)?;
        if report.key.boot_epoch!=decision.boot_epoch||report.key.controller_epoch!=decision.controller_epoch
            ||report.key.plan_seq!=decision.plan_seq||report.domain_id!=decision.domain_id
            ||report.target.id!=decision.target_id||report.target.generation!=decision.target_generation
            ||report.state==ActionStatus::Unknown||report.action!=p.action(index)?.action_payload{
            return Err(Error::Denied);
        }
        let needs_pair=decision.source==DecisionSource::AiAssisted||decision.reason_code==7;
        let advice=if needs_pair{
            let pair=self.causal.ok_or(Error::NotReady)?;
            let disposition=AdviceDispositionV1::decode(pair.disposition)?;
            disposition.matches_decision_pair(decision.boot_epoch,pair.advice,&raw)?;
            Some((*pair.advice,*pair.disposition))
        }else{
            if self.causal.is_some(){return Err(Error::Denied);}None
        };
        let causal_label=if report.state==ActionStatus::Applied&&decision.source==DecisionSource::AiAssisted{
            if decision.selected_index==decision.fallback_index{CausalLabel::AdoptedSameFallback}
            else{CausalLabel::AdoptedDifferentFallback}
        }else{CausalLabel::NoAdoption};
        let mut bytes=[0;MAX_APPLY_REPORT_BYTES];bytes[..report_wire.len()].copy_from_slice(report_wire);
        Ok(FeedbackRecord{decision:raw,report:bytes,report_len:report_wire.len() as u16,causal_label,advice})
    }
}
/// Bounded protected inbox. Allocate this from the control pool, not an EL0
/// writable mailbox. Only the authenticated learner may read. Supervisor
/// retires exact retained bytes only after external durable/evidence custody.
/// Backpressure cannot convert UNKNOWN or rejected recommendations to labels.
pub struct FeedbackInbox{
    supervisor:Identity,learner:Identity,
    rows:[Option<FeedbackRecord>;FEEDBACK_SLOTS],
}
impl FeedbackInbox{
    pub const fn new(supervisor:Identity,learner:Identity)->Result<Self,Error>{
        if !supervisor.valid()||!learner.valid()||supervisor.id==learner.id{return Err(Error::Invalid);}
        Ok(Self{supervisor,learner,rows:[None;FEEDBACK_SLOTS]})
    }
    pub fn retain(&mut self,actor:Identity,batch:&VerifiedFeedbackBatch<'_>)->Result<(),Error>{
        if actor!=self.supervisor{return Err(Error::Denied);}
        if batch.count()==0||batch.count()>MAX_ACTIONS{return Err(Error::Invalid);}
        // Complete preflight before installing any record. Retrying the
        // exact same batch is harmless; a conflicting decision is denied.
        let mut needed=0usize;
        let mut missing=0u16;
        for i in 0..batch.count(){
            let r=batch.record(i)?;
            let d=DecisionRecordV3::decode(&r.decision)?;
            if let Some(old)=self.rows.iter().flatten().find(|old|{
                DecisionRecordV3::decode(&old.decision).is_ok_and(|v|
                    (v.boot_epoch,v.controller_epoch,v.decision_seq)==(d.boot_epoch,d.controller_epoch,d.decision_seq))
            }){
                if old.evidence_digest()!=r.evidence_digest(){return Err(Error::Denied);}
            }else{needed+=1;missing|=1u16<<i;}
        }
        if needed>self.rows.iter().filter(|r|r.is_none()).count(){return Err(Error::Exhausted);}
        // Repeat the deterministic decode of immutable verified input, rather
        // than allocating an entire 16-record (~16KiB) EL1 stack staging array.
        // No new fallible external work occurs after preflight.
        for i in 0..batch.count(){
            if missing&(1u16<<i)!=0{
                let r=batch.record(i).expect("immutable feedback preflight");
                *self.rows.iter_mut().find(|v|v.is_none()).unwrap()=Some(r);
            }
        }
        Ok(())
    }
    pub fn read(&self,actor:Identity,index:usize)->Result<Option<&FeedbackRecord>,Error>{
        if actor!=self.learner{return Err(Error::Denied);}
        Ok(self.rows.get(index).ok_or(Error::Invalid)?.as_ref())
    }
    pub fn retire(&mut self,actor:Identity,index:usize,expected:[u8;32],
        verify_custody:impl FnOnce(&FeedbackRecord)->Result<(),Error>)->Result<(),Error>{
        if actor!=self.supervisor{return Err(Error::Denied);}
        let slot=self.rows.get_mut(index).ok_or(Error::Invalid)?;
        let row=slot.as_ref().ok_or(Error::Stale)?;
        if row.evidence_digest()!=expected{return Err(Error::Denied);}
        verify_custody(row)?;
        *slot=None;Ok(())
    }
    pub fn len(&self)->usize{self.rows.iter().flatten().count()}
}
const _:()=assert!(core::mem::size_of::<FeedbackInbox>()<=96*1024);

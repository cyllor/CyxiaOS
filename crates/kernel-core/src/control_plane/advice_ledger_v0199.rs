//! V0.19.9 bounded Advice -> AdviceDisposition causal evidence ledger.
//!
//! The operations brain cannot register a Decision or mark APPLIED. The
//! deterministic controller alone freezes one terminal Disposition per
//! authenticated AdviceKey, and the supervisor must consume evidence before
//! credit is recycled. This is a no_std G1 component, not the native SVC.
use sha2::{Digest,Sha256};
use super::{
    Error,Identity,
    advice_envelope_v1::{AdviceEnvelopeV1,TrustedAdviceScope,ADVICE_BYTES},
    advice_disposition_v1::{AdviceDispositionV1,DISPOSITION_BYTES},
    decision_record_v3::DECISION_BYTES,
};
pub const ADVICE_SLOTS:usize=64;
pub const SLOT_LIMIT_BYTES:usize=512;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct AdviceKey{pub boot_epoch:u64,pub advisor_epoch:u64,pub advice_seq:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum AdviceResult{Recorded,ExactRetry,Finalized}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct AdviceEvidence{
    pub key:AdviceKey,
    pub advice_hash:[u8;32],
    pub disposition_hash:[u8;32],
    pub state:u16,
}
#[derive(Clone,Copy)]
struct Slot{
    key:AdviceKey,
    advice_wire:[u8;ADVICE_BYTES],
    disposition_wire:[u8;DISPOSITION_BYTES],
    advice_hash:[u8;32],
    disposition_hash:[u8;32],
    has_terminal:bool,
    received_ns:u64,
    controller_epoch:u64,
}
const _:()=assert!(core::mem::size_of::<Option<Slot>>()<=SLOT_LIMIT_BYTES);
fn digest(x:&[u8])->[u8;32]{let mut d=Sha256::new();d.update(x);d.finalize().into()}
pub struct EvidenceLedger{
    operations:Identity,
    controller:Identity,
    supervisor:Identity,
    boot_epoch:u64,
    advisor_epoch:u64,
    hi:u64,
    last_ns:u64,
    rows:[Option<Slot>;ADVICE_SLOTS],
}
impl EvidenceLedger{
    pub fn new(
        operations:Identity,controller:Identity,supervisor:Identity,
        boot_epoch:u64,advisor_epoch:u64
    )->Result<Self,Error>{
        if !operations.valid() || !controller.valid() || !supervisor.valid()
            || operations.id==controller.id || operations.id==supervisor.id
            || controller.id==supervisor.id
            || boot_epoch==0 || advisor_epoch==0
        {return Err(Error::Invalid);}
        Ok(Self{
            operations,controller,supervisor,boot_epoch,advisor_epoch,hi:0,last_ns:0,
            rows:[None;ADVICE_SLOTS]
        })
    }
    pub fn record(
        &mut self,actor:Identity,wire:&[u8],
        trusted:&TrustedAdviceScope<'_>
    )->Result<AdviceResult,Error>{
        if actor!=self.operations {return Err(Error::Denied);}
        let packet=AdviceEnvelopeV1::decode(wire)?;
        if trusted.epochs.boot!=self.boot_epoch
            || packet.advisor_epoch!=self.advisor_epoch
        {return Err(Error::Stale);}
        if trusted.now_ns<self.last_ns{return Err(Error::Clock);}
        self.last_ns=trusted.now_ns;
        let key=AdviceKey{
            boot_epoch:self.boot_epoch,
            advisor_epoch:packet.advisor_epoch,
            advice_seq:packet.advice_seq,
        };
        let hash=digest(wire);
        if let Some(row)=self.rows.iter().flatten().find(|v|v.key==key){
            return if row.advice_hash==hash{
                Ok(if row.has_terminal {AdviceResult::Finalized}
                else {AdviceResult::ExactRetry})
            }else{Err(Error::Denied)};
        }
        if key.advice_seq<=self.hi {return Err(Error::Stale);}
        // A retained key is query-only, including after expiry. Only new
        // admissions require the current model/snapshot/candidate authority.
        packet.into_advice(trusted)?;
        let at=self.rows.iter().position(Option::is_none)
            .ok_or(Error::Exhausted)?;
        let mut copy=[0u8;ADVICE_BYTES];copy.copy_from_slice(wire);
        self.rows[at]=Some(Slot{
            key,advice_wire:copy,advice_hash:hash,
            disposition_wire:[0;DISPOSITION_BYTES],
            disposition_hash:[0;32],has_terminal:false,
            received_ns:trusted.now_ns,controller_epoch:trusted.epochs.controller,
        });
        self.hi=key.advice_seq;
        self.last_ns=trusted.now_ns;
        Ok(AdviceResult::Recorded)
    }
    /// Controller-side read of the exact admitted AdviceKey. It is not
    /// a capability or a new inference. The decision gate independently
    /// checks the current authority and commits the disposition only after
    /// all registration checks pass.
    pub(super) fn admitted_wire(&self,actor:Identity,key:AdviceKey)->Result<[u8;ADVICE_BYTES],Error>{
        if actor!=self.controller{return Err(Error::Denied);}
        self.rows.iter().flatten().find(|row|row.key==key && !row.has_terminal)
            .map(|row|row.advice_wire).ok_or(Error::Stale)
    }
    /// CONTROL_AUX observation/expiry path: states 3..6 only. A matching
    /// DecisionRecord digest is not evidence of a registered decision.
    pub fn finalize(
        &mut self,actor:Identity,disposition:&[u8],decision:Option<&[u8]>,now_ns:u64,
    )->Result<AdviceResult,Error>{
        if actor!=self.controller && actor!=self.supervisor{return Err(Error::Denied);}
        let disp=AdviceDispositionV1::decode(disposition)?;
        if matches!(disp.state,1|2)||decision.is_some(){return Err(Error::Denied);}
        self.finalize_inner(actor,disposition,None,now_ns)
    }
    /// Called by the protected decision registration gate ONLY after all
    /// independent rule, model, candidate, identity and sequence checks.
    /// State 2 stays closed until an atomic reason7 fallback gate exists.
    pub(super) fn finalize_registered_adoption(
        &mut self,actor:Identity,disposition:&[u8],decision:&[u8;DECISION_BYTES],now_ns:u64,
    )->Result<AdviceResult,Error>{
        if actor!=self.controller{return Err(Error::Denied);}
        if AdviceDispositionV1::decode(disposition)?.state!=1{return Err(Error::NotReady);}
        self.finalize_inner(actor,disposition,Some(decision),now_ns)
    }
    fn finalize_inner(
        &mut self,actor:Identity,disposition:&[u8],decision:Option<&[u8]>,
        // Trusted monotonic timestamp supplied by the serialized EL1 owner.
        now_ns:u64,
    )->Result<AdviceResult,Error>{
        if actor!=self.controller && actor!=self.supervisor{return Err(Error::Denied);}
        let disp=AdviceDispositionV1::decode(disposition)?;
        if actor==self.supervisor && disp.state!=4{return Err(Error::Denied);}
        if now_ns<self.last_ns{return Err(Error::Clock);}
        let key=AdviceKey{
            boot_epoch:disp.boot_epoch,
            advisor_epoch:disp.advisor_epoch,
            advice_seq:disp.advice_seq,
        };
        let row=self.rows.iter_mut().flatten().find(|v|v.key==key)
            .ok_or(Error::Stale)?;
        let digest_new=digest(disposition);
        if row.has_terminal {
            return if row.disposition_hash==digest_new{
                Ok(AdviceResult::Finalized)
            }else{Err(Error::Denied)};
        }
        if disp.advice_digest!=row.advice_hash
            || disp.boot_epoch!=self.boot_epoch
            || disp.advisor_epoch!=self.advisor_epoch
        {return Err(Error::Denied);}
        disp.matches_advice(self.boot_epoch, &row.advice_wire)?;
        let advice=AdviceEnvelopeV1::decode(&row.advice_wire)?;
        if disp.processed_ns!=now_ns || now_ns<row.received_ns{
            return Err(Error::Clock);
        }
        if actor==self.supervisor && now_ns<advice.expires_ns{return Err(Error::Denied);}
        // Expiry has precedence over observation/adoption. The only causal
        // fallback after expiry is reason 4, with its own current decision.
        if now_ns>=advice.expires_ns && !(disp.state==4 || (disp.state==2 && disp.reason_code==4)){
            return Err(Error::Expired);
        }
        if matches!(disp.state,1|2){
            if disp.controller_epoch!=row.controller_epoch{return Err(Error::Denied);}
            let d=decision.ok_or(Error::NotReady)?;
            if d.len()!=DECISION_BYTES{return Err(Error::Invalid);}
            disp.matches_decision_pair(self.boot_epoch,&row.advice_wire,d)?;
        }else{
            if decision.is_some(){return Err(Error::Denied);}
            // No-decision states are observation only and must never turn a
            // rejected recommendation into a phantom APPLIED success.
        }
        row.disposition_wire.copy_from_slice(disposition);
        row.disposition_hash=digest_new;
        row.has_terminal=true;
        self.last_ns=now_ns;
        Ok(AdviceResult::Finalized)
    }
    pub fn consume(
        &mut self,actor:Identity,key:AdviceKey
    )->Result<AdviceEvidence,Error>{
        if actor!=self.supervisor{return Err(Error::Denied);}
        let at=self.rows.iter().position(|row|row.is_some_and(|v|v.key==key))
            .ok_or(Error::Stale)?;
        let row=self.rows[at].ok_or(Error::Stale)?;
        if !row.has_terminal {return Err(Error::NotReady);}
        let state=AdviceDispositionV1::decode(&row.disposition_wire)?.state;
        let evidence=AdviceEvidence{
            key,advice_hash:row.advice_hash,
            disposition_hash:row.disposition_hash,state,
        };
        self.rows[at]=None; // key high-water stays burned
        Ok(evidence)
    }
    pub fn pending(&self)->usize{self.rows.iter().flatten().count()}
}
#[cfg(test)]
mod tests {
    use super::*;
    const OPERATIONS:Identity=Identity{id:6,generation:1};
    const CONTROLLER:Identity=Identity{id:2,generation:1};
    const SUPERVISOR:Identity=Identity{id:11,generation:1};
    fn advice()->[u8;ADVICE_BYTES]{
        let mut a=[0u8;ADVICE_BYTES];
        a[0..4].copy_from_slice(&0x4359_4131u32.to_le_bytes());
        a[4..6].copy_from_slice(&1u16.to_le_bytes());
        a[6..8].copy_from_slice(&152u16.to_le_bytes());
        for (i,v) in [(8,1u64),(16,1),(24,4),(32,17),(40,5),
            (48,2),(56,3),(64,200),(72,6)]{
            a[i..i+8].copy_from_slice(&v.to_le_bytes());
        }
        a[80..82].copy_from_slice(&1u16.to_le_bytes());
        a[82..84].copy_from_slice(&1u16.to_le_bytes());
        a[86..88].copy_from_slice(&2u16.to_le_bytes());
        a[88..120].copy_from_slice(&[3u8;32]);
        a[120..152].copy_from_slice(&[4u8;32]);
        a
    }
    fn trusted()->TrustedAdviceScope<'static>{
        TrustedAdviceScope{
            epochs:super::super::Epochs{
                boot:1,controller:2,model:6,resources:2,cores:3
            },
            advisor_epoch:1,snapshot_seq:4,domain:1,
            target:Identity{id:17,generation:5},
            sampled_ns:100,now_ns:150,action_kind:1,
            candidates:&[2,4],
            model_hash:[3;32],candidate_set_hash:[4;32],
        }
    }
    fn shadow_disposition(a:&[u8])->[u8;DISPOSITION_BYTES]{
        let mut b=[0u8;DISPOSITION_BYTES];
        b[0..4].copy_from_slice(&0x4359_4144u32.to_le_bytes());
        b[4..6].copy_from_slice(&1u16.to_le_bytes());
        b[6..8].copy_from_slice(&240u16.to_le_bytes());
        for (i,v) in [(8,1u64),(16,1),(24,1),(32,4),(56,17),
            (64,5),(72,6),(80,150)]{
            b[i..i+8].copy_from_slice(&v.to_le_bytes());
        }
        b[88..90].copy_from_slice(&1u16.to_le_bytes());
        b[90..92].copy_from_slice(&1u16.to_le_bytes());
        b[92..94].copy_from_slice(&5u16.to_le_bytes());
        b[94..96].copy_from_slice(&6u16.to_le_bytes());
        b[100..102].copy_from_slice(&u16::MAX.to_le_bytes());
        b[104..106].copy_from_slice(&u16::MAX.to_le_bytes());
        b[106..108].copy_from_slice(&u16::MAX.to_le_bytes());
        b[112..144].copy_from_slice(&[4u8;32]);
        b[144..176].copy_from_slice(&digest(a));
        b
    }
    #[test]
    fn observation_cannot_relabel_original_advice_scope() {
        let mut ledger=EvidenceLedger::new(OPERATIONS,CONTROLLER,SUPERVISOR,1,1).unwrap();
        let frame=advice();
        ledger.record(OPERATIONS,&frame,&trusted()).unwrap();
        let disp=shadow_disposition(&frame);
        for at in [56usize,64,72,88,102,112] {
            let mut bad=disp;
            // Change to another structurally valid target/domain/ordinal/hash
            // while retaining the exact recorded advice digest.
            bad[at]=if at==102 {1} else {bad[at].wrapping_add(1)};
            assert!(AdviceDispositionV1::decode(&bad).is_ok(),"offset {at}");
            assert_eq!(ledger.finalize(CONTROLLER,&bad,None,150),Err(Error::Denied),"offset {at}");
        }
        assert_eq!(ledger.finalize(CONTROLLER,&disp,None,150),Ok(AdviceResult::Finalized));
    }
    #[test]
    fn bounded_advice_slot_is_never_a_capability_or_replayable_after_ack(){
        let mut ledger=EvidenceLedger::new(OPERATIONS,CONTROLLER,SUPERVISOR,1,1).unwrap();
        let frame=advice();
        assert_eq!(ledger.record(CONTROLLER,&frame,&trusted()),Err(Error::Denied));
        assert_eq!(ledger.record(OPERATIONS,&frame,&trusted()),Ok(AdviceResult::Recorded));
        assert_eq!(ledger.record(OPERATIONS,&frame,&trusted()),Ok(AdviceResult::ExactRetry));
        let mut forged=frame;forged[80]=2;
        assert_eq!(ledger.record(OPERATIONS,&forged,&trusted()),Err(Error::Denied));
        assert_eq!(ledger.pending(),1);
        let disp=shadow_disposition(&frame);
        assert_eq!(ledger.finalize(OPERATIONS,&disp,None,150),Err(Error::Denied));
        assert_eq!(ledger.consume(SUPERVISOR,AdviceKey{
            boot_epoch:1,advisor_epoch:1,advice_seq:1
        }),Err(Error::NotReady));
        assert_eq!(ledger.finalize(CONTROLLER,&disp,None,150),Ok(AdviceResult::Finalized));
        assert_eq!(ledger.finalize(CONTROLLER,&disp,None,150),Ok(AdviceResult::Finalized));
        assert_eq!(ledger.consume(OPERATIONS,AdviceKey{
            boot_epoch:1,advisor_epoch:1,advice_seq:1
        }),Err(Error::Denied));
        let evidence=ledger.consume(SUPERVISOR,AdviceKey{
            boot_epoch:1,advisor_epoch:1,advice_seq:1
        }).unwrap();
        assert_eq!(evidence.state,5);
        assert_eq!(ledger.pending(),0);
        assert_eq!(ledger.record(OPERATIONS,&frame,&trusted()),Err(Error::Stale));
    }
    #[test]
    fn exact_advice_retry_does_not_reauthorize_and_supervisor_only_expires(){
        let mut ledger=EvidenceLedger::new(OPERATIONS,CONTROLLER,SUPERVISOR,1,1).unwrap();
        let frame=advice();
        ledger.record(OPERATIONS,&frame,&trusted()).unwrap();
        let mut later=trusted();later.now_ns=200;
        assert_eq!(ledger.record(OPERATIONS,&frame,&later),Ok(AdviceResult::ExactRetry));
        let mut disp=shadow_disposition(&frame);
        assert_eq!(ledger.finalize(CONTROLLER,&disp,None,199),Err(Error::Clock));
        disp[80..88].copy_from_slice(&200u64.to_le_bytes());
        assert_eq!(ledger.finalize(CONTROLLER,&disp,None,200),Err(Error::Expired));
        assert_eq!(ledger.finalize(SUPERVISOR,&disp,None,200),Err(Error::Denied));
        disp[92..94].copy_from_slice(&4u16.to_le_bytes());
        disp[94..96].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(ledger.finalize(SUPERVISOR,&disp,None,200),Ok(AdviceResult::Finalized));
        later.now_ns=201;
        assert_eq!(ledger.record(OPERATIONS,&frame,&later),Ok(AdviceResult::Finalized));
        assert_eq!(ledger.finalize(SUPERVISOR,&disp,None,201),Ok(AdviceResult::Finalized));
        assert_eq!(ledger.consume(SUPERVISOR,AdviceKey{boot_epoch:1,advisor_epoch:1,advice_seq:1}).unwrap().state,4);
        assert_eq!(ledger.record(OPERATIONS,&frame,&later),Err(Error::Stale));
        assert!(EvidenceLedger::new(OPERATIONS,Identity{id:OPERATIONS.id,generation:2},SUPERVISOR,1,1).is_err());
    }

}

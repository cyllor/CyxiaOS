//! V0.19.9 ApplyReport v1: exact executor-origin and action-value binding.
//!
//! 0x43 is restricted to an EL1-registered executor (role12 for D04). Neither
//! an AI recommendation nor an arbitrary wire "APPLIED" state proves that
//! the device, memory map or redo transaction actually took effect.
//! \`verified_terminal_mask\` requires a separate trusted evidence callback
//! for each action; UNKNOWN never settles or releases any reference.
use super::{Error, Identity, plan_wire_v2::{PlanV2,MAX_ACTIONS}};

pub const APPLY_HEADER_BYTES:usize=96;
pub const MAX_ACTION_BYTES:usize=256;
pub const MAX_APPLY_REPORT_BYTES:usize=APPLY_HEADER_BYTES+MAX_ACTION_BYTES;
pub const PLAN_QUERY_BYTES:usize=64;

fn le16(b:&[u8],at:usize)->Result<u16,Error>{
    let s=b.get(at..at+2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([s[0],s[1]]))
}
fn le32(b:&[u8],at:usize)->Result<u32,Error>{
    let s=b.get(at..at+4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0],s[1],s[2],s[3]]))
}
fn le64(b:&[u8],at:usize)->Result<u64,Error>{
    let s=b.get(at..at+8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([
        s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]
    ]))
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct PlanKey{
    pub boot_epoch:u64,
    pub controller_epoch:u64,
    pub plan_seq:u64,
}
impl PlanKey {
    pub fn valid(self)->bool{
        self.boot_epoch!=0 && self.controller_epoch!=0 && self.plan_seq!=0
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ActionStatus{Applied,Rejected,Unknown,Cancelled}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct ApplyReportV1<'a>{
    pub key:PlanKey,
    pub action_index:u16,
    pub domain_id:u16,
    pub state:ActionStatus,
    pub target:Identity,
    pub executor_generation:u64,
    pub plan_version:u64,
    pub result:i32,
    pub completed_ns:u64,
    pub action:&'a[u8],
}
impl<'a> ApplyReportV1<'a>{
    pub fn decode(frame:&'a[u8])->Result<Self,Error>{
        if frame.len()<APPLY_HEADER_BYTES
            || frame.len()>MAX_APPLY_REPORT_BYTES
            || le16(frame,30)?!=0
            || frame[80..96].iter().any(|x|*x!=0)
        {return Err(Error::Invalid);}
        let n=usize::try_from(le32(frame,68)?).map_err(|_|Error::Invalid)?;
        if n==0 || n>MAX_ACTION_BYTES
            || APPLY_HEADER_BYTES.checked_add(n)!=Some(frame.len())
        {return Err(Error::Invalid);}
        let state=match le16(frame,28)?{
            1=>ActionStatus::Applied,2=>ActionStatus::Rejected,
            3=>ActionStatus::Unknown,4=>ActionStatus::Cancelled,
            _=>return Err(Error::Invalid),
        };
        let key=PlanKey{
            boot_epoch:le64(frame,0)?,
            controller_epoch:le64(frame,8)?,
            plan_seq:le64(frame,16)?,
        };
        let target=Identity{
            id:le64(frame,32)?,generation:le64(frame,40)?,
        };
        let generation=le64(frame,48)?;
        let completed_ns=le64(frame,72)?;
        let result=le32(frame,64)? as i32;
        if !key.valid() || !target.valid() || generation==0
            || le16(frame,24)? >=MAX_ACTIONS as u16
            || !(1..=15).contains(&le16(frame,26)?)
            || completed_ns==0 || (state==ActionStatus::Applied&&result!=0)
        {return Err(Error::Invalid);}
        Ok(Self {
            key,action_index:le16(frame,24)?,domain_id:le16(frame,26)?,
            state,target,executor_generation:generation,
            plan_version:le64(frame,56)?,result,completed_ns,
            action:&frame[APPLY_HEADER_BYTES..],
        })
    }

    /// A copied report must match a frozen accepted plan, trusted executor
    /// identity/generation and its original exact action bytes. The caller
    /// also must verify real capability rights at the 0x43 entry.
    pub fn matches_frozen(
        self,
        plan:&PlanV2<'_>,
        current:TrustedExecutor,
    )->Result<(),Error>{
        if !current.actor.valid() || current.actor!=current.authorized_executor
            || self.key.boot_epoch!=current.boot_epoch
            || self.key.controller_epoch!=plan.header.controller_epoch
            || self.key.plan_seq!=plan.header.plan_seq
            || self.plan_version!=current.plan_version
            || self.executor_generation!=current.executor_generation
            || self.completed_ns>current.now_ns
        {return Err(Error::Denied);}
        let action=plan.action(usize::from(self.action_index))?;
        if self.domain_id!=action.domain_id
            || self.target.id!=action.target_id
            || self.target.generation!=action.target_generation
            || self.action!=action.action_payload
        {return Err(Error::Denied);}
        Ok(())
    }
}
#[derive(Clone,Copy,Debug)]
pub struct TrustedExecutor{
    pub actor:Identity,
    pub authorized_executor:Identity,
    pub executor_generation:u64,
    pub boot_epoch:u64,
    pub plan_version:u64,
    pub now_ns:u64,
}
/// Only authoritative verification of ALL per-action results may close an
/// in-flight plan. This is an EL1 helper; a caller must supply real executor
/// and persistent/device evidence in the independent callback.
pub fn verified_terminal_mask(
    plan:&PlanV2<'_>,
    report_frames:&[&[u8]],
    executor:TrustedExecutor,
    mut verify_native:impl FnMut(usize,&ApplyReportV1<'_>)->Result<(),Error>,
)->Result<u16,Error>{
    let count=usize::from(plan.header.action_count);
    if count==0 || report_frames.len()!=count || count>MAX_ACTIONS {
        return Err(Error::Invalid);
    }
    let mut seen=0u16;
    // Validate the ENTIRE independent report set before asking the native
    // proof verifier to acknowledge even one terminal item.
    for frame in report_frames {
        let report=ApplyReportV1::decode(frame)?;
        let i=usize::from(report.action_index);
        let bit=1u16.checked_shl(i as u32).ok_or(Error::Invalid)?;
        if seen&bit!=0 {return Err(Error::Denied);}
        report.matches_frozen(plan,executor)?;
        // Even if UNKNOWN carries a completed timestamp, it is nonterminal.
        if report.state==ActionStatus::Unknown{return Err(Error::NotReady);}
        seen|=bit;
    }
    let required=if count==16{u16::MAX}else{(1u16<<count)-1};
    if seen!=required{return Err(Error::Denied);}
    for frame in report_frames {
        let report=ApplyReportV1::decode(frame)?;
        verify_native(usize::from(report.action_index),&report)?;
    }
    Ok(seen)
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct PlanQueryReplyV3{
    pub key:PlanKey,
    pub plan_version:u64,
    pub state:u16,
    pub result:i32,
    pub action_count:u16,
    pub terminal_count:u16,
}
impl PlanQueryReplyV3{
    /// Reply status is query-only; it never grants new registration or
    /// changes a plan's actual hardware/persistent completion state.
    pub fn decode(frame:&[u8])->Result<Self,Error>{
        if frame.len()!=PLAN_QUERY_BYTES
            || le16(frame,34)?!=0
            || frame[44..].iter().any(|x|*x!=0)
        {return Err(Error::Invalid);}
        let state=le16(frame,32)?;
        let key=PlanKey{
            boot_epoch:le64(frame,0)?,
            controller_epoch:le64(frame,8)?,
            plan_seq:le64(frame,16)?,
        };
        let count=le16(frame,40)?;
        let term=le16(frame,42)?;
        if !key.valid() || !(1..=5).contains(&state)
            || count==0 || usize::from(count)>MAX_ACTIONS
            || term>count || (state==4 && term!=count)
        {return Err(Error::Invalid);}
        Ok(Self {
            key,plan_version:le64(frame,24)?,state,
            result:le32(frame,36)? as i32,
            action_count:count,terminal_count:term
        })
    }
}
#[cfg(test)]
mod tests{
    extern crate std;
    use super::*;
    fn plan()->[u8;212]{
        let mut p=[0u8;212];
        p[0..4].copy_from_slice(&0x4359_4c31u32.to_le_bytes());
        p[4..6].copy_from_slice(&2u16.to_le_bytes());
        p[6..8].copy_from_slice(&64u16.to_le_bytes());
        p[8..12].copy_from_slice(&212u32.to_le_bytes());
        p[12..14].copy_from_slice(&1u16.to_le_bytes());
        p[16..24].copy_from_slice(&1u64.to_le_bytes());
        p[40..48].copy_from_slice(&2u64.to_le_bytes());
        p[48..56].copy_from_slice(&3u64.to_le_bytes());
        p[56..64].copy_from_slice(&10_000_000_100u64.to_le_bytes());
        let h=64;
        p[h..h+4].copy_from_slice(&0x4359_5031u32.to_le_bytes());
        p[h+4..h+6].copy_from_slice(&2u16.to_le_bytes());
        p[h+6..h+8].copy_from_slice(&144u16.to_le_bytes());
        p[h+8..h+10].copy_from_slice(&1u16.to_le_bytes());
        p[h+10..h+12].copy_from_slice(&1u16.to_le_bytes());
        p[h+12..h+16].copy_from_slice(&4u32.to_le_bytes());
        for (at,v) in [
            (16,2u64),(24,4),(32,3),(40,17),(48,1),
            (56,5),(64,6),(72,200)
        ] {p[h+at..h+at+8].copy_from_slice(&v.to_le_bytes());}
        p[h+112..h+144].copy_from_slice(&[1u8;32]);
        p[h+144..h+146].copy_from_slice(&1u16.to_le_bytes());
        p[h+146..h+148].copy_from_slice(&[2u8,0]);
        p
    }
    fn report()->[u8;98]{
        let mut r=[0u8;98];
        for (at,v) in [
            (0,1u64),(8,2),(16,1),(32,17),
            (40,1),(48,9),(56,7),(72,1000)
        ]{r[at..at+8].copy_from_slice(&v.to_le_bytes());}
        r[26..28].copy_from_slice(&1u16.to_le_bytes());
        r[28..30].copy_from_slice(&1u16.to_le_bytes());
        r[68..72].copy_from_slice(&2u32.to_le_bytes());
        r[96..98].copy_from_slice(&[2u8,0]);
        r
    }
    fn executor()->TrustedExecutor{
        TrustedExecutor{
            actor:Identity{id:12,generation:9},
            authorized_executor:Identity{id:12,generation:9},
            executor_generation:9,boot_epoch:1,plan_version:7,now_ns:1200,
        }
    }
    #[test]
    fn authentic_executor_and_real_effect_callback_are_both_required(){
        let raw=plan();
        let p=PlanV2::decode(&raw).unwrap();
        let r=report();
        let a=ApplyReportV1::decode(&r).unwrap();
        a.matches_frozen(&p,executor()).unwrap();
        let mut checked=0;
        assert_eq!(verified_terminal_mask(&p,&[&r],executor(),|_,_|{
            checked+=1;Ok(())
        }),Ok(1));
        assert_eq!(checked,1);
        let mut attacker=executor();attacker.actor.id=6;
        assert_eq!(verified_terminal_mask(
            &p,&[&r],attacker,|_,_|{checked+=1;Ok(())}
        ),Err(Error::Denied));
        assert_eq!(checked,1);
    }
    #[test]
    fn unknown_or_modified_action_never_becomes_a_terminal_proof(){
        let raw=plan();
        let p=PlanV2::decode(&raw).unwrap();
        let mut r=report();
        r[28..30].copy_from_slice(&3u16.to_le_bytes());
        let mut checked=0;
        assert_eq!(verified_terminal_mask(&p,&[&r],executor(),|_,_|{
            checked+=1;Ok(())
        }),Err(Error::NotReady));
        assert_eq!(checked,0);
        r=report();r[96]=3;
        assert_eq!(verified_terminal_mask(&p,&[&r],executor(),|_,_|{
            checked+=1;Ok(())
        }),Err(Error::Denied));
        assert_eq!(checked,0);
        r=report();r[28..30].copy_from_slice(&1u16.to_le_bytes());
        r[64..68].copy_from_slice(&(-1i32).to_le_bytes());
        assert!(ApplyReportV1::decode(&r).is_err());
    }
    #[test]
    fn plan_query_is_not_an_apply_receipt(){
        let mut raw=[0u8;64];
        raw[0..8].copy_from_slice(&1u64.to_le_bytes());
        raw[8..16].copy_from_slice(&2u64.to_le_bytes());
        raw[16..24].copy_from_slice(&3u64.to_le_bytes());
        raw[32..34].copy_from_slice(&4u16.to_le_bytes());
        raw[40..42].copy_from_slice(&1u16.to_le_bytes());
        raw[42..44].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(PlanQueryReplyV3::decode(&raw).unwrap().state,4);
        raw[42..44].copy_from_slice(&0u16.to_le_bytes());
        assert!(PlanQueryReplyV3::decode(&raw).is_err());
        raw[42..44].copy_from_slice(&1u16.to_le_bytes());
        raw[44]=1;assert!(PlanQueryReplyV3::decode(&raw).is_err());
    }
}

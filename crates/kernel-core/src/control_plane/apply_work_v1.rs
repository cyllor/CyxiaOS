//! Canonical ApplyWork v1, delivered only after a native accept point.
//! EL1 constructs this from a frozen published plan and its current
//! ExecutorBinding, never from AI bytes or an executor's self-report.
use super::{Error,Identity,action_schema_v2::ActionV2,
    apply_report_v1::{PlanKey,ExecutorBindingV1,ReportOrigin,ApplyReportV1},
    plan_wire_v2::PlanV2};
pub const HEADER_BYTES:usize=80;
pub const MAX_BYTES:usize=336;
fn u16at(b:&[u8],i:usize)->u16{u16::from_le_bytes(b[i..i+2].try_into().unwrap())}
fn u32at(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}
fn u64at(b:&[u8],i:usize)->u64{u64::from_le_bytes(b[i..i+8].try_into().unwrap())}
fn put16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes())}
fn put32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes())}
fn put64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes())}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct ApplyWorkV1<'a>{
    pub key:PlanKey,pub action_index:u16,pub domain:u16,pub target:Identity,
    pub executor_generation:u64,pub plan_version:u64,pub payload:&'a[u8],
}
impl<'a> ApplyWorkV1<'a>{
    pub fn decode(b:&'a[u8])->Result<Self,Error>{
        if !(HEADER_BYTES..=MAX_BYTES).contains(&b.len())||u32at(b,0)!=0x43594157
            ||u16at(b,4)!=1||u16at(b,6)!=80||u16at(b,36)!=1||u16at(b,38)!=0
            ||u32at(b,76)!=0||u32at(b,72) as usize!=b.len()-80{return Err(Error::Invalid);}
        let w=Self{key:PlanKey{boot_epoch:u64at(b,8),controller_epoch:u64at(b,16),plan_seq:u64at(b,24)},
            action_index:u16at(b,32),domain:u16at(b,34),target:Identity{id:u64at(b,40),generation:u64at(b,48)},
            executor_generation:u64at(b,56),plan_version:u64at(b,64),payload:&b[80..]};
        if !w.key.valid()||w.action_index>=16||!w.target.valid()||w.executor_generation==0||w.plan_version==0{
            return Err(Error::Invalid);
        }
        ActionV2::decode(w.domain,1,w.payload)?;Ok(w)
    }
    pub fn matches_report(self,r:ApplyReportV1<'_>)->bool{
        self.key==r.key&&self.action_index==r.action_index&&self.domain==r.domain_id
            &&self.target==r.target&&self.executor_generation==r.executor_generation
            &&self.plan_version==r.plan_version&&self.payload==r.action
    }
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct WorkFrame{bytes:[u8;MAX_BYTES],len:u16}
impl WorkFrame{
    pub fn bytes(&self)->&[u8]{&self.bytes[..usize::from(self.len)]}
    /// The protected publisher supplies the actual installed plan version.
    /// This constructor only binds bytes, not the acceptance obligation.
    pub fn from_plan(plan:&PlanV2<'_>,index:usize,boot_epoch:u64,version:u64,
        binding:ExecutorBindingV1,origin:ReportOrigin)->Result<Self,Error>{
        let a=plan.action(index)?;
        let target=Identity{id:a.target_id,generation:a.target_generation};
        if binding.domain!=a.domain_id||binding.target!=target||!binding.permits(origin)
            ||boot_epoch==0||version==0{return Err(Error::Denied);}
        let mut b=[0;MAX_BYTES];
        put32(&mut b,0,0x43594157);put16(&mut b,4,1);put16(&mut b,6,80);
        for (at,v) in [(8,boot_epoch),(16,plan.header.controller_epoch),(24,plan.header.plan_seq),
            (40,target.id),(48,target.generation),(56,binding.executor_generation),(64,version)]{put64(&mut b,at,v);}
        put16(&mut b,32,index as u16);put16(&mut b,34,a.domain_id);put16(&mut b,36,a.action_kind);
        put32(&mut b,72,a.action_payload.len() as u32);
        b[80..80+a.action_payload.len()].copy_from_slice(a.action_payload);
        let out=Self{bytes:b,len:(80+a.action_payload.len()) as u16};
        ApplyWorkV1::decode(out.bytes())?;Ok(out)
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn work_and_report_bind_exact_identity_and_action(){
        let mut b=[0u8;82];
        put32(&mut b,0,0x43594157);put16(&mut b,4,1);put16(&mut b,6,80);
        for (at,v) in [(8,1),(16,2),(24,3),(40,17),(48,5),(56,6),(64,7)]{put64(&mut b,at,v);}
        put16(&mut b,34,1);put16(&mut b,36,1);put32(&mut b,72,2);put16(&mut b,80,2);
        let w=ApplyWorkV1::decode(&b).unwrap();
        let r=ApplyReportV1{key:w.key,action_index:0,domain_id:1,
            state:super::super::apply_report_v1::ActionStatus::Applied,target:w.target,
            executor_generation:6,plan_version:7,result:0,completed_ns:8,action:&[2,0]};
        assert!(w.matches_report(r));assert!(!w.matches_report(ApplyReportV1{executor_generation:7,..r}));
        assert!(!w.matches_report(ApplyReportV1{action:&[4,0],..r}));
        for at in [0,4,6,36,38,76]{let mut bad=b;bad[at]^=1;assert!(ApplyWorkV1::decode(&bad).is_err());}
        b[80]=3;assert!(ApplyWorkV1::decode(&b).is_err());
    }
}

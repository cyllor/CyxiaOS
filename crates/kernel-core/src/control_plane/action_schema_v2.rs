//! Canonical ActionSchema v2 local D01..D15 values (main §8).
//! A valid static value is NOT permission, target admission, or an APPLY
//! receipt. Native executors must recheck live generations and hard limits.
use super::Error;
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum ActionV2{
    GroupWeight(u16),SpawnTokens(u16),Cache{pages:u32,batch:u16},
    File{readahead:u16,flush:u16},Ipc{budget:u16,batch:u8},
    IrqCpu(u16),SoftCoalesce(u16),ServiceBatch(u8),IoShare(u16),
    TxBatch(u8),NotifyBatch(u8),UnauthRate(u16),BackgroundBudget(u16),
    RecoveryRecipe(u16),ConsolePump(u16),
}
impl ActionV2{
    pub fn decode(domain:u16,kind:u16,b:&[u8])->Result<Self,Error>{
        if kind!=1{return Err(Error::Invalid);}
        let u16at=|i:usize|->Result<u16,Error>{
            Ok(u16::from_le_bytes(b.get(i..i+2).ok_or(Error::Invalid)?.try_into().unwrap()))
        };
        let v=match (domain,b.len()){
            (1,2)=>Self::GroupWeight(u16at(0)?),
            (2,2)=>Self::SpawnTokens(u16at(0)?),
            (3,6)=>Self::Cache{pages:u32::from_le_bytes(b[..4].try_into().unwrap()),batch:u16at(4)?},
            (4,4)=>Self::File{readahead:u16at(0)?,flush:u16at(2)?},
            (5,3)=>Self::Ipc{budget:u16at(0)?,batch:b[2]},
            (6,2)=>Self::IrqCpu(u16at(0)?),
            (7,2)=>Self::SoftCoalesce(u16at(0)?),
            (8,1)=>Self::ServiceBatch(b[0]),
            (9,2)=>Self::IoShare(u16at(0)?),
            (10,1)=>Self::TxBatch(b[0]),
            (11,1)=>Self::NotifyBatch(b[0]),
            (12,2)=>Self::UnauthRate(u16at(0)?),
            (13,2)=>Self::BackgroundBudget(u16at(0)?),
            (14,2)=>Self::RecoveryRecipe(u16at(0)?),
            (15,2)=>Self::ConsolePump(u16at(0)?),
            _=>return Err(Error::Invalid),
        };
        if !v.valid(){return Err(Error::Denied);}Ok(v)
    }
    pub fn valid(self)->bool{
        match self{
            Self::GroupWeight(v)|Self::SpawnTokens(v)=>matches!(v,1|2|4|8),
            Self::Cache{pages,batch}=>matches!((pages,batch),(64,4)|(256,16)|(1024,32)|(4096,64)),
            Self::File{readahead,flush}=>matches!((readahead,flush),(0,4)|(2,8)|(8,16)|(16,32)),
            Self::Ipc{budget,batch}=>matches!((budget,batch),(8,1)|(32,4)|(64,8)|(128,16)),
            Self::IrqCpu(v)=>matches!(v,1..=3),
            Self::SoftCoalesce(v)=>matches!(v,0|50|200|1000),
            Self::ServiceBatch(v)|Self::NotifyBatch(v)=>matches!(v,1|2|4|8),
            Self::IoShare(v)=>matches!(v,100|250|500|750),
            Self::TxBatch(v)=>matches!(v,1|4|8|16),
            Self::UnauthRate(v)=>matches!(v,4|8|16|32),
            Self::BackgroundBudget(v)=>matches!(v,50|100|200|400),
            Self::RecoveryRecipe(v)=>matches!(v,0..=2),
            Self::ConsolePump(v)=>matches!(v,1|8|32|64),
        }
    }
    /// Every local family has a fixed, exhaustive parameter inventory.
    /// The authenticated schema catalog binds these values to its actual
    /// static ordinals; this list itself does not assign ordinal numbers.
    pub fn values(domain:u16)->Result<&'static[Self],Error>{
        use ActionV2::*;
        Ok(match domain{
            1=>&[GroupWeight(1),GroupWeight(2),GroupWeight(4),GroupWeight(8)],
            2=>&[SpawnTokens(1),SpawnTokens(2),SpawnTokens(4),SpawnTokens(8)],
            3=>&[Cache{pages:64,batch:4},Cache{pages:256,batch:16},Cache{pages:1024,batch:32},Cache{pages:4096,batch:64}],
            4=>&[File{readahead:0,flush:4},File{readahead:2,flush:8},File{readahead:8,flush:16},File{readahead:16,flush:32}],
            5=>&[Ipc{budget:8,batch:1},Ipc{budget:32,batch:4},Ipc{budget:64,batch:8},Ipc{budget:128,batch:16}],
            6=>&[IrqCpu(1),IrqCpu(2),IrqCpu(3)],
            7=>&[SoftCoalesce(0),SoftCoalesce(50),SoftCoalesce(200),SoftCoalesce(1000)],
            8=>&[ServiceBatch(1),ServiceBatch(2),ServiceBatch(4),ServiceBatch(8)],
            9=>&[IoShare(100),IoShare(250),IoShare(500),IoShare(750)],
            10=>&[TxBatch(1),TxBatch(4),TxBatch(8),TxBatch(16)],
            11=>&[NotifyBatch(1),NotifyBatch(2),NotifyBatch(4),NotifyBatch(8)],
            12=>&[UnauthRate(4),UnauthRate(8),UnauthRate(16),UnauthRate(32)],
            13=>&[BackgroundBudget(50),BackgroundBudget(100),BackgroundBudget(200),BackgroundBudget(400)],
            14=>&[RecoveryRecipe(0),RecoveryRecipe(1),RecoveryRecipe(2)],
            15=>&[ConsolePump(1),ConsolePump(8),ConsolePump(32),ConsolePump(64)],
            _=>return Err(Error::Invalid),
        })
    }
    pub fn encode(self,domain:u16,out:&mut [u8;6])->Result<usize,Error>{
        if !Self::values(domain)?.contains(&self){return Err(Error::Denied);}
        out.fill(0);
        let n=match self{
            Self::Cache{pages,batch}=>{
                out[..4].copy_from_slice(&pages.to_le_bytes());out[4..].copy_from_slice(&batch.to_le_bytes());6
            }
            Self::File{readahead,flush}=>{
                out[..2].copy_from_slice(&readahead.to_le_bytes());out[2..4].copy_from_slice(&flush.to_le_bytes());4
            }
            Self::Ipc{budget,batch}=>{
                out[..2].copy_from_slice(&budget.to_le_bytes());out[2]=batch;3
            }
            Self::ServiceBatch(v)|Self::TxBatch(v)|Self::NotifyBatch(v)=>{out[0]=v;1}
            Self::GroupWeight(v)|Self::SpawnTokens(v)|Self::IrqCpu(v)|Self::SoftCoalesce(v)
            |Self::IoShare(v)|Self::UnauthRate(v)|Self::BackgroundBudget(v)
            |Self::RecoveryRecipe(v)|Self::ConsolePump(v)=>{
                out[..2].copy_from_slice(&v.to_le_bytes());2
            }
        };
        if Self::decode(domain,1,&out[..n])?!=self{return Err(Error::Invalid);}
        Ok(n)
    }

    /// D12 values below the ordinary minimum are offline trial only.
    pub const fn requires_trial(self)->bool{matches!(self,Self::UnauthRate(4|8))}
}
#[cfg(test)]
mod tests{
    use super::*;
    /// Literal reference bytes transcribed from the normative §8.1–8.15
    /// field widths and the V0.19.9 parameter table on pp.127–128.
    /// No expected bytes are generated by the implementation under test.
    /// These cover ActionSchema payloads only, not a frozen full G1 schema.
    #[test]
    fn independent_literal_action_vectors_cover_every_normative_tier(){
        use ActionV2::*;
        let rows:[&[(ActionV2,&[u8])];15]=[
            &[(GroupWeight(1),b"\x01\x00"),(GroupWeight(2),b"\x02\x00"),
              (GroupWeight(4),b"\x04\x00"),(GroupWeight(8),b"\x08\x00")],
            &[(SpawnTokens(1),b"\x01\x00"),(SpawnTokens(2),b"\x02\x00"),
              (SpawnTokens(4),b"\x04\x00"),(SpawnTokens(8),b"\x08\x00")],
            &[(Cache{pages:64,batch:4},b"\x40\x00\x00\x00\x04\x00"),
              (Cache{pages:256,batch:16},b"\x00\x01\x00\x00\x10\x00"),
              (Cache{pages:1024,batch:32},b"\x00\x04\x00\x00\x20\x00"),
              (Cache{pages:4096,batch:64},b"\x00\x10\x00\x00\x40\x00")],
            &[(File{readahead:0,flush:4},b"\x00\x00\x04\x00"),
              (File{readahead:2,flush:8},b"\x02\x00\x08\x00"),
              (File{readahead:8,flush:16},b"\x08\x00\x10\x00"),
              (File{readahead:16,flush:32},b"\x10\x00\x20\x00")],
            &[(Ipc{budget:8,batch:1},b"\x08\x00\x01"),
              (Ipc{budget:32,batch:4},b"\x20\x00\x04"),
              (Ipc{budget:64,batch:8},b"\x40\x00\x08"),
              (Ipc{budget:128,batch:16},b"\x80\x00\x10")],
            &[(IrqCpu(1),b"\x01\x00"),(IrqCpu(2),b"\x02\x00"),(IrqCpu(3),b"\x03\x00")],
            &[(SoftCoalesce(0),b"\x00\x00"),(SoftCoalesce(50),b"\x32\x00"),
              (SoftCoalesce(200),b"\xc8\x00"),(SoftCoalesce(1000),b"\xe8\x03")],
            &[(ServiceBatch(1),b"\x01"),(ServiceBatch(2),b"\x02"),
              (ServiceBatch(4),b"\x04"),(ServiceBatch(8),b"\x08")],
            &[(IoShare(100),b"\x64\x00"),(IoShare(250),b"\xfa\x00"),
              (IoShare(500),b"\xf4\x01"),(IoShare(750),b"\xee\x02")],
            &[(TxBatch(1),b"\x01"),(TxBatch(4),b"\x04"),(TxBatch(8),b"\x08"),(TxBatch(16),b"\x10")],
            &[(NotifyBatch(1),b"\x01"),(NotifyBatch(2),b"\x02"),(NotifyBatch(4),b"\x04"),(NotifyBatch(8),b"\x08")],
            &[(UnauthRate(4),b"\x04\x00"),(UnauthRate(8),b"\x08\x00"),
              (UnauthRate(16),b"\x10\x00"),(UnauthRate(32),b"\x20\x00")],
            &[(BackgroundBudget(50),b"\x32\x00"),(BackgroundBudget(100),b"\x64\x00"),
              (BackgroundBudget(200),b"\xc8\x00"),(BackgroundBudget(400),b"\x90\x01")],
            &[(RecoveryRecipe(0),b"\x00\x00"),(RecoveryRecipe(1),b"\x01\x00"),(RecoveryRecipe(2),b"\x02\x00")],
            &[(ConsolePump(1),b"\x01\x00"),(ConsolePump(8),b"\x08\x00"),
              (ConsolePump(32),b"\x20\x00"),(ConsolePump(64),b"\x40\x00")],
        ];
        assert_eq!(rows.iter().map(|r|r.len()).sum::<usize>(),58);
        for (i,entries) in rows.iter().enumerate(){
            let domain=i as u16+1;
            let inventory=ActionV2::values(domain).unwrap();
            assert_eq!(inventory.len(),entries.len());
            for (j,&(value,expected)) in entries.iter().enumerate(){
                assert_eq!(inventory[j],value);
                assert_eq!(ActionV2::decode(domain,1,expected),Ok(value));
                let mut out=[0xff;6];let n=value.encode(domain,&mut out).unwrap();
                assert_eq!(&out[..n],expected);assert_eq!(n,expected.len());
                assert!(out[n..].iter().all(|&v|v==0));
                assert!(ActionV2::decode(domain,2,expected).is_err());
                assert!(ActionV2::decode(domain,1,&expected[..expected.len()-1]).is_err());
                let mut extra=[0u8;7];extra[..n].copy_from_slice(expected);
                assert!(ActionV2::decode(domain,1,&extra[..n+1]).is_err());
                assert_eq!(value.requires_trial(),domain==12&&j<2);
            }
        }
        // Valid individual parameters cannot be recombined into an
        // unregistered pair. Numerically valid foreign-domain variants
        // cannot be encoded by changing only the domain selector.
        for (domain,bad) in [(3,&b"\x40\x00\x00\x00\x10\x00"[..]),
            (4,&b"\x02\x00\x10\x00"[..]),(5,&b"\x20\x00\x08"[..]) ]{
            assert_eq!(ActionV2::decode(domain,1,bad),Err(Error::Denied));
        }
        assert_eq!(GroupWeight(1).encode(2,&mut[0;6]),Err(Error::Denied));
        assert_eq!(NotifyBatch(1).encode(8,&mut[0;6]),Err(Error::Denied));
    }
    #[test]
    fn canonical_payload_widths_and_values_for_every_local_domain(){
        let good:[&[u8];15]=[&[2,0],&[8,0],&[0,1,0,0,16,0],&[2,0,8,0],&[32,0,4],
            &[3,0],&[50,0],&[4],&[250,0],&[16],&[8],&[16,0],&[100,0],&[2,0],&[64,0]];
        for (i,b) in good.into_iter().enumerate(){
            let domain=i as u16+1;
            assert!(ActionV2::decode(domain,1,b).is_ok());
            assert!(ActionV2::decode(domain,2,b).is_err());
            assert!(ActionV2::decode(domain,1,&b[..b.len()-1]).is_err());
            let mut extra=[0;7];extra[..b.len()].copy_from_slice(b);
            assert!(ActionV2::decode(domain,1,&extra[..b.len()+1]).is_err());
        }
        assert!(ActionV2::decode(16,1,&[1,0]).is_err());
        assert!(ActionV2::decode(6,1,&[0,0]).is_err());
        assert!(ActionV2::decode(3,1,&[0,1,0,0,32,0]).is_err());
        assert!(ActionV2::decode(12,1,&[8,0]).unwrap().requires_trial());
        assert!(!ActionV2::decode(12,1,&[16,0]).unwrap().requires_trial());
    }
}

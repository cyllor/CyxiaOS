//! Frozen BootEpochStore v1 (§9.6) and atomic two-home startup redo.
//! The independently authenticated file owner supplies exact inode/extent
//! locations and exclusive transaction space. A single state block is not
//! a complete startup grant. Diagnostic media never become production
//! credentials merely because their CRC/FLUSH checks pass.
use super::{Error,durable_role_epoch_v0199::{Change,PreparedEpoch,CommitEvidence},
    file_index_v0199::SecurityStateStoreV2,
    file_media_v0199::{SUPER_BYTES as BLOCK,DATA_START,BLOCK_COUNT,SuperblockV1,
        crc32c_payload,crc32c_zeroed,verify_state_redo_v1},
    epoch_redo_v0199::EpochBlockIo};
use sha2::{Digest,Sha256};
fn p16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
fn p32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
fn p64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
fn u32at(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}
fn u64at(b:&[u8],i:usize)->u64{u64::from_le_bytes(b[i..i+8].try_into().unwrap())}
fn hash(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct BootEpochStoreV1{pub fs_uuid:[u8;16],pub boot_epoch:u64}
impl BootEpochStoreV1{
    pub fn decode(b:&[u8])->Result<Self,Error>{
        if b.len()!=BLOCK||u32at(b,0)!=0x43594245||b[4..6]!=1u16.to_le_bytes()
            ||b[6..8]!=40u16.to_le_bytes()||u32at(b,36)!=0
            ||b[40..].iter().any(|&v|v!=0)||u32at(b,32)!=crc32c_zeroed(b,32)?{
            return Err(Error::Invalid);
        }
        let v=Self{fs_uuid:b[8..24].try_into().unwrap(),boot_epoch:u64at(b,24)};
        if v.fs_uuid==[0;16]{return Err(Error::Invalid);}Ok(v)
    }
    pub fn encode(self)->Result<[u8;BLOCK],Error>{
        if self.fs_uuid==[0;16]{return Err(Error::Invalid);}
        let mut b=[0;BLOCK];p32(&mut b,0,0x43594245);p16(&mut b,4,1);p16(&mut b,6,40);
        b[8..24].copy_from_slice(&self.fs_uuid);p64(&mut b,24,self.boot_epoch);
        let c=crc32c_zeroed(&b,32)?;p32(&mut b,32,c);Ok(b)
    }
    pub fn matches(self,state:&SecurityStateStoreV2)->bool{
        self.fs_uuid==state.fs_uuid&&self.boot_epoch==state.last_boot_epoch
    }
}
fn seal(b:&mut[u8],kind:u16,len:usize,txid:u64,epoch:u64,lsn:u64)->Result<(),Error>{
    p32(b,0,0x43594c47);p16(b,4,1);p16(b,6,kind);p32(b,8,len as u32);
    p64(b,16,txid);p64(b,24,lsn);p64(b,32,epoch);
    let c=crc32c_payload(&b[64..len]);p32(b,12,c);
    let c=crc32c_zeroed(&b[..64],56)?;p32(b,56,c);Ok(())
}
/// Both canonical afterimages in one exact committed v1 transaction.
/// General log validation is shared with service-generation updates.
pub fn verify_boot_pair(sb:SuperblockV1,first:u32,state_home:u32,boot_home:u32,
    begin:&[u8],redos:&[&[u8]],commit:&[u8],expected_state:&[u8],expected_boot:&[u8],
    txid:u64,commit_lsn:u64)->Result<SecurityStateStoreV2,Error>{
    if redos.len()!=2||state_home==boot_home||!(DATA_START..BLOCK_COUNT).contains(&boot_home){
        return Err(Error::Invalid);
    }
    let state=SecurityStateStoreV2::decode(expected_state)?;
    let boot=BootEpochStoreV1::decode(expected_boot)?;
    if !boot.matches(&state)||state.fs_uuid!=sb.fs_uuid{return Err(Error::Conflict);}
    verify_state_redo_v1(sb,first,u64::from(state_home),begin,redos,commit,expected_state,txid,commit_lsn)?;
    verify_state_redo_v1(sb,first,u64::from(boot_home),begin,redos,commit,expected_boot,txid,commit_lsn)?;
    Ok(state)
}
/// 24 KiB explicitly preallocated progress workspace; no stack-sized copy
/// of the whole transaction. Ordered records occupy six log blocks.
pub struct BootPairRedo{
    pub begin:[u8;BLOCK],pub state_redo:[u8;2*BLOCK],pub boot_redo:[u8;2*BLOCK],pub commit:[u8;BLOCK],
}
impl BootPairRedo{
    pub const fn new()->Self{Self{begin:[0;BLOCK],state_redo:[0;2*BLOCK],boot_redo:[0;2*BLOCK],commit:[0;BLOCK]}}
    fn extent(first:u32)->Result<(),Error>{
        if !(2..=4092).contains(&first){return Err(Error::Invalid);}Ok(())
    }
    pub fn read(&mut self,io:&mut impl EpochBlockIo,first:u32)->Result<(),Error>{
        Self::extent(first)?;io.read(first,&mut self.begin)?;
        for (i,raw) in [&mut self.state_redo,&mut self.boot_redo].into_iter().enumerate(){
            let (a,b)=raw.split_at_mut(BLOCK);
            io.read(first+1+2*i as u32,a.try_into().unwrap())?;
            io.read(first+2+2*i as u32,b.try_into().unwrap())?;
        }
        io.read(first+5,&mut self.commit)?;Ok(())
    }
    pub fn blank(&self)->bool{
        self.begin.iter().chain(self.state_redo.iter()).chain(self.boot_redo.iter()).chain(self.commit.iter()).all(|&v|v==0)
    }
    pub fn state_image(&self)->&[u8;BLOCK]{self.state_redo[64..4160].try_into().unwrap()}
    pub fn boot_image(&self)->&[u8;BLOCK]{self.boot_redo[64..4160].try_into().unwrap()}
    pub fn verify(&self,sb:SuperblockV1,first:u32,state_home:u32,boot_home:u32,txid:u64,lsn:u64)
        ->Result<SecurityStateStoreV2,Error>{
        // Canonical encoder writes state then boot. Reject a reordered
        // otherwise valid chain for this exact startup transaction.
        verify_boot_pair(sb,first,state_home,boot_home,&self.begin,&[&self.state_redo,&self.boot_redo],
            &self.commit,self.state_image(),self.boot_image(),txid,lsn)
    }
    fn encode(&mut self,sb:SuperblockV1,state_home:u32,boot_home:u32,txid:u64,lsn:u64,
        state:&[u8;BLOCK],boot:&[u8;BLOCK])->Result<(),Error>{
        let start=lsn.checked_sub(3).ok_or(Error::Invalid)?;
        if start<=sb.checkpoint_lsn||txid==0{return Err(Error::Invalid);}
        self.begin.fill(0);p32(&mut self.begin,64,2);p64(&mut self.begin,72,8192);
        seal(&mut self.begin,1,80,txid,sb.log_epoch,start)?;
        let mut digest=Sha256::new();
        for (i,(home,raw,image)) in [(state_home,&mut self.state_redo,state),(boot_home,&mut self.boot_redo,boot)].into_iter().enumerate(){
            raw.fill(0);p64(raw,40,u64::from(home));p32(raw,48,i as u32);p32(raw,52,2);
            raw[64..4160].copy_from_slice(image);
            digest.update(u64::from(home).to_le_bytes());digest.update(image);
            seal(raw,2,4160,txid,sb.log_epoch,start+1+i as u64)?;
        }
        self.commit.fill(0);p64(&mut self.commit,64,txid);p64(&mut self.commit,72,start);
        p64(&mut self.commit,80,lsn-1);p32(&mut self.commit,88,2);
        self.commit[96..128].copy_from_slice(&digest.finalize());
        seal(&mut self.commit,3,128,txid,sb.log_epoch,lsn)?;
        Ok(())
    }
    pub fn append(&mut self,io:&mut impl EpochBlockIo,sb:SuperblockV1,first:u32,
        state_home:u32,boot_home:u32,txid:u64,lsn:u64,ticket:PreparedEpoch,state:&[u8;BLOCK])
        ->Result<BootPairCommit,Error>{
        let decoded=SecurityStateStoreV2::decode(state)?;
        if ticket.change!=Change::AllocateBoot||ticket.fs_uuid!=sb.fs_uuid||decoded.fs_uuid!=sb.fs_uuid
            ||decoded.state_generation!=ticket.new_state_generation||decoded.last_boot_epoch!=ticket.target_boot_epoch
            ||ticket.old_state_generation.checked_add(1)!=Some(ticket.new_state_generation)
            ||ticket.target_boot_epoch==0||hash(state)!=ticket.after_digest{return Err(Error::Conflict);}
        let boot=BootEpochStoreV1{fs_uuid:sb.fs_uuid,boot_epoch:ticket.target_boot_epoch}.encode()?;
        self.read(io,first)?;if !self.blank(){return Err(Error::Conflict);}
        self.encode(sb,state_home,boot_home,txid,lsn,state,&boot)?;
        self.verify(sb,first,state_home,boot_home,txid,lsn)?;
        io.write(first,&self.begin).map_err(|_|Error::Unknown)?;
        for (i,raw) in [&self.state_redo,&self.boot_redo].into_iter().enumerate(){
            io.write(first+1+2*i as u32,raw[..BLOCK].try_into().unwrap()).map_err(|_|Error::Unknown)?;
            io.write(first+2+2*i as u32,raw[BLOCK..].try_into().unwrap()).map_err(|_|Error::Unknown)?;
        }
        io.flush().map_err(|_|Error::Unknown)?;
        io.write(first+5,&self.commit).map_err(|_|Error::Unknown)?;
        io.flush().map_err(|_|Error::Unknown)?;
        self.read(io,first).map_err(|_|Error::Unknown)?;
        self.verify(sb,first,state_home,boot_home,txid,lsn).map_err(|_|Error::Unknown)?;
        if self.state_image()!=state||self.boot_image()!=&boot{return Err(Error::Unknown);}
        Ok(BootPairCommit{ticket,receipt:CommitEvidence{fs_uuid:sb.fs_uuid,log_epoch:sb.log_epoch,txid,
            commit_lsn:lsn,after_digest:hash(state)},boot_digest:hash(&boot)})
    }
}
pub struct BootPairCommit{ticket:PreparedEpoch,receipt:CommitEvidence,boot_digest:[u8;32]}
impl BootPairCommit{
    pub fn receipt(&self)->CommitEvidence{self.receipt}
    pub fn verifies(&self,ticket:&PreparedEpoch,receipt:&CommitEvidence,boot:&[u8])->Result<(),Error>{
        if self.ticket!=*ticket||self.receipt!=*receipt||hash(boot)!=self.boot_digest{return Err(Error::Conflict);}Ok(())
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn paired_gate_requires_both_exact_committed_homes_and_keeps_unknown(){
        use super::super::durable_role_epoch_v0199::{DurableEpochGate,SlotBinding,Outcome};
        use crate::control_plane::role_manifest_v0199::ROLES;
        struct Disk{log:[[u8;BLOCK];6],writes:u32,flushes:u32,fail_second:bool}
        impl EpochBlockIo for Disk{
            fn read(&mut self,b:u32,out:&mut[u8;BLOCK])->Result<(),Error>{*out=self.log[(b-2) as usize];Ok(())}
            fn write(&mut self,b:u32,data:&[u8;BLOCK])->Result<(),Error>{
                self.log[(b-2) as usize]=*data;self.writes+=1;Ok(())
            }
            fn flush(&mut self)->Result<(),Error>{
                self.flushes+=1;if self.fail_second&&self.flushes==2{return Err(Error::Unknown);}Ok(())
            }
        }
        let state=SecurityStateStoreV2{fs_uuid:[1;16],state_generation:1,rule_min_generation:1,
            security_min_generation:1,key_generation:1,isolated_service_bitmap:0,last_boot_epoch:0,
            offline_config_generation:1,offline_config_hash:[2;32],service_generations:[1;16]}.encode().unwrap();
        let boot=BootEpochStoreV1{fs_uuid:[1;16],boot_epoch:0}.encode().unwrap();
        let wrong=BootEpochStoreV1{fs_uuid:[1;16],boot_epoch:1}.encode().unwrap();
        let slots=core::array::from_fn(|i|SlotBinding{role:ROLES[i],slot:i as u8});
        assert!(matches!(DurableEpochGate::recovered_pair(&state,&wrong,slots,|_|panic!()),Err(Error::Conflict)));
        let mut gate=DurableEpochGate::recovered_pair(&state,&boot,slots,|_|Ok(())).unwrap();
        let ticket=gate.prepare(Change::AllocateBoot,|_|panic!()).unwrap();
        let image=gate.after_image(ticket).unwrap();
        let mut pair=BootPairRedo::new();
        let sb=SuperblockV1{fs_uuid:[1;16],generation:1,checkpoint_lsn:0,log_epoch:1};
        let mut disk=Disk{log:[[0;BLOCK];6],writes:0,flushes:0,fail_second:true};
        assert!(matches!(pair.append(&mut disk,sb,2,7000,7002,1,4,ticket,&image),Err(Error::Unknown)));
        assert_eq!(gate.boot_epoch(),None);assert_eq!((disk.writes,disk.flushes),(6,2));
        assert!(matches!(pair.append(&mut disk,sb,2,7000,7002,1,4,ticket,&image),Err(Error::Conflict)));
        // Separate successful native-owner fixture. Do not retry the
        // ambiguous transaction on another device under the old gate.
        let mut gate=DurableEpochGate::recovered_pair(&state,&boot,slots,|_|Ok(())).unwrap();
        let ticket=gate.prepare(Change::AllocateBoot,|_|panic!()).unwrap();
        let image=gate.after_image(ticket).unwrap();
        let mut disk=Disk{log:[[0;BLOCK];6],writes:0,flushes:0,fail_second:false};
        let proof=pair.append(&mut disk,sb,2,7000,7002,1,4,ticket,&image).unwrap();
        let receipt=proof.receipt();
        assert_eq!(gate.confirm(ticket,receipt,&image,|_,_|panic!()),Err(Error::Unauthorized));
        let mut super_raw=[0;BLOCK];
        p32(&mut super_raw,0,0x43594653);p16(&mut super_raw,4,1);p16(&mut super_raw,6,80);
        p32(&mut super_raw,8,4096);p32(&mut super_raw,12,131072);super_raw[16..32].fill(1);
        p64(&mut super_raw,32,1);p64(&mut super_raw,48,1);p32(&mut super_raw,56,4098);
        p32(&mut super_raw,60,4102);p32(&mut super_raw,64,4118);p32(&mut super_raw,68,256);
        let crc=crc32c_zeroed(&super_raw,76).unwrap();p32(&mut super_raw,76,crc);
        assert_eq!(gate.confirm_boot_from_redo(ticket,receipt,pair.state_image(),&boot,&super_raw,2,7000,7002,
            &pair.begin,&[&pair.state_redo,&pair.boot_redo],&pair.commit,|_,_,_|panic!()),Err(Error::Conflict));
        assert_eq!(gate.confirm_boot_from_redo(ticket,receipt,pair.state_image(),pair.boot_image(),&super_raw,2,7000,7002,
            &pair.begin,&[&pair.state_redo,&pair.boot_redo],&pair.commit,|t,r,b|proof.verifies(t,r,b)),Ok(Outcome::Boot{epoch:1}));
        assert_eq!(gate.boot_epoch(),Some(1));
    }
    #[test]
    fn exact_boot_epoch_store_roundtrip_and_crc_reserved_rejection(){
        let s=BootEpochStoreV1{fs_uuid:[1;16],boot_epoch:42};let b=s.encode().unwrap();
        assert_eq!(BootEpochStoreV1::decode(&b),Ok(s));
        let mut bad=b;bad[24]^=1;assert!(BootEpochStoreV1::decode(&bad).is_err());
        let mut bad=b;bad[4095]=1;let c=crc32c_zeroed(&bad,32).unwrap();p32(&mut bad,32,c);
        assert!(BootEpochStoreV1::decode(&bad).is_err());
    }
}

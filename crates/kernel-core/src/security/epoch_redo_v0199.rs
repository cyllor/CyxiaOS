//! Narrow baseline-v1 journal append for a single protected state block.
//! Caller owns the actual file mapping, free log extent, exclusive journal
//! and device completion path. This is not a general filesystem mount.
//! An error after the first write leaves an UNKNOWN obligation; do not retry
//! at a different location or release the pending durable identity.
use super::{Error,durable_role_epoch_v0199::{PreparedEpoch,CommitEvidence},
    file_index_v0199::{SecurityStateStoreV2,BLOCK_BYTES},
    file_media_v0199::{SuperblockV1,crc32c_payload,crc32c_zeroed,verify_state_redo_v1,DATA_START,BLOCK_COUNT}};
use sha2::{Digest,Sha256};

pub trait EpochBlockIo {
    fn read(&mut self,block:u32,out:&mut [u8;BLOCK_BYTES])->Result<(),Error>;
    fn write(&mut self,block:u32,data:&[u8;BLOCK_BYTES])->Result<(),Error>;
    /// Must represent successful completion of the actual device FLUSH,
    /// not only queue admission, a CPU barrier, or a buffered write.
    fn flush(&mut self)->Result<(),Error>;
}
fn put16(b:&mut[u8],at:usize,v:u16){b[at..at+2].copy_from_slice(&v.to_le_bytes());}
fn put32(b:&mut[u8],at:usize,v:u32){b[at..at+4].copy_from_slice(&v.to_le_bytes());}
fn put64(b:&mut[u8],at:usize,v:u64){b[at..at+8].copy_from_slice(&v.to_le_bytes());}
fn digest(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn seal(b:&mut[u8],kind:u16,len:usize,txid:u64,epoch:u64,lsn:u64)->Result<(),Error>{
    put32(b,0,0x4359_4c47);put16(b,4,1);put16(b,6,kind);put32(b,8,len as u32);
    put64(b,16,txid);put64(b,24,lsn);put64(b,32,epoch);
    let crc=crc32c_payload(&b[64..len]);put32(b,12,crc);
    let crc=crc32c_zeroed(&b[..64],56)?;put32(b,56,crc);
    Ok(())
}
pub struct OneStateRedo {
    pub begin:[u8;BLOCK_BYTES],
    pub redo:[u8;2*BLOCK_BYTES],
    pub commit:[u8;BLOCK_BYTES],
}
impl OneStateRedo{
    pub const fn zeroed()->Self{Self{begin:[0;BLOCK_BYTES],redo:[0;2*BLOCK_BYTES],commit:[0;BLOCK_BYTES]}}
    fn extent(first:u32)->Result<(),Error>{
        if !(2..=4094).contains(&first){return Err(Error::Invalid);}Ok(())
    }
    pub fn read(&mut self,io:&mut impl EpochBlockIo,first:u32)->Result<(),Error>{
        Self::extent(first)?;
        io.read(first,&mut self.begin)?;
        let (left,right)=self.redo.split_at_mut(BLOCK_BYTES);
        io.read(first+1,left.try_into().map_err(|_|Error::Invalid)?)?;
        io.read(first+2,right.try_into().map_err(|_|Error::Invalid)?)?;
        io.read(first+3,&mut self.commit)?;
        Ok(())
    }
    pub fn blank(&self)->bool{
        self.begin.iter().chain(self.redo.iter()).chain(self.commit.iter()).all(|v|*v==0)
    }
    pub fn image(&self)->&[u8;BLOCK_BYTES]{self.redo[64..64+BLOCK_BYTES].try_into().unwrap()}
    pub fn verify(&self,sb:SuperblockV1,first:u32,home:u32,txid:u64,commit_lsn:u64)
        ->Result<SecurityStateStoreV2,Error>{
        verify_state_redo_v1(sb,first,u64::from(home),&self.begin,&[&self.redo],&self.commit,
            self.image(),txid,commit_lsn)?;
        let state=SecurityStateStoreV2::decode(self.image())?;
        if state.fs_uuid!=sb.fs_uuid{return Err(Error::Conflict);}Ok(state)
    }
    fn encode(&mut self,sb:SuperblockV1,home:u32,txid:u64,commit_lsn:u64,image:&[u8;BLOCK_BYTES])
        ->Result<(),Error>{
        let begin=commit_lsn.checked_sub(2).ok_or(Error::Invalid)?;
        if begin<=sb.checkpoint_lsn||txid==0||!(DATA_START..BLOCK_COUNT).contains(&home){
            return Err(Error::Invalid);
        }
        self.begin.fill(0);self.redo.fill(0);self.commit.fill(0);
        put32(&mut self.begin,64,1);put64(&mut self.begin,72,BLOCK_BYTES as u64);
        seal(&mut self.begin,1,80,txid,sb.log_epoch,begin)?;
        put64(&mut self.redo,40,u64::from(home));put32(&mut self.redo,52,1);
        self.redo[64..64+BLOCK_BYTES].copy_from_slice(image);
        seal(&mut self.redo,2,4160,txid,sb.log_epoch,begin+1)?;
        let mut h=Sha256::new();h.update(u64::from(home).to_le_bytes());h.update(image);
        put64(&mut self.commit,64,txid);put64(&mut self.commit,72,begin);
        put64(&mut self.commit,80,begin+1);put32(&mut self.commit,88,1);
        self.commit[96..128].copy_from_slice(&h.finalize());
        seal(&mut self.commit,3,128,txid,sb.log_epoch,commit_lsn)?;
        Ok(())
    }
    /// Append one transaction only to a reserved empty four-block extent.
    /// Before any write verify exact prepared identity and canonical afterimage.
    /// BEGIN/REDO -> FLUSH -> COMMIT -> FLUSH -> independent device readback.
    /// Home blocks remain untouched until the journal owner's checkpoint.
    pub fn append(&mut self,io:&mut impl EpochBlockIo,sb:SuperblockV1,first:u32,home:u32,
        txid:u64,commit_lsn:u64,ticket:PreparedEpoch,image:&[u8;BLOCK_BYTES])
        ->Result<VerifiedStateCommit,Error>{
        let state=SecurityStateStoreV2::decode(image)?;
        if state.fs_uuid!=sb.fs_uuid||ticket.fs_uuid!=sb.fs_uuid
            ||state.state_generation!=ticket.new_state_generation
            ||ticket.old_state_generation.checked_add(1)!=Some(ticket.new_state_generation)
            ||state.last_boot_epoch!=ticket.target_boot_epoch||digest(image)!=ticket.after_digest{
            return Err(Error::Conflict);
        }
        self.read(io,first)?;
        if !self.blank(){return Err(Error::Conflict);}
        self.encode(sb,home,txid,commit_lsn,image)?;
        self.verify(sb,first,home,txid,commit_lsn)?;
        let (left,right)=self.redo.split_at(BLOCK_BYTES);
        io.write(first,&self.begin).map_err(|_|Error::Unknown)?;
        io.write(first+1,left.try_into().unwrap()).map_err(|_|Error::Unknown)?;
        io.write(first+2,right.try_into().unwrap()).map_err(|_|Error::Unknown)?;
        io.flush().map_err(|_|Error::Unknown)?;
        io.write(first+3,&self.commit).map_err(|_|Error::Unknown)?;
        io.flush().map_err(|_|Error::Unknown)?;
        self.read(io,first).map_err(|_|Error::Unknown)?;
        self.verify(sb,first,home,txid,commit_lsn).map_err(|_|Error::Unknown)?;
        if self.image()!=image{return Err(Error::Unknown);}
        Ok(VerifiedStateCommit{ticket,receipt:CommitEvidence{fs_uuid:sb.fs_uuid,
            log_epoch:sb.log_epoch,txid,commit_lsn,after_digest:digest(image)}})
    }
}
/// Constructed only after both ordered I/O completions and the exact log
/// readback. Its trust is no stronger than the protected BlockIo adapter.
/// A host test double is not native persistence evidence.
pub struct VerifiedStateCommit{ticket:PreparedEpoch,receipt:CommitEvidence}
impl VerifiedStateCommit{
    pub fn receipt(&self)->CommitEvidence{self.receipt}
    pub fn verifies(&self,ticket:&PreparedEpoch,receipt:&CommitEvidence)->Result<(),Error>{
        if self.ticket!=*ticket||self.receipt!=*receipt{return Err(Error::Conflict);}Ok(())
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::security::durable_role_epoch_v0199::{Change,DurableEpochGate,SlotBinding};
    use crate::control_plane::role_manifest_v0199::ROLES;
    struct HostDisk{
        blocks:[[u8;BLOCK_BYTES];4],events:[u8;8],count:usize,fail_second_flush:bool,flushes:u8,
    }
    impl EpochBlockIo for HostDisk{
        fn read(&mut self,b:u32,out:&mut[u8;BLOCK_BYTES])->Result<(),Error>{*out=self.blocks[(b-2) as usize];Ok(())}
        fn write(&mut self,b:u32,data:&[u8;BLOCK_BYTES])->Result<(),Error>{
            self.events[self.count]=b as u8;self.count+=1;self.blocks[(b-2) as usize]=*data;Ok(())
        }
        fn flush(&mut self)->Result<(),Error>{
            self.events[self.count]=9;self.count+=1;self.flushes+=1;
            if self.fail_second_flush&&self.flushes==2{return Err(Error::Unknown);}Ok(())
        }
    }
    fn state()->SecurityStateStoreV2{
        SecurityStateStoreV2{fs_uuid:[1;16],state_generation:1,rule_min_generation:1,
            security_min_generation:1,key_generation:1,isolated_service_bitmap:0,last_boot_epoch:0,
            offline_config_generation:1,offline_config_hash:[2;32],service_generations:[1;16]}
    }
    fn disk(fail:bool)->HostDisk{HostDisk{blocks:[[0;BLOCK_BYTES];4],events:[0;8],count:0,fail_second_flush:fail,flushes:0}}
    #[test]
    fn write_order_and_unknown_after_second_flush(){
        let raw=state().encode().unwrap();
        let slots=core::array::from_fn(|i|SlotBinding{role:ROLES[i],slot:i as u8});
        let mut gate=DurableEpochGate::recovered(&raw,slots,|_|Ok(())).unwrap();
        let ticket=gate.prepare(Change::AllocateBoot,|_|panic!("not a stop")).unwrap();
        let image=gate.after_image(ticket).unwrap();
        let sb=SuperblockV1{fs_uuid:[1;16],generation:1,checkpoint_lsn:0,log_epoch:1};
        let mut scratch=OneStateRedo::zeroed();
        let mut failing=disk(true);
        assert!(matches!(scratch.append(&mut failing,sb,2,7000,1,3,ticket,&image),Err(Error::Unknown)));
        assert_eq!(failing.events[..6],[2,3,4,9,5,9]);assert_eq!(gate.boot_epoch(),None);
        assert!(matches!(scratch.append(&mut failing,sb,2,7000,1,3,ticket,&image),Err(Error::Conflict)));
        // Separate successful scenario: never retry the unknown transaction
        // on another device or extent under the original gate.
        let mut gate=DurableEpochGate::recovered(&raw,slots,|_|Ok(())).unwrap();
        let ticket=gate.prepare(Change::AllocateBoot,|_|panic!("not a stop")).unwrap();
        let image=gate.after_image(ticket).unwrap();
        let mut ok=disk(false);
        let proof=scratch.append(&mut ok,sb,2,7000,1,3,ticket,&image).unwrap();
        assert_eq!(ok.events[..6],[2,3,4,9,5,9]);
        let receipt=proof.receipt();
        assert_eq!(gate.confirm(ticket,receipt,scratch.image(),|t,r|proof.verifies(t,r)),
            Ok(crate::security::durable_role_epoch_v0199::Outcome::Boot{epoch:1}));
        assert_eq!(gate.boot_epoch(),Some(1));
    }
}

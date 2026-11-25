//! V0.19.10 candidate: protected restore/reopen fence, not a media ABI.
//! The filesystem owner supplies the actual durable freeze, historical root,
//! ACL/receipt/resource projection and transaction evidence. This component
//! cannot mount a snapshot or clear an UNKNOWN journal obligation. No AI
//! role or ordinary FileCap can construct recovery authority.
use super::{Error,file_index_v0199::validate_snapshot_restore_system_projection};
use crate::control_plane::Identity;
use sha2::{Digest,Sha256};
fn hash(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct View{
    pub fs_uuid:[u8;16],pub live_epoch:u64,pub protection_generation:u64,
    pub root_hash:[u8;32],pub retention_watermark:u64,
}
impl View{fn valid(self)->bool{
    self.fs_uuid!=[0;16]&&self.live_epoch!=0&&self.protection_generation!=0&&self.root_hash!=[0;32]
}}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct SnapshotKey{
    pub fs_uuid:[u8;16],pub snapshot_id:u64,pub slot:u16,pub generation:u64,
    pub root_hash:[u8;32],
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct RestoreKey{pub principal:Identity,pub request_seq:u64}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Prepared{
    pub key:RestoreKey,pub snapshot:SnapshotKey,pub prior:View,pub next_live_epoch:u64,
    pub system_index_hash:[u8;32],pub security_hash:[u8;32],pub request_hash:[u8;32],
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Commit{
    pub key:RestoreKey,pub txid:u64,pub log_epoch:u64,pub commit_lsn:u64,
    pub view:View,pub request_hash:[u8;32],
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Phase{Frozen,PreparingUnknown,Prepared,Unknown,RestoredFrozen,Open}
pub struct RestoreGate{
    recovery:Identity,reopen:Identity,view:View,phase:Phase,
    pending:Option<Prepared>,last:Option<(Prepared,Commit)>,
}
impl RestoreGate{
    /// Actual native file owner must already have closed new write
    /// admission and proved the durable freeze/protection generation.
    pub fn from_frozen(view:View,recovery:Identity,reopen:Identity,
        verify_durable_freeze:impl FnOnce(View)->Result<(),Error>)->Result<Self,Error>{
        // Independent reopen authority must not be the same registered
        // principal (including a later generation of the recovery role).
        if !view.valid()||!recovery.valid()||!reopen.valid()||recovery.id==reopen.id{return Err(Error::Invalid);}
        verify_durable_freeze(view)?;
        Ok(Self{recovery,reopen,view,phase:Phase::Frozen,pending:None,last:None})
    }
    pub fn phase(&self)->Phase{self.phase}
    pub fn view(&self)->View{self.view}
    pub fn may_write(&self,epoch:u64,protection:u64)->bool{
        self.phase==Phase::Open&&epoch==self.view.live_epoch&&protection==self.view.protection_generation
    }
    /// The native protected owner attests exact persisted preparation,
    /// valid historical root, explicit handling of accepted writes, live
    /// view revocation, actual capacity and current independent policy.
    /// These cannot be supplied by a model or by this record alone.
    pub fn prepare(&mut self,actor:Identity,key:RestoreKey,snapshot:SnapshotKey,
        request_hash:[u8;32],index:&[u8],security:&[u8],
        verify_native_prepare:impl FnOnce(&Prepared)->Result<(),Error>)->Result<Prepared,Error>{
        if actor!=self.recovery{return Err(Error::Unauthorized);}
        if let Some((p,_))=self.last{
            if p.key==key{
                return if p.request_hash==request_hash&&p.snapshot==snapshot{Ok(p)}else{Err(Error::Conflict)};
            }
            return Err(Error::Busy);
        }
        if let Some(p)=self.pending{
            if p.key!=key{return Err(Error::Busy);}
            if p.request_hash!=request_hash||p.snapshot!=snapshot{return Err(Error::Conflict);}
            return if self.phase==Phase::Prepared{Ok(p)}else{Err(Error::Unknown)};
        }
        if self.phase!=Phase::Frozen||!key.principal.valid()||key.request_seq==0
            ||snapshot.fs_uuid!=self.view.fs_uuid||snapshot.snapshot_id==0||snapshot.generation==0
            ||snapshot.root_hash==[0;32]||request_hash==[0;32]{return Err(Error::Invalid);}
        validate_snapshot_restore_system_projection(self.view.fs_uuid,index,security,index,security)?;
        let p=Prepared{key,snapshot,prior:self.view,next_live_epoch:self.view.live_epoch.checked_add(1).ok_or(Error::Exhausted)?,
            system_index_hash:hash(index),security_hash:hash(security),request_hash};
        // The preparation callback may have written a durable record
        // before its reply was lost. Close the retry gate BEFORE invoking it.
        self.pending=Some(p);self.phase=Phase::PreparingUnknown;
        verify_native_prepare(&p)?;
        self.phase=Phase::Prepared;Ok(p)
    }
    /// Read-only reconciliation of an ambiguous preparation. Do not invoke
    /// the original prepare writer again. The storage owner must prove the
    /// exact retained record is durable; otherwise the gate stays closed.
    pub fn reconcile_prepare(&mut self,actor:Identity,key:RestoreKey,request_hash:[u8;32],
        verify_prepared:impl FnOnce(&Prepared)->Result<(),Error>)->Result<Prepared,Error>{
        if actor!=self.recovery{return Err(Error::Unauthorized);}
        if self.phase!=Phase::PreparingUnknown{return Err(Error::Busy);}
        let p=self.pending.ok_or(Error::Unknown)?;
        if p.key!=key||p.request_hash!=request_hash{return Err(Error::Conflict);}
        verify_prepared(&p)?;
        self.phase=Phase::Prepared;Ok(p)
    }
    /// Before the possibly side-effecting commit, mark UNKNOWN. Any
    /// failure retains the same request and cannot initiate another write.
    pub fn submit(&mut self,actor:Identity,ticket:Prepared,
        native_commit:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if actor!=self.recovery{return Err(Error::Unauthorized);}
        if self.pending!=Some(ticket)||self.phase!=Phase::Prepared{return Err(Error::Busy);}
        self.phase=Phase::Unknown;
        native_commit()
    }
    /// Confirm or reconcile the exact transaction with independent
    /// durable proof. No open writes on success; old LIVE epoch retired.
    pub fn confirm(&mut self,actor:Identity,ticket:Prepared,commit:Commit,
        current_index:&[u8],current_security:&[u8],projected_index:&[u8],projected_security:&[u8],
        verify_commit:impl FnOnce(&Prepared,&Commit)->Result<(),Error>)->Result<View,Error>{
        if actor!=self.recovery{return Err(Error::Unauthorized);}
        if let Some((old,saved))=self.last{
            return if old==ticket&&saved==commit{Ok(saved.view)}else{Err(Error::Conflict)};
        }
        if self.phase!=Phase::Unknown||self.pending!=Some(ticket){return Err(Error::Busy);}
        let v=commit.view;
        if commit.key!=ticket.key||commit.request_hash!=ticket.request_hash||commit.txid==0||commit.log_epoch==0
            ||commit.commit_lsn==0||!v.valid()||v.fs_uuid!=ticket.prior.fs_uuid||v.live_epoch!=ticket.next_live_epoch
            ||v.root_hash!=ticket.snapshot.root_hash||v.protection_generation<ticket.prior.protection_generation
            ||v.retention_watermark<ticket.prior.retention_watermark{
            return Err(Error::Conflict);
        }
        // This restricted candidate rejects concurrent system-state
        // changes. G1 may later define a proven merge, never rollback.
        if hash(current_index)!=ticket.system_index_hash||hash(current_security)!=ticket.security_hash{
            return Err(Error::Conflict);
        }
        validate_snapshot_restore_system_projection(v.fs_uuid,current_index,current_security,projected_index,projected_security)?;
        verify_commit(&ticket,&commit)?;
        self.view=v;self.last=Some((ticket,commit));self.pending=None;
        self.phase=Phase::RestoredFrozen;Ok(v)
    }
    /// Independent deterministic open-writes capability, current
    /// protection and actual persisted completion; never an implicit ACK.
    pub fn reopen(&mut self,actor:Identity,expected:View,
        verify_open:impl FnOnce(View,Commit)->Result<(),Error>)->Result<(),Error>{
        if actor!=self.reopen{return Err(Error::Unauthorized);}
        if self.phase!=Phase::RestoredFrozen||expected!=self.view||self.pending.is_some(){return Err(Error::Busy);}
        let (_,c)=self.last.ok_or(Error::Unknown)?;
        verify_open(expected,c)?;
        self.phase=Phase::Open;Ok(())
    }
}

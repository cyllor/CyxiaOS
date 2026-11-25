//! V0.19.10 candidate GC custody, independent of any unfrozen media ABI.
//! The real file owner must establish a frozen, complete census of every
//! live/history/system root and every pin, accepted transaction, DMA and
//! UNKNOWN obligation. A missing bitmap or unauthenticated census is not
//! proof of unreachability. No actual storage write or allocator grant here.
//! Internal bounded batch size is an implementation limit, not a new schema.
use super::{Error,file_media_v0199::BLOCK_COUNT};
use crate::control_plane::Identity;
use sha2::{Digest,Sha256};

pub const MAP_BYTES:usize=BLOCK_COUNT as usize/8;
pub const BATCH:usize=128;
type Bitmap=[u8;MAP_BYTES];

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Census{
    pub fs_uuid:[u8;16],pub live_epoch:u64,pub protection_generation:u64,
    pub catalog_generation:u64,pub bitmap_generation:u64,pub retention_watermark:u64,
    pub roots_digest:[u8;32],pub allocated_digest:[u8;32],
    pub reachable_digest:[u8;32],pub blocked_digest:[u8;32],
}
impl Census{
    fn valid(self)->bool{
        self.fs_uuid!=[0;16]&&self.live_epoch!=0&&self.protection_generation!=0
            &&self.catalog_generation!=0&&self.bitmap_generation!=0&&self.roots_digest!=[0;32]
    }
}
#[derive(Clone,Copy)]
pub struct Maps<'a>{pub allocated:&'a Bitmap,pub reachable:&'a Bitmap,pub blocked:&'a Bitmap}
fn hash(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn has(map:&Bitmap,b:u32)->bool{map[b as usize/8]&(1<<(b%8))!=0}
fn check(c:Census,m:&Maps<'_>)->Result<(),Error>{
    if !c.valid()||hash(m.allocated)!=c.allocated_digest||hash(m.reachable)!=c.reachable_digest
        ||hash(m.blocked)!=c.blocked_digest{return Err(Error::Conflict);}
    // Reachable or blocked allocations may not be advertised as free.
    for ((a,r),b) in m.allocated.iter().zip(m.reachable).zip(m.blocked){
        if (*r|*b)&!*a!=0{return Err(Error::Conflict);}
    }
    Ok(())
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Batch{
    census:Census,blocks:[u32;BATCH],len:u16,
}
impl Batch{
    pub fn census(&self)->Census{self.census}
    pub fn blocks(&self)->&[u32]{&self.blocks[..usize::from(self.len)]}
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Commit{
    pub txid:u64,pub log_epoch:u64,pub commit_lsn:u64,pub checkpoint_lsn:u64,
    pub after:Census,
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Phase{Prepared,Unknown,Committed}
pub struct Gate{owner:Identity,supervisor:Identity,batch:Batch,phase:Phase,commit:Option<Commit>,handed_off:u128,handoff_unknown:u128}
impl Gate{
    /// Select only explicitly enumerated, sorted candidate blocks. The
    /// media owner supplies the eligible business region/ownership proof;
    /// this code intentionally does not guess v1/v2 data_start or treat
    /// all allocated but unmarked bits as business blocks.
    pub fn prepare(owner:Identity,supervisor:Identity,census:Census,maps:&Maps<'_>,
        candidates:&[u32],
        verify_frozen_complete:impl FnOnce(Census,&Maps<'_>,&[u32])->Result<(),Error>,
    )->Result<Self,Error>{
        if !owner.valid()||!supervisor.valid()||owner.id==supervisor.id
            ||candidates.is_empty()||candidates.len()>BATCH{return Err(Error::Invalid);}
        check(census,maps)?;
        for (i,&b) in candidates.iter().enumerate(){
            if b>=BLOCK_COUNT||i>0&&candidates[i-1]>=b{return Err(Error::Invalid);}
            if !has(maps.allocated,b)||has(maps.reachable,b)||has(maps.blocked,b){return Err(Error::Conflict);}
        }
        // Independently prove complete roots, native block eligibility,
        // closed root removal/reallocation and no older GC obligations.
        verify_frozen_complete(census,maps,candidates)?;
        let mut blocks=[0;BATCH];blocks[..candidates.len()].copy_from_slice(candidates);
        Ok(Self{owner,supervisor,batch:Batch{census,blocks,len:candidates.len() as u16},
            phase:Phase::Prepared,commit:None,handed_off:0,handoff_unknown:0})
    }
    /// Restore the prior exact candidate batch after a lost commit or
    /// reboot, never as a fresh Prepared writer. The history verifier
    /// authenticates the original preimage census, batch and durable
    /// obligation; live allocator admission remains closed.
    pub fn recover_unknown(owner:Identity,supervisor:Identity,census:Census,before:&Maps<'_>,
        candidates:&[u32],verify_retained:impl FnOnce(Census,&Maps<'_>,&[u32])->Result<(),Error>,
    )->Result<Self,Error>{
        let mut g=Self::prepare(owner,supervisor,census,before,candidates,verify_retained)?;
        g.phase=Phase::Unknown;Ok(g)
    }
    /// Reconstruct a committed batch with its exact allocator handoff
    /// history. The original checkpoint/bitmap evidence is historical;
    /// the independent recovery scan must authenticate every already
    /// transferred bit, including allocations subsequently made from it.
    /// Never reset this mask merely because the process restarted.
    /// A missing or ambiguous handoff history must keep allocation closed.
    pub fn recover_committed(owner:Identity,supervisor:Identity,census:Census,before:&Maps<'_>,
        candidates:&[u32],receipt:Commit,after:&Maps<'_>,handed_off:u128,handoff_unknown:u128,
        verify_history:impl FnOnce(&Batch,Commit,u128,u128)->Result<(),Error>,
    )->Result<Self,Error>{
        if candidates.is_empty()||candidates.len()>BATCH{return Err(Error::Invalid);}
        let allowed=if candidates.len()==128{u128::MAX}else{(1u128<<candidates.len())-1};
        if (handed_off|handoff_unknown)&!allowed!=0||handed_off&handoff_unknown!=0{return Err(Error::Conflict);}
        // This local constructor performs structural checks only. No
        // capability escapes until the complete independent history proof.
        let mut g=Self::recover_unknown(owner,supervisor,census,before,candidates,|_,_,_|Ok(()))?;
        let batch=g.batch();
        g.confirm(supervisor,batch,receipt,before,after,|b,c|verify_history(b,c,handed_off,handoff_unknown))?;
        g.handed_off=handed_off;g.handoff_unknown=handoff_unknown;Ok(g)
    }
    pub fn phase(&self)->Phase{self.phase}
    pub fn batch(&self)->Batch{self.batch}
    /// Recheck exact frozen census just before one side-effecting journal
    /// transaction. Any uncertain write retains the same batch and fences
    /// allocation. No second writer, even under an identical request.
    pub fn submit(&mut self,actor:Identity,expected:Batch,current:Census,maps:&Maps<'_>,
        verify_current_freeze:impl FnOnce(Census)->Result<(),Error>,
        native_commit:impl FnOnce(&Batch)->Result<(),Error>,
    )->Result<(),Error>{
        if actor!=self.owner{return Err(Error::Unauthorized);}
        if self.phase!=Phase::Prepared{return Err(Error::Busy);}
        if expected!=self.batch||current!=self.batch.census{return Err(Error::Conflict);}
        check(current,maps)?;
        verify_current_freeze(current)?;
        self.phase=Phase::Unknown;
        native_commit(&self.batch)
    }
    /// Exact bitwise after-image, same complete reachability/pin census,
    /// independently confirmed redo, FLUSH, checkpoint, cache invalidation
    /// and device quiescence. A callback must NOT make more GC writes.
    /// No allocator may reuse a block before this succeeds.
    pub fn confirm(&mut self,actor:Identity,expected:Batch,receipt:Commit,
        before:&Maps<'_>,after:&Maps<'_>,
        verify_durable_and_quiet:impl FnOnce(&Batch,Commit)->Result<(),Error>,
    )->Result<(),Error>{
        if actor!=self.supervisor{return Err(Error::Unauthorized);}
        if expected!=self.batch{return Err(Error::Conflict);}
        if let Some(old)=self.commit{
            return if old==receipt{Ok(())}else{Err(Error::Conflict)};
        }
        if self.phase!=Phase::Unknown{return Err(Error::Busy);}
        let old=self.batch.census;let new=receipt.after;
        check(old,before)?;check(new,after)?;
        if receipt.txid==0||receipt.log_epoch==0||receipt.commit_lsn==0
            ||receipt.checkpoint_lsn<receipt.commit_lsn
            ||old.bitmap_generation.checked_add(1)!=Some(new.bitmap_generation)
            ||(Census{bitmap_generation:old.bitmap_generation,allocated_digest:old.allocated_digest,..new})!=old{
            return Err(Error::Conflict);
        }
        // All and only the selected allocated bits may clear. No extra
        // allocation, root/pin changes or hidden bitmap edits in this proof.
        let mut cursor=0;
        for i in 0..MAP_BYTES{
            let mut mask=0u8;
            while cursor<self.batch.blocks().len()&&self.batch.blocks()[cursor] as usize/8==i{
                mask|=1<<(self.batch.blocks()[cursor]%8);cursor+=1;
            }
            if after.allocated[i]!=before.allocated[i]&!mask{return Err(Error::Conflict);}
        }
        if cursor!=self.batch.blocks().len(){return Err(Error::Conflict);}
        verify_durable_and_quiet(&self.batch,receipt)?;
        self.commit=Some(receipt);self.phase=Phase::Committed;Ok(())
    }
    /// Eligibility is not a new allocation grant. Transfer each block to
    /// the actual allocator at most once after checking current bitmap
    /// generation, allocator ownership and physical quiescence. The callback
    /// is an atomic metadata handoff: non-UNKNOWN Err proves no effect;
    /// UNKNOWN is sticky until independent allocator reconciliation.
    pub fn reusable(&self,block:u32)->bool{
        self.phase==Phase::Committed&&self.batch.blocks().binary_search(&block)
            .is_ok_and(|i|(self.handed_off|self.handoff_unknown)&(1u128<<i)==0)
    }
    pub fn handoff_once(&mut self,actor:Identity,block:u32,
        transfer_native:impl FnOnce(u32,Commit)->Result<(),Error>)->Result<(),Error>{
        if actor!=self.supervisor{return Err(Error::Unauthorized);}
        if self.phase!=Phase::Committed{return Err(Error::Busy);}
        let i=self.batch.blocks().binary_search(&block).map_err(|_|Error::Invalid)?;
        let bit=1u128<<i;
        if self.handed_off&bit!=0{return Err(Error::Stale);}
        if self.handoff_unknown&bit!=0{return Err(Error::Unknown);}
        let commit=self.commit.ok_or(Error::Unknown)?;
        // Transfer callback is permitted to lose its reply. UNKNOWN is
        // not the same as a proven atomic no-effect rejection.
        self.handoff_unknown|=bit;
        match transfer_native(block,commit){
            Ok(())=>{self.handed_off|=bit;self.handoff_unknown&=!bit;Ok(())}
            Err(Error::Unknown)=>Err(Error::Unknown),
            Err(e)=>{self.handoff_unknown&=!bit;Err(e)}
        }
    }
    /// Reconcile without another allocator handoff. Only the independent
    /// current allocator census can establish transfer or prove no effect.
    pub fn reconcile_handoff(&mut self,actor:Identity,block:u32,transferred:bool,
        verify_current:impl FnOnce(u32,Commit,bool)->Result<(),Error>)->Result<(),Error>{
        if actor!=self.supervisor{return Err(Error::Unauthorized);}
        if self.phase!=Phase::Committed{return Err(Error::Busy);}
        let i=self.batch.blocks().binary_search(&block).map_err(|_|Error::Invalid)?;
        let bit=1u128<<i;
        if self.handoff_unknown&bit==0{return Err(Error::Stale);}
        verify_current(block,self.commit.ok_or(Error::Unknown)?,transferred)?;
        if transferred{self.handed_off|=bit;}
        self.handoff_unknown&=!bit;Ok(())
    }

}
const _:()=assert!(core::mem::size_of::<Gate>()<2048);

#[cfg(test)]
mod tests{
    use super::*;
    const OWNER:Identity=Identity{id:4,generation:1};
    const SUP:Identity=Identity{id:11,generation:1};
    fn set(m:&mut Bitmap,b:u32){m[b as usize/8]|=1<<(b%8);}
    fn clear(m:&mut Bitmap,b:u32){m[b as usize/8]&=!(1<<(b%8));}
    fn census(m:&Maps<'_>)->Census{
        Census{fs_uuid:[1;16],live_epoch:3,protection_generation:4,catalog_generation:5,
            bitmap_generation:6,retention_watermark:7,roots_digest:[8;32],
            allocated_digest:hash(m.allocated),reachable_digest:hash(m.reachable),blocked_digest:hash(m.blocked)}
    }
    #[test]
    fn complete_census_and_exact_bitmap_delta_required_before_reuse(){
        let mut allocated=[0;MAP_BYTES];let mut reachable=[0;MAP_BYTES];let mut blocked=[0;MAP_BYTES];
        for b in [7000,7001,7002,7003,7004]{set(&mut allocated,b);}
        set(&mut reachable,7001);set(&mut blocked,7002);
        let before=Maps{allocated:&allocated,reachable:&reachable,blocked:&blocked};
        let c=census(&before);
        for b in [7001,7002,7005]{
            assert!(matches!(Gate::prepare(OWNER,SUP,c,&before,&[b],|_,_,_|panic!()),Err(Error::Conflict)));
        }
        assert!(matches!(Gate::prepare(OWNER,SUP,c,&before,&[7003,7000],|_,_,_|panic!()),Err(Error::Invalid)));
        assert!(matches!(Gate::prepare(OWNER,SUP,c,&before,&[7000,7003],|_,_,_|Err(Error::Unknown)),Err(Error::Unknown)));
        let mut g=Gate::prepare(OWNER,SUP,c,&before,&[7000,7003],|v,_,b|{
            assert_eq!(v,c);assert_eq!(b,&[7000,7003]);Ok(())
        }).unwrap();
        let batch=g.batch();assert!(!g.reusable(7000));
        assert_eq!(g.submit(OWNER,batch,Census{catalog_generation:6,..c},&before,|_|panic!(),|_|panic!()),Err(Error::Conflict));
        assert_eq!(g.submit(OWNER,batch,c,&before,|_|Ok(()),|_|Err(Error::Unknown)),Err(Error::Unknown));
        assert_eq!(g.submit(OWNER,batch,c,&before,|_|panic!(),|_|panic!()),Err(Error::Busy));
        // Crash recovery cannot reissue the lost GC transaction.
        let mut g=Gate::recover_unknown(OWNER,SUP,c,&before,batch.blocks(),|_,_,_|Ok(())).unwrap();
        assert_eq!(g.submit(OWNER,batch,c,&before,|_|panic!(),|_|panic!()),Err(Error::Busy));
        let mut next=allocated;clear(&mut next,7000);clear(&mut next,7003);
        let after=Maps{allocated:&next,reachable:&reachable,blocked:&blocked};
        let new=Census{bitmap_generation:7,..census(&after)};
        let commit=Commit{txid:1,log_epoch:1,commit_lsn:3,checkpoint_lsn:3,after:new};
        let mut bad=next;clear(&mut bad,7004);
        let invalid=Maps{allocated:&bad,..after};
        let bad_commit=Commit{after:Census{bitmap_generation:7,..census(&invalid)},..commit};
        assert_eq!(g.confirm(SUP,batch,bad_commit,&before,&invalid,|_,_|panic!()),Err(Error::Conflict));
        assert_eq!(g.confirm(SUP,batch,Commit{checkpoint_lsn:2,..commit},&before,&after,|_,_|panic!()),Err(Error::Conflict));
        assert_eq!(g.confirm(OWNER,batch,commit,&before,&after,|_,_|panic!()),Err(Error::Unauthorized));
        assert_eq!(g.confirm(SUP,batch,commit,&before,&after,|_,_|Err(Error::Unknown)),Err(Error::Unknown));
        assert!(!g.reusable(7000));
        g.confirm(SUP,batch,commit,&before,&after,|b,r|{assert_eq!(b.blocks(),&[7000,7003]);assert_eq!(r,commit);Ok(())}).unwrap();
        assert!(g.reusable(7000)&&g.reusable(7003));assert!(!g.reusable(7001)&&!g.reusable(7004));
        assert_eq!(g.handoff_once(SUP,7000,|_,_|Err(Error::Busy)),Err(Error::Busy));
        assert!(g.reusable(7000));
        g.handoff_once(SUP,7000,|b,r|{assert_eq!(b,7000);assert_eq!(r,commit);Ok(())}).unwrap();
        assert!(!g.reusable(7000));assert_eq!(g.handoff_once(SUP,7000,|_,_|panic!()),Err(Error::Stale));
        assert_eq!(g.handoff_once(OWNER,7003,|_,_|panic!()),Err(Error::Unauthorized));
        let owner2=Identity{generation:2,..OWNER};
        let sup2=Identity{generation:2,..SUP};
        assert!(matches!(Gate::recover_committed(owner2,sup2,c,&before,batch.blocks(),commit,&after,4,0,
            |_,_,_,_|panic!()),Err(Error::Conflict)));
        assert!(matches!(Gate::recover_committed(owner2,sup2,c,&before,batch.blocks(),commit,&after,1,0,
            |_,_,_,_|Err(Error::Unknown)),Err(Error::Unknown)));
        let mut recovered=Gate::recover_committed(owner2,sup2,c,&before,batch.blocks(),commit,&after,1,0,
            |b,r,mask,unknown|{assert_eq!(*b,batch);assert_eq!(r,commit);assert_eq!((mask,unknown),(1,0));Ok(())}).unwrap();
        assert!(!recovered.reusable(7000));assert!(recovered.reusable(7003));
        assert_eq!(recovered.handoff_once(SUP,7003,|_,_|panic!()),Err(Error::Unauthorized));
        assert_eq!(recovered.handoff_once(sup2,7000,|_,_|panic!()),Err(Error::Stale));
        assert_eq!(recovered.handoff_once(sup2,7003,|_,_|Err(Error::Unknown)),Err(Error::Unknown));
        assert!(!recovered.reusable(7003));
        assert_eq!(recovered.handoff_once(sup2,7003,|_,_|panic!()),Err(Error::Unknown));
        assert_eq!(recovered.reconcile_handoff(sup2,7003,true,|_,_,_|Err(Error::Unknown)),Err(Error::Unknown));
        assert!(matches!(Gate::recover_committed(owner2,sup2,c,&before,batch.blocks(),commit,&after,1,1,
            |_,_,_,_|panic!()),Err(Error::Conflict)));
        let mut rebooted=Gate::recover_committed(owner2,sup2,c,&before,batch.blocks(),commit,&after,1,2,
            |_,_,done,unknown|{assert_eq!((done,unknown),(1,2));Ok(())}).unwrap();
        assert!(!rebooted.reusable(7003));
        rebooted.reconcile_handoff(sup2,7003,true,|block,receipt,transferred|{
            assert_eq!((block,receipt,transferred),(7003,commit,true));Ok(())
        }).unwrap();
        assert_eq!(rebooted.handoff_once(sup2,7003,|_,_|panic!()),Err(Error::Stale));
    }
}

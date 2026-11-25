//! Conservative V0.19.10 COW protection projection, no new media ABI.
//! All business blocks changed by this restricted transaction are newly
//! allocated. The protected file owner authenticates complete live and
//! historical roots, extent mappings, allocation ownership, and exact
//! journal write-set (including system metadata); this module cannot
//! infer any of those from a model or a bare digest.
use super::{Error,file_media_v0199::BLOCK_COUNT,snapshot_gc_gate::MAP_BYTES};
use crate::control_plane::Identity;
use sha2::{Digest,Sha256};
const MAX_NEW:usize=128;
type Bitmap=[u8;MAP_BYTES];
fn hash(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn has(m:&Bitmap,b:u32)->bool{m[b as usize/8]&(1<<(b%8))!=0}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct View{
    pub fs_uuid:[u8;16],pub live_epoch:u64,pub protection_generation:u64,
    pub catalog_generation:u64,pub bitmap_generation:u64,
    pub live_root:[u8;32],pub history_roots:[u8;32],
    pub allocated:[u8;32],pub historical:[u8;32],
}
impl View{
    fn valid(self)->bool{
        self.fs_uuid!=[0;16]&&self.live_epoch!=0&&self.protection_generation!=0
            &&self.catalog_generation!=0&&self.bitmap_generation!=0
            &&self.live_root!=[0;32]&&self.history_roots!=[0;32]
    }
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Ticket{
    prior:View,key:[u8;32],blocks:[u32;MAX_NEW],len:u16,
}
impl Ticket{
    pub fn prior(&self)->View{self.prior}
    pub fn key(&self)->[u8;32]{self.key}
    pub fn blocks(&self)->&[u32]{&self.blocks[..self.len as usize]}
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Commit{pub view:View,pub txid:u64,pub log_epoch:u64,pub commit_lsn:u64}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Phase{Prepared,Unknown,Committed}
pub struct Gate{owner:Identity,supervisor:Identity,ticket:Ticket,phase:Phase,commit:Option<Commit>}
fn check(v:View,allocated:&Bitmap,history:&Bitmap)->Result<(),Error>{
    if !v.valid()||hash(allocated)!=v.allocated||hash(history)!=v.historical{
        return Err(Error::Conflict);
    }
    if allocated.iter().zip(history).any(|(a,h)|*h&!*a!=0){return Err(Error::Conflict);}
    Ok(())
}
impl Gate{
    pub fn prepare(owner:Identity,supervisor:Identity,view:View,key:[u8;32],
        allocated:&Bitmap,history:&Bitmap,new_blocks:&[u32],
        verify_free_and_roots:impl FnOnce(View,&Bitmap,&Bitmap,&[u32])->Result<(),Error>,
    )->Result<Self,Error>{
        if !owner.valid()||!supervisor.valid()||owner.id==supervisor.id||key==[0;32]
            ||new_blocks.is_empty()||new_blocks.len()>MAX_NEW{return Err(Error::Invalid);}
        check(view,allocated,history)?;
        if view.live_epoch==u64::MAX||view.bitmap_generation==u64::MAX{return Err(Error::Exhausted);}
        for (i,&b) in new_blocks.iter().enumerate(){
            if b>=BLOCK_COUNT||i>0&&new_blocks[i-1]>=b{return Err(Error::Invalid);}
            if has(allocated,b)||has(history,b){return Err(Error::Conflict);}
        }
        // Prove no other reservation/UNKNOWN or DMA owner, complete
        // history census and business-only region; never guess data_start.
        verify_free_and_roots(view,allocated,history,new_blocks)?;
        let mut blocks=[0;MAX_NEW];blocks[..new_blocks.len()].copy_from_slice(new_blocks);
        Ok(Self{owner,supervisor,ticket:Ticket{prior:view,key,blocks,len:new_blocks.len() as u16},
            phase:Phase::Prepared,commit:None})
    }
    pub fn ticket(&self)->Ticket{self.ticket}
    pub fn phase(&self)->Phase{self.phase}
    pub fn recover_unknown(owner:Identity,supervisor:Identity,view:View,key:[u8;32],
        allocated:&Bitmap,history:&Bitmap,new_blocks:&[u32],
        verify_retained:impl FnOnce(View,&Bitmap,&Bitmap,&[u32])->Result<(),Error>,
    )->Result<Self,Error>{
        let mut g=Self::prepare(owner,supervisor,view,key,allocated,history,new_blocks,verify_retained)?;
        g.phase=Phase::Unknown;Ok(g)
    }
    pub fn submit(&mut self,actor:Identity,t:Ticket,current:View,allocated:&Bitmap,history:&Bitmap,
        verify_frozen:impl FnOnce(&Ticket)->Result<(),Error>,
        write_once:impl FnOnce(&Ticket)->Result<(),Error>,
    )->Result<(),Error>{
        if actor!=self.owner{return Err(Error::Unauthorized);}
        if self.phase!=Phase::Prepared{return Err(Error::Busy);}
        if t!=self.ticket||current!=t.prior{return Err(Error::Conflict);}
        check(current,allocated,history)?;verify_frozen(&t)?;
        self.phase=Phase::Unknown;write_once(&t)
    }
    /// Independent exact after-image and write-set proof. All previous
    /// allocations stay owned (GC is separate), historical root and map
    /// remain unchanged; all and only the reserved new blocks are allocated.
    /// The verifier checks actual written homes, unchanged protected
    /// metadata, new root integrity, and durable native commit/FLUSH.
    pub fn confirm(&mut self,actor:Identity,t:Ticket,c:Commit,before:&Bitmap,after:&Bitmap,history:&Bitmap,
        verify_native:impl FnOnce(&Ticket,Commit)->Result<(),Error>,
    )->Result<(),Error>{
        if actor!=self.supervisor{return Err(Error::Unauthorized);}
        if t!=self.ticket{return Err(Error::Conflict);}
        if let Some(old)=self.commit{return if old==c{Ok(())}else{Err(Error::Conflict)};}
        if self.phase!=Phase::Unknown{return Err(Error::Busy);}
        check(t.prior,before,history)?;check(c.view,after,history)?;
        let old=t.prior;let new=c.view;
        if c.txid==0||c.log_epoch==0||c.commit_lsn==0
            ||old.live_epoch.checked_add(1)!=Some(new.live_epoch)
            ||old.bitmap_generation.checked_add(1)!=Some(new.bitmap_generation)
            ||new.live_root==old.live_root
            ||(View{live_epoch:old.live_epoch,bitmap_generation:old.bitmap_generation,
                live_root:old.live_root,allocated:old.allocated,..new})!=old{return Err(Error::Conflict);}
        let mut cursor=0;
        for i in 0..MAP_BYTES{
            let mut mask=0u8;
            while cursor<t.blocks().len()&&t.blocks()[cursor] as usize/8==i{
                mask|=1<<(t.blocks()[cursor]%8);cursor+=1;
            }
            if after[i]!=before[i]|mask{return Err(Error::Conflict);}
        }
        if cursor!=t.blocks().len(){return Err(Error::Conflict);}
        verify_native(&t,c)?;
        self.commit=Some(c);self.phase=Phase::Committed;Ok(())
    }
    /// Read-only confirmed root handoff; actual publication belongs to
    /// the native file owner and must invalidate prior live handles.
    pub fn committed(&self)->Option<View>{self.commit.map(|c|c.view)}
}
const _:()=assert!(core::mem::size_of::<Gate>()<2048);
#[cfg(test)]
mod tests{
    use super::*;
    const OWNER:Identity=Identity{id:4,generation:1};
    const SUP:Identity=Identity{id:11,generation:1};
    fn set(m:&mut Bitmap,b:u32){m[b as usize/8]|=1<<(b%8);}
    #[test]
    fn cow_preserves_history_and_only_adds_reserved_blocks_across_unknown(){
        let mut before=[0;MAP_BYTES];let mut history=[0;MAP_BYTES];
        set(&mut before,7000);set(&mut before,7001);set(&mut history,7000);
        let v=View{fs_uuid:[1;16],live_epoch:1,protection_generation:2,catalog_generation:3,
            bitmap_generation:4,live_root:[5;32],history_roots:[6;32],allocated:hash(&before),historical:hash(&history)};
        assert!(matches!(Gate::prepare(OWNER,SUP,v,[7;32],&before,&history,&[7000],|_,_,_,_|panic!()),Err(Error::Conflict)));
        let mut g=Gate::prepare(OWNER,SUP,v,[7;32],&before,&history,&[7002,7003],|_,_,_,_|Ok(())).unwrap();
        let t=g.ticket();assert_eq!(g.submit(OWNER,t,v,&before,&history,|_|Ok(()),|_|Err(Error::Unknown)),Err(Error::Unknown));
        let mut g=Gate::recover_unknown(OWNER,SUP,v,[7;32],&before,&history,&[7002,7003],|_,_,_,_|Ok(())).unwrap();
        assert_eq!(g.submit(OWNER,t,v,&before,&history,|_|panic!(),|_|panic!()),Err(Error::Busy));
        let mut after=before;set(&mut after,7002);set(&mut after,7003);
        let new=View{live_epoch:2,bitmap_generation:5,live_root:[8;32],allocated:hash(&after),..v};
        let c=Commit{view:new,txid:1,log_epoch:1,commit_lsn:4};
        assert_eq!(g.confirm(SUP,t,Commit{view:View{history_roots:[9;32],..new},..c},&before,&after,&history,|_,_|panic!()),Err(Error::Conflict));
        let mut bad=after;set(&mut bad,7004);
        assert_eq!(g.confirm(SUP,t,Commit{view:View{allocated:hash(&bad),..new},..c},&before,&bad,&history,|_,_|panic!()),Err(Error::Conflict));
        assert_eq!(g.confirm(SUP,t,c,&before,&after,&history,|_,_|Err(Error::Unknown)),Err(Error::Unknown));
        assert_eq!(g.committed(),None);
        g.confirm(SUP,t,c,&before,&after,&history,|t,c|{assert_eq!(t.blocks(),&[7002,7003]);assert_eq!(c.view,new);Ok(())}).unwrap();
        assert_eq!(g.committed(),Some(new));
    }
}

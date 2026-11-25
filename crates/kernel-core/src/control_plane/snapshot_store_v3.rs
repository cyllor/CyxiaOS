//! Protected SnapshotReply v3 producer/reader custody. No generated metric
//! may stand in for a missing actual subsystem observation. This table is
//! owned by EL1; architecture adapter must authenticate the current cap,
//! task and target and use a checked copyout. Business code never waits for
//! a model. All 15 domains share the same registration/read mechanism.
use super::{Error,Identity,role_manifest_v0199::{NativeRoleManifest,SnapshotView}};
use cyxia_control_model::native_v0199::{SnapshotReplyV3,MAX_AGE_NS,SNAPSHOT_BYTES};
pub const TARGETS:usize=96;
pub const VIEWS:usize=96;
const FIELD_MASK:u16=0x0f7f;
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Target{pub domain:u16,pub object:Identity,pub owner:Identity}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct ViewGrant{
    pub cap:u64,pub holder:Identity,pub endpoint:u64,pub view:SnapshotView,
    pub selector:u64,pub domain:u16,pub target:Identity,pub allowed_fields:u16,
}
#[derive(Clone,Copy)]
pub struct DomainObservation{pub target:Target,pub fields:[Option<u64>;4]}
#[derive(Clone,Copy)]
// Retired object IDs retain their highest generation within this boot.
// Same-ID replacement can reuse the slot, never the old generation.
struct Row{target:Target,snapshot:Option<SnapshotReplyV3>,active:bool}
pub struct SnapshotStore{
    boot:u64,sequence:u64,last_sample_ns:u64,last_ledger:u64,last_cores:u64,targets:[Option<Row>;TARGETS],grants:[Option<ViewGrant>;VIEWS],
}
impl SnapshotStore{
    pub const fn empty()->Self{Self{boot:0,sequence:0,last_sample_ns:0,last_ledger:0,last_cores:0,targets:[None;TARGETS],grants:[None;VIEWS]}}
    pub fn new(boot:u64)->Result<Self,Error>{
        let mut out=Self::empty();out.bind_boot(boot,||Ok(()))?;Ok(out)
    }
    /// Native static storage starts unbound. Bind once after independently
    /// verified boot confirmation; cannot reset a live registry.
    pub fn bind_boot(&mut self,boot:u64,verify_boot:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if self.boot!=0{return Err(Error::Busy);}
        if boot==0{return Err(Error::Invalid);}
        verify_boot()?;self.boot=boot;Ok(())
    }
    pub fn register_target(&mut self,target:Target,
        verify_native_owner:impl FnOnce(Target)->Result<(),Error>)->Result<(),Error>{
        if self.boot==0{return Err(Error::NotReady);}
        if !(1..=15).contains(&target.domain)||!target.object.valid()||!target.owner.valid(){
            return Err(Error::Denied);
        }
        let old=self.targets.iter().position(|r|r.is_some_and(|r|
            r.target.domain==target.domain&&r.target.object.id==target.object.id));
        let index=if let Some(i)=old{
            let r=self.targets[i].unwrap();
            if r.active{return Err(Error::Busy);}
            if target.object.generation<=r.target.object.generation{return Err(Error::Stale);}
            i
        }else{self.targets.iter().position(Option::is_none).ok_or(Error::Exhausted)?};
        verify_native_owner(target)?;
        self.targets[index]=Some(Row{target,snapshot:None,active:true});Ok(())
    }
    pub fn register_view(&mut self,manifest:&NativeRoleManifest,g:ViewGrant,
        verify_actual_cap:impl FnOnce(ViewGrant)->Result<(),Error>)->Result<(),Error>{
        if self.boot==0{return Err(Error::NotReady);}
        if g.cap==0||g.selector==0||g.allowed_fields==0||g.allowed_fields&!FIELD_MASK!=0
            ||!self.targets.iter().flatten().any(|r|r.active&&r.target.domain==g.domain&&r.target.object==g.target)
            ||self.grants.iter().flatten().any(|v|v.cap==g.cap&&v.selector==g.selector){
            return Err(Error::Denied);
        }
        manifest.check_snapshot_view(g.holder,g.endpoint,0,g.view)?;
        let slot=self.grants.iter_mut().find(|v|v.is_none()).ok_or(Error::Exhausted)?;
        verify_actual_cap(g)?;*slot=Some(g);Ok(())
    }
    /// One frozen common accounting sample plus exact domain-owner
    /// observations. The native caller captures these under the proper
    /// ledger/object lock order; independently verifies live owner and
    /// raw source counters before any new sequence is published.
    pub fn capture(&mut self,ledger:u64,cores:u64,sampled_ns:u64,
        common:[Option<u64>;8],observations:&[DomainObservation],
        mut verify_source:impl FnMut(&DomainObservation)->Result<(),Error>)->Result<u64,Error>{
        if self.boot==0{return Err(Error::NotReady);}
        if ledger==0||cores==0||sampled_ns==0||sampled_ns<self.last_sample_ns||observations.is_empty()
            ||observations.len()>TARGETS||common[6].is_some()||common[7].is_some(){
            return Err(Error::Invalid);
        }
        // Ledger/core generations are native monotonic identities, not
        // merely tags for a caller to reuse after a resource replacement.
        if ledger<self.last_ledger||cores<self.last_cores{return Err(Error::Stale);}
        let seq=self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        // Complete preflight before altering any prior snapshot; no
        // per-target partial new sequence on owner or bounds error.
        let boot=self.boot;
        let make=|o:&DomainObservation|{
            let mut fields=[None;12];fields[..8].copy_from_slice(&common);fields[8..].copy_from_slice(&o.fields);
            SnapshotReplyV3{snapshot_seq:seq,boot_epoch:boot,ledger_generation:ledger,
                core_generation:cores,target_id:o.target.object.id,target_generation:o.target.object.generation,
                sampled_ns,domain:o.target.domain,fields}
        };
        for (i,o) in observations.iter().enumerate(){
            if observations[..i].iter().any(|v|v.target==o.target)
                ||!self.targets.iter().flatten().any(|r|r.active&&r.target==o.target){
                return Err(Error::Denied);
            }
            make(o).encode().map_err(|_|Error::Invalid)?;
            verify_source(o)?;
        }
        // The old batch becomes stale as a whole, including objects not
        // selected in this round. Never mix snapshots across sequences.
        for r in self.targets.iter_mut().flatten(){r.snapshot=None;}
        for o in observations{
            self.targets.iter_mut().flatten().find(|r|r.active&&r.target==o.target)
                .expect("immutable capture preflight").snapshot=Some(make(o));
        }
        self.sequence=seq;self.last_sample_ns=sampled_ns;self.last_ledger=ledger;self.last_cores=cores;Ok(seq)
    }
    /// EL1-only owner handoff of exact captured evidence for candidate
    /// registration. Unlike a redacted user read, preserves the original
    /// snapshot bytes (including absent age) and requires the registered
    /// target/owner, current ledger/core generation and native owner check.
    pub fn frozen_for_owner(&self,target:Target,ledger:u64,cores:u64,now_ns:u64,
        verify_owner:impl FnOnce(Target)->Result<(),Error>)->Result<SnapshotReplyV3,Error>{
        if self.boot==0{return Err(Error::NotReady);}
        let r=self.targets.iter().flatten().find(|r|r.active&&r.target==target).ok_or(Error::Stale)?;
        let snap=r.snapshot.ok_or(Error::NotReady)?;
        if snap.snapshot_seq!=self.sequence||snap.ledger_generation!=ledger||snap.core_generation!=cores
            ||now_ns<snap.sampled_ns||now_ns-snap.sampled_ns>=MAX_AGE_NS{return Err(Error::Stale);}
        verify_owner(target)?;Ok(snap)
    }
    pub fn read(&self,manifest:&NativeRoleManifest,actor:Identity,cpu:usize,cap:u64,
        domain:u16,selector:u64,ledger:u64,cores:u64,now_ns:u64,
        verify_live_cap:impl FnOnce(ViewGrant)->Result<(),Error>)->Result<[u8;SNAPSHOT_BYTES],Error>{
        if self.boot==0{return Err(Error::NotReady);}
        let grant=*self.grants.iter().flatten().find(|g|g.cap==cap&&g.holder==actor
            &&g.selector==selector&&g.domain==domain).ok_or(Error::Denied)?;
        manifest.check_snapshot_view(actor,grant.endpoint,cpu,grant.view)?;
        verify_live_cap(grant)?;
        let r=self.targets.iter().flatten().find(|r|r.active&&r.target.domain==domain&&r.target.object==grant.target)
            .ok_or(Error::Stale)?;
        let mut snap=r.snapshot.ok_or(Error::NotReady)?;
        if snap.snapshot_seq!=self.sequence||snap.ledger_generation!=ledger||snap.core_generation!=cores
            ||now_ns<snap.sampled_ns||now_ns-snap.sampled_ns>=MAX_AGE_NS{return Err(Error::Stale);}
        snap.fields[6]=Some((now_ns-snap.sampled_ns)/1000);
        for (i,v) in snap.fields.iter_mut().enumerate(){
            if grant.allowed_fields&(1<<i)==0{*v=None;}
        }
        snap.encode().map_err(|_|Error::Invalid)
    }
    pub fn revoke_view(&mut self,holder:Identity,cap:u64)->Result<(),Error>{
        let mut found=false;
        for v in &mut self.grants{
            if v.as_ref().is_some_and(|g|g.holder==holder&&g.cap==cap){*v=None;found=true;}
        }
        if found{Ok(())}else{Err(Error::Denied)}
    }
    pub fn retire_target(&mut self,target:Target,
        verify_native_stop:impl FnOnce(Target)->Result<(),Error>)->Result<(),Error>{
        let row=self.targets.iter_mut().flatten().find(|r|r.active&&r.target==target).ok_or(Error::Stale)?;
        verify_native_stop(target)?;
        row.active=false;row.snapshot=None;
        for grant in &mut self.grants{
            if grant.as_ref().is_some_and(|g|g.domain==target.domain&&g.target==target.object){*grant=None;}
        }
        Ok(())
    }
}
const _:()=assert!(core::mem::size_of::<SnapshotStore>()<=64*1024);
#[cfg(test)]
mod tests{
    use super::*;
    use super::super::role_manifest_v0199::{NativeRole,PrivateRegion,ROLES};
    fn manifest()->NativeRoleManifest{
        NativeRoleManifest{online_mask:15,other_protected_pool_bytes:1024,other_control_ns_per_100ms:10,
            members:core::array::from_fn(|i|NativeRole{role:ROLES[i],
                actor:Identity{id:u64::from(ROLES[i].id()),generation:1},ttbr0_root:0x100000+i as u64*4096,
                private_rw:PrivateRegion{base:0x200000+i as u64*4096,bytes:4096},caps:ROLES[i].allowed_caps(),
                control_ns_per_100ms:1,cpu_mask:1,thread_count:1,endpoint_id:10+i as u64})}
    }
    #[test]
    fn resource_generation_regression_does_not_replace_current_batch(){
        let mut s=SnapshotStore::new(7).unwrap();
        let target=Target{domain:2,object:Identity{id:2,generation:1},owner:Identity{id:1,generation:1}};
        s.register_target(target,|_|Ok(())).unwrap();
        let o=DomainObservation{target,fields:[None,Some(1),None,Some(2)]};
        assert_eq!(s.capture(2,3,100,[None;8],&[o],|_|Ok(())),Ok(1));
        assert_eq!(s.capture(1,4,101,[None;8],&[o],|_|panic!()),Err(Error::Stale));
        assert_eq!(s.capture(3,2,101,[None;8],&[o],|_|panic!()),Err(Error::Stale));
        assert_eq!(s.frozen_for_owner(target,2,3,101,|_|Ok(())).unwrap().snapshot_seq,1);
        assert_eq!(s.capture(3,4,102,[None;8],&[o],|_|Ok(())),Ok(2));
    }
    #[test]
    fn native_frozen_snapshot_requires_bound_boot_and_exact_live_owner(){
        let mut s=SnapshotStore::empty();let target=Target{domain:15,object:Identity{id:15,generation:1},
            owner:Identity{id:100,generation:1}};
        assert_eq!(s.register_target(target,|_|panic!()),Err(Error::NotReady));
        assert_eq!(s.bind_boot(1,||Err(Error::Denied)),Err(Error::Denied));
        s.bind_boot(7,||Ok(())).unwrap();
        assert_eq!(s.bind_boot(8,||panic!()),Err(Error::Busy));
        s.register_target(target,|_|Ok(())).unwrap();
        let o=DomainObservation{target,fields:[Some(17),None,None,None]};
        s.capture(2,3,100,[None;8],&[o],|_|Ok(())).unwrap();
        let v=s.frozen_for_owner(target,2,3,101,|_|Ok(())).unwrap();
        assert_eq!(v.boot_epoch,7);assert_eq!(v.snapshot_seq,1);assert_eq!(v.fields[8],Some(17));
        assert_eq!(v.fields[6],None);
        let bad=Target{owner:Identity{generation:2,..target.owner},..target};
        assert!(matches!(s.frozen_for_owner(bad,2,3,101,|_|panic!()),Err(Error::Stale)));
        assert!(matches!(s.frozen_for_owner(target,3,3,101,|_|panic!()),Err(Error::Stale)));
        assert!(matches!(s.frozen_for_owner(target,2,3,101,|_|Err(Error::Denied)),Err(Error::Denied)));
        s.retire_target(target,|_|Ok(())).unwrap();
        assert!(matches!(s.frozen_for_owner(target,2,3,101,|_|panic!()),Err(Error::Stale)));
        assert_eq!(s.register_target(target,|_|panic!()),Err(Error::Stale));
        assert_eq!(s.register_target(bad,|_|panic!()),Err(Error::Stale));
        let next=Target{object:Identity{generation:2,..target.object},owner:bad.owner,..target};
        s.register_target(next,|_|Ok(())).unwrap();
        assert!(matches!(s.frozen_for_owner(next,2,3,102,|_|panic!()),Err(Error::NotReady)));
        assert_eq!(s.capture(2,3,102,[None;8],&[o],|_|panic!()),Err(Error::Denied));
        assert_eq!(s.capture(2,3,102,[None;8],&[DomainObservation{target:next,..o}],|_|Ok(())),Ok(2));
        assert_eq!(s.frozen_for_owner(next,2,3,103,|_|Ok(())).unwrap().target_generation,2);
        assert!(matches!(s.frozen_for_owner(target,2,3,103,|_|panic!()),Err(Error::Stale)));
    }
    #[test]
    fn snapshot_scope_redaction_age_and_retirement(){
        let m=manifest();let owner=Identity{id:100,generation:1};
        let target=Target{domain:12,object:Identity{id:200,generation:1},owner};
        let mut store=SnapshotStore::new(3).unwrap();
        store.register_target(target,|_|Ok(())).unwrap();
        let role=m.members[1];
        let grant=ViewGrant{cap:9,holder:role.actor,endpoint:role.endpoint_id,view:SnapshotView::RedactedSecurity,
            selector:5,domain:12,target:target.object,allowed_fields:(1<<6)|(1<<8)|(1<<10)};
        store.register_view(&m,grant,|_|Ok(())).unwrap();
        let observation=DomainObservation{target,fields:[Some(5),None,Some(1),None]};
        let common=[Some(10),None,None,None,None,None,None,None];
        assert_eq!(store.capture(2,3,1000,common,&[observation],|_|Err(Error::Denied)),Err(Error::Denied));
        assert!(matches!(store.read(&m,role.actor,0,9,12,5,2,3,1000,|_|Ok(())),Err(Error::NotReady)));
        assert_eq!(store.capture(2,3,1000,common,&[observation],|_|Ok(())),Ok(1));
        let wire=store.read(&m,role.actor,0,9,12,5,2,3,2000,|_|Ok(())).unwrap();
        let snap=SnapshotReplyV3::decode(&wire).unwrap();
        assert_eq!(snap.snapshot_seq,1);assert_eq!(snap.fields[6],Some(1));
        assert_eq!(snap.fields[8],Some(5));assert_eq!(snap.fields[0],None);assert_eq!(snap.fields[9],None);
        assert_eq!(store.read(&m,m.members[0].actor,0,9,12,5,2,3,2000,|_|panic!()),Err(Error::Denied));
        assert_eq!(store.read(&m,role.actor,0,9,12,5,2,3,1000+MAX_AGE_NS,|_|Ok(())),Err(Error::Stale));
        assert_eq!(store.read(&m,role.actor,0,9,12,5,3,3,2000,|_|Ok(())),Err(Error::Stale));
        store.retire_target(target,|_|Ok(())).unwrap();
        assert_eq!(store.read(&m,role.actor,0,9,12,5,2,3,2000,|_|panic!()),Err(Error::Denied));
    }
}

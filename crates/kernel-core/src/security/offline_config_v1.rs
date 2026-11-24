//! OfflineConfigEnvelope v1 admission (V0.19.9 安§0.2).
//! Structural decoding, payload hash and signature verification precede
//! any trusted startup decision. The public key and schema verifier come
//! exclusively from the immutable trusted boot catalog. No online admin.
//! Unfrozen payload schemas, new configuration transitions and missing
//! signature/volume evidence stay closed.
use super::{Error,file_index_v0199::SecurityStateStoreV2};
use sha2::{Digest,Sha256};
pub const HEADER:usize=256;
pub const SIGNATURE:usize=64;
pub const MAX_PAYLOAD:usize=65536;
pub const SIGNATURE_LABEL:&[u8]=b"CYX/OFFLINE/v1";
fn u16at(b:&[u8],i:usize)->u16{u16::from_le_bytes(b[i..i+2].try_into().unwrap())}
fn u32at(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}
fn u64at(b:&[u8],i:usize)->u64{u64::from_le_bytes(b[i..i+8].try_into().unwrap())}
fn hash(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Principal{pub id:u64,pub generation:u64}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct ConfigHeader{
    pub fs_uuid:[u8;16],pub generation:u64,pub rule_generation:u64,
    pub security_generation:u64,pub key_generation:u64,
    pub rule_hash:[u8;32],pub security_hash:[u8;32],pub key_manifest_hash:[u8;32],
    pub payload_hash:[u8;32],pub clear_isolation_bitmap:u64,pub mode:u16,
}
/// Exact independently authenticated Rule/Security/key catalog. The
/// sub-schema owner must also validate the length-prefixed payload lists
/// against its frozen schemas (service/trial/object creation, no trailing
/// bytes). No interpretation of those unfrozen lists is invented here.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct CatalogBindings{
    pub rule_generation:u64,pub security_generation:u64,pub key_generation:u64,
    pub rule_hash:[u8;32],pub security_hash:[u8;32],pub key_manifest_hash:[u8;32],
}
pub struct VerifiedOfflineConfig<'a>{
    header:ConfigHeader,principals:[Principal;16],digest:[u8;32],wire:&'a[u8],
}
impl<'a> VerifiedOfflineConfig<'a>{
    /// The caller supplies immutable private copied bytes and a real
    /// Ed25519 verifier. Signature is over label || exact header || payload,
    /// NOT a hash standing in for this message. A backend error denies boot.
    /// verify_payload must validate all *current frozen* sub-schema bytes.
    pub fn verify(
        wire:&'a[u8],locked_public_key:&[u8;32],catalog:CatalogBindings,
        verify_ed25519:impl FnOnce(&[u8;32],&[u8],&[u8],&[u8;64])->Result<(),Error>,
        verify_payload:impl FnOnce(&ConfigHeader,&[Principal;16],&[u8])->Result<(),Error>,
    )->Result<Self,Error>{
        if !(HEADER+256+SIGNATURE..=HEADER+MAX_PAYLOAD+SIGNATURE).contains(&wire.len())
            ||u32at(wire,0)!=0x43594f46||u16at(wire,4)!=1||u16at(wire,6)!=256
            ||u32at(wire,8) as usize!=wire.len()||wire[202..256].iter().any(|&v|v!=0){
            return Err(Error::Invalid);
        }
        let n=u32at(wire,12) as usize;
        if !(256..=MAX_PAYLOAD).contains(&n)||HEADER+n+SIGNATURE!=wire.len(){
            return Err(Error::Invalid);
        }
        let header=ConfigHeader{
            fs_uuid:wire[16..32].try_into().unwrap(),generation:u64at(wire,32),
            rule_generation:u64at(wire,40),security_generation:u64at(wire,48),key_generation:u64at(wire,56),
            rule_hash:wire[64..96].try_into().unwrap(),security_hash:wire[96..128].try_into().unwrap(),
            key_manifest_hash:wire[128..160].try_into().unwrap(),payload_hash:wire[160..192].try_into().unwrap(),
            clear_isolation_bitmap:u64at(wire,192),mode:u16at(wire,200),
        };
        if header.fs_uuid==[0;16]||header.generation==0||header.rule_generation==0
            ||header.security_generation==0||header.key_generation==0||header.mode>2
            ||header.clear_isolation_bitmap&!0xffff!=0||locked_public_key==&[0;32]
            ||[header.rule_hash,header.security_hash,header.key_manifest_hash].contains(&[0;32]){
            return Err(Error::Invalid);
        }
        let payload=&wire[HEADER..HEADER+n];
        if hash(payload)!=header.payload_hash{return Err(Error::Conflict);}
        if catalog!=(CatalogBindings{
            rule_generation:header.rule_generation,security_generation:header.security_generation,
            key_generation:header.key_generation,rule_hash:header.rule_hash,
            security_hash:header.security_hash,key_manifest_hash:header.key_manifest_hash,
        }){return Err(Error::Conflict);}
        let mut principals=[Principal{id:0,generation:0};16];
        for i in 0..16{
            let p=Principal{id:u64at(payload,16*i),generation:u64at(payload,16*i+8)};
            if p.id==0||p.generation==0||principals[..i].iter().any(|old|old.id==p.id){
                return Err(Error::Invalid);
            }
            principals[i]=p;
        }
        verify_ed25519(locked_public_key,SIGNATURE_LABEL,&wire[..HEADER+n],
            wire[HEADER+n..].try_into().unwrap())?;
        verify_payload(&header,&principals,&payload[256..])?;
        Ok(Self{header,principals,digest:hash(wire),wire})
    }
    pub fn header(&self)->ConfigHeader{self.header}
    pub fn principals(&self)->&[Principal;16]{&self.principals}
    pub fn digest(&self)->[u8;32]{self.digest}
    pub fn wire(&self)->&'a[u8]{self.wire}
    /// Only the exact already-confirmed config may start ordinary work.
    /// A higher signed config needs a separate real persistent transition;
    /// same generation + different hash is a rollback/conflict, never a
    /// new admission. No restart implicitly clears isolation bits.
    pub fn check_committed(&self,state:&SecurityStateStoreV2)->Result<(),Error>{
        let h=self.header;
        if h.fs_uuid!=state.fs_uuid||h.generation<state.offline_config_generation
            ||h.rule_generation<state.rule_min_generation||h.security_generation<state.security_min_generation
            ||h.key_generation<state.key_generation{return Err(Error::Stale);}
        if h.generation!=state.offline_config_generation||h.key_generation!=state.key_generation{
            return Err(Error::Busy);
        }
        if self.digest!=state.offline_config_hash{return Err(Error::Conflict);}
        Ok(())
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    fn fixture()->([u8;577],CatalogBindings){
        let mut b=[0u8;577];
        b[..4].copy_from_slice(&0x43594f46u32.to_le_bytes());
        b[4..6].copy_from_slice(&1u16.to_le_bytes());b[6..8].copy_from_slice(&256u16.to_le_bytes());
        b[8..12].copy_from_slice(&577u32.to_le_bytes());b[12..16].copy_from_slice(&257u32.to_le_bytes());
        b[16..32].fill(1);
        for (at,v) in [(32,7u64),(40,3),(48,4),(56,5)]{b[at..at+8].copy_from_slice(&v.to_le_bytes());}
        b[64..96].fill(2);b[96..128].fill(3);b[128..160].fill(4);
        for i in 0..16{
            let at=256+i*16;b[at..at+8].copy_from_slice(&(i as u64+1).to_le_bytes());
            b[at+8..at+16].copy_from_slice(&1u64.to_le_bytes());
        }
        b[512]=42;let p=hash(&b[256..513]);b[160..192].copy_from_slice(&p);b[513..].fill(9);
        (b,CatalogBindings{rule_generation:3,security_generation:4,key_generation:5,
            rule_hash:[2;32],security_hash:[3;32],key_manifest_hash:[4;32]})
    }
    // A transport test double, explicitly not an Ed25519 KAT or signed
    // production fixture. Assert the complete signed message is passed.
    fn parsed<'a>(b:&'a[u8],c:CatalogBindings)->Result<VerifiedOfflineConfig<'a>,Error>{
        VerifiedOfflineConfig::verify(b,&[1;32],c,|key,label,message,sig|{
            assert_eq!(key,&[1;32]);assert_eq!(label,b"CYX/OFFLINE/v1");
            assert_eq!(message,&b[..513]);
            if sig==&[9;64]{Ok(())}else{Err(Error::Unauthorized)}
        },|_,p,lists|{
            assert_eq!(p[15].id,16);
            if lists==[42]{Ok(())}else{Err(Error::Invalid)}
        })
    }
    #[test]
    fn same_committed_config_only_and_no_implicit_clear(){
        let (b,c)=fixture();let v=parsed(&b,c).unwrap();
        let mut state=SecurityStateStoreV2{fs_uuid:[1;16],state_generation:1,rule_min_generation:3,
            security_min_generation:4,key_generation:5,isolated_service_bitmap:2,last_boot_epoch:1,
            offline_config_generation:7,offline_config_hash:v.digest(),service_generations:[1;16]};
        assert_eq!(v.check_committed(&state),Ok(()));
        assert_eq!(state.isolated_service_bitmap,2);
        state.offline_config_hash=[9;32];assert_eq!(v.check_committed(&state),Err(Error::Conflict));
        state.offline_config_generation=8;assert_eq!(v.check_committed(&state),Err(Error::Stale));
        state.offline_config_generation=6;assert_eq!(v.check_committed(&state),Err(Error::Busy));
    }
    #[test]
    fn invalid_signature_catalog_reserved_and_payload_deny_admission(){
        let (b,c)=fixture();
        let mut bad=b;bad[513]^=1;assert!(matches!(parsed(&bad,c),Err(Error::Unauthorized)));
        let mut bad=b;bad[512]^=1;assert!(matches!(parsed(&bad,c),Err(Error::Conflict)));
        let mut bad=b;bad[202]=1;assert!(matches!(parsed(&bad,c),Err(Error::Invalid)));
        assert!(matches!(parsed(&b,CatalogBindings{key_generation:6,..c}),Err(Error::Conflict)));
        assert!(matches!(VerifiedOfflineConfig::verify(&b,&[1;32],c,|_,_,_,_|Ok(()),|_,_,_|Err(Error::Invalid)),Err(Error::Invalid)));
    }
}

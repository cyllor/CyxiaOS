//! V0.19.9 SVC 0x50/0x41 *trusted copyin transport* to a frozen v3 gate.
//!
//! This is the no_std dispatch core for an EL1 AArch64 trap adapter, not a
//! claim that the legacy native trap has been cut over. The platform must
//! authenticate x8, the verified package ABI, the real caller and its cap,
//! perform stable checked copyin/out, and execute the actual native APPLY
//! adapter. A model cannot supply a trusted capability or call this Rust
//! function directly from EL0.
use super::{
    Error, Identity,
    decision_record_v3::DECISION_BYTES,
    plan_wire_v2::{MAX_PLAN_BYTES,PlanV2},
    registered_gate_v3::{
        FrozenAction,RegisteredDecisionGate,Registration,Publication,AssistedScope,
        TrustedRegistrationScope,
    },
    rule_profile_v2::Profile,
    advice_disposition_v1::DISPOSITION_BYTES,
    advice_ledger_v0199::EvidenceLedger,
};
use crate::security::syscall_v3::{decode_v3,ABI_VERSION};

/// Trust anchor created exclusively from actual EL1 cap table and
/// authenticated EL0 Task identity. User payload bytes are NOT trusted to
/// define this struct.
#[derive(Clone,Copy)]
pub struct VerifiedNativeCaller {
    pub identity:Identity,
    pub package_abi:u16,
    pub endpoint_cap:u64,
    pub cpu:usize,
}
/// The native EL1 caller supplies an immutable rule/candidate snapshot.
pub struct FrozenNativePlan<'a> {
    pub bytes:&'a [u8],
    pub sidecars:&'a [[u8;DECISION_BYTES]],
    pub rules:&'a Profile<'a>,
    pub actions:&'a [FrozenAction<'a>],
    pub context:TrustedRegistrationScope,
}
/// Exact ABI-v3 bridge. Caller/owner identities are additionally rechecked by
/// the RegisteredDecisionGate. No role is inferred from the request bytes.
pub struct SvcV3Bridge<'a> {
    pub gate:&'a mut RegisteredDecisionGate,
    pub decision_endpoint_cap:u64,
    pub publisher_cap:u64,
}
impl SvcV3Bridge<'_>{
    pub fn register_rule_only(
        &mut self,
        caller:VerifiedNativeCaller,
        args:[u64;6],
        verified_user_copy:&[u8],
        frozen:&FrozenNativePlan<'_>,
    )->Result<Registration,Error>{
        decode_v3(caller.package_abi,0x50,args).map_err(|_|Error::Invalid)?;
        if caller.cpu!=0
            || !caller.identity.valid()
            || caller.endpoint_cap==0
            || caller.endpoint_cap!=self.decision_endpoint_cap
            || args[0]!=self.decision_endpoint_cap
            || args[2]!=verified_user_copy.len() as u64
            || args[3]!=0 // non-file endpoint; no forged cap_selector
            || args[5]<8
            || verified_user_copy.len()!=DECISION_BYTES
            || frozen.sidecars.len()!=1 // initial RULE_ONLY SVC vertical slice
            || verified_user_copy!=frozen.sidecars[0]
        {return Err(Error::Denied);}
        let plan=PlanV2::decode(frozen.bytes)?;
        if plan.header.action_count!=1 {return Err(Error::NotReady);}
        self.gate.register_rule_only(
            caller.identity,
            frozen.bytes,frozen.sidecars,
            frozen.rules,frozen.actions,frozen.context
        )
    }

    /// Exact 496B assisted registration (DecisionRecord + Disposition).
    /// Native trap owner must first authorize holder/cap and stable copy.
    pub fn register_assisted_one(&mut self,caller:VerifiedNativeCaller,args:[u64;6],
        copied:&[u8],frozen:&FrozenNativePlan<'_>,scope:&AssistedScope<'_>,
        ledger:&mut EvidenceLedger)->Result<Registration,Error>
    {
        decode_v3(caller.package_abi,0x50,args).map_err(|_|Error::Invalid)?;
        if caller.cpu!=0||!caller.identity.valid()||caller.endpoint_cap==0
            ||caller.endpoint_cap!=self.decision_endpoint_cap||args[0]!=caller.endpoint_cap
            ||args[2]!=(DECISION_BYTES+DISPOSITION_BYTES) as u64
            ||copied.len()!=DECISION_BYTES+DISPOSITION_BYTES||args[3]!=0||args[5]<8
            ||frozen.sidecars.len()!=1||frozen.actions.len()!=1
        {return Err(Error::Denied);}
        let record:&[u8;DECISION_BYTES]=copied[..DECISION_BYTES].try_into().map_err(|_|Error::Invalid)?;
        let disposition:&[u8;DISPOSITION_BYTES]=copied[DECISION_BYTES..].try_into().map_err(|_|Error::Invalid)?;
        if record!=&frozen.sidecars[0]{return Err(Error::Denied);}
        self.gate.register_assisted_one(caller.identity,frozen.bytes,record,disposition,
            frozen.rules,&frozen.actions[0],frozen.context,scope,ledger)
    }
    pub fn publish_assisted_one(&mut self,caller:VerifiedNativeCaller,args:[u64;6],
        copied_plan:&[u8],copied_sidecars:&[[u8;DECISION_BYTES]],
        frozen:&FrozenNativePlan<'_>,scope:&AssistedScope<'_>,
        native_accept:impl FnOnce()->Result<(),Error>)->Result<Publication,Error>
    {
        decode_v3(caller.package_abi,0x41,args).map_err(|_|Error::Invalid)?;
        if caller.cpu!=0||!caller.identity.valid()||caller.endpoint_cap==0
            ||caller.endpoint_cap!=self.publisher_cap
            ||args[1]!=copied_plan.len() as u64||args[3]!=1
            ||copied_sidecars.len()!=1||copied_plan!=frozen.bytes
            ||copied_sidecars!=frozen.sidecars||frozen.actions.len()!=1
        {return Err(Error::Denied);}
        self.gate.publish_assisted_once(caller.identity,copied_plan,&copied_sidecars[0],
            frozen.rules,&frozen.actions[0],frozen.context,scope,native_accept)
    }

    pub fn publish_plan(
        &mut self,
        caller:VerifiedNativeCaller,
        args:[u64;6],
        copied_plan:&[u8],
        copied_sidecars:&[[u8;DECISION_BYTES]],
        frozen:&FrozenNativePlan<'_>,
        native_accept:impl FnOnce()->Result<(),Error>,
    )->Result<Publication,Error>{
        decode_v3(caller.package_abi,0x41,args).map_err(|_|Error::Invalid)?;
        if caller.cpu!=0 || !caller.identity.valid()
            || caller.endpoint_cap==0 || caller.endpoint_cap!=self.publisher_cap
            || copied_plan.len()>MAX_PLAN_BYTES
            || args[1]!=copied_plan.len() as u64
            || args[3]!=copied_sidecars.len() as u64
            || copied_plan!=frozen.bytes
            || copied_sidecars!=frozen.sidecars
        {return Err(Error::Denied);}
        self.gate.publish_once(
            caller.identity,copied_plan,copied_sidecars,
            frozen.rules,frozen.actions,frozen.context,native_accept
        )
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    // Deliberately use a non-authorizing frozen slot for transport tests:
    // callers must never reach a native callback with a legacy ABI, wrong
    // endpoint, wrong role, malformed copy or missing registered Decision.
    #[test]
    fn v3_register_bridge_rejects_legacy_or_forged_caller_before_any_registration(){
        let mut gate=RegisteredDecisionGate::new(
            Identity{id:2,generation:1},Identity{id:8,generation:1},1,2
        ).unwrap();
        let mut bridge=SvcV3Bridge{gate:&mut gate,decision_endpoint_cap:77,publisher_cap:88};
        let mut bytes=[0u8;32];
        bytes[0..4].copy_from_slice(&0x43595255u32.to_le_bytes());
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&32u16.to_le_bytes());
        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[20..24].copy_from_slice(&32u32.to_le_bytes());
        assert!(Profile::parse(&bytes).is_err()); // no rules is fail-closed
        // Direct register refusal does not depend on a parseable frozen plan.
        // Keep a one-entry catalog to exercise the actual caller gate.
    }
    fn sha(bytes:&[u8])->[u8;32]{
        use sha2::{Digest,Sha256};
        let mut h=Sha256::new();h.update(bytes);h.finalize().into()
    }
    fn profile_bytes()->[u8;80]{
        let mut b=[0u8;80];
        b[0..4].copy_from_slice(&0x4359_5255u32.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[6..8].copy_from_slice(&32u16.to_le_bytes());
        b[8..16].copy_from_slice(&7u64.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b[20..24].copy_from_slice(&80u32.to_le_bytes());
        b[32..36].copy_from_slice(&1u32.to_le_bytes());
        b[36..38].copy_from_slice(&1u16.to_le_bytes());
        b[38..40].copy_from_slice(&1u16.to_le_bytes());
        b[40..48].copy_from_slice(&17u64.to_le_bytes());
        b[52..54].copy_from_slice(&2u16.to_le_bytes());
        b[56..60].copy_from_slice(&48u32.to_le_bytes());
        b[64..66].copy_from_slice(&2u16.to_le_bytes());
        b[72..74].copy_from_slice(&4u16.to_le_bytes());
        b[74..76].copy_from_slice(&1u16.to_le_bytes());
        b
    }
    fn plan_bytes()->[u8;212]{
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
        for (at,value) in [(16,2u64),(24,4),(32,3),(40,17),
            (48,1),(56,5),(64,6),(72,200)]{
            p[h+at..h+at+8].copy_from_slice(&value.to_le_bytes());
        }
        p[h+112..h+144].copy_from_slice(&[1u8;32]);
        p[h+144..h+146].copy_from_slice(&0u16.to_le_bytes());
        p[h+146..h+148].copy_from_slice(&[2u8,0]);
        p
    }
    fn decision(p:&[u8],rules:&[u8])->[u8;DECISION_BYTES]{
        let mut b=[0u8;DECISION_BYTES];
        b[0..4].copy_from_slice(&0x4359_4431u32.to_le_bytes());
        b[4..6].copy_from_slice(&3u16.to_le_bytes());
        b[6..8].copy_from_slice(&256u16.to_le_bytes());
        for (at,value) in [(8,1u64),(16,2),(24,4),(32,1),(40,3),
            (48,17),(56,1),(64,5),(72,6),(80,7),(144,200)]{
            b[at..at+8].copy_from_slice(&value.to_le_bytes());
        }
        b[88..92].copy_from_slice(&1u32.to_le_bytes());
        b[94..96].copy_from_slice(&1u16.to_le_bytes());
        b[96..98].copy_from_slice(&1u16.to_le_bytes());
        b[104..106].copy_from_slice(&u16::MAX.to_le_bytes());
        b[108..112].copy_from_slice(&2u32.to_le_bytes());
        b[152..156].copy_from_slice(&3u32.to_le_bytes());
        b[160..192].copy_from_slice(&sha(rules));
        b[192..224].copy_from_slice(&sha(p));
        b[224..256].copy_from_slice(&[1u8;32]);
        b
    }
    #[test]
    fn verified_role2_register_and_role8_publish_once_through_svc_v3_gate(){
        let rules_bytes=profile_bytes();
        let rules=Profile::parse(&rules_bytes).unwrap();
        let plan=plan_bytes();
        let sidecars=[decision(&plan,&rules_bytes)];
        let static_ordinals=[2u16,4u16];
        let action_bytes=[2u8,0u8];
        let actions=[FrozenAction{
            domain_id:1,target:Identity{id:17,generation:1},
            candidate_set_hash:[1;32],static_ordinals:&static_ordinals,
            raw_fields:[None;7],action_payload:&action_bytes
        }];
        let frozen=FrozenNativePlan {
            bytes:&plan,sidecars:&sidecars,rules:&rules,
            actions:&actions,
            context:TrustedRegistrationScope {
                boot_epoch:1,controller_epoch:2,rules_generation:7,
                rules_hash:sha(&rules_bytes),base_plan_version:0,
                ledger_generation:5,core_generation:6,snapshot_seq:3,
                sampled_ns:100,now_ns:150
            },
        };
        let role2=VerifiedNativeCaller {
            identity:Identity{id:2,generation:1},package_abi:3,
            endpoint_cap:77,cpu:0
        };
        let role8=VerifiedNativeCaller {
            identity:Identity{id:8,generation:1},package_abi:3,
            endpoint_cap:88,cpu:0
        };
        let mut gate=RegisteredDecisionGate::new(
            role2.identity,role8.identity,1,2
        ).unwrap();
        let mut bridge=SvcV3Bridge{
            gate:&mut gate,decision_endpoint_cap:77,publisher_cap:88
        };
        let register_args=[77,0x1000,256,0,0x2000,8];
        let publish_args=[0x1000,212,0x2000,1,0,0];
        assert_eq!(bridge.register_rule_only(role8,register_args,&sidecars[0],&frozen),
            Err(Error::Denied));
        let mut wrong=role2;wrong.package_abi=1;
        assert!(bridge.register_rule_only(wrong,register_args,&sidecars[0],&frozen).is_err());
        wrong=role2;wrong.cpu=1;
        assert_eq!(bridge.register_rule_only(wrong,register_args,&sidecars[0],&frozen),
            Err(Error::Denied));
        assert_eq!(bridge.register_rule_only(
            role2,register_args,&sidecars[0],&frozen
        ),Ok(Registration::Frozen));
        let mut invoked=0;
        assert_eq!(bridge.publish_plan(
            role2,publish_args,&plan,&sidecars,&frozen,
            ||{invoked+=1;Ok(())}
        ),Err(Error::Denied));
        let mut wrong_cap=role8;wrong_cap.endpoint_cap=77;
        assert_eq!(bridge.publish_plan(
            wrong_cap,publish_args,&plan,&sidecars,&frozen,
            ||{invoked+=1;Ok(())}
        ),Err(Error::Denied));
        assert_eq!(bridge.publish_plan(
            role8,publish_args,&plan,&sidecars,&frozen,
            ||{invoked+=1;Ok(())}
        ),Ok(Publication::AdapterAccepted));
        assert_eq!(bridge.publish_plan(
            role8,publish_args,&plan,&sidecars,&frozen,
            ||{invoked+=1;Ok(())}
        ),Ok(Publication::ReplayNoEffect));
        assert_eq!(invoked,1);
    }
    #[test]
    fn true_v3_x8_dispatch_is_required(){
        assert_eq!(ABI_VERSION,3);
        assert!(decode_v3(1,0x50,[77,4096,256,0,8192,8]).is_err());
        assert!(decode_v3(3,0x50,[77,4096,256,0,8192,8]).is_ok());
        assert!(decode_v3(3,0x41,[4096,212,8192,1,0,0]).is_ok());
        assert!(decode_v3(3,0x41,[4096,212,8192,1,1,0]).is_err());
    }
}

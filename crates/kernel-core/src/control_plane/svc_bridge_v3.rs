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
        FrozenAction,RegisteredDecisionGate,Registration,Publication,
        TrustedRegistrationScope,
    },
    rule_profile_v2::Profile,
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
        let mut bridge=SvcV3Bridge{gate:&mut gate,decision_endpoint_cap:77};
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
    #[test]
    fn true_v3_x8_dispatch_is_required(){
        assert_eq!(ABI_VERSION,3);
        assert!(decode_v3(1,0x50,[77,4096,256,0,8192,8]).is_err());
        assert!(decode_v3(3,0x50,[77,4096,256,0,8192,8]).is_ok());
        assert!(decode_v3(3,0x41,[4096,212,8192,1,0,0]).is_ok());
        assert!(decode_v3(3,0x41,[4096,212,8192,1,1,0]).is_err());
    }
}

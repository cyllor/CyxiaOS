//! V0.19.9 system-call ABI v3 register/argument preflight (SEC-S).
//!
//! The input is a *copied* AArch64 EL0 x8 + x0..x5 register image plus the
//! trusted startup-package ABI tag, not an SVC immediate or Linux ABI.
//! Validation here is necessary but not sufficient. The real EL1 trap handler
//! must also authorize the caller/capability, check actual user VA permissions,
//! copy all payloads to bounded kernel memory, and validate subprotocol bytes.
//! In particular 0x50 cannot be trusted based on user-supplied endpoint labels.
use super::{Error, syscall::{Syscall,decode_syscall}};

pub const ABI_VERSION:u16=3;
pub const MAX_PLAN_BYTES:usize=6464;
pub const MAX_DECISIONS:usize=16;
pub const DECISION_RECORD_BYTES:usize=256;
pub const MAX_APPLY_REPORT_BYTES:usize=96+256;

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct ValidatedCall {
    pub operation:Syscall,
    pub args:[u64;6],
}

/// The package's trusted ABI selection must be checked at every native trap.
/// This module intentionally has no auto-migration from the v1 calling
/// convention (SVC immediate + x0..x4 + multiple return registers).
pub fn decode_v3(verified_package_abi:u16,x8:u64,args:[u64;6])
    ->Result<ValidatedCall,Error>
{
    if verified_package_abi!=ABI_VERSION{return Err(Error::Invalid);}
    let operation=decode_syscall(x8)?;
    let zero_tail=|start:usize| args[start..].iter().all(|v|*v==0);
    let allowed=match x8{
        0x01 => zero_tail(1) && args[0]==(args[0] as i32 as i64 as u64),
        0x02|0x04 => zero_tail(0),
        0x03 => zero_tail(1),
        0x10 => zero_tail(5)
            && args[0]!=0 && args[1]!=0 && args[2]!=0
            && args[3]!=0 && args[4]!=0,
        0x11 => zero_tail(4)
            && args[0]!=0 && args[1]!=0 && args[2]!=0 && args[3]!=0,
        0x12 => zero_tail(3) && args[0]!=0 && args[1]!=0 && args[2]!=0,
        0x13 => zero_tail(5)
            && args[0]!=0 && args[1]!=0 && args[3]!=0 && args[4]!=0,
        0x20 => args[1]!=0 && args[2]&!1==0
            && args[1]%4096==0 && args[4]!=0 && args[5]!=0,
        0x21 => zero_tail(5)
            && args[0]!=0 && args[1]!=0
            && args[2]%4096==0 && matches!(args[3],1|2)
            && args[4]!=0,
        0x22 => zero_tail(4)
            && args[0]!=0 && args[1]%4096==0
            && args[2]!=0 && args[2]%4096==0 && args[3]!=0,
        0x30 => args[0]!=0 && args[1]!=0 && args[2]<=512
            && args[3]!=0 && args[5]&!1==0
            && (args[4]!=0 || args[5]&1==1),
        0x31 => args[0]!=0 && args[4]&!3==0 && args[5]!=0
            && (if args[4]&2!=0 {
                args[4]==2 && args[1]==0 && args[2]==0 && args[3]==0
            }else{
                args[1]!=0 && args[2]>=552 && (args[3]!=0 || args[4]&1!=0)
            }),
        0x32 => zero_tail(5) && args[0]!=0 && args[1]!=0
            && args[2]!=0 && args[3]!=0 && args[4]!=0,
        0x40 => zero_tail(5)
            && args[0]!=0 && (1..=15).contains(&args[1])
            && args[3]!=0 && args[4]>=264,
        0x41 => zero_tail(4)
            && args[0]!=0 && args[1]>=64
            && args[1]<=MAX_PLAN_BYTES as u64
            && args[2]!=0 && (1..=MAX_DECISIONS as u64).contains(&args[3]),
        0x42 => zero_tail(4)
            && args[0]!=0 && args[1]==24
            && args[2]!=0 && args[3]>=64,
        0x43 => zero_tail(3)
            && args[0]!=0 && args[1]!=0
            && (96..=MAX_APPLY_REPORT_BYTES as u64).contains(&args[2]),
        0x50 => args[0]!=0 && args[1]!=0 && args[2]!=0
            && args[4]!=0 && args[5]!=0,
        _=>false,
    };
    if !allowed{return Err(Error::Invalid);}
    Ok(ValidatedCall {operation,args})
}

/// An independently authenticated EL1 role/capability check must run on both
/// sides of any blocking/retry boundary. A caller may not select its role by
/// changing x8, a service ID or any user-visible field.
pub fn requires_protected_capability(operation:Syscall)->bool{
    matches!(operation,Syscall::SubmitPlan|Syscall::ReportResult|Syscall::ServiceCall)
}

#[cfg(test)]
mod tests{
    use super::*;
    fn allowed(n:u64,a:[u64;6])->bool{decode_v3(3,n,a).is_ok()}

    #[test]
    fn frozen_nineteen_calls_have_unique_syscall_numbers(){
        let mut seen=[false;256];
        let nums=[0x01,0x02,0x03,0x04,0x10,0x11,0x12,0x13,
            0x20,0x21,0x22,0x30,0x31,0x32,0x40,0x41,0x42,0x43,0x50];
        assert_eq!(nums.len(),19);
        for n in nums{
            assert!(!seen[n as usize]);
            seen[n as usize]=true;
            assert!(decode_syscall(n).is_ok());
        }
        assert_eq!(decode_syscall(0x51),Err(Error::Invalid));
    }
    #[test]
    fn v1_abi_or_svc_immediate_cannot_silently_become_v3(){
        assert_eq!(decode_v3(1,0x02,[0;6]),Err(Error::Invalid));
        assert_eq!(decode_v3(0,0x02,[0;6]),Err(Error::Invalid));
        assert_eq!(decode_v3(3,0,[0;6]),Err(Error::Invalid));
        assert!(allowed(0x02,[0;6]));
        assert!(!allowed(0x02,[0,0,0,0,0,1]));
        assert!(allowed(0x01,[u64::MAX,0,0,0,0,0]));
        assert!(!allowed(0x01,[0x0000_0000_ffff_ffff,0,0,0,0,0]));
        assert!(allowed(0x04,[0;6]));
    }
    #[test]
    fn v3_publication_and_decision_capability_arguments_fail_closed(){
        assert!(allowed(0x41,[0x1000,212,0x2000,1,0,0]));
        assert!(!allowed(0x41,[0x1000,212,0x2000,0,0,0]));
        assert!(!allowed(0x41,[0x1000,6465,0x2000,1,0,0]));
        assert!(!allowed(0x41,[0x1000,212,0x2000,1,1,0]));
        assert!(!allowed(0x41,[0x1000,212,0x2000,1,0,1]));
        assert!(allowed(0x42,[0x1000,24,0x2000,64,0,0]));
        assert!(!allowed(0x42,[0x1000,16,0x2000,64,0,0]));
        assert!(allowed(0x43,[3,0x1000,96,0,0,0]));
        assert!(!allowed(0x43,[3,0x1000,95,0,0,0]));
        assert!(!allowed(0x43,[3,0x1000,96,1,0,0]));
        assert!(allowed(0x50,[3,0x1000,256,0,0x2000,8]));
        assert!(!allowed(0x50,[3,0x1000,256,0,0x2000,0]));
        assert!(requires_protected_capability(Syscall::SubmitPlan));
        assert!(requires_protected_capability(Syscall::ServiceCall));
        assert!(!requires_protected_capability(Syscall::Clock));
    }
    #[test]
    fn read_only_and_nonblocking_ipc_state_machine_argument_gate(){
        assert!(allowed(0x31,[3,0x1000,552,100,0,1]));
        assert!(allowed(0x31,[3,0,0,0,2,1]));
        assert!(!allowed(0x31,[3,0x1000,552,100,2,1]));
        assert!(!allowed(0x31,[3,0,0,0,2,0]));
        assert!(!allowed(0x31,[3,0x1000,551,100,0,1]));
        assert!(!allowed(0x30,[3,0x1000,32,1,0,0]));
        assert!(allowed(0x30,[3,0x1000,32,1,0,1]));
        assert!(!allowed(0x30,[3,0x1000,32,1,100,2]));
        assert!(allowed(0x40,[4,12,1,0x1000,264,0]));
        assert!(!allowed(0x40,[4,16,1,0x1000,264,0]));
        assert!(allowed(0x32,[0x1000,32,0x2000,512,100,0]));
        assert!(!allowed(0x32,[0x1000,32,0x2000,512,100,1]));
    }
}
